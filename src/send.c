/* Copyright (c) Mark Harmstone 2017
 * 
 * This file is part of WinBtrfs.
 * 
 * WinBtrfs is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public Licence as published by
 * the Free Software Foundation, either version 3 of the Licence, or
 * (at your option) any later version.
 * 
 * WinBtrfs is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public Licence for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public Licence
 * along with WinBtrfs.  If not, see <http://www.gnu.org/licenses/>. */

#include "btrfs_drv.h"

typedef struct {
    HANDLE h;
    UINT8* data;
    ULONG datalen;
} send_context;

static void send_write_data(send_context* context, void* data, ULONG datalen) {
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    
    Status = ZwWriteFile(context->h, NULL, NULL, NULL, &iosb, data, datalen, NULL, NULL);
    if (!NT_SUCCESS(Status))
        ERR("ZwWriteFile returned %08x\n", Status);
}

static void send_command(send_context* context, UINT16 cmd) {
    btrfs_send_command* bsc = (btrfs_send_command*)&context->data[context->datalen];
    
    bsc->cmd = cmd;
    bsc->csum = 0;

    context->datalen += sizeof(btrfs_send_command);
}

static void send_command_finish(send_context* context, ULONG pos) {
    btrfs_send_command* bsc = (btrfs_send_command*)&context->data[pos];
    
    bsc->length = context->datalen - pos - sizeof(btrfs_send_command);
    bsc->csum = calc_crc32c(0, (UINT8*)bsc, context->datalen - pos);
}

static void send_add_tlv(send_context* context, UINT16 type, void* data, UINT16 length) {
    btrfs_send_tlv* tlv = (btrfs_send_tlv*)&context->data[context->datalen];

    tlv->type = type;
    tlv->length = length;

    if (length > 0)
        RtlCopyMemory(&tlv[1], data, length);

    context->datalen += sizeof(btrfs_send_tlv) + length;
}

static char* uint64_to_char(UINT64 num, char* buf) {
    char *tmp, tmp2[20];
    
    if (num == 0) {
        buf[0] = '0';
        return buf + 1;
    }
    
    tmp = &tmp2[20];
    while (num > 0) {
        tmp--;
        *tmp = (num % 10) + '0';
        num /= 10;
    }
    
    RtlCopyMemory(buf, tmp, tmp2 + sizeof(tmp2) - tmp);

    return &buf[tmp2 + sizeof(tmp2) - tmp];
}

static void get_orphan_name(UINT64 inode, UINT64 generation, char* name) {
    char* ptr;
    UINT64 index = 0;
    
    // FIXME - increment index if name already exists
    
    name[0] = 'o';
    
    ptr = uint64_to_char(inode, &name[1]);
    *ptr = '-'; ptr++;
    ptr = uint64_to_char(generation, ptr);
    *ptr = '-'; ptr++;
    ptr = uint64_to_char(index, ptr);
    *ptr = 0;

    return;
}

static NTSTATUS send_inode(device_extension* Vcb, send_context* context, traverse_ptr* tp) {
    if (tp->item->size < sizeof(INODE_ITEM)) {
        ERR("(%llx,%x,%llx) was %u bytes, expected %u\n", tp->item->key.obj_id, tp->item->key.obj_type, tp->item->key.offset,
            tp->item->size, sizeof(INODE_ITEM));
        return STATUS_INTERNAL_ERROR;
    }

    if (tp->item->key.obj_id == SUBVOL_ROOT_INODE) {
        // FIXME - send "subvol" item
    } else {
        ULONG pos = context->datalen;
        UINT16 cmd;
        INODE_ITEM* ii = (INODE_ITEM*)tp->item->data;
        char name[64];
        
        if (ii->st_mode & __S_IFDIR)
            cmd = BTRFS_SEND_CMD_MKDIR;
        else
            cmd = BTRFS_SEND_CMD_MKFILE; // FIXME - mknod, fifo, socket, symlink
        
        send_command(context, cmd);

        get_orphan_name(tp->item->key.obj_id, ii->generation, name);

        send_add_tlv(context, BTRFS_SEND_TLV_PATH, name, strlen(name));
        send_add_tlv(context, BTRFS_SEND_TLV_INODE, &tp->item->key.obj_id, sizeof(UINT64));
        
        send_command_finish(context, pos);
    }
    
    return STATUS_SUCCESS;
}

NTSTATUS send_subvol(device_extension* Vcb, PFILE_OBJECT FileObject, PIRP Irp) {
    NTSTATUS Status;
    fcb* fcb;
    send_context context;
    UNICODE_STRING fn;
    IO_STATUS_BLOCK iosb;
    OBJECT_ATTRIBUTES atts;
    btrfs_send_header* header;
    KEY searchkey;
    traverse_ptr tp;
    
    // FIXME - incremental sends
    // FIXME - cloning

    if (!FileObject || !FileObject->FsContext || FileObject->FsContext == Vcb->volume_fcb)
        return STATUS_INVALID_PARAMETER;
    
    // FIXME - check user has volume privilege

    fcb = FileObject->FsContext;

    if (fcb->inode != SUBVOL_ROOT_INODE)
        return STATUS_INVALID_PARAMETER;

    // FIXME - check subvol or FS is readonly
    // FIXME - if subvol only just made readonly, check it has been flushed
    // FIXME - make it so any relevant subvols can't be made read-write while this is running
    
    fn.Buffer = L"\\??\\C:\\send";
    fn.Length = fn.MaximumLength = wcslen(fn.Buffer) * sizeof(WCHAR);
    
    InitializeObjectAttributes(&atts, &fn, OBJ_KERNEL_HANDLE, NULL, NULL);
    
    Status = ZwCreateFile(&context.h, FILE_WRITE_DATA | SYNCHRONIZE, &atts, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, 0,
                          FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_ALERT, NULL, 0);
    if (!NT_SUCCESS(Status)) {
        ERR("ZwCreateFile returned %08x\n", Status);
        return Status;
    }

    context.data = ExAllocatePoolWithTag(PagedPool, 1048576, ALLOC_TAG); // FIXME
    if (!context.data) {
        ZwClose(context.h);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    header = (btrfs_send_header*)context.data;
    
    RtlCopyMemory(header->magic, BTRFS_SEND_MAGIC, sizeof(BTRFS_SEND_MAGIC));
    header->version = 1;
    context.datalen = sizeof(btrfs_send_header);

    ExAcquireResourceSharedLite(&Vcb->tree_lock, TRUE);
    
    searchkey.obj_id = searchkey.obj_type = searchkey.offset = 0;
    
    Status = find_item(Vcb, fcb->subvol, &tp, &searchkey, FALSE, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("find_item returned %08x\n", Status);
        goto end;
    }
    
    do {
        traverse_ptr next_tp;
        
        if (tp.item->key.obj_type == TYPE_INODE_ITEM) {
            Status = send_inode(Vcb, &context, &tp);
            if (!NT_SUCCESS(Status)) {
                ERR("send_inode returned %08x\n", Status);
                goto end;
            }
        }

        if (find_next_item(Vcb, &tp, &next_tp, FALSE, Irp))
            tp = next_tp;
        else
            break;
    } while (TRUE);
    
    send_write_data(&context, context.data, context.datalen);
    
    Status = STATUS_SUCCESS;
    
end:
    ExReleaseResourceLite(&Vcb->tree_lock);

    ZwClose(context.h);
    
    return Status;
}
