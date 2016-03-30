/* Copyright (c) Mark Harmstone 2016
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
#include "btrfsioctl.h"

#ifndef FSCTL_CSV_CONTROL
#define FSCTL_CSV_CONTROL CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 181, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

#define DOTDOT ".."

static NTSTATUS get_file_ids(PFILE_OBJECT FileObject, void* data, ULONG length) {
    btrfs_get_file_ids* bgfi;
    fcb* fcb;
    
    if (length < sizeof(btrfs_get_file_ids))
        return STATUS_BUFFER_OVERFLOW;
    
    if (!FileObject)
        return STATUS_INVALID_PARAMETER;
    
    fcb = FileObject->FsContext;
    
    if (!fcb)
        return STATUS_INVALID_PARAMETER;
    
    bgfi = data;
    
    bgfi->subvol = fcb->subvol->id;
    bgfi->inode = fcb->inode;
    bgfi->top = fcb->Vcb->root_fcb == fcb ? TRUE : FALSE;
    
    return STATUS_SUCCESS;
}

static NTSTATUS create_subvol(device_extension* Vcb, PFILE_OBJECT FileObject, WCHAR* name, ULONG length) {
    fcb* fcb;
    NTSTATUS Status;
    LIST_ENTRY rollback;
    UINT64 id;
    root* r;
    LARGE_INTEGER time;
    BTRFS_TIME now;
    ULONG len, disize, rrsize, irsize;
    ANSI_STRING utf8;
    UINT64 dirpos;
    DIR_ITEM *di, *di2;
    UINT32 crc32;
    ROOT_REF *rr, *rr2;
    INODE_ITEM* ii;
    INODE_REF* ir;
    KEY searchkey;
    traverse_ptr tp;
    
    fcb = FileObject->FsContext;
    if (!fcb) {
        ERR("error - fcb was NULL\n");
        return STATUS_INTERNAL_ERROR;
    }
    
    utf8.Buffer = NULL;
    
    Status = RtlUnicodeToUTF8N(NULL, 0, &len, name, length);
    if (!NT_SUCCESS(Status)) {
        ERR("RtlUnicodeToUTF8N failed with error %08x\n", Status);
        return Status;
    }
    
    if (len == 0) {
        ERR("RtlUnicodeToUTF8N returned a length of 0\n");
        return STATUS_INTERNAL_ERROR;
    }
    
    utf8.MaximumLength = utf8.Length = len;
    utf8.Buffer = ExAllocatePoolWithTag(PagedPool, utf8.Length, ALLOC_TAG);
    
    if (!utf8.Buffer) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    Status = RtlUnicodeToUTF8N(utf8.Buffer, len, &len, name, length);
    if (!NT_SUCCESS(Status)) {
        ERR("RtlUnicodeToUTF8N failed with error %08x\n", Status);
        goto end2;
    }
    
    acquire_tree_lock(Vcb, TRUE);
    
    KeQuerySystemTime(&time);
    win_time_to_unix(time, &now);
    
    ERR("create subvol!\n");
    
    // FIXME - check FileObject is a directory and hasn't been deleted
    // FIXME - check name doesn't already exist
    // FIXME - check name doesn't contain slashes or backslashes
    // FIXME - check we have permissions to create a subdirectory
    
    InitializeListHead(&rollback);
    
    if (Vcb->root_root->lastinode == 0)
        get_last_inode(Vcb, Vcb->root_root);
    
    id = Vcb->root_root->lastinode > 0x100 ? (Vcb->root_root->lastinode + 1) : 0x101;
    Status = create_root(Vcb, id, &r, &rollback);
    
    if (!NT_SUCCESS(Status)) {
        ERR("create_root returned %08x\n", Status);
        goto end;
    }
    
    ERR("created root %llx\n", id);
    
    // FIXME - generate r->root_item.uuid
    // FIXME - add entry to tree 9
    
    r->root_item.inode.generation = 1;
    r->root_item.inode.st_size = 3;
    r->root_item.inode.st_blocks = Vcb->superblock.node_size;
    r->root_item.inode.st_nlink = 1;
    r->root_item.inode.st_mode = __S_IFDIR | S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH; // 40755
    r->root_item.inode.flags = 0xffffffff80000000; // FIXME - find out what these mean
    
    r->root_item.objid = SUBVOL_ROOT_INODE;
    r->root_item.bytes_used = Vcb->superblock.node_size;
    r->root_item.ctransid = Vcb->superblock.generation;
    r->root_item.otransid = Vcb->superblock.generation;
    r->root_item.ctime = now;
    r->root_item.otime = now;
    
    // add .. inode to new subvol
    
    ii = ExAllocatePoolWithTag(PagedPool, sizeof(INODE_ITEM), ALLOC_TAG);
    if (!ii) {
        ERR("out of memory\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }
    
    RtlZeroMemory(ii, sizeof(INODE_ITEM));
    ii->generation = Vcb->superblock.generation;
    ii->transid = Vcb->superblock.generation;
    ii->st_nlink = 1;
    ii->st_mode = __S_IFDIR | S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH; // 40755
    ii->st_atime = ii->st_ctime = ii->st_mtime = ii->otime = now;

    if (!insert_tree_item(Vcb, r, r->root_item.objid, TYPE_INODE_ITEM, 0, ii, sizeof(INODE_ITEM), NULL, &rollback)) {
        ERR("insert_tree_item failed\n");
        Status = STATUS_INTERNAL_ERROR;
        goto end;
    }
    
    // add INODE_REF
    
    irsize = sizeof(INODE_REF) - 1 + strlen(DOTDOT);
    ir = ExAllocatePoolWithTag(PagedPool, irsize, ALLOC_TAG);
    if (!ir) {
        ERR("out of memory\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }
    
    ir->index = 0;
    ir->n = strlen(DOTDOT);
    RtlCopyMemory(ir->name, DOTDOT, ir->n);

    if (!insert_tree_item(Vcb, r, r->root_item.objid, TYPE_INODE_REF, r->root_item.objid, ir, irsize, NULL, &rollback)) {
        ERR("insert_tree_item failed\n");
        Status = STATUS_INTERNAL_ERROR;
        goto end;
    }
    
    // add DIR_ITEM
    
    dirpos = find_next_dir_index(Vcb, fcb->subvol, fcb->inode);
    if (dirpos == 0) {
        ERR("find_next_dir_index failed\n");
        Status = STATUS_INTERNAL_ERROR;
        goto end;
    }
    
    disize = sizeof(DIR_ITEM) - 1 + utf8.Length;
    di = ExAllocatePoolWithTag(PagedPool, disize, ALLOC_TAG);
    if (!di) {
        ERR("out of memory\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }
    
    di2 = ExAllocatePoolWithTag(PagedPool, disize, ALLOC_TAG);
    if (!di2) {
        ERR("out of memory\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        ExFreePool(di);
        goto end;
    }
    
    di->key.obj_id = id;
    di->key.obj_type = TYPE_ROOT_ITEM;
    di->key.offset = 0;
    di->transid = Vcb->superblock.generation;
    di->m = 0;
    di->n = utf8.Length;
    di->type = BTRFS_TYPE_DIRECTORY;
    RtlCopyMemory(di->name, utf8.Buffer, utf8.Length);
    
    RtlCopyMemory(di2, di, disize);
    
    crc32 = calc_crc32c(0xfffffffe, (UINT8*)utf8.Buffer, utf8.Length);
    
    Status = add_dir_item(Vcb, fcb->subvol, fcb->inode, crc32, di, disize, &rollback);
    if (!NT_SUCCESS(Status)) {
        ERR("add_dir_item returned %08x\n", Status);
        goto end;
    }
    
    // add DIR_INDEX
    
    if (!insert_tree_item(Vcb, fcb->subvol, fcb->inode, TYPE_DIR_INDEX, dirpos, di2, disize, NULL, &rollback)) {
        ERR("insert_tree_item failed\n");
        Status = STATUS_INTERNAL_ERROR;
        goto end;
    }
    
    // add ROOT_REF
    
    rrsize = sizeof(ROOT_REF) - 1 + utf8.Length;
    rr = ExAllocatePoolWithTag(PagedPool, rrsize, ALLOC_TAG);
    if (!rr) {
        ERR("out of memory\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }
    
    rr->dir = fcb->inode;
    rr->index = dirpos;
    rr->n = utf8.Length;
    RtlCopyMemory(rr->name, utf8.Buffer, utf8.Length);
    
    if (!insert_tree_item(Vcb, Vcb->root_root, fcb->subvol->id, TYPE_ROOT_REF, r->id, rr, rrsize, NULL, &rollback)) {
        ERR("insert_tree_item failed\n");
        Status = STATUS_INTERNAL_ERROR;
        goto end;
    }
    
    // add ROOT_BACKREF
    
    rr2 = ExAllocatePoolWithTag(PagedPool, rrsize, ALLOC_TAG);
    if (!rr2) {
        ERR("out of memory\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }
    
    RtlCopyMemory(rr2, rr, rrsize);
    
    if (!insert_tree_item(Vcb, Vcb->root_root, r->id, TYPE_ROOT_BACKREF, fcb->subvol->id, rr2, rrsize, NULL, &rollback)) {
        ERR("insert_tree_item failed\n");
        Status = STATUS_INTERNAL_ERROR;
        goto end;
    }
    
    // change fcb->subvol's ROOT_ITEM
    
    fcb->subvol->root_item.ctransid = Vcb->superblock.generation;
    fcb->subvol->root_item.ctime = now;
    
    // change fcb's INODE_ITEM
    
    // unlike when we create a file normally, the times and seq of the parent don't appear to change
    fcb->inode_item.transid = Vcb->superblock.generation;
    fcb->inode_item.st_size += utf8.Length * 2;
    
    searchkey.obj_id = fcb->inode;
    searchkey.obj_type = TYPE_INODE_ITEM;
    searchkey.offset = 0;
    
    Status = find_item(Vcb, fcb->subvol, &tp, &searchkey, FALSE);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08x\n", Status);
        goto end;
    }
    
    if (keycmp(&searchkey, &tp.item->key)) {
        ERR("error - could not find INODE_ITEM for directory %llx in subvol %llx\n", fcb->inode, fcb->subvol->id);
        free_traverse_ptr(&tp);
        Status = STATUS_INTERNAL_ERROR;
        goto end;
    }
    
    ii = ExAllocatePoolWithTag(PagedPool, sizeof(INODE_ITEM), ALLOC_TAG);
    if (!ii) {
        ERR("out of memory\n");
        free_traverse_ptr(&tp);
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }
    
    RtlCopyMemory(ii, &fcb->inode_item, sizeof(INODE_ITEM));
    delete_tree_item(Vcb, &tp, &rollback);
    
    insert_tree_item(Vcb, fcb->subvol, searchkey.obj_id, searchkey.obj_type, searchkey.offset, ii, sizeof(INODE_ITEM), NULL, &rollback);
    
    free_traverse_ptr(&tp);
    
    // FIXME - send notification
    
    Vcb->root_root->lastinode = id;

    Status = STATUS_SUCCESS;    
    
end:
    if (NT_SUCCESS(Status))
        Status = consider_write(Vcb);
    
    if (!NT_SUCCESS(Status))
        do_rollback(Vcb, &rollback);
    else
        clear_rollback(&rollback);
    
    release_tree_lock(Vcb, TRUE);
    
    if (NT_SUCCESS(Status)) {
        UNICODE_STRING ffn;
        
        ffn.Length = fcb->full_filename.Length + length;
        if (fcb != fcb->Vcb->root_fcb)
            ffn.Length += sizeof(WCHAR);
        
        ffn.MaximumLength = ffn.Length;
        ffn.Buffer = ExAllocatePoolWithTag(PagedPool, ffn.Length, ALLOC_TAG);
        
        if (ffn.Buffer) {
            ULONG i;
            
            RtlCopyMemory(ffn.Buffer, fcb->full_filename.Buffer, fcb->full_filename.Length);
            i = fcb->full_filename.Length;
            
            if (fcb != fcb->Vcb->root_fcb) {
                ffn.Buffer[i / sizeof(WCHAR)] = '\\';
                i += sizeof(WCHAR);
            }
            
            RtlCopyMemory(&ffn.Buffer[i / sizeof(WCHAR)], name, length);
            
            TRACE("full filename = %.*S\n", ffn.Length / sizeof(WCHAR), ffn.Buffer);
            
            FsRtlNotifyFullReportChange(Vcb->NotifySync, &Vcb->DirNotifyList, (PSTRING)&ffn, i, NULL, NULL,
                                        FILE_NOTIFY_CHANGE_DIR_NAME, FILE_ACTION_ADDED, NULL);
            
            ExFreePool(ffn.Buffer);
        } else
            ERR("out of memory\n");
    }
    
end2:
    if (utf8.Buffer)
        ExFreePool(utf8.Buffer);
    
    return Status;
}

NTSTATUS fsctl_request(PDEVICE_OBJECT DeviceObject, PIRP Irp, UINT32 type, BOOL user) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status;
    
    switch (type) {
        case FSCTL_REQUEST_OPLOCK_LEVEL_1:
            WARN("STUB: FSCTL_REQUEST_OPLOCK_LEVEL_1\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_REQUEST_OPLOCK_LEVEL_2:
            WARN("STUB: FSCTL_REQUEST_OPLOCK_LEVEL_2\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_REQUEST_BATCH_OPLOCK:
            WARN("STUB: FSCTL_REQUEST_BATCH_OPLOCK\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_OPLOCK_BREAK_ACKNOWLEDGE:
            WARN("STUB: FSCTL_OPLOCK_BREAK_ACKNOWLEDGE\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_OPBATCH_ACK_CLOSE_PENDING:
            WARN("STUB: FSCTL_OPBATCH_ACK_CLOSE_PENDING\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_OPLOCK_BREAK_NOTIFY:
            WARN("STUB: FSCTL_OPLOCK_BREAK_NOTIFY\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_LOCK_VOLUME:
            WARN("STUB: FSCTL_LOCK_VOLUME\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_UNLOCK_VOLUME:
            WARN("STUB: FSCTL_UNLOCK_VOLUME\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_DISMOUNT_VOLUME:
            WARN("STUB: FSCTL_DISMOUNT_VOLUME\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_IS_VOLUME_MOUNTED:
            WARN("STUB: FSCTL_IS_VOLUME_MOUNTED\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_IS_PATHNAME_VALID:
            WARN("STUB: FSCTL_IS_PATHNAME_VALID\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_MARK_VOLUME_DIRTY:
            WARN("STUB: FSCTL_MARK_VOLUME_DIRTY\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_QUERY_RETRIEVAL_POINTERS:
            WARN("STUB: FSCTL_QUERY_RETRIEVAL_POINTERS\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_GET_COMPRESSION:
            WARN("STUB: FSCTL_GET_COMPRESSION\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_SET_COMPRESSION:
            WARN("STUB: FSCTL_SET_COMPRESSION\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_SET_BOOTLOADER_ACCESSED:
            WARN("STUB: FSCTL_SET_BOOTLOADER_ACCESSED\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_OPLOCK_BREAK_ACK_NO_2:
            WARN("STUB: FSCTL_OPLOCK_BREAK_ACK_NO_2\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_INVALIDATE_VOLUMES:
            WARN("STUB: FSCTL_INVALIDATE_VOLUMES\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_QUERY_FAT_BPB:
            WARN("STUB: FSCTL_QUERY_FAT_BPB\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_REQUEST_FILTER_OPLOCK:
            WARN("STUB: FSCTL_REQUEST_FILTER_OPLOCK\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_FILESYSTEM_GET_STATISTICS:
            WARN("STUB: FSCTL_FILESYSTEM_GET_STATISTICS\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_GET_NTFS_VOLUME_DATA:
            WARN("STUB: FSCTL_GET_NTFS_VOLUME_DATA\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_GET_NTFS_FILE_RECORD:
            WARN("STUB: FSCTL_GET_NTFS_FILE_RECORD\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_GET_VOLUME_BITMAP:
            WARN("STUB: FSCTL_GET_VOLUME_BITMAP\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_GET_RETRIEVAL_POINTERS:
            WARN("STUB: FSCTL_GET_RETRIEVAL_POINTERS\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_MOVE_FILE:
            WARN("STUB: FSCTL_MOVE_FILE\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_IS_VOLUME_DIRTY:
            WARN("STUB: FSCTL_IS_VOLUME_DIRTY\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_ALLOW_EXTENDED_DASD_IO:
            WARN("STUB: FSCTL_ALLOW_EXTENDED_DASD_IO\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_FIND_FILES_BY_SID:
            WARN("STUB: FSCTL_FIND_FILES_BY_SID\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_SET_OBJECT_ID:
            WARN("STUB: FSCTL_SET_OBJECT_ID\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_GET_OBJECT_ID:
            WARN("STUB: FSCTL_GET_OBJECT_ID\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_DELETE_OBJECT_ID:
            WARN("STUB: FSCTL_DELETE_OBJECT_ID\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_SET_REPARSE_POINT:
            Status = set_reparse_point(DeviceObject, Irp);
            break;

        case FSCTL_GET_REPARSE_POINT:
            Status = get_reparse_point(DeviceObject, IrpSp->FileObject, Irp->AssociatedIrp.SystemBuffer,
                                       IrpSp->Parameters.DeviceIoControl.OutputBufferLength, &Irp->IoStatus.Information);
            break;

        case FSCTL_DELETE_REPARSE_POINT:
            WARN("STUB: FSCTL_DELETE_REPARSE_POINT\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_ENUM_USN_DATA:
            WARN("STUB: FSCTL_ENUM_USN_DATA\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_SECURITY_ID_CHECK:
            WARN("STUB: FSCTL_SECURITY_ID_CHECK\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_READ_USN_JOURNAL:
            WARN("STUB: FSCTL_READ_USN_JOURNAL\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_SET_OBJECT_ID_EXTENDED:
            WARN("STUB: FSCTL_SET_OBJECT_ID_EXTENDED\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_CREATE_OR_GET_OBJECT_ID:
            WARN("STUB: FSCTL_CREATE_OR_GET_OBJECT_ID\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_SET_SPARSE:
            WARN("STUB: FSCTL_SET_SPARSE\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_SET_ZERO_DATA:
            WARN("STUB: FSCTL_SET_ZERO_DATA\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_QUERY_ALLOCATED_RANGES:
            WARN("STUB: FSCTL_QUERY_ALLOCATED_RANGES\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_ENABLE_UPGRADE:
            WARN("STUB: FSCTL_ENABLE_UPGRADE\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_SET_ENCRYPTION:
            WARN("STUB: FSCTL_SET_ENCRYPTION\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_ENCRYPTION_FSCTL_IO:
            WARN("STUB: FSCTL_ENCRYPTION_FSCTL_IO\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_WRITE_RAW_ENCRYPTED:
            WARN("STUB: FSCTL_WRITE_RAW_ENCRYPTED\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_READ_RAW_ENCRYPTED:
            WARN("STUB: FSCTL_READ_RAW_ENCRYPTED\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_CREATE_USN_JOURNAL:
            WARN("STUB: FSCTL_CREATE_USN_JOURNAL\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_READ_FILE_USN_DATA:
            WARN("STUB: FSCTL_READ_FILE_USN_DATA\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_WRITE_USN_CLOSE_RECORD:
            WARN("STUB: FSCTL_WRITE_USN_CLOSE_RECORD\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_EXTEND_VOLUME:
            WARN("STUB: FSCTL_EXTEND_VOLUME\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_QUERY_USN_JOURNAL:
            WARN("STUB: FSCTL_QUERY_USN_JOURNAL\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_DELETE_USN_JOURNAL:
            WARN("STUB: FSCTL_DELETE_USN_JOURNAL\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_MARK_HANDLE:
            WARN("STUB: FSCTL_MARK_HANDLE\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_SIS_COPYFILE:
            WARN("STUB: FSCTL_SIS_COPYFILE\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_SIS_LINK_FILES:
            WARN("STUB: FSCTL_SIS_LINK_FILES\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_RECALL_FILE:
            WARN("STUB: FSCTL_RECALL_FILE\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_READ_FROM_PLEX:
            WARN("STUB: FSCTL_READ_FROM_PLEX\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_FILE_PREFETCH:
            WARN("STUB: FSCTL_FILE_PREFETCH\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

#if WIN32_WINNT >= 0x0600
        case FSCTL_MAKE_MEDIA_COMPATIBLE:
            WARN("STUB: FSCTL_MAKE_MEDIA_COMPATIBLE\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_SET_DEFECT_MANAGEMENT:
            WARN("STUB: FSCTL_SET_DEFECT_MANAGEMENT\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_QUERY_SPARING_INFO:
            WARN("STUB: FSCTL_QUERY_SPARING_INFO\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_QUERY_ON_DISK_VOLUME_INFO:
            WARN("STUB: FSCTL_QUERY_ON_DISK_VOLUME_INFO\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_SET_VOLUME_COMPRESSION_STATE:
            WARN("STUB: FSCTL_SET_VOLUME_COMPRESSION_STATE\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_TXFS_MODIFY_RM:
            WARN("STUB: FSCTL_TXFS_MODIFY_RM\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_TXFS_QUERY_RM_INFORMATION:
            WARN("STUB: FSCTL_TXFS_QUERY_RM_INFORMATION\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_TXFS_ROLLFORWARD_REDO:
            WARN("STUB: FSCTL_TXFS_ROLLFORWARD_REDO\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_TXFS_ROLLFORWARD_UNDO:
            WARN("STUB: FSCTL_TXFS_ROLLFORWARD_UNDO\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_TXFS_START_RM:
            WARN("STUB: FSCTL_TXFS_START_RM\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_TXFS_SHUTDOWN_RM:
            WARN("STUB: FSCTL_TXFS_SHUTDOWN_RM\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_TXFS_READ_BACKUP_INFORMATION:
            WARN("STUB: FSCTL_TXFS_READ_BACKUP_INFORMATION\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_TXFS_WRITE_BACKUP_INFORMATION:
            WARN("STUB: FSCTL_TXFS_WRITE_BACKUP_INFORMATION\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_TXFS_CREATE_SECONDARY_RM:
            WARN("STUB: FSCTL_TXFS_CREATE_SECONDARY_RM\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_TXFS_GET_METADATA_INFO:
            WARN("STUB: FSCTL_TXFS_GET_METADATA_INFO\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_TXFS_GET_TRANSACTED_VERSION:
            WARN("STUB: FSCTL_TXFS_GET_TRANSACTED_VERSION\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_TXFS_SAVEPOINT_INFORMATION:
            WARN("STUB: FSCTL_TXFS_SAVEPOINT_INFORMATION\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_TXFS_CREATE_MINIVERSION:
            WARN("STUB: FSCTL_TXFS_CREATE_MINIVERSION\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_TXFS_TRANSACTION_ACTIVE:
            WARN("STUB: FSCTL_TXFS_TRANSACTION_ACTIVE\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_SET_ZERO_ON_DEALLOCATION:
            WARN("STUB: FSCTL_SET_ZERO_ON_DEALLOCATION\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_SET_REPAIR:
            WARN("STUB: FSCTL_SET_REPAIR\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_GET_REPAIR:
            WARN("STUB: FSCTL_GET_REPAIR\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_WAIT_FOR_REPAIR:
            WARN("STUB: FSCTL_WAIT_FOR_REPAIR\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_INITIATE_REPAIR:
            WARN("STUB: FSCTL_INITIATE_REPAIR\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_CSC_INTERNAL:
            WARN("STUB: FSCTL_CSC_INTERNAL\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_SHRINK_VOLUME:
            WARN("STUB: FSCTL_SHRINK_VOLUME\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_SET_SHORT_NAME_BEHAVIOR:
            WARN("STUB: FSCTL_SET_SHORT_NAME_BEHAVIOR\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_DFSR_SET_GHOST_HANDLE_STATE:
            WARN("STUB: FSCTL_DFSR_SET_GHOST_HANDLE_STATE\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_TXFS_LIST_TRANSACTION_LOCKED_FILES:
            WARN("STUB: FSCTL_TXFS_LIST_TRANSACTION_LOCKED_FILES\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_TXFS_LIST_TRANSACTIONS:
            WARN("STUB: FSCTL_TXFS_LIST_TRANSACTIONS\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_QUERY_PAGEFILE_ENCRYPTION:
            WARN("STUB: FSCTL_QUERY_PAGEFILE_ENCRYPTION\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_RESET_VOLUME_ALLOCATION_HINTS:
            WARN("STUB: FSCTL_RESET_VOLUME_ALLOCATION_HINTS\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        case FSCTL_TXFS_READ_BACKUP_INFORMATION2:
            WARN("STUB: FSCTL_TXFS_READ_BACKUP_INFORMATION2\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;
            
        case FSCTL_CSV_CONTROL:
            WARN("STUB: FSCTL_CSV_CONTROL\n");
            Status = STATUS_NOT_IMPLEMENTED;
            break;
#endif
        case FSCTL_BTRFS_GET_FILE_IDS:
            Status = get_file_ids(IrpSp->FileObject, map_user_buffer(Irp), IrpSp->Parameters.DeviceIoControl.OutputBufferLength);
            break;
            
        case FSCTL_BTRFS_CREATE_SUBVOL:
            Status = create_subvol(DeviceObject->DeviceExtension, IrpSp->FileObject, map_user_buffer(Irp), IrpSp->Parameters.DeviceIoControl.OutputBufferLength);
            break;

        default:
            WARN("unknown control code %x (DeviceType = %x, Access = %x, Function = %x, Method = %x)\n",
                          IrpSp->Parameters.FileSystemControl.FsControlCode, (IrpSp->Parameters.FileSystemControl.FsControlCode & 0xff0000) >> 16,
                          (IrpSp->Parameters.FileSystemControl.FsControlCode & 0xc000) >> 14, (IrpSp->Parameters.FileSystemControl.FsControlCode & 0x3ffc) >> 2,
                          IrpSp->Parameters.FileSystemControl.FsControlCode & 0x3);
            Status = STATUS_NOT_IMPLEMENTED;
            break;
    }
    
    return Status;
}
