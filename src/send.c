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

typedef struct send_dir {
    LIST_ENTRY list_entry;
    UINT64 inode;
    BOOL dummy;
    BTRFS_TIME atime;
    BTRFS_TIME mtime;
    BTRFS_TIME ctime;
    struct send_dir* parent;
    ULONG namelen;
    char* name;
} send_dir;

typedef struct {
    LIST_ENTRY list_entry;
    UINT64 inode;
    BOOL dir;
    send_dir* sd;
    char tmpname[64];
} orphan;

typedef struct {
    LIST_ENTRY list_entry;
    send_dir* sd;
    ULONG namelen;
    char name[1];
} ref;

typedef struct {
    device_extension* Vcb;
    root* root;
    root* parent;
    UINT8* data;
    ULONG datalen;
    LIST_ENTRY orphans;
    LIST_ENTRY dirs;
    KEVENT buffer_event, cleared_event;

    struct {
        BTRFS_TIME atime;
        BTRFS_TIME mtime;
        BTRFS_TIME ctime;
    } root_dir;

    struct {
        UINT64 inode;
        UINT64 gen;
        UINT64 uid;
        UINT64 gid;
        UINT64 mode;
        UINT64 size;
        BTRFS_TIME atime;
        BTRFS_TIME mtime;
        BTRFS_TIME ctime;
        BOOL file;
        char* path;
        orphan* o;
        LIST_ENTRY refs;
    } lastinode;
} send_context;

#define MAX_SEND_WRITE 0xc000 // 48 KB
#define SEND_BUFFER_LENGTH 0x100000 // 1 MB

static void send_utimes_command(send_context* context, char* path, BTRFS_TIME* atime, BTRFS_TIME* mtime, BTRFS_TIME* ctime);
static NTSTATUS send_add_dir(send_context* context, UINT64 inode, send_dir* parent, char* name, ULONG namelen, BOOL dummy, LIST_ENTRY* lastentry, send_dir** psd);

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

static void add_orphan(send_context* context, orphan* o) {
    LIST_ENTRY* le;

    le = context->orphans.Flink;
    while (le != &context->orphans) {
        orphan* o2 = CONTAINING_RECORD(le, orphan, list_entry);

        if (o2->inode > o->inode) {
            InsertHeadList(o2->list_entry.Blink, &o->list_entry);
            return;
        }

        le = le->Flink;
    }

    InsertTailList(&context->orphans, &o->list_entry);
}

static NTSTATUS send_read_symlink(send_context* context, UINT64 inode, char** link, ULONG* linklen) {
    NTSTATUS Status;
    KEY searchkey;
    traverse_ptr tp;
    EXTENT_DATA* ed;

    searchkey.obj_id = inode;
    searchkey.obj_type = TYPE_EXTENT_DATA;
    searchkey.offset = 0;

    Status = find_item(context->Vcb, context->root, &tp, &searchkey, FALSE, NULL);
    if (!NT_SUCCESS(Status)) {
        ERR("find_item returned %08x\n", Status);
        return Status;
    }

    if (keycmp(tp.item->key, searchkey)) {
        ERR("could not find (%llx,%x,%llx)\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset);
        return STATUS_INTERNAL_ERROR;
    }

    if (tp.item->size < sizeof(EXTENT_DATA)) {
        ERR("(%llx,%x,%llx) was %u bytes, expected at least %u\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset,
            tp.item->size, sizeof(EXTENT_DATA));
        return STATUS_INTERNAL_ERROR;
    }

    ed = (EXTENT_DATA*)tp.item->data;

    if (ed->type != EXTENT_TYPE_INLINE) {
        WARN("symlink data was not inline, returning blank string\n");
        *link = NULL;
        *linklen = 0;
        return STATUS_SUCCESS;
    }

    if (tp.item->size < offsetof(EXTENT_DATA, data[0]) + ed->decoded_size) {
        ERR("(%llx,%x,%llx) was %u bytes, expected %u\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset,
            tp.item->size, offsetof(EXTENT_DATA, data[0]) + ed->decoded_size);
        return STATUS_INTERNAL_ERROR;
    }

    *link = (char*)ed->data;
    *linklen = ed->decoded_size;

    return STATUS_SUCCESS;
}

static NTSTATUS send_inode(send_context* context, traverse_ptr* tp, traverse_ptr* tp2) {
    NTSTATUS Status;
    INODE_ITEM* ii;

    if (tp2 && !tp)
        return STATUS_SUCCESS; // FIXME

    ii = (INODE_ITEM*)tp->item->data;

    if (tp->item->size < sizeof(INODE_ITEM)) {
        ERR("(%llx,%x,%llx) was %u bytes, expected %u\n", tp->item->key.obj_id, tp->item->key.obj_type, tp->item->key.offset,
            tp->item->size, sizeof(INODE_ITEM));
        return STATUS_INTERNAL_ERROR;
    }

    context->lastinode.inode = tp->item->key.obj_id;
    context->lastinode.gen = ii->generation;
    context->lastinode.uid = ii->st_uid;
    context->lastinode.gid = ii->st_gid;
    context->lastinode.mode = ii->st_mode;
    context->lastinode.size = ii->st_size;
    context->lastinode.atime = ii->st_atime;
    context->lastinode.mtime = ii->st_mtime;
    context->lastinode.ctime = ii->st_ctime;
    context->lastinode.file = FALSE;

    if (tp->item->key.obj_id != SUBVOL_ROOT_INODE) {
        ULONG pos = context->datalen;
        UINT16 cmd;
        send_dir* sd;

        char name[64];
        orphan* o;

        // skip creating orphan directory if we've already done so
        if (ii->st_mode & __S_IFDIR) {
            LIST_ENTRY* le;

            le = context->orphans.Flink;
            while (le != &context->orphans) {
                orphan* o2 = CONTAINING_RECORD(le, orphan, list_entry);

                if (o2->inode == tp->item->key.obj_id) {
                    context->lastinode.o = o2;
                    o2->sd->atime = ii->st_atime;
                    o2->sd->mtime = ii->st_mtime;
                    o2->sd->ctime = ii->st_ctime;
                    o2->sd->dummy = FALSE;
                    return STATUS_SUCCESS;
                } else if (o2->inode > tp->item->key.obj_id)
                    break;

                le = le->Flink;
            }
        }

        if ((ii->st_mode & __S_IFSOCK) == __S_IFSOCK)
            cmd = BTRFS_SEND_CMD_MKSOCK;
        else if ((ii->st_mode & __S_IFLNK) == __S_IFLNK)
            cmd = BTRFS_SEND_CMD_SYMLINK;
        else if ((ii->st_mode & __S_IFCHR) == __S_IFCHR || (ii->st_mode & __S_IFBLK) == __S_IFBLK)
            cmd = BTRFS_SEND_CMD_MKNOD;
        else if ((ii->st_mode & __S_IFDIR) == __S_IFDIR)
            cmd = BTRFS_SEND_CMD_MKDIR;
        else if ((ii->st_mode & __S_IFIFO) == __S_IFIFO)
            cmd = BTRFS_SEND_CMD_MKFIFO;
        else {
            cmd = BTRFS_SEND_CMD_MKFILE;
            context->lastinode.file = TRUE;
        }
        
        send_command(context, cmd);

        get_orphan_name(tp->item->key.obj_id, ii->generation, name);

        send_add_tlv(context, BTRFS_SEND_TLV_PATH, name, strlen(name));
        send_add_tlv(context, BTRFS_SEND_TLV_INODE, &tp->item->key.obj_id, sizeof(UINT64));
        
        if (cmd == BTRFS_SEND_CMD_MKNOD || cmd == BTRFS_SEND_CMD_MKFIFO || cmd == BTRFS_SEND_CMD_MKSOCK) {
            UINT64 rdev = makedev((ii->st_rdev & 0xFFFFFFFFFFF) >> 20, ii->st_rdev & 0xFFFFF), mode = ii->st_mode;

            send_add_tlv(context, BTRFS_SEND_TLV_RDEV, &rdev, sizeof(UINT64));
            send_add_tlv(context, BTRFS_SEND_TLV_MODE, &mode, sizeof(UINT64));
        } else if (cmd == BTRFS_SEND_CMD_SYMLINK && ii->st_size > 0) {
            char* link;
            ULONG linklen;

            Status = send_read_symlink(context, tp->item->key.obj_id, &link, &linklen);
            if (!NT_SUCCESS(Status)) {
                ERR("send_read_symlink returned %08x\n", Status);
                return Status;
            }

            send_add_tlv(context, BTRFS_SEND_TLV_PATH_LINK, link, linklen);
        }

        send_command_finish(context, pos);

        if (ii->st_mode & __S_IFDIR) {
            Status = send_add_dir(context, tp->item->key.obj_id, NULL, name, strlen(name), FALSE, NULL, &sd);
            if (!NT_SUCCESS(Status)) {
                ERR("send_add_dir returned %08x\n", Status);
                return Status;
            }
        } else
            sd = NULL;

        o = ExAllocatePoolWithTag(PagedPool, sizeof(orphan), ALLOC_TAG);
        if (!o) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        o->inode = tp->item->key.obj_id;
        o->dir = (ii->st_mode & __S_IFDIR && ii->st_size > 0) ? TRUE : FALSE;
        strcpy(o->tmpname, name);
        o->sd = sd;
        add_orphan(context, o);

        context->lastinode.path = ExAllocatePoolWithTag(PagedPool, strlen(o->tmpname) + 1, ALLOC_TAG);
        if (!context->lastinode.path) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        strcpy(context->lastinode.path, o->tmpname);

        context->lastinode.o = o;
    } else {
        context->lastinode.path = NULL;
        context->root_dir.atime = ii->st_atime;
        context->root_dir.mtime = ii->st_mtime;
        context->root_dir.ctime = ii->st_ctime;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS send_add_dir(send_context* context, UINT64 inode, send_dir* parent, char* name, ULONG namelen, BOOL dummy, LIST_ENTRY* lastentry, send_dir** psd) {
    LIST_ENTRY* le;
    send_dir* sd = ExAllocatePoolWithTag(PagedPool, sizeof(send_dir), ALLOC_TAG);

    if (!sd) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    sd->inode = inode;
    sd->dummy = dummy;
    sd->parent = parent;

    if (!dummy) {
        sd->atime = context->lastinode.atime;
        sd->mtime = context->lastinode.mtime;
        sd->ctime = context->lastinode.ctime;
    }

    sd->name = ExAllocatePoolWithTag(PagedPool, namelen, ALLOC_TAG);
    if (!sd->name) {
        ERR("out of memory\n");
        ExFreePool(sd);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    memcpy(sd->name, name, namelen);
    sd->namelen = namelen;

    if (lastentry)
        InsertHeadList(lastentry, &sd->list_entry);
    else {
        le = context->dirs.Flink;
        while (le != &context->dirs) {
            send_dir* sd2 = CONTAINING_RECORD(le, send_dir, list_entry);

            if (sd2->inode > sd->inode) {
                InsertHeadList(sd2->list_entry.Blink, &sd->list_entry);

                if (psd)
                    *psd = sd;

                return STATUS_SUCCESS;
            }

            le = le->Flink;
        }

        InsertTailList(&context->dirs, &sd->list_entry);
    }

    if (psd)
        *psd = sd;

    return STATUS_SUCCESS;
}

static __inline ULONG find_path_len(send_dir* parent, ULONG namelen) {
    ULONG len = namelen;

    while (parent) {
        len += parent->namelen + 1;
        parent = parent->parent;
    }

    return len;
}

static void find_path(char* path, send_dir* parent, char* name, ULONG namelen) {
    ULONG len = namelen;

    RtlCopyMemory(path, name, namelen);

    while (parent) {
        RtlMoveMemory(path + parent->namelen + 1, path, len);
        RtlCopyMemory(path, parent->name, parent->namelen);
        path[parent->namelen] = '/';
        len += parent->namelen + 1;

        parent = parent->parent;
    }
}

static NTSTATUS send_add_tlv_path(send_context* context, UINT16 type, send_dir* parent, char* name, ULONG namelen) {
    ULONG len = find_path_len(parent, namelen);
    char* path;

    path = ExAllocatePoolWithTag(PagedPool, len, ALLOC_TAG);
    if (!path) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    find_path(path, parent, name, namelen);
    send_add_tlv(context, type, path, len);

    ExFreePool(path);

    return STATUS_SUCCESS;
}

static NTSTATUS found_path(send_context* context, send_dir* parent, char* name, ULONG namelen) {
    NTSTATUS Status;
    ULONG pos = context->datalen;

    if (context->lastinode.o) {
        send_command(context, BTRFS_SEND_CMD_RENAME);

        send_add_tlv(context, BTRFS_SEND_TLV_PATH, context->lastinode.o->tmpname, strlen(context->lastinode.o->tmpname));

        Status = send_add_tlv_path(context, BTRFS_SEND_TLV_PATH_TO, parent, name, namelen);
        if (!NT_SUCCESS(Status)) {
            ERR("send_add_tlv_path returned %08x\n", Status);
            return Status;
        }

        send_command_finish(context, pos);
    } else {
        send_command(context, BTRFS_SEND_CMD_LINK);

        Status = send_add_tlv_path(context, BTRFS_SEND_TLV_PATH, parent, name, namelen);
        if (!NT_SUCCESS(Status)) {
            ERR("send_add_tlv_path returned %08x\n", Status);
            return Status;
        }

        send_add_tlv(context, BTRFS_SEND_TLV_PATH_LINK, context->lastinode.path, context->lastinode.path ? strlen(context->lastinode.path) : 0);

        send_command_finish(context, pos);
    }

    if (context->lastinode.o) {
        ULONG pathlen;

        if (context->lastinode.o->sd) {
            if (context->lastinode.o->sd->name)
                ExFreePool(context->lastinode.o->sd->name);

            context->lastinode.o->sd->name = ExAllocatePoolWithTag(PagedPool, namelen, ALLOC_TAG);
            if (!context->lastinode.o->sd->name) {
                ERR("out of memory\n");
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            RtlCopyMemory(context->lastinode.o->sd->name, name, namelen);
            context->lastinode.o->sd->namelen = namelen;
            context->lastinode.o->sd->parent = parent;
        }

        if (context->lastinode.path)
            ExFreePool(context->lastinode.path);

        pathlen = find_path_len(parent, namelen);
        context->lastinode.path = ExAllocatePoolWithTag(PagedPool, pathlen + 1, ALLOC_TAG);
        if (!context->lastinode.path) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        find_path(context->lastinode.path, parent, name, namelen);
        context->lastinode.path[pathlen] = 0;

        RemoveEntryList(&context->lastinode.o->list_entry);
        ExFreePool(context->lastinode.o);

        context->lastinode.o = NULL;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS send_utimes_command_dir(send_context* context, send_dir* sd, BTRFS_TIME* atime, BTRFS_TIME* mtime, BTRFS_TIME* ctime) {
    NTSTATUS Status;
    ULONG pos = context->datalen;

    send_command(context, BTRFS_SEND_CMD_UTIMES);

    Status = send_add_tlv_path(context, BTRFS_SEND_TLV_PATH, sd->parent, sd->name, sd->namelen);
    if (!NT_SUCCESS(Status)) {
        ERR("send_add_tlv_path returned %08x\n", Status);
        return Status;
    }

    send_add_tlv(context, BTRFS_SEND_TLV_ATIME, atime, sizeof(BTRFS_TIME));
    send_add_tlv(context, BTRFS_SEND_TLV_MTIME, mtime, sizeof(BTRFS_TIME));
    send_add_tlv(context, BTRFS_SEND_TLV_CTIME, ctime, sizeof(BTRFS_TIME));

    send_command_finish(context, pos);

    return STATUS_SUCCESS;
}

static NTSTATUS send_inode_ref(send_context* context, traverse_ptr* tp, traverse_ptr* tp2) {
    NTSTATUS Status;
    UINT64 inode = tp ? tp->item->key.obj_id : 0, dir = tp ? tp->item->key.offset : 0;
    LIST_ENTRY* le;
    INODE_REF* ir;
    ULONG len;
    send_dir* sd = NULL;
    orphan* o2 = NULL;

    if (tp2 && !tp)
        return STATUS_SUCCESS; // FIXME

    if (inode == dir) // root
        return STATUS_SUCCESS;

    if (tp->item->size < sizeof(INODE_REF)) {
        ERR("(%llx,%x,%llx) was %u bytes, expected at least %u\n", tp->item->key.obj_id, tp->item->key.obj_type, tp->item->key.offset,
            tp->item->size, sizeof(INODE_REF));
        return STATUS_INTERNAL_ERROR;
    }

    if (dir != SUBVOL_ROOT_INODE) {
        BOOL added = FALSE;

        le = context->dirs.Flink;
        while (le != &context->dirs) {
            send_dir* sd2 = CONTAINING_RECORD(le, send_dir, list_entry);

            if (sd2->inode > dir) {
                char name[64];

                get_orphan_name(dir, context->lastinode.inode == inode ? context->lastinode.gen : 0, name);

                Status = send_add_dir(context, dir, NULL, name, strlen(name), TRUE, &sd2->list_entry, &sd);
                if (!NT_SUCCESS(Status)) {
                    ERR("send_add_dir returned %08x\n", Status);
                    return Status;
                }

                added = TRUE;
                break;
            } else if (sd2->inode == dir) {
                sd = sd2;
                break;
            }

            le = le->Flink;
        }

        if (!added && !sd) {
            char name[64];

            get_orphan_name(dir, context->lastinode.inode == inode ? context->lastinode.gen : 0, name);

            Status = send_add_dir(context, dir, NULL, name, strlen(name), TRUE, context->dirs.Blink, &sd);
            if (!NT_SUCCESS(Status)) {
                ERR("send_add_dir returned %08x\n", Status);
                return Status;
            }
        }

        // directory has higher inode number than file, so might need to be created
        if (added) {
            BOOL found = FALSE;

            le = context->orphans.Flink;
            while (le != &context->orphans) {
                o2 = CONTAINING_RECORD(le, orphan, list_entry);

                if (o2->inode == dir) {
                    found = TRUE;
                    break;
                } else if (o2->inode > dir)
                    break;

                le = le->Flink;
            }

            if (!found) {
                ULONG pos = context->datalen;

                send_command(context, BTRFS_SEND_CMD_MKDIR);

                Status = send_add_tlv_path(context, BTRFS_SEND_TLV_PATH, NULL, sd->name, sd->namelen);
                if (!NT_SUCCESS(Status)) {
                    ERR("send_add_tlv_path returned %08x\n", Status);
                    return Status;
                }

                send_add_tlv(context, BTRFS_SEND_TLV_INODE, &dir, sizeof(UINT64));

                send_command_finish(context, pos);

                o2 = ExAllocatePoolWithTag(PagedPool, sizeof(orphan), ALLOC_TAG);
                if (!o2) {
                    ERR("out of memory\n");
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                o2->inode = dir;
                o2->dir = TRUE;
                memcpy(o2->tmpname, sd->name, sd->namelen);
                o2->tmpname[sd->namelen] = 0;
                o2->sd = sd;
                add_orphan(context, o2);
            }
        }
    }

    len = tp->item->size;
    ir = (INODE_REF*)tp->item->data;

    while (len > 0) {
        ref* r;

        if (len < sizeof(INODE_REF) || len < offsetof(INODE_REF, name[0]) + ir->n) {
            ERR("(%llx,%x,%llx) was truncated\n", tp->item->key.obj_id, tp->item->key.obj_type, tp->item->key.offset);
            return STATUS_INTERNAL_ERROR;
        }

        r = ExAllocatePoolWithTag(PagedPool, offsetof(ref, name[0]) + ir->n, ALLOC_TAG);
        if (!r) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        r->sd = sd;
        r->namelen = ir->n;
        RtlCopyMemory(r->name, ir->name, ir->n);

        InsertTailList(&context->lastinode.refs, &r->list_entry);

        len -= offsetof(INODE_REF, name[0]) + ir->n;
        ir = (INODE_REF*)&ir->name[ir->n];
    }

    return STATUS_SUCCESS;
}

static NTSTATUS send_inode_extref(send_context* context, traverse_ptr* tp, traverse_ptr* tp2) {
    UINT64 inode = tp ? tp->item->key.obj_id : 0;
    INODE_EXTREF* ier;
    ULONG len;

    if (tp2 && !tp)
        return STATUS_SUCCESS; // FIXME

    if (tp->item->size < sizeof(INODE_EXTREF)) {
        ERR("(%llx,%x,%llx) was %u bytes, expected at least %u\n", tp->item->key.obj_id, tp->item->key.obj_type, tp->item->key.offset,
            tp->item->size, sizeof(INODE_EXTREF));
        return STATUS_INTERNAL_ERROR;
    }

    len = tp->item->size;
    ier = (INODE_EXTREF*)tp->item->data;

    while (len > 0) {
        NTSTATUS Status;
        send_dir* sd = NULL;
        orphan* o2 = NULL;
        ref* r;

        if (len < sizeof(INODE_EXTREF) || len < offsetof(INODE_EXTREF, name[0]) + ier->n) {
            ERR("(%llx,%x,%llx) was truncated\n", tp->item->key.obj_id, tp->item->key.obj_type, tp->item->key.offset);
            return STATUS_INTERNAL_ERROR;
        }

        if (ier->dir != SUBVOL_ROOT_INODE) {
            LIST_ENTRY* le;
            BOOL added = FALSE;

            le = context->dirs.Flink;
            while (le != &context->dirs) {
                send_dir* sd2 = CONTAINING_RECORD(le, send_dir, list_entry);

                if (sd2->inode > ier->dir) {
                    char name[64];

                    get_orphan_name(ier->dir, context->lastinode.inode == inode ? context->lastinode.gen : 0, name);

                    Status = send_add_dir(context, ier->dir, NULL, name, strlen(name), TRUE, &sd2->list_entry, &sd);
                    if (!NT_SUCCESS(Status)) {
                        ERR("send_add_dir returned %08x\n", Status);
                        return Status;
                    }

                    added = TRUE;
                    break;
                } else if (sd2->inode == ier->dir) {
                    sd = sd2;
                    break;
                }

                le = le->Flink;
            }

            if (!added && !sd) {
                char name[64];

                get_orphan_name(ier->dir, context->lastinode.inode == inode ? context->lastinode.gen : 0, name);

                Status = send_add_dir(context, ier->dir, NULL, name, strlen(name), TRUE, context->dirs.Blink, &sd);
                if (!NT_SUCCESS(Status)) {
                    ERR("send_add_dir returned %08x\n", Status);
                    return Status;
                }
            }

            // directory has higher inode number than file, so might need to be created
            if (added) {
                BOOL found = FALSE;

                le = context->orphans.Flink;
                while (le != &context->orphans) {
                    o2 = CONTAINING_RECORD(le, orphan, list_entry);

                    if (o2->inode == ier->dir) {
                        found = TRUE;
                        break;
                    } else if (o2->inode > ier->dir)
                        break;

                    le = le->Flink;
                }

                if (!found) {
                    ULONG pos = context->datalen;

                    send_command(context, BTRFS_SEND_CMD_MKDIR);

                    Status = send_add_tlv_path(context, BTRFS_SEND_TLV_PATH, NULL, sd->name, sd->namelen);
                    if (!NT_SUCCESS(Status)) {
                        ERR("send_add_tlv_path returned %08x\n", Status);
                        return Status;
                    }

                    send_add_tlv(context, BTRFS_SEND_TLV_INODE, &ier->dir, sizeof(UINT64));

                    send_command_finish(context, pos);

                    o2 = ExAllocatePoolWithTag(PagedPool, sizeof(orphan), ALLOC_TAG);
                    if (!o2) {
                        ERR("out of memory\n");
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }

                    o2->inode = ier->dir;
                    o2->dir = TRUE;
                    memcpy(o2->tmpname, sd->name, sd->namelen);
                    o2->tmpname[sd->namelen] = 0;
                    o2->sd = sd;
                    add_orphan(context, o2);
                }
            }
        }

        r = ExAllocatePoolWithTag(PagedPool, offsetof(ref, name[0]) + ier->n, ALLOC_TAG);
        if (!r) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        r->sd = sd;
        r->namelen = ier->n;
        RtlCopyMemory(r->name, ier->name, ier->n);

        InsertTailList(&context->lastinode.refs, &r->list_entry);

        len -= offsetof(INODE_EXTREF, name[0]) + ier->n;
        ier = (INODE_EXTREF*)&ier->name[ier->n];
    }

    return STATUS_SUCCESS;
}

static void send_subvol_header(send_context* context, root* r, file_ref* fr) {
    ULONG pos = context->datalen;
    
    send_command(context, BTRFS_SEND_CMD_SUBVOL);
    
    send_add_tlv(context, BTRFS_SEND_TLV_PATH, fr->dc->utf8.Buffer, fr->dc->utf8.Length);
    
    if (r->root_item.rtransid == 0)
        send_add_tlv(context, BTRFS_SEND_TLV_UUID, &r->root_item.uuid, sizeof(BTRFS_UUID));
    else
        send_add_tlv(context, BTRFS_SEND_TLV_UUID, &r->root_item.received_uuid, sizeof(BTRFS_UUID));

    send_add_tlv(context, BTRFS_SEND_TLV_TRANSID, &r->root_item.ctransid, sizeof(UINT64));

    send_command_finish(context, pos);
}

static void send_end_command(send_context* context) {
    ULONG pos = context->datalen;

    send_command(context, BTRFS_SEND_CMD_END);
    send_command_finish(context, pos);
}

static void send_chown_command(send_context* context, char* path, UINT64 uid, UINT64 gid) {
    ULONG pos = context->datalen;

    send_command(context, BTRFS_SEND_CMD_CHOWN);

    send_add_tlv(context, BTRFS_SEND_TLV_PATH, path, path ? strlen(path) : 0);
    send_add_tlv(context, BTRFS_SEND_TLV_UID, &uid, sizeof(UINT64));
    send_add_tlv(context, BTRFS_SEND_TLV_GID, &gid, sizeof(UINT64));

    send_command_finish(context, pos);
}

static void send_chmod_command(send_context* context, char* path, UINT64 mode) {
    ULONG pos = context->datalen;

    send_command(context, BTRFS_SEND_CMD_CHMOD);

    mode &= 07777;

    send_add_tlv(context, BTRFS_SEND_TLV_PATH, path, path ? strlen(path) : 0);
    send_add_tlv(context, BTRFS_SEND_TLV_MODE, &mode, sizeof(UINT64));

    send_command_finish(context, pos);
}

static void send_utimes_command(send_context* context, char* path, BTRFS_TIME* atime, BTRFS_TIME* mtime, BTRFS_TIME* ctime) {
    ULONG pos = context->datalen;

    send_command(context, BTRFS_SEND_CMD_UTIMES);

    send_add_tlv(context, BTRFS_SEND_TLV_PATH, path, path ? strlen(path) : 0);
    send_add_tlv(context, BTRFS_SEND_TLV_ATIME, atime, sizeof(BTRFS_TIME));
    send_add_tlv(context, BTRFS_SEND_TLV_MTIME, mtime, sizeof(BTRFS_TIME));
    send_add_tlv(context, BTRFS_SEND_TLV_CTIME, ctime, sizeof(BTRFS_TIME));

    send_command_finish(context, pos);
}

static void send_truncate_command(send_context* context, char* path, UINT64 size) {
    ULONG pos = context->datalen;

    send_command(context, BTRFS_SEND_CMD_TRUNCATE);

    send_add_tlv(context, BTRFS_SEND_TLV_PATH, path, path ? strlen(path) : 0);
    send_add_tlv(context, BTRFS_SEND_TLV_SIZE, &size, sizeof(UINT64));

    send_command_finish(context, pos);
}

static NTSTATUS flush_refs(send_context* context) {
    NTSTATUS Status;

    while (!IsListEmpty(&context->lastinode.refs)) {
        ref* r = CONTAINING_RECORD(RemoveHeadList(&context->lastinode.refs), ref, list_entry);

        Status = found_path(context, r->sd, r->name, r->namelen);
        if (!NT_SUCCESS(Status)) {
            ERR("found_path returned %08x\n", Status);
            return Status;
        }

        if (!r->sd)
            send_utimes_command(context, NULL, &context->root_dir.atime, &context->root_dir.mtime, &context->root_dir.ctime);
        else if (!r->sd->dummy) {
            Status = send_utimes_command_dir(context, r->sd, &r->sd->atime, &r->sd->mtime, &r->sd->ctime);
            if (!NT_SUCCESS(Status)) {
                ERR("send_utimes_command_dir returned %08x\n", Status);
                return Status;
            }
        }

        ExFreePool(r);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS finish_inode(send_context* context) {
    if (!IsListEmpty(&context->lastinode.refs)) {
        NTSTATUS Status = flush_refs(context);
        if (!NT_SUCCESS(Status)) {
            ERR("flush_refs returned %08x\n", Status);
            return Status;
        }
    }

    if (context->lastinode.file)
        send_truncate_command(context, context->lastinode.path, context->lastinode.size);

    send_chown_command(context, context->lastinode.path, context->lastinode.uid, context->lastinode.gid);

    if ((context->lastinode.mode & __S_IFLNK) != __S_IFLNK || ((context->lastinode.mode & 07777) != 0777))
        send_chmod_command(context, context->lastinode.path, context->lastinode.mode);

    send_utimes_command(context, context->lastinode.path, &context->lastinode.atime, &context->lastinode.mtime, &context->lastinode.ctime);

    context->lastinode.inode = 0;
    context->lastinode.o = NULL;

    if (context->lastinode.path) {
        ExFreePool(context->lastinode.path);
        context->lastinode.path = NULL;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS send_extent_data(send_context* context, traverse_ptr* tp, traverse_ptr* tp2) {
    NTSTATUS Status;
    ULONG pos;
    EXTENT_DATA* ed;
    EXTENT_DATA2* ed2;

    if (tp2 && !tp)
        return STATUS_SUCCESS; // FIXME

    if (!IsListEmpty(&context->lastinode.refs)) {
        Status = flush_refs(context);
        if (!NT_SUCCESS(Status)) {
            ERR("flush_refs returned %08x\n", Status);
            return Status;
        }
    }

    if ((context->lastinode.mode & __S_IFLNK) == __S_IFLNK)
        return STATUS_SUCCESS;

    if (tp->item->size < sizeof(EXTENT_DATA)) {
        ERR("(%llx,%x,%llx) was %u bytes, expected at least %u\n", tp->item->key.obj_id, tp->item->key.obj_type, tp->item->key.offset,
            tp->item->size, sizeof(EXTENT_DATA));
        return STATUS_INTERNAL_ERROR;
    }

    ed = (EXTENT_DATA*)tp->item->data;

    if (ed->type == EXTENT_TYPE_PREALLOC)
        return STATUS_SUCCESS;

    if (ed->type != EXTENT_TYPE_INLINE && ed->type != EXTENT_TYPE_REGULAR) {
        ERR("unknown EXTENT_DATA type %u\n", ed->type);
        return STATUS_INTERNAL_ERROR;
    }

    if (ed->encryption != BTRFS_ENCRYPTION_NONE) {
        ERR("unknown encryption type %u\n", ed->encryption);
        return STATUS_INTERNAL_ERROR;
    }

    if (ed->encoding != BTRFS_ENCODING_NONE) {
        ERR("unknown encoding type %u\n", ed->encoding);
        return STATUS_INTERNAL_ERROR;
    }

    if (ed->compression != BTRFS_COMPRESSION_NONE && ed->compression != BTRFS_COMPRESSION_ZLIB && ed->compression != BTRFS_COMPRESSION_LZO) {
        ERR("unknown compression type %u\n", ed->compression);
        return STATUS_INTERNAL_ERROR;
    }

    if (ed->type == EXTENT_TYPE_INLINE) {
        if (tp->item->size < offsetof(EXTENT_DATA, data[0]) + ed->decoded_size) {
            ERR("(%llx,%x,%llx) was %u bytes, expected %u\n", tp->item->key.obj_id, tp->item->key.obj_type, tp->item->key.offset,
                tp->item->size, offsetof(EXTENT_DATA, data[0]) + ed->decoded_size);
            return STATUS_INTERNAL_ERROR;
        }

        pos = context->datalen;

        send_command(context, BTRFS_SEND_CMD_WRITE);

        send_add_tlv(context, BTRFS_SEND_TLV_PATH, context->lastinode.path, context->lastinode.path ? strlen(context->lastinode.path) : 0);
        send_add_tlv(context, BTRFS_SEND_TLV_OFFSET, &tp->item->key.offset, sizeof(UINT64));
        send_add_tlv(context, BTRFS_SEND_TLV_DATA, ed->data, ed->decoded_size);

        send_command_finish(context, pos);

        return STATUS_SUCCESS;
    }

    if (tp->item->size < offsetof(EXTENT_DATA, data[0]) + sizeof(EXTENT_DATA2)) {
        ERR("(%llx,%x,%llx) was %u bytes, expected %u\n", tp->item->key.obj_id, tp->item->key.obj_type, tp->item->key.offset,
            tp->item->size, offsetof(EXTENT_DATA, data[0]) + sizeof(EXTENT_DATA2));
        return STATUS_INTERNAL_ERROR;
    }

    ed2 = (EXTENT_DATA2*)ed->data;

    if (ed2->size == 0) // sparse
        return STATUS_SUCCESS;

    if (ed->compression == BTRFS_COMPRESSION_NONE) {
        UINT64 off, offset;
        UINT8* buf;

        buf = ExAllocatePoolWithTag(NonPagedPool, MAX_SEND_WRITE, ALLOC_TAG);
        if (!buf) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        for (off = ed2->offset; off < ed2->offset + ed2->num_bytes; off += MAX_SEND_WRITE) {
            ULONG length = min(ed2->offset + ed2->num_bytes - off, MAX_SEND_WRITE);

            if (context->datalen > SEND_BUFFER_LENGTH) {
                KEY key = tp->item->key;

                ExReleaseResourceLite(&context->Vcb->tree_lock);

                KeClearEvent(&context->cleared_event);
                KeSetEvent(&context->buffer_event, 0, TRUE);
                KeWaitForSingleObject(&context->cleared_event, Executive, KernelMode, FALSE, NULL);

                ExAcquireResourceSharedLite(&context->Vcb->tree_lock, TRUE);

                Status = find_item(context->Vcb, context->root, tp, &key, FALSE, NULL);
                if (!NT_SUCCESS(Status)) {
                    ERR("find_item returned %08x\n", Status);
                    return Status;
                }

                if (keycmp(tp->item->key, key)) {
                    ERR("readonly subvolume changed\n");
                    return STATUS_INTERNAL_ERROR;
                }

                if (tp->item->size < sizeof(EXTENT_DATA)) {
                    ERR("(%llx,%x,%llx) was %u bytes, expected at least %u\n", tp->item->key.obj_id, tp->item->key.obj_type, tp->item->key.offset,
                        tp->item->size, sizeof(EXTENT_DATA));
                    return STATUS_INTERNAL_ERROR;
                }

                ed = (EXTENT_DATA*)tp->item->data;

                if (tp->item->size < offsetof(EXTENT_DATA, data[0]) + sizeof(EXTENT_DATA2)) {
                    ERR("(%llx,%x,%llx) was %u bytes, expected %u\n", tp->item->key.obj_id, tp->item->key.obj_type, tp->item->key.offset,
                        tp->item->size, offsetof(EXTENT_DATA, data[0]) + sizeof(EXTENT_DATA2));
                    return STATUS_INTERNAL_ERROR;
                }

                ed2 = (EXTENT_DATA2*)ed->data;
            }

            Status = read_data(context->Vcb, ed2->address + off, length, NULL, FALSE,
                               buf, NULL, NULL, NULL, 0, FALSE);
            if (!NT_SUCCESS(Status)) {
                ERR("read_data returned %08x\n", Status);
                ExFreePool(buf);
                return Status;
            }

            pos = context->datalen;

            send_command(context, BTRFS_SEND_CMD_WRITE);

            send_add_tlv(context, BTRFS_SEND_TLV_PATH, context->lastinode.path, context->lastinode.path ? strlen(context->lastinode.path) : 0);

            offset = tp->item->key.offset + off;
            send_add_tlv(context, BTRFS_SEND_TLV_OFFSET, &offset, sizeof(UINT64));

            length = min(context->lastinode.size - tp->item->key.offset - off, length);
            send_add_tlv(context, BTRFS_SEND_TLV_DATA, buf, length);

            send_command_finish(context, pos);
        }

        ExFreePool(buf);
    } else {
        UINT8 *buf, *compbuf;
        UINT64 off;

        if (ed->decoded_size == 0) {
            ERR("EXTENT_DATA decoded_size was 0\n");
            return STATUS_INTERNAL_ERROR;
        }

        buf = ExAllocatePoolWithTag(PagedPool, ed->decoded_size, ALLOC_TAG);
        if (!buf) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        compbuf = ExAllocatePoolWithTag(PagedPool, ed2->size, ALLOC_TAG);
        if (!compbuf) {
            ERR("out of memory\n");
            ExFreePool(buf);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        Status = read_data(context->Vcb, ed2->address, ed2->size, NULL, FALSE,
                           compbuf, NULL, NULL, NULL, 0, FALSE);
        if (!NT_SUCCESS(Status)) {
            ERR("read_data returned %08x\n", Status);
            ExFreePool(compbuf);
            ExFreePool(buf);
            return Status;
        }

        if (ed->compression == BTRFS_COMPRESSION_ZLIB) {
            Status = zlib_decompress(compbuf, ed2->size, buf, ed->decoded_size);
            if (!NT_SUCCESS(Status)) {
                ERR("zlib_decompress returned %08x\n", Status);
                ExFreePool(compbuf);
                ExFreePool(buf);
                return Status;
            }
        } else if (ed->compression == BTRFS_COMPRESSION_LZO) {
            Status = lzo_decompress(&compbuf[sizeof(UINT32)], ed2->size, buf, ed->decoded_size, sizeof(UINT32));
            if (!NT_SUCCESS(Status)) {
                ERR("lzo_decompress returned %08x\n", Status);
                ExFreePool(compbuf);
                ExFreePool(buf);
                return Status;
            }
        }

        ExFreePool(compbuf);

        for (off = ed2->offset; off < ed2->offset + ed2->num_bytes; off += MAX_SEND_WRITE) {
            ULONG length = min(ed2->offset + ed2->num_bytes - off, MAX_SEND_WRITE);
            UINT64 offset;

            if (context->datalen > SEND_BUFFER_LENGTH) {
                KEY key = tp->item->key;

                ExReleaseResourceLite(&context->Vcb->tree_lock);

                KeClearEvent(&context->cleared_event);
                KeSetEvent(&context->buffer_event, 0, TRUE);
                KeWaitForSingleObject(&context->cleared_event, Executive, KernelMode, FALSE, NULL);

                ExAcquireResourceSharedLite(&context->Vcb->tree_lock, TRUE);

                Status = find_item(context->Vcb, context->root, tp, &key, FALSE, NULL);
                if (!NT_SUCCESS(Status)) {
                    ERR("find_item returned %08x\n", Status);
                    return Status;
                }

                if (keycmp(tp->item->key, key)) {
                    ERR("readonly subvolume changed\n");
                    return STATUS_INTERNAL_ERROR;
                }

                if (tp->item->size < sizeof(EXTENT_DATA)) {
                    ERR("(%llx,%x,%llx) was %u bytes, expected at least %u\n", tp->item->key.obj_id, tp->item->key.obj_type, tp->item->key.offset,
                        tp->item->size, sizeof(EXTENT_DATA));
                    return STATUS_INTERNAL_ERROR;
                }

                ed = (EXTENT_DATA*)tp->item->data;

                if (tp->item->size < offsetof(EXTENT_DATA, data[0]) + sizeof(EXTENT_DATA2)) {
                    ERR("(%llx,%x,%llx) was %u bytes, expected %u\n", tp->item->key.obj_id, tp->item->key.obj_type, tp->item->key.offset,
                        tp->item->size, offsetof(EXTENT_DATA, data[0]) + sizeof(EXTENT_DATA2));
                    return STATUS_INTERNAL_ERROR;
                }

                ed2 = (EXTENT_DATA2*)ed->data;
            }

            pos = context->datalen;

            send_command(context, BTRFS_SEND_CMD_WRITE);

            send_add_tlv(context, BTRFS_SEND_TLV_PATH, context->lastinode.path, context->lastinode.path ? strlen(context->lastinode.path) : 0);

            offset = tp->item->key.offset + off;
            send_add_tlv(context, BTRFS_SEND_TLV_OFFSET, &offset, sizeof(UINT64));

            length = min(context->lastinode.size - tp->item->key.offset - off, length);
            send_add_tlv(context, BTRFS_SEND_TLV_DATA, &buf[off], length);

            send_command_finish(context, pos);
        }

        ExFreePool(buf);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS send_xattr(send_context* context, traverse_ptr* tp, traverse_ptr* tp2) {
    DIR_ITEM* di;
    ULONG len;

    if (tp2 && !tp)
        return STATUS_SUCCESS; // FIXME

    if (!IsListEmpty(&context->lastinode.refs)) {
        NTSTATUS Status = flush_refs(context);
        if (!NT_SUCCESS(Status)) {
            ERR("flush_refs returned %08x\n", Status);
            return Status;
        }
    }

    if (tp->item->size < sizeof(DIR_ITEM)) {
        ERR("(%llx,%x,%llx) was %u bytes, expected at least %u\n", tp->item->key.obj_id, tp->item->key.obj_type, tp->item->key.offset,
            tp->item->size, sizeof(DIR_ITEM));
        return STATUS_INTERNAL_ERROR;
    }

    len = tp->item->size;
    di = (DIR_ITEM*)tp->item->data;

    do {
        ULONG pos;

        if (len < sizeof(DIR_ITEM) || len < offsetof(DIR_ITEM, name[0]) + di->m + di->n) {
            ERR("(%llx,%x,%llx) was truncated\n", tp->item->key.obj_id, tp->item->key.obj_type, tp->item->key.offset);
            return STATUS_INTERNAL_ERROR;
        }

        pos = context->datalen;
        send_command(context, BTRFS_SEND_CMD_SET_XATTR);
        send_add_tlv(context, BTRFS_SEND_TLV_PATH, context->lastinode.path, context->lastinode.path ? strlen(context->lastinode.path) : 0);
        send_add_tlv(context, BTRFS_SEND_TLV_XATTR_NAME, di->name, di->n);
        send_add_tlv(context, BTRFS_SEND_TLV_XATTR_DATA, &di->name[di->n], di->m);
        send_command_finish(context, pos);

        len -= offsetof(DIR_ITEM, name[0]) + di->m + di->n;
        di = (DIR_ITEM*)&di->name[di->m + di->n];
    } while (len > 0);

    return STATUS_SUCCESS;
}

static void send_thread(void* ctx) {
    send_context* context = (send_context*)ctx;
    device_extension* Vcb = context->Vcb;
    NTSTATUS Status;
    KEY searchkey;
    traverse_ptr tp, tp2;

    ExAcquireResourceSharedLite(&context->Vcb->tree_lock, TRUE);

    searchkey.obj_id = searchkey.obj_type = searchkey.offset = 0;

    Status = find_item(context->Vcb, context->root, &tp, &searchkey, FALSE, NULL);
    if (!NT_SUCCESS(Status)) {
        ERR("find_item returned %08x\n", Status);
        goto end;
    }

    if (context->parent) {
        BOOL ended1 = FALSE, ended2 = FALSE;
        Status = find_item(context->Vcb, context->parent, &tp2, &searchkey, FALSE, NULL);
        if (!NT_SUCCESS(Status)) {
            ERR("find_item returned %08x\n", Status);
            goto end;
        }

        // FIXME - skip blocks entirely if they are reflinked to the same place on disk
        do {
            traverse_ptr next_tp;

            if (context->datalen > SEND_BUFFER_LENGTH) {
                KEY key1 = tp.item->key, key2 = tp2.item->key;

                ExReleaseResourceLite(&context->Vcb->tree_lock);

                KeClearEvent(&context->cleared_event);
                KeSetEvent(&context->buffer_event, 0, TRUE);
                KeWaitForSingleObject(&context->cleared_event, Executive, KernelMode, FALSE, NULL);

                ExAcquireResourceSharedLite(&context->Vcb->tree_lock, TRUE);

                if (!ended1) {
                    Status = find_item(context->Vcb, context->root, &tp, &key1, FALSE, NULL);
                    if (!NT_SUCCESS(Status)) {
                        ERR("find_item returned %08x\n", Status);
                        goto end;
                    }

                    if (keycmp(tp.item->key, key1)) {
                        ERR("readonly subvolume changed\n");
                        Status = STATUS_INTERNAL_ERROR;
                        goto end;
                    }
                }

                if (!ended2) {
                    Status = find_item(context->Vcb, context->parent, &tp2, &key2, FALSE, NULL);
                    if (!NT_SUCCESS(Status)) {
                        ERR("find_item returned %08x\n", Status);
                        goto end;
                    }

                    if (keycmp(tp.item->key, key2)) {
                        ERR("readonly subvolume changed\n");
                        Status = STATUS_INTERNAL_ERROR;
                        goto end;
                    }
                }
            }

            if (!ended1 && !ended2 && !keycmp(tp.item->key, tp2.item->key)) {
                TRACE("~ %llx,%x,%llx\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset);

                if (tp.item->key.obj_type == TYPE_INODE_ITEM) {
                    Status = send_inode(context, &tp, &tp2);
                    if (!NT_SUCCESS(Status)) {
                        ERR("send_inode returned %08x\n", Status);
                        ExReleaseResourceLite(&context->Vcb->tree_lock);
                        goto end;
                    }
                } else if (tp.item->key.obj_type == TYPE_INODE_REF) {
                    Status = send_inode_ref(context, &tp, &tp2);
                    if (!NT_SUCCESS(Status)) {
                        ERR("send_inode_ref returned %08x\n", Status);
                        ExReleaseResourceLite(&context->Vcb->tree_lock);
                        goto end;
                    }
                } else if (tp.item->key.obj_type == TYPE_INODE_EXTREF) {
                    Status = send_inode_extref(context, &tp, &tp2);
                    if (!NT_SUCCESS(Status)) {
                        ERR("send_inode_extref returned %08x\n", Status);
                        ExReleaseResourceLite(&context->Vcb->tree_lock);
                        goto end;
                    }
                } else if (tp.item->key.obj_type == TYPE_EXTENT_DATA) {
                    Status = send_extent_data(context, &tp, &tp2);
                    if (!NT_SUCCESS(Status)) {
                        ERR("send_extent_data returned %08x\n", Status);
                        ExReleaseResourceLite(&context->Vcb->tree_lock);
                        goto end;
                    }
                } else if (tp.item->key.obj_type == TYPE_XATTR_ITEM) {
                    Status = send_xattr(context, &tp, &tp2);
                    if (!NT_SUCCESS(Status)) {
                        ERR("send_xattr returned %08x\n", Status);
                        ExReleaseResourceLite(&context->Vcb->tree_lock);
                        goto end;
                    }
                }

                if (find_next_item(context->Vcb, &tp, &next_tp, FALSE, NULL))
                    tp = next_tp;
                else
                    ended1 = TRUE;

                if (find_next_item(context->Vcb, &tp2, &next_tp, FALSE, NULL))
                    tp2 = next_tp;
                else
                    ended2 = TRUE;
            } else if (ended2 || keycmp(tp.item->key, tp2.item->key) == -1) {
                TRACE("A %llx,%x,%llx\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset);

                if (tp.item->key.obj_type == TYPE_INODE_ITEM) {
                    Status = send_inode(context, &tp, NULL);
                    if (!NT_SUCCESS(Status)) {
                        ERR("send_inode returned %08x\n", Status);
                        ExReleaseResourceLite(&context->Vcb->tree_lock);
                        goto end;
                    }
                } else if (tp.item->key.obj_type == TYPE_INODE_REF) {
                    Status = send_inode_ref(context, &tp, NULL);
                    if (!NT_SUCCESS(Status)) {
                        ERR("send_inode_ref returned %08x\n", Status);
                        ExReleaseResourceLite(&context->Vcb->tree_lock);
                        goto end;
                    }
                } else if (tp.item->key.obj_type == TYPE_INODE_EXTREF) {
                    Status = send_inode_extref(context, &tp, NULL);
                    if (!NT_SUCCESS(Status)) {
                        ERR("send_inode_extref returned %08x\n", Status);
                        ExReleaseResourceLite(&context->Vcb->tree_lock);
                        goto end;
                    }
                } else if (tp.item->key.obj_type == TYPE_EXTENT_DATA) {
                    Status = send_extent_data(context, &tp, NULL);
                    if (!NT_SUCCESS(Status)) {
                        ERR("send_extent_data returned %08x\n", Status);
                        ExReleaseResourceLite(&context->Vcb->tree_lock);
                        goto end;
                    }
                } else if (tp.item->key.obj_type == TYPE_XATTR_ITEM) {
                    Status = send_xattr(context, &tp, NULL);
                    if (!NT_SUCCESS(Status)) {
                        ERR("send_xattr returned %08x\n", Status);
                        ExReleaseResourceLite(&context->Vcb->tree_lock);
                        goto end;
                    }
                }

                if (find_next_item(context->Vcb, &tp, &next_tp, FALSE, NULL))
                    tp = next_tp;
                else
                    ended1 = TRUE;
            } else if (ended1 || keycmp(tp.item->key, tp2.item->key) == 1) {
                TRACE("B %llx,%x,%llx\n", tp2.item->key.obj_id, tp2.item->key.obj_type, tp2.item->key.offset);

                if (tp2.item->key.obj_type == TYPE_INODE_ITEM) {
                    Status = send_inode(context, NULL, &tp2);
                    if (!NT_SUCCESS(Status)) {
                        ERR("send_inode returned %08x\n", Status);
                        ExReleaseResourceLite(&context->Vcb->tree_lock);
                        goto end;
                    }
                } else if (tp2.item->key.obj_type == TYPE_INODE_REF) {
                    Status = send_inode_ref(context, NULL, &tp2);
                    if (!NT_SUCCESS(Status)) {
                        ERR("send_inode_ref returned %08x\n", Status);
                        ExReleaseResourceLite(&context->Vcb->tree_lock);
                        goto end;
                    }
                } else if (tp2.item->key.obj_type == TYPE_INODE_EXTREF) {
                    Status = send_inode_extref(context, NULL, &tp2);
                    if (!NT_SUCCESS(Status)) {
                        ERR("send_inode_extref returned %08x\n", Status);
                        ExReleaseResourceLite(&context->Vcb->tree_lock);
                        goto end;
                    }
                } else if (tp2.item->key.obj_type == TYPE_EXTENT_DATA) {
                    Status = send_extent_data(context, NULL, &tp2);
                    if (!NT_SUCCESS(Status)) {
                        ERR("send_extent_data returned %08x\n", Status);
                        ExReleaseResourceLite(&context->Vcb->tree_lock);
                        goto end;
                    }
                } else if (tp2.item->key.obj_type == TYPE_XATTR_ITEM) {
                    Status = send_xattr(context, NULL, &tp2);
                    if (!NT_SUCCESS(Status)) {
                        ERR("send_xattr returned %08x\n", Status);
                        ExReleaseResourceLite(&context->Vcb->tree_lock);
                        goto end;
                    }
                }

                if (find_next_item(context->Vcb, &tp2, &next_tp, FALSE, NULL))
                    tp2 = next_tp;
                else
                    ended2 = TRUE;
            }
        } while (!ended1 || !ended2);
    } else {
        do {
            traverse_ptr next_tp;

            if (context->datalen > SEND_BUFFER_LENGTH) {
                KEY key = tp.item->key;

                ExReleaseResourceLite(&context->Vcb->tree_lock);

                KeClearEvent(&context->cleared_event);
                KeSetEvent(&context->buffer_event, 0, TRUE);
                KeWaitForSingleObject(&context->cleared_event, Executive, KernelMode, FALSE, NULL);

                ExAcquireResourceSharedLite(&context->Vcb->tree_lock, TRUE);

                Status = find_item(context->Vcb, context->root, &tp, &key, FALSE, NULL);
                if (!NT_SUCCESS(Status)) {
                    ERR("find_item returned %08x\n", Status);
                    goto end;
                }

                if (keycmp(tp.item->key, key)) {
                    ERR("readonly subvolume changed\n");
                    Status = STATUS_INTERNAL_ERROR;
                    goto end;
                }
            }

            if (context->lastinode.inode != 0 && tp.item->key.obj_id > context->lastinode.inode) {
                Status = finish_inode(context);
                if (!NT_SUCCESS(Status)) {
                    ERR("finish_inode returned %08x\n", Status);
                    ExReleaseResourceLite(&context->Vcb->tree_lock);
                    goto end;
                }
            }

            if (tp.item->key.obj_type == TYPE_INODE_ITEM) {
                Status = send_inode(context, &tp, NULL);
                if (!NT_SUCCESS(Status)) {
                    ERR("send_inode returned %08x\n", Status);
                    ExReleaseResourceLite(&context->Vcb->tree_lock);
                    goto end;
                }
            } else if (tp.item->key.obj_type == TYPE_INODE_REF) {
                Status = send_inode_ref(context, &tp, NULL);
                if (!NT_SUCCESS(Status)) {
                    ERR("send_inode_ref returned %08x\n", Status);
                    ExReleaseResourceLite(&context->Vcb->tree_lock);
                    goto end;
                }
            } else if (tp.item->key.obj_type == TYPE_INODE_EXTREF) {
                Status = send_inode_extref(context, &tp, NULL);
                if (!NT_SUCCESS(Status)) {
                    ERR("send_inode_extref returned %08x\n", Status);
                    ExReleaseResourceLite(&context->Vcb->tree_lock);
                    goto end;
                }
            } else if (tp.item->key.obj_type == TYPE_EXTENT_DATA) {
                Status = send_extent_data(context, &tp, NULL);
                if (!NT_SUCCESS(Status)) {
                    ERR("send_extent_data returned %08x\n", Status);
                    ExReleaseResourceLite(&context->Vcb->tree_lock);
                    goto end;
                }
            } else if (tp.item->key.obj_type == TYPE_XATTR_ITEM) {
                Status = send_xattr(context, &tp, NULL);
                if (!NT_SUCCESS(Status)) {
                    ERR("send_xattr returned %08x\n", Status);
                    ExReleaseResourceLite(&context->Vcb->tree_lock);
                    goto end;
                }
            }

            if (find_next_item(context->Vcb, &tp, &next_tp, FALSE, NULL))
                tp = next_tp;
            else
                break;
        } while (TRUE);
    }

    ExReleaseResourceLite(&context->Vcb->tree_lock);

    if (context->lastinode.inode != 0) {
        Status = finish_inode(context);
        if (!NT_SUCCESS(Status)) {
            ERR("finish_inode returned %08x\n", Status);
            goto end;
        }
    }

    send_end_command(context);

//     send_write_data(context, context->data, context->datalen);

    KeClearEvent(&context->cleared_event);
    KeSetEvent(&context->buffer_event, 0, TRUE);
    KeWaitForSingleObject(&context->cleared_event, Executive, KernelMode, FALSE, NULL);

end:
    ExAcquireResourceExclusiveLite(&Vcb->send.load_lock, TRUE);

    while (!IsListEmpty(&context->orphans)) {
        orphan* o = CONTAINING_RECORD(RemoveHeadList(&context->orphans), orphan, list_entry);
        ExFreePool(o);
    }

    while (!IsListEmpty(&context->dirs)) {
        send_dir* sd = CONTAINING_RECORD(RemoveHeadList(&context->dirs), send_dir, list_entry);

        if (sd->name)
            ExFreePool(sd->name);

        ExFreePool(sd);
    }

    ZwClose(context->Vcb->send.thread);
    context->Vcb->send.thread = NULL;

    ExFreePool(context->data);
    ExFreePool(context);

    ExReleaseResourceLite(&Vcb->send.load_lock);
}

NTSTATUS send_subvol(device_extension* Vcb, void* data, ULONG datalen, PFILE_OBJECT FileObject, PIRP Irp) {
    NTSTATUS Status;
    fcb* fcb;
    ccb* ccb;
    root* parsubvol = NULL;
    send_context* context;
    btrfs_send_header* header;
    
    // FIXME - cloning

    if (!FileObject || !FileObject->FsContext || !FileObject->FsContext2 || FileObject->FsContext == Vcb->volume_fcb)
        return STATUS_INVALID_PARAMETER;

    // FIXME - check user has volume privilege

    fcb = FileObject->FsContext;
    ccb = FileObject->FsContext2;

    if (fcb->inode != SUBVOL_ROOT_INODE || fcb == Vcb->root_fileref->fcb)
        return STATUS_INVALID_PARAMETER;

    if (data) {
        btrfs_send_subvol* bss = (btrfs_send_subvol*)data;

        if (datalen < sizeof(btrfs_send_subvol))
            return STATUS_INVALID_PARAMETER;

        if (bss->parent) {
            HANDLE h;
            PFILE_OBJECT fileobj;
            struct _fcb* parfcb;

#if defined(_WIN64)
            if (IoIs32bitProcess(Irp))
                h = (HANDLE)LongToHandle(*(PUINT32)&bss->parent);
            else
#endif
                h = bss->parent;

            Status = ObReferenceObjectByHandle(h, 0, *IoFileObjectType, Irp->RequestorMode, (void**)&fileobj, NULL);
            if (!NT_SUCCESS(Status)) {
                ERR("ObReferenceObjectByHandle returned %08x\n", Status);
                return Status;
            }

            parfcb = fileobj->FsContext;

            if (!parfcb || parfcb == Vcb->root_fileref->fcb || parfcb == Vcb->volume_fcb || parfcb->inode != SUBVOL_ROOT_INODE) {
                ObDereferenceObject(fileobj);
                return STATUS_INVALID_PARAMETER;
            }

            parsubvol = parfcb->subvol;
            ObDereferenceObject(fileobj);
        }
    }

    // FIXME - check subvol or FS is readonly
    // FIXME - if subvol only just made readonly, check it has been flushed
    // FIXME - make it so any relevant subvols can't be made read-write while this is running

    ExAcquireResourceExclusiveLite(&Vcb->send.load_lock, TRUE);

    if (Vcb->send.thread) {
        WARN("send operation already running\n");
        ExReleaseResourceLite(&Vcb->send.load_lock);
        return STATUS_DEVICE_NOT_READY;
    }

    context = ExAllocatePoolWithTag(NonPagedPool, sizeof(send_context), ALLOC_TAG);
    if (!context) {
        ERR("out of memory\n");
        ExReleaseResourceLite(&Vcb->send.load_lock);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    context->Vcb = Vcb;
    context->root = fcb->subvol;
    context->parent = parsubvol;
    InitializeListHead(&context->orphans);
    InitializeListHead(&context->dirs);
    context->lastinode.inode = 0;
    InitializeListHead(&context->lastinode.refs);

    context->data = ExAllocatePoolWithTag(PagedPool, SEND_BUFFER_LENGTH + (2 * MAX_SEND_WRITE), ALLOC_TAG); // give ourselves some wiggle room
    if (!context->data) {
        ExFreePool(context);
        ExReleaseResourceLite(&Vcb->send.load_lock);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    header = (btrfs_send_header*)context->data;

    RtlCopyMemory(header->magic, BTRFS_SEND_MAGIC, sizeof(BTRFS_SEND_MAGIC));
    header->version = 1;
    context->datalen = sizeof(btrfs_send_header);

    send_subvol_header(context, fcb->subvol, ccb->fileref); // FIXME - fileref needs some sort of lock here

    Vcb->send.context = context;

    KeInitializeEvent(&context->buffer_event, NotificationEvent, FALSE);
    KeInitializeEvent(&context->cleared_event, NotificationEvent, FALSE);

    Status = PsCreateSystemThread(&Vcb->send.thread, 0, NULL, NULL, NULL, send_thread, context);
    if (!NT_SUCCESS(Status)) {
        ERR("PsCreateSystemThread returned %08x\n", Status);
        ExFreePool(context->data);
        ExFreePool(context);
        ExReleaseResourceLite(&Vcb->send.load_lock);
        return Status;
    }

    ExReleaseResourceLite(&Vcb->send.load_lock);

    return STATUS_SUCCESS;
}

NTSTATUS read_send_buffer(device_extension* Vcb, void* data, ULONG datalen, ULONG_PTR* retlen) {
    send_context* context = (send_context*)Vcb->send.context;

    // FIXME - check for volume privileges

    ExAcquireResourceExclusiveLite(&Vcb->send.load_lock, TRUE);

    if (!Vcb->send.thread) {
        ExReleaseResourceLite(&Vcb->send.load_lock);
        return STATUS_END_OF_FILE;
    }

    KeWaitForSingleObject(&context->buffer_event, Executive, KernelMode, FALSE, NULL);

    if (datalen == 0) {
        ExReleaseResourceLite(&Vcb->send.load_lock);
        return STATUS_SUCCESS;
    }

    RtlCopyMemory(data, context->data, min(datalen, context->datalen));

    if (datalen < context->datalen) { // not empty yet
        *retlen = datalen;
        RtlMoveMemory(context->data, &context->data[datalen], context->datalen - datalen);
        context->datalen -= datalen;
        ExReleaseResourceLite(&Vcb->send.load_lock);
    } else {
        *retlen = context->datalen;
        context->datalen = 0;
        ExReleaseResourceLite(&Vcb->send.load_lock);

        KeClearEvent(&context->buffer_event);
        KeSetEvent(&context->cleared_event, 0, FALSE);
    }

    return STATUS_SUCCESS;
}
