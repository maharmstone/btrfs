/* Copyright (c) Mark Harmstone 2016-17
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

// not currently in mingw - introduced with Windows 10
#ifndef FileIdInformation
#define FileIdInformation (enum _FILE_INFORMATION_CLASS)59
#endif

static NTSTATUS set_basic_information(device_extension* Vcb, PIRP Irp, PFILE_OBJECT FileObject) {
    FILE_BASIC_INFORMATION* fbi = Irp->AssociatedIrp.SystemBuffer;
    fcb* fcb = FileObject->FsContext;
    ccb* ccb = FileObject->FsContext2;
    file_ref* fileref = ccb ? ccb->fileref : NULL;
    ULONG defda, filter = 0;
    BOOL inode_item_changed = FALSE;
    NTSTATUS Status;

    if (fcb->ads) {
        if (fileref && fileref->parent)
            fcb = fileref->parent->fcb;
        else {
            ERR("stream did not have fileref\n");
            return STATUS_INTERNAL_ERROR;
        }
    }

    if (!ccb) {
        ERR("ccb was NULL\n");
        return STATUS_INVALID_PARAMETER;
    }

    TRACE("file = %S, attributes = %x\n", file_desc(FileObject), fbi->FileAttributes);

    ExAcquireResourceExclusiveLite(fcb->Header.Resource, TRUE);

    if (fbi->FileAttributes & FILE_ATTRIBUTE_DIRECTORY && fcb->type != BTRFS_TYPE_DIRECTORY) {
        WARN("attempted to set FILE_ATTRIBUTE_DIRECTORY on non-directory\n");
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    if (fcb->inode == SUBVOL_ROOT_INODE && is_subvol_readonly(fcb->subvol, Irp) &&
        (fbi->FileAttributes == 0 || fbi->FileAttributes & FILE_ATTRIBUTE_READONLY)) {
        Status = STATUS_ACCESS_DENIED;
        goto end;
    }

    // don't allow readonly subvol to be made r/w if send operation running on it
    if (fcb->inode == SUBVOL_ROOT_INODE && fcb->subvol->root_item.flags & BTRFS_SUBVOL_READONLY &&
        fcb->subvol->send_ops > 0) {
        Status = STATUS_DEVICE_NOT_READY;
        goto end;
    }

    if (fbi->CreationTime.QuadPart == -1)
        ccb->user_set_creation_time = TRUE;
    else if (fbi->CreationTime.QuadPart != 0) {
        win_time_to_unix(fbi->CreationTime, &fcb->inode_item.otime);
        inode_item_changed = TRUE;
        filter |= FILE_NOTIFY_CHANGE_CREATION;

        ccb->user_set_creation_time = TRUE;
    }

    if (fbi->LastAccessTime.QuadPart == -1)
        ccb->user_set_access_time = TRUE;
    else if (fbi->LastAccessTime.QuadPart != 0) {
        win_time_to_unix(fbi->LastAccessTime, &fcb->inode_item.st_atime);
        inode_item_changed = TRUE;
        filter |= FILE_NOTIFY_CHANGE_LAST_ACCESS;

        ccb->user_set_access_time = TRUE;
    }

    if (fbi->LastWriteTime.QuadPart == -1)
        ccb->user_set_write_time = TRUE;
    else if (fbi->LastWriteTime.QuadPart != 0) {
        win_time_to_unix(fbi->LastWriteTime, &fcb->inode_item.st_mtime);
        inode_item_changed = TRUE;
        filter |= FILE_NOTIFY_CHANGE_LAST_WRITE;

        ccb->user_set_write_time = TRUE;
    }

    if (fbi->ChangeTime.QuadPart == -1)
        ccb->user_set_change_time = TRUE;
    else if (fbi->ChangeTime.QuadPart != 0) {
        win_time_to_unix(fbi->ChangeTime, &fcb->inode_item.st_ctime);
        inode_item_changed = TRUE;
        // no filter for this

        ccb->user_set_change_time = TRUE;
    }

    // FileAttributes == 0 means don't set - undocumented, but seen in fastfat
    if (fbi->FileAttributes != 0) {
        LARGE_INTEGER time;
        BTRFS_TIME now;

        fbi->FileAttributes &= ~FILE_ATTRIBUTE_NORMAL;

        defda = get_file_attributes(Vcb, fcb->subvol, fcb->inode, fcb->type, fileref && fileref->dc && fileref->dc->name.Length >= sizeof(WCHAR) && fileref->dc->name.Buffer[0] == '.',
                                    TRUE, Irp);

        if (fcb->type == BTRFS_TYPE_DIRECTORY)
            fbi->FileAttributes |= FILE_ATTRIBUTE_DIRECTORY;
        else if (fcb->type == BTRFS_TYPE_SYMLINK)
            fbi->FileAttributes |= FILE_ATTRIBUTE_REPARSE_POINT;

        fcb->atts_changed = TRUE;

        if (fcb->atts & FILE_ATTRIBUTE_REPARSE_POINT)
            fbi->FileAttributes |= FILE_ATTRIBUTE_REPARSE_POINT;

        if (defda == fbi->FileAttributes)
            fcb->atts_deleted = TRUE;
        else if (fcb->inode == SUBVOL_ROOT_INODE && (defda | FILE_ATTRIBUTE_READONLY) == (fbi->FileAttributes | FILE_ATTRIBUTE_READONLY))
            fcb->atts_deleted = TRUE;

        fcb->atts = fbi->FileAttributes;

        KeQuerySystemTime(&time);
        win_time_to_unix(time, &now);

        if (!ccb->user_set_change_time)
            fcb->inode_item.st_ctime = now;

        fcb->subvol->root_item.ctransid = Vcb->superblock.generation;
        fcb->subvol->root_item.ctime = now;

        if (fcb->inode == SUBVOL_ROOT_INODE) {
            if (fbi->FileAttributes & FILE_ATTRIBUTE_READONLY)
                fcb->subvol->root_item.flags |= BTRFS_SUBVOL_READONLY;
            else
                fcb->subvol->root_item.flags &= ~BTRFS_SUBVOL_READONLY;
        }

        inode_item_changed = TRUE;

        filter |= FILE_NOTIFY_CHANGE_ATTRIBUTES;
    }

    if (inode_item_changed) {
        fcb->inode_item.transid = Vcb->superblock.generation;
        fcb->inode_item.sequence++;
        fcb->inode_item_changed = TRUE;

        mark_fcb_dirty(fcb);
    }

    if (filter != 0)
        send_notification_fcb(fileref, filter, FILE_ACTION_MODIFIED, NULL);

    Status = STATUS_SUCCESS;

end:
    ExReleaseResourceLite(fcb->Header.Resource);

    return Status;
}

static NTSTATUS set_disposition_information(device_extension* Vcb, PIRP Irp, PFILE_OBJECT FileObject) {
    FILE_DISPOSITION_INFORMATION* fdi = Irp->AssociatedIrp.SystemBuffer;
    fcb* fcb = FileObject->FsContext;
    ccb* ccb = FileObject->FsContext2;
    file_ref* fileref = ccb ? ccb->fileref : NULL;
    ULONG atts;
    NTSTATUS Status;

    if (!fileref)
        return STATUS_INVALID_PARAMETER;

    acquire_fcb_lock_exclusive(Vcb);

    ExAcquireResourceExclusiveLite(fcb->Header.Resource, TRUE);

    TRACE("changing delete_on_close to %s for %S (fcb %p)\n", fdi->DeleteFile ? "TRUE" : "FALSE", file_desc(FileObject), fcb);

    if (fcb->ads) {
        if (fileref->parent)
            atts = fileref->parent->fcb->atts;
        else {
            ERR("no fileref for stream\n");
            Status = STATUS_INTERNAL_ERROR;
            goto end;
        }
    } else
        atts = fcb->atts;

    TRACE("atts = %x\n", atts);

    if (atts & FILE_ATTRIBUTE_READONLY) {
        TRACE("not allowing readonly file to be deleted\n");
        Status = STATUS_CANNOT_DELETE;
        goto end;
    }

    // FIXME - can we skip this bit for subvols?
    if (fcb->type == BTRFS_TYPE_DIRECTORY && fcb->inode_item.st_size > 0 && (!fileref || fileref->fcb != Vcb->dummy_fcb)) {
        TRACE("directory not empty\n");
        Status = STATUS_DIRECTORY_NOT_EMPTY;
        goto end;
    }

    if (!MmFlushImageSection(&fcb->nonpaged->segment_object, MmFlushForDelete)) {
        TRACE("trying to delete file which is being mapped as an image\n");
        Status = STATUS_CANNOT_DELETE;
        goto end;
    }

    ccb->fileref->delete_on_close = fdi->DeleteFile;

    FileObject->DeletePending = fdi->DeleteFile;

    Status = STATUS_SUCCESS;

end:
    ExReleaseResourceLite(fcb->Header.Resource);

    release_fcb_lock(Vcb);

    // send notification that directory is about to be deleted
    if (NT_SUCCESS(Status) && fdi->DeleteFile && fcb->type == BTRFS_TYPE_DIRECTORY) {
        FsRtlNotifyFullChangeDirectory(Vcb->NotifySync, &Vcb->DirNotifyList, FileObject->FsContext,
                                       NULL, FALSE, FALSE, 0, NULL, NULL, NULL);
    }

    return Status;
}

BOOL has_open_children(file_ref* fileref) {
    LIST_ENTRY* le = fileref->children.Flink;

    if (IsListEmpty(&fileref->children))
        return FALSE;

    while (le != &fileref->children) {
        file_ref* c = CONTAINING_RECORD(le, file_ref, list_entry);

        if (c->open_count > 0)
            return TRUE;

        if (has_open_children(c))
            return TRUE;

        le = le->Flink;
    }

    return FALSE;
}

static NTSTATUS duplicate_fcb(fcb* oldfcb, fcb** pfcb) {
    device_extension* Vcb = oldfcb->Vcb;
    fcb* fcb;
    LIST_ENTRY* le;

    // FIXME - we can skip a lot of this if the inode is about to be deleted

    fcb = create_fcb(Vcb, PagedPool); // FIXME - what if we duplicate the paging file?
    if (!fcb) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    fcb->Vcb = Vcb;

    fcb->Header.IsFastIoPossible = fast_io_possible(fcb);
    fcb->Header.AllocationSize = oldfcb->Header.AllocationSize;
    fcb->Header.FileSize = oldfcb->Header.FileSize;
    fcb->Header.ValidDataLength = oldfcb->Header.ValidDataLength;

    fcb->type = oldfcb->type;

    if (oldfcb->ads) {
        fcb->ads = TRUE;
        fcb->adshash = oldfcb->adshash;
        fcb->adsmaxlen = oldfcb->adsmaxlen;

        if (oldfcb->adsxattr.Buffer && oldfcb->adsxattr.Length > 0) {
            fcb->adsxattr.Length = oldfcb->adsxattr.Length;
            fcb->adsxattr.MaximumLength = fcb->adsxattr.Length + 1;
            fcb->adsxattr.Buffer = ExAllocatePoolWithTag(PagedPool, fcb->adsxattr.MaximumLength, ALLOC_TAG);

            if (!fcb->adsxattr.Buffer) {
                ERR("out of memory\n");
                free_fcb(Vcb, fcb);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            RtlCopyMemory(fcb->adsxattr.Buffer, oldfcb->adsxattr.Buffer, fcb->adsxattr.Length);
            fcb->adsxattr.Buffer[fcb->adsxattr.Length] = 0;
        }

        if (oldfcb->adsdata.Buffer && oldfcb->adsdata.Length > 0) {
            fcb->adsdata.Length = fcb->adsdata.MaximumLength = oldfcb->adsdata.Length;
            fcb->adsdata.Buffer = ExAllocatePoolWithTag(PagedPool, fcb->adsdata.MaximumLength, ALLOC_TAG);

            if (!fcb->adsdata.Buffer) {
                ERR("out of memory\n");
                free_fcb(Vcb, fcb);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            RtlCopyMemory(fcb->adsdata.Buffer, oldfcb->adsdata.Buffer, fcb->adsdata.Length);
        }

        goto end;
    }

    RtlCopyMemory(&fcb->inode_item, &oldfcb->inode_item, sizeof(INODE_ITEM));
    fcb->inode_item_changed = TRUE;

    if (oldfcb->sd && RtlLengthSecurityDescriptor(oldfcb->sd) > 0) {
        fcb->sd = ExAllocatePoolWithTag(PagedPool, RtlLengthSecurityDescriptor(oldfcb->sd), ALLOC_TAG);
        if (!fcb->sd) {
            ERR("out of memory\n");
            free_fcb(Vcb, fcb);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlCopyMemory(fcb->sd, oldfcb->sd, RtlLengthSecurityDescriptor(oldfcb->sd));
    }

    fcb->atts = oldfcb->atts;

    le = oldfcb->extents.Flink;
    while (le != &oldfcb->extents) {
        extent* ext = CONTAINING_RECORD(le, extent, list_entry);

        if (!ext->ignore) {
            extent* ext2 = ExAllocatePoolWithTag(PagedPool, offsetof(extent, extent_data) + ext->datalen, ALLOC_TAG);

            if (!ext2) {
                ERR("out of memory\n");
                free_fcb(Vcb, fcb);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            ext2->offset = ext->offset;
            ext2->datalen = ext->datalen;

            if (ext2->datalen > 0)
                RtlCopyMemory(&ext2->extent_data, &ext->extent_data, ext2->datalen);

            ext2->unique = FALSE;
            ext2->ignore = FALSE;
            ext2->inserted = TRUE;

            if (ext->csum) {
                ULONG len;
                EXTENT_DATA2* ed2 = (EXTENT_DATA2*)ext->extent_data.data;

                if (ext->extent_data.compression == BTRFS_COMPRESSION_NONE)
                    len = (ULONG)ed2->num_bytes;
                else
                    len = (ULONG)ed2->size;

                len = len * sizeof(UINT32) / Vcb->superblock.sector_size;

                ext2->csum = ExAllocatePoolWithTag(PagedPool, len, ALLOC_TAG);
                if (!ext2->csum) {
                    ERR("out of memory\n");
                    free_fcb(Vcb, fcb);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                RtlCopyMemory(ext2->csum, ext->csum, len);
            } else
                ext2->csum = NULL;

            InsertTailList(&fcb->extents, &ext2->list_entry);
        }

        le = le->Flink;
    }

    le = oldfcb->hardlinks.Flink;
    while (le != &oldfcb->hardlinks) {
        hardlink *hl = CONTAINING_RECORD(le, hardlink, list_entry), *hl2;

        hl2 = ExAllocatePoolWithTag(PagedPool, sizeof(hardlink), ALLOC_TAG);

        if (!hl2) {
            ERR("out of memory\n");
            free_fcb(Vcb, fcb);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        hl2->parent = hl->parent;
        hl2->index = hl->index;

        hl2->name.Length = hl2->name.MaximumLength = hl->name.Length;
        hl2->name.Buffer = ExAllocatePoolWithTag(PagedPool, hl2->name.MaximumLength, ALLOC_TAG);

        if (!hl2->name.Buffer) {
            ERR("out of memory\n");
            ExFreePool(hl2);
            free_fcb(Vcb, fcb);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlCopyMemory(hl2->name.Buffer, hl->name.Buffer, hl->name.Length);

        hl2->utf8.Length = hl2->utf8.MaximumLength = hl->utf8.Length;
        hl2->utf8.Buffer = ExAllocatePoolWithTag(PagedPool, hl2->utf8.MaximumLength, ALLOC_TAG);

        if (!hl2->utf8.Buffer) {
            ERR("out of memory\n");
            ExFreePool(hl2->name.Buffer);
            ExFreePool(hl2);
            free_fcb(Vcb, fcb);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlCopyMemory(hl2->utf8.Buffer, hl->utf8.Buffer, hl->utf8.Length);

        InsertTailList(&fcb->hardlinks, &hl2->list_entry);

        le = le->Flink;
    }

    if (oldfcb->reparse_xattr.Buffer && oldfcb->reparse_xattr.Length > 0) {
        fcb->reparse_xattr.Length = fcb->reparse_xattr.MaximumLength = oldfcb->reparse_xattr.Length;

        fcb->reparse_xattr.Buffer = ExAllocatePoolWithTag(PagedPool, fcb->reparse_xattr.MaximumLength, ALLOC_TAG);
        if (!fcb->reparse_xattr.Buffer) {
            ERR("out of memory\n");
            free_fcb(Vcb, fcb);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlCopyMemory(fcb->reparse_xattr.Buffer, oldfcb->reparse_xattr.Buffer, fcb->reparse_xattr.Length);
    }

    if (oldfcb->ea_xattr.Buffer && oldfcb->ea_xattr.Length > 0) {
        fcb->ea_xattr.Length = fcb->ea_xattr.MaximumLength = oldfcb->ea_xattr.Length;

        fcb->ea_xattr.Buffer = ExAllocatePoolWithTag(PagedPool, fcb->ea_xattr.MaximumLength, ALLOC_TAG);
        if (!fcb->ea_xattr.Buffer) {
            ERR("out of memory\n");
            free_fcb(Vcb, fcb);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlCopyMemory(fcb->ea_xattr.Buffer, oldfcb->ea_xattr.Buffer, fcb->ea_xattr.Length);
    }

    fcb->prop_compression = oldfcb->prop_compression;

    le = oldfcb->xattrs.Flink;
    while (le != &oldfcb->xattrs) {
        xattr* xa = CONTAINING_RECORD(le, xattr, list_entry);

        if (xa->valuelen > 0) {
            xattr* xa2;

            xa2 = ExAllocatePoolWithTag(PagedPool, offsetof(xattr, data[0]) + xa->namelen + xa->valuelen, ALLOC_TAG);

            if (!xa2) {
                ERR("out of memory\n");
                free_fcb(Vcb, fcb);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            xa2->namelen = xa->namelen;
            xa2->valuelen = xa->valuelen;
            xa2->dirty = xa->dirty;
            memcpy(xa2->data, xa->data, xa->namelen + xa->valuelen);

            InsertTailList(&fcb->xattrs, &xa2->list_entry);
        }

        le = le->Flink;
    }

end:
    *pfcb = fcb;

    return STATUS_SUCCESS;
}

typedef struct _move_entry {
    file_ref* fileref;
    fcb* dummyfcb;
    file_ref* dummyfileref;
    struct _move_entry* parent;
    LIST_ENTRY list_entry;
} move_entry;

static NTSTATUS add_children_to_move_list(device_extension* Vcb, move_entry* me, PIRP Irp) {
    NTSTATUS Status;
    LIST_ENTRY* le;

    ExAcquireResourceSharedLite(&me->fileref->fcb->nonpaged->dir_children_lock, TRUE);

    le = me->fileref->fcb->dir_children_index.Flink;

    while (le != &me->fileref->fcb->dir_children_index) {
        dir_child* dc = CONTAINING_RECORD(le, dir_child, list_entry_index);
        file_ref* fr;
        move_entry* me2;

        Status = open_fileref_child(Vcb, me->fileref, &dc->name, TRUE, TRUE, dc->index == 0 ? TRUE : FALSE, PagedPool, &fr, Irp);

        if (!NT_SUCCESS(Status)) {
            ERR("open_fileref_child returned %08x\n", Status);
            ExReleaseResourceLite(&me->fileref->fcb->nonpaged->dir_children_lock);
            return Status;
        }

        me2 = ExAllocatePoolWithTag(PagedPool, sizeof(move_entry), ALLOC_TAG);
        if (!me2) {
            ERR("out of memory\n");
            ExReleaseResourceLite(&me->fileref->fcb->nonpaged->dir_children_lock);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        me2->fileref = fr;
        me2->dummyfcb = NULL;
        me2->dummyfileref = NULL;
        me2->parent = me;

        InsertHeadList(&me->list_entry, &me2->list_entry);

        le = le->Flink;
    }

    ExReleaseResourceLite(&me->fileref->fcb->nonpaged->dir_children_lock);

    return STATUS_SUCCESS;
}

void remove_dir_child_from_hash_lists(fcb* fcb, dir_child* dc) {
    UINT8 c;

    c = dc->hash >> 24;

    if (fcb->hash_ptrs[c] == &dc->list_entry_hash) {
        if (dc->list_entry_hash.Flink == &fcb->dir_children_hash)
            fcb->hash_ptrs[c] = NULL;
        else {
            dir_child* dc2 = CONTAINING_RECORD(dc->list_entry_hash.Flink, dir_child, list_entry_hash);

            if (dc2->hash >> 24 == c)
                fcb->hash_ptrs[c] = &dc2->list_entry_hash;
            else
                fcb->hash_ptrs[c] = NULL;
        }
    }

    RemoveEntryList(&dc->list_entry_hash);

    c = dc->hash_uc >> 24;

    if (fcb->hash_ptrs_uc[c] == &dc->list_entry_hash_uc) {
        if (dc->list_entry_hash_uc.Flink == &fcb->dir_children_hash_uc)
            fcb->hash_ptrs_uc[c] = NULL;
        else {
            dir_child* dc2 = CONTAINING_RECORD(dc->list_entry_hash_uc.Flink, dir_child, list_entry_hash_uc);

            if (dc2->hash_uc >> 24 == c)
                fcb->hash_ptrs_uc[c] = &dc2->list_entry_hash_uc;
            else
                fcb->hash_ptrs_uc[c] = NULL;
        }
    }

    RemoveEntryList(&dc->list_entry_hash_uc);
}

static NTSTATUS create_directory_fcb(device_extension* Vcb, root* r, fcb* parfcb, fcb** pfcb) {
    NTSTATUS Status;
    fcb* fcb;
    SECURITY_SUBJECT_CONTEXT subjcont;
    PSID owner;
    BOOLEAN defaulted;
    LARGE_INTEGER time;
    BTRFS_TIME now;

    fcb = create_fcb(Vcb, PagedPool);
    if (!fcb) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeQuerySystemTime(&time);
    win_time_to_unix(time, &now);

    fcb->Vcb = Vcb;

    fcb->subvol = r;
    fcb->inode = InterlockedIncrement64(&r->lastinode);
    fcb->type = BTRFS_TYPE_DIRECTORY;

    fcb->inode_item.generation = Vcb->superblock.generation;
    fcb->inode_item.transid = Vcb->superblock.generation;
    fcb->inode_item.st_nlink = 1;
    fcb->inode_item.st_mode = __S_IFDIR | inherit_mode(parfcb, TRUE);
    fcb->inode_item.st_atime = fcb->inode_item.st_ctime = fcb->inode_item.st_mtime = fcb->inode_item.otime = now;
    fcb->inode_item.st_gid = GID_NOBODY;

    fcb->atts = get_file_attributes(Vcb, fcb->subvol, fcb->inode, fcb->type, FALSE, TRUE, NULL);

    SeCaptureSubjectContext(&subjcont);

    Status = SeAssignSecurity(parfcb->sd, NULL, (void**)&fcb->sd, TRUE, &subjcont, IoGetFileObjectGenericMapping(), PagedPool);

    if (!NT_SUCCESS(Status)) {
        ERR("SeAssignSecurity returned %08x\n", Status);
        return Status;
    }

    if (!fcb->sd) {
        ERR("SeAssignSecurity returned NULL security descriptor\n");
        return STATUS_INTERNAL_ERROR;
    }

    Status = RtlGetOwnerSecurityDescriptor(fcb->sd, &owner, &defaulted);
    if (!NT_SUCCESS(Status)) {
        ERR("RtlGetOwnerSecurityDescriptor returned %08x\n", Status);
        fcb->inode_item.st_uid = UID_NOBODY;
        fcb->sd_dirty = TRUE;
    } else {
        fcb->inode_item.st_uid = sid_to_uid(owner);
        fcb->sd_dirty = fcb->inode_item.st_uid == UID_NOBODY;
    }

    find_gid(fcb, parfcb, &subjcont);

    fcb->inode_item_changed = TRUE;

    InsertTailList(&r->fcbs, &fcb->list_entry);
    InsertTailList(&Vcb->all_fcbs, &fcb->list_entry_all);

    fcb->Header.IsFastIoPossible = fast_io_possible(fcb);
    fcb->Header.AllocationSize.QuadPart = 0;
    fcb->Header.FileSize.QuadPart = 0;
    fcb->Header.ValidDataLength.QuadPart = 0;

    fcb->created = TRUE;
    mark_fcb_dirty(fcb);

    if (parfcb->inode_item.flags & BTRFS_INODE_COMPRESS)
        fcb->inode_item.flags |= BTRFS_INODE_COMPRESS;

    fcb->prop_compression = parfcb->prop_compression;
    fcb->prop_compression_changed = fcb->prop_compression != PropCompression_None;

    fcb->hash_ptrs = ExAllocatePoolWithTag(PagedPool, sizeof(LIST_ENTRY*) * 256, ALLOC_TAG);
    if (!fcb->hash_ptrs) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(fcb->hash_ptrs, sizeof(LIST_ENTRY*) * 256);

    fcb->hash_ptrs_uc = ExAllocatePoolWithTag(PagedPool, sizeof(LIST_ENTRY*) * 256, ALLOC_TAG);
    if (!fcb->hash_ptrs_uc) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(fcb->hash_ptrs_uc, sizeof(LIST_ENTRY*) * 256);

    *pfcb = fcb;

    return STATUS_SUCCESS;
}

static NTSTATUS move_across_subvols(file_ref* fileref, ccb* ccb, file_ref* destdir, PANSI_STRING utf8, PUNICODE_STRING fnus, PIRP Irp, LIST_ENTRY* rollback) {
    NTSTATUS Status;
    LIST_ENTRY move_list, *le;
    move_entry* me;
    LARGE_INTEGER time;
    BTRFS_TIME now;
    file_ref* origparent;

    InitializeListHead(&move_list);

    KeQuerySystemTime(&time);
    win_time_to_unix(time, &now);

    me = ExAllocatePoolWithTag(PagedPool, sizeof(move_entry), ALLOC_TAG);

    if (!me) {
        ERR("out of memory\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }

    origparent = fileref->parent;

    me->fileref = fileref;
    increase_fileref_refcount(me->fileref);
    me->dummyfcb = NULL;
    me->dummyfileref = NULL;
    me->parent = NULL;

    InsertTailList(&move_list, &me->list_entry);

    le = move_list.Flink;
    while (le != &move_list) {
        me = CONTAINING_RECORD(le, move_entry, list_entry);

        ExAcquireResourceSharedLite(me->fileref->fcb->Header.Resource, TRUE);

        if (!me->fileref->fcb->ads && me->fileref->fcb->subvol == origparent->fcb->subvol) {
            Status = add_children_to_move_list(fileref->fcb->Vcb, me, Irp);

            if (!NT_SUCCESS(Status)) {
                ERR("add_children_to_move_list returned %08x\n", Status);
                goto end;
            }
        }

        ExReleaseResourceLite(me->fileref->fcb->Header.Resource);

        le = le->Flink;
    }

    send_notification_fileref(fileref, fileref->fcb->type == BTRFS_TYPE_DIRECTORY ? FILE_NOTIFY_CHANGE_DIR_NAME : FILE_NOTIFY_CHANGE_FILE_NAME, FILE_ACTION_REMOVED, NULL);

    // loop through list and create new inodes

    le = move_list.Flink;
    while (le != &move_list) {
        me = CONTAINING_RECORD(le, move_entry, list_entry);

        if (me->fileref->fcb->inode != SUBVOL_ROOT_INODE && me->fileref->fcb != fileref->fcb->Vcb->dummy_fcb) {
            if (!me->dummyfcb) {
                ULONG defda;
                BOOL inserted = FALSE;
                LIST_ENTRY* le3;

                ExAcquireResourceExclusiveLite(me->fileref->fcb->Header.Resource, TRUE);

                Status = duplicate_fcb(me->fileref->fcb, &me->dummyfcb);
                if (!NT_SUCCESS(Status)) {
                    ERR("duplicate_fcb returned %08x\n", Status);
                    ExReleaseResourceLite(me->fileref->fcb->Header.Resource);
                    goto end;
                }

                me->dummyfcb->subvol = me->fileref->fcb->subvol;
                me->dummyfcb->inode = me->fileref->fcb->inode;

                if (!me->dummyfcb->ads) {
                    me->dummyfcb->sd_dirty = me->fileref->fcb->sd_dirty;
                    me->dummyfcb->atts_changed = me->fileref->fcb->atts_changed;
                    me->dummyfcb->atts_deleted = me->fileref->fcb->atts_deleted;
                    me->dummyfcb->extents_changed = me->fileref->fcb->extents_changed;
                    me->dummyfcb->reparse_xattr_changed = me->fileref->fcb->reparse_xattr_changed;
                    me->dummyfcb->ea_changed = me->fileref->fcb->ea_changed;
                }

                me->dummyfcb->created = me->fileref->fcb->created;
                me->dummyfcb->deleted = me->fileref->fcb->deleted;
                mark_fcb_dirty(me->dummyfcb);

                if (!me->fileref->fcb->ads) {
                    LIST_ENTRY* le2;

                    me->fileref->fcb->subvol = destdir->fcb->subvol;
                    me->fileref->fcb->inode = InterlockedIncrement64(&destdir->fcb->subvol->lastinode);
                    me->fileref->fcb->inode_item.st_nlink = 1;

                    defda = get_file_attributes(me->fileref->fcb->Vcb, me->fileref->fcb->subvol, me->fileref->fcb->inode,
                                                me->fileref->fcb->type, me->fileref->dc && me->fileref->dc->name.Length >= sizeof(WCHAR) && me->fileref->dc->name.Buffer[0] == '.',
                                                TRUE, Irp);

                    me->fileref->fcb->sd_dirty = !!me->fileref->fcb->sd;
                    me->fileref->fcb->atts_changed = defda != me->fileref->fcb->atts;
                    me->fileref->fcb->extents_changed = !IsListEmpty(&me->fileref->fcb->extents);
                    me->fileref->fcb->reparse_xattr_changed = !!me->fileref->fcb->reparse_xattr.Buffer;
                    me->fileref->fcb->ea_changed = !!me->fileref->fcb->ea_xattr.Buffer;
                    me->fileref->fcb->xattrs_changed = !IsListEmpty(&me->fileref->fcb->xattrs);
                    me->fileref->fcb->inode_item_changed = TRUE;

                    le2 = me->fileref->fcb->xattrs.Flink;
                    while (le2 != &me->fileref->fcb->xattrs) {
                        xattr* xa = CONTAINING_RECORD(le2, xattr, list_entry);

                        xa->dirty = TRUE;

                        le2 = le2->Flink;
                    }

                    if (le == move_list.Flink) { // first entry
                        me->fileref->fcb->inode_item.transid = me->fileref->fcb->Vcb->superblock.generation;
                        me->fileref->fcb->inode_item.sequence++;

                        if (!ccb->user_set_change_time)
                            me->fileref->fcb->inode_item.st_ctime = now;
                    }

                    le2 = me->fileref->fcb->extents.Flink;
                    while (le2 != &me->fileref->fcb->extents) {
                        extent* ext = CONTAINING_RECORD(le2, extent, list_entry);

                        if (!ext->ignore && (ext->extent_data.type == EXTENT_TYPE_REGULAR || ext->extent_data.type == EXTENT_TYPE_PREALLOC)) {
                            EXTENT_DATA2* ed2 = (EXTENT_DATA2*)ext->extent_data.data;

                            if (ed2->size != 0) {
                                chunk* c = get_chunk_from_address(me->fileref->fcb->Vcb, ed2->address);

                                if (!c) {
                                    ERR("get_chunk_from_address(%llx) failed\n", ed2->address);
                                } else {
                                    Status = update_changed_extent_ref(me->fileref->fcb->Vcb, c, ed2->address, ed2->size, me->fileref->fcb->subvol->id, me->fileref->fcb->inode,
                                                                       ext->offset - ed2->offset, 1, me->fileref->fcb->inode_item.flags & BTRFS_INODE_NODATASUM, FALSE, Irp);

                                    if (!NT_SUCCESS(Status)) {
                                        ERR("update_changed_extent_ref returned %08x\n", Status);
                                        ExReleaseResourceLite(me->fileref->fcb->Header.Resource);
                                        goto end;
                                    }
                                }

                            }
                        }

                        le2 = le2->Flink;
                    }
                } else {
                    me->fileref->fcb->subvol = me->parent->fileref->fcb->subvol;
                    me->fileref->fcb->inode = me->parent->fileref->fcb->inode;
                }

                me->fileref->fcb->created = TRUE;

                InsertHeadList(&me->fileref->fcb->list_entry, &me->dummyfcb->list_entry);
                RemoveEntryList(&me->fileref->fcb->list_entry);

                le3 = destdir->fcb->subvol->fcbs.Flink;
                while (le3 != &destdir->fcb->subvol->fcbs) {
                    fcb* fcb = CONTAINING_RECORD(le3, struct _fcb, list_entry);

                    if (fcb->inode > me->fileref->fcb->inode) {
                        InsertHeadList(le3->Blink, &me->fileref->fcb->list_entry);
                        inserted = TRUE;
                        break;
                    }

                    le3 = le3->Flink;
                }

                if (!inserted)
                    InsertTailList(&destdir->fcb->subvol->fcbs, &me->fileref->fcb->list_entry);

                InsertTailList(&me->fileref->fcb->Vcb->all_fcbs, &me->dummyfcb->list_entry_all);

                while (!IsListEmpty(&me->fileref->fcb->hardlinks)) {
                    hardlink* hl = CONTAINING_RECORD(RemoveHeadList(&me->fileref->fcb->hardlinks), hardlink, list_entry);

                    if (hl->name.Buffer)
                        ExFreePool(hl->name.Buffer);

                    if (hl->utf8.Buffer)
                        ExFreePool(hl->utf8.Buffer);

                    ExFreePool(hl);
                }

                me->fileref->fcb->inode_item_changed = TRUE;
                mark_fcb_dirty(me->fileref->fcb);

                if ((!me->dummyfcb->ads && me->dummyfcb->inode_item.st_nlink > 1) || (me->dummyfcb->ads && me->parent->dummyfcb->inode_item.st_nlink > 1)) {
                    LIST_ENTRY* le2 = le->Flink;

                    while (le2 != &move_list) {
                        move_entry* me2 = CONTAINING_RECORD(le2, move_entry, list_entry);

                        if (me2->fileref->fcb == me->fileref->fcb && !me2->fileref->fcb->ads) {
                            me2->dummyfcb = me->dummyfcb;
                            InterlockedIncrement(&me->dummyfcb->refcount);
                        }

                        le2 = le2->Flink;
                    }
                }

                ExReleaseResourceLite(me->fileref->fcb->Header.Resource);
            } else {
                ExAcquireResourceExclusiveLite(me->fileref->fcb->Header.Resource, TRUE);
                me->fileref->fcb->inode_item.st_nlink++;
                me->fileref->fcb->inode_item_changed = TRUE;
                ExReleaseResourceLite(me->fileref->fcb->Header.Resource);
            }
        }

        le = le->Flink;
    }

    fileref->fcb->subvol->root_item.ctransid = fileref->fcb->Vcb->superblock.generation;
    fileref->fcb->subvol->root_item.ctime = now;

    // loop through list and create new filerefs

    le = move_list.Flink;
    while (le != &move_list) {
        hardlink* hl;
        BOOL name_changed = FALSE;

        me = CONTAINING_RECORD(le, move_entry, list_entry);

        me->dummyfileref = create_fileref(fileref->fcb->Vcb);
        if (!me->dummyfileref) {
            ERR("out of memory\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }

        if (me->fileref->fcb == me->fileref->fcb->Vcb->dummy_fcb) {
            root* r = me->parent ? me->parent->fileref->fcb->subvol : destdir->fcb->subvol;

            Status = create_directory_fcb(me->fileref->fcb->Vcb, r, me->fileref->parent->fcb, &me->fileref->fcb);
            if (!NT_SUCCESS(Status)) {
                ERR("create_directory_fcb returnd %08x\n", Status);
                goto end;
            }

            me->fileref->dc->key.obj_id = me->fileref->fcb->inode;
            me->fileref->dc->key.obj_type = TYPE_INODE_ITEM;

            me->dummyfileref->fcb = me->fileref->fcb->Vcb->dummy_fcb;
        } else if (me->fileref->fcb->inode == SUBVOL_ROOT_INODE) {
            me->dummyfileref->fcb = me->fileref->fcb;

            me->fileref->fcb->subvol->parent = le == move_list.Flink ? destdir->fcb->subvol->id : me->parent->fileref->fcb->subvol->id;
        } else
            me->dummyfileref->fcb = me->dummyfcb;

        InterlockedIncrement(&me->dummyfileref->fcb->refcount);

        me->dummyfileref->oldutf8 = me->fileref->oldutf8;
        me->dummyfileref->oldindex = me->fileref->dc->index;

        if (le == move_list.Flink && (me->fileref->dc->utf8.Length != utf8->Length || RtlCompareMemory(me->fileref->dc->utf8.Buffer, utf8->Buffer, utf8->Length) != utf8->Length))
            name_changed = TRUE;

        if ((le == move_list.Flink || me->fileref->fcb->inode == SUBVOL_ROOT_INODE) && !me->dummyfileref->oldutf8.Buffer) {
            me->dummyfileref->oldutf8.Buffer = ExAllocatePoolWithTag(PagedPool, me->fileref->dc->utf8.Length, ALLOC_TAG);
            if (!me->dummyfileref->oldutf8.Buffer) {
                ERR("out of memory\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto end;
            }

            RtlCopyMemory(me->dummyfileref->oldutf8.Buffer, me->fileref->dc->utf8.Buffer, me->fileref->dc->utf8.Length);

            me->dummyfileref->oldutf8.Length = me->dummyfileref->oldutf8.MaximumLength = me->fileref->dc->utf8.Length;
        }

        me->dummyfileref->delete_on_close = me->fileref->delete_on_close;
        me->dummyfileref->deleted = me->fileref->deleted;

        me->dummyfileref->created = me->fileref->created;
        me->fileref->created = TRUE;

        me->dummyfileref->parent = me->parent ? me->parent->dummyfileref : origparent;
        increase_fileref_refcount(me->dummyfileref->parent);

        ExAcquireResourceExclusiveLite(&me->dummyfileref->parent->nonpaged->children_lock, TRUE);
        InsertTailList(&me->dummyfileref->parent->children, &me->dummyfileref->list_entry);
        ExReleaseResourceLite(&me->dummyfileref->parent->nonpaged->children_lock);

        me->dummyfileref->debug_desc = me->fileref->debug_desc;

        if (me->dummyfileref->fcb->type == BTRFS_TYPE_DIRECTORY)
            me->dummyfileref->fcb->fileref = me->dummyfileref;

        if (!me->parent) {
            RemoveEntryList(&me->fileref->list_entry);

            increase_fileref_refcount(destdir);

            if (me->fileref->dc) {
                // remove from old parent
                ExAcquireResourceExclusiveLite(&me->fileref->parent->fcb->nonpaged->dir_children_lock, TRUE);
                RemoveEntryList(&me->fileref->dc->list_entry_index);
                remove_dir_child_from_hash_lists(me->fileref->parent->fcb, me->fileref->dc);
                ExReleaseResourceLite(&me->fileref->parent->fcb->nonpaged->dir_children_lock);

                me->fileref->parent->fcb->inode_item.st_size -= me->fileref->dc->utf8.Length * 2;
                me->fileref->parent->fcb->inode_item.transid = me->fileref->fcb->Vcb->superblock.generation;
                me->fileref->parent->fcb->inode_item.sequence++;
                me->fileref->parent->fcb->inode_item.st_ctime = now;
                me->fileref->parent->fcb->inode_item.st_mtime = now;
                me->fileref->parent->fcb->inode_item_changed = TRUE;
                mark_fcb_dirty(me->fileref->parent->fcb);

                if (name_changed) {
                    ExFreePool(me->fileref->dc->utf8.Buffer);
                    ExFreePool(me->fileref->dc->name.Buffer);
                    ExFreePool(me->fileref->dc->name_uc.Buffer);

                    me->fileref->dc->utf8.Buffer = ExAllocatePoolWithTag(PagedPool, utf8->Length, ALLOC_TAG);
                    if (!me->fileref->dc->utf8.Buffer) {
                        ERR("out of memory\n");
                        Status = STATUS_INSUFFICIENT_RESOURCES;
                        goto end;
                    }

                    me->fileref->dc->utf8.Length = me->fileref->dc->utf8.MaximumLength = utf8->Length;
                    RtlCopyMemory(me->fileref->dc->utf8.Buffer, utf8->Buffer, utf8->Length);

                    me->fileref->dc->name.Buffer = ExAllocatePoolWithTag(PagedPool, fnus->Length, ALLOC_TAG);
                    if (!me->fileref->dc->name.Buffer) {
                        ERR("out of memory\n");
                        Status = STATUS_INSUFFICIENT_RESOURCES;
                        goto end;
                    }

                    me->fileref->dc->name.Length = me->fileref->dc->name.MaximumLength = fnus->Length;
                    RtlCopyMemory(me->fileref->dc->name.Buffer, fnus->Buffer, fnus->Length);

                    Status = RtlUpcaseUnicodeString(&fileref->dc->name_uc, &fileref->dc->name, TRUE);
                    if (!NT_SUCCESS(Status)) {
                        ERR("RtlUpcaseUnicodeString returned %08x\n", Status);
                        goto end;
                    }

                    me->fileref->dc->hash = calc_crc32c(0xffffffff, (UINT8*)me->fileref->dc->name.Buffer, me->fileref->dc->name.Length);
                    me->fileref->dc->hash_uc = calc_crc32c(0xffffffff, (UINT8*)me->fileref->dc->name_uc.Buffer, me->fileref->dc->name_uc.Length);
                }

                if (me->fileref->dc->key.obj_type == TYPE_INODE_ITEM)
                    me->fileref->dc->key.obj_id = me->fileref->fcb->inode;

                // add to new parent

                ExAcquireResourceExclusiveLite(&destdir->fcb->nonpaged->dir_children_lock, TRUE);

                if (IsListEmpty(&destdir->fcb->dir_children_index))
                    me->fileref->dc->index = 2;
                else {
                    dir_child* dc2 = CONTAINING_RECORD(destdir->fcb->dir_children_index.Blink, dir_child, list_entry_index);

                    me->fileref->dc->index = max(2, dc2->index + 1);
                }

                InsertTailList(&destdir->fcb->dir_children_index, &me->fileref->dc->list_entry_index);
                insert_dir_child_into_hash_lists(destdir->fcb, me->fileref->dc);
                ExReleaseResourceLite(&destdir->fcb->nonpaged->dir_children_lock);
            }

            free_fileref(fileref->fcb->Vcb, me->fileref->parent);
            me->fileref->parent = destdir;

            ExAcquireResourceExclusiveLite(&me->fileref->parent->nonpaged->children_lock, TRUE);
            InsertTailList(&me->fileref->parent->children, &me->fileref->list_entry);
            ExReleaseResourceLite(&me->fileref->parent->nonpaged->children_lock);

            TRACE("me->fileref->parent->fcb->inode_item.st_size (inode %llx) was %llx\n", me->fileref->parent->fcb->inode, me->fileref->parent->fcb->inode_item.st_size);
            me->fileref->parent->fcb->inode_item.st_size += me->fileref->dc->utf8.Length * 2;
            TRACE("me->fileref->parent->fcb->inode_item.st_size (inode %llx) now %llx\n", me->fileref->parent->fcb->inode, me->fileref->parent->fcb->inode_item.st_size);
            me->fileref->parent->fcb->inode_item.transid = me->fileref->fcb->Vcb->superblock.generation;
            me->fileref->parent->fcb->inode_item.sequence++;
            me->fileref->parent->fcb->inode_item.st_ctime = now;
            me->fileref->parent->fcb->inode_item.st_mtime = now;
            me->fileref->parent->fcb->inode_item_changed = TRUE;
            mark_fcb_dirty(me->fileref->parent->fcb);
        } else {
            if (me->fileref->dc) {
                ExAcquireResourceExclusiveLite(&me->fileref->parent->fcb->nonpaged->dir_children_lock, TRUE);
                RemoveEntryList(&me->fileref->dc->list_entry_index);

                if (!me->fileref->fcb->ads)
                    remove_dir_child_from_hash_lists(me->fileref->parent->fcb, me->fileref->dc);

                ExReleaseResourceLite(&me->fileref->parent->fcb->nonpaged->dir_children_lock);

                ExAcquireResourceExclusiveLite(&me->parent->fileref->fcb->nonpaged->dir_children_lock, TRUE);

                if (me->fileref->fcb->ads)
                    InsertHeadList(&me->parent->fileref->fcb->dir_children_index, &me->fileref->dc->list_entry_index);
                else {
                    if (me->fileref->fcb->inode != SUBVOL_ROOT_INODE)
                        me->fileref->dc->key.obj_id = me->fileref->fcb->inode;

                    if (IsListEmpty(&me->parent->fileref->fcb->dir_children_index))
                        me->fileref->dc->index = 2;
                    else {
                        dir_child* dc2 = CONTAINING_RECORD(me->parent->fileref->fcb->dir_children_index.Blink, dir_child, list_entry_index);

                        me->fileref->dc->index = max(2, dc2->index + 1);
                    }

                    InsertTailList(&me->parent->fileref->fcb->dir_children_index, &me->fileref->dc->list_entry_index);
                    insert_dir_child_into_hash_lists(me->parent->fileref->fcb, me->fileref->dc);
                }

                ExReleaseResourceLite(&me->parent->fileref->fcb->nonpaged->dir_children_lock);
            }
        }

        if (!me->dummyfileref->fcb->ads) {
            Status = delete_fileref(me->dummyfileref, NULL, Irp, rollback);
            if (!NT_SUCCESS(Status)) {
                ERR("delete_fileref returned %08x\n", Status);
                goto end;
            }
        }

        if (me->fileref->fcb->inode_item.st_nlink > 1) {
            hl = ExAllocatePoolWithTag(PagedPool, sizeof(hardlink), ALLOC_TAG);
            if (!hl) {
                ERR("out of memory\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto end;
            }

            hl->parent = me->fileref->parent->fcb->inode;
            hl->index = me->fileref->dc->index;

            hl->utf8.Length = hl->utf8.MaximumLength = me->fileref->dc->utf8.Length;
            hl->utf8.Buffer = ExAllocatePoolWithTag(PagedPool, hl->utf8.MaximumLength, ALLOC_TAG);
            if (!hl->utf8.Buffer) {
                ERR("out of memory\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                ExFreePool(hl);
                goto end;
            }

            RtlCopyMemory(hl->utf8.Buffer, me->fileref->dc->utf8.Buffer, me->fileref->dc->utf8.Length);

            hl->name.Length = hl->name.MaximumLength = me->fileref->dc->name.Length;
            hl->name.Buffer = ExAllocatePoolWithTag(PagedPool, hl->name.MaximumLength, ALLOC_TAG);
            if (!hl->name.Buffer) {
                ERR("out of memory\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                ExFreePool(hl->utf8.Buffer);
                ExFreePool(hl);
                goto end;
            }

            RtlCopyMemory(hl->name.Buffer, me->fileref->dc->name.Buffer, me->fileref->dc->name.Length);

            InsertTailList(&me->fileref->fcb->hardlinks, &hl->list_entry);
        }

        mark_fileref_dirty(me->fileref);

        le = le->Flink;
    }

    // loop through, and only mark streams as deleted if their parent inodes are also deleted

    le = move_list.Flink;
    while (le != &move_list) {
        me = CONTAINING_RECORD(le, move_entry, list_entry);

        if (me->dummyfileref->fcb->ads && me->parent->dummyfileref->fcb->deleted) {
            Status = delete_fileref(me->dummyfileref, NULL, Irp, rollback);
            if (!NT_SUCCESS(Status)) {
                ERR("delete_fileref returned %08x\n", Status);
                goto end;
            }
        }

        le = le->Flink;
    }

    destdir->fcb->subvol->root_item.ctransid = destdir->fcb->Vcb->superblock.generation;
    destdir->fcb->subvol->root_item.ctime = now;

    me = CONTAINING_RECORD(move_list.Flink, move_entry, list_entry);
    send_notification_fileref(fileref, fileref->fcb->type == BTRFS_TYPE_DIRECTORY ? FILE_NOTIFY_CHANGE_DIR_NAME : FILE_NOTIFY_CHANGE_FILE_NAME, FILE_ACTION_ADDED, NULL);
    send_notification_fileref(me->dummyfileref->parent, FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_ACTION_MODIFIED, NULL);
    send_notification_fileref(fileref->parent, FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_ACTION_MODIFIED, NULL);

    Status = STATUS_SUCCESS;

end:
    while (!IsListEmpty(&move_list)) {
        le = RemoveHeadList(&move_list);
        me = CONTAINING_RECORD(le, move_entry, list_entry);

        if (me->dummyfcb)
            free_fcb(fileref->fcb->Vcb, me->dummyfcb);

        if (me->dummyfileref)
            free_fileref(fileref->fcb->Vcb, me->dummyfileref);

        free_fileref(fileref->fcb->Vcb, me->fileref);

        ExFreePool(me);
    }

    return Status;
}

void insert_dir_child_into_hash_lists(fcb* fcb, dir_child* dc) {
    BOOL inserted;
    LIST_ENTRY* le;
    UINT8 c, d;

    c = dc->hash >> 24;

    inserted = FALSE;

    d = c;
    do {
        le = fcb->hash_ptrs[d];

        if (d == 0)
            break;

        d--;
    } while (!le);

    if (!le)
        le = fcb->dir_children_hash.Flink;

    while (le != &fcb->dir_children_hash) {
        dir_child* dc2 = CONTAINING_RECORD(le, dir_child, list_entry_hash);

        if (dc2->hash > dc->hash) {
            InsertHeadList(le->Blink, &dc->list_entry_hash);
            inserted = TRUE;
            break;
        }

        le = le->Flink;
    }

    if (!inserted)
        InsertTailList(&fcb->dir_children_hash, &dc->list_entry_hash);

    if (!fcb->hash_ptrs[c])
        fcb->hash_ptrs[c] = &dc->list_entry_hash;
    else {
        dir_child* dc2 = CONTAINING_RECORD(fcb->hash_ptrs[c], dir_child, list_entry_hash);

        if (dc2->hash > dc->hash)
            fcb->hash_ptrs[c] = &dc->list_entry_hash;
    }

    c = dc->hash_uc >> 24;

    inserted = FALSE;

    d = c;
    do {
        le = fcb->hash_ptrs_uc[d];

        if (d == 0)
            break;

        d--;
    } while (!le);

    if (!le)
        le = fcb->dir_children_hash_uc.Flink;

    while (le != &fcb->dir_children_hash_uc) {
        dir_child* dc2 = CONTAINING_RECORD(le, dir_child, list_entry_hash_uc);

        if (dc2->hash_uc > dc->hash_uc) {
            InsertHeadList(le->Blink, &dc->list_entry_hash_uc);
            inserted = TRUE;
            break;
        }

        le = le->Flink;
    }

    if (!inserted)
        InsertTailList(&fcb->dir_children_hash_uc, &dc->list_entry_hash_uc);

    if (!fcb->hash_ptrs_uc[c])
        fcb->hash_ptrs_uc[c] = &dc->list_entry_hash_uc;
    else {
        dir_child* dc2 = CONTAINING_RECORD(fcb->hash_ptrs_uc[c], dir_child, list_entry_hash_uc);

        if (dc2->hash_uc > dc->hash_uc)
            fcb->hash_ptrs_uc[c] = &dc->list_entry_hash_uc;
    }
}

static NTSTATUS set_rename_information(device_extension* Vcb, PIRP Irp, PFILE_OBJECT FileObject, PFILE_OBJECT tfo) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    FILE_RENAME_INFORMATION* fri = Irp->AssociatedIrp.SystemBuffer;
    fcb *fcb = FileObject->FsContext;
    ccb* ccb = FileObject->FsContext2;
    file_ref *fileref = ccb ? ccb->fileref : NULL, *oldfileref = NULL, *related = NULL, *fr2 = NULL;
    WCHAR* fn;
    ULONG fnlen, utf8len, origutf8len;
    UNICODE_STRING fnus;
    ANSI_STRING utf8;
    NTSTATUS Status;
    LARGE_INTEGER time;
    BTRFS_TIME now;
    LIST_ENTRY rollback, *le;
    hardlink* hl;
    SECURITY_SUBJECT_CONTEXT subjcont;
    ACCESS_MASK access;

    InitializeListHead(&rollback);

    TRACE("tfo = %p\n", tfo);
    TRACE("ReplaceIfExists = %u\n", IrpSp->Parameters.SetFile.ReplaceIfExists);
    TRACE("RootDirectory = %p\n", fri->RootDirectory);
    TRACE("FileName = %.*S\n", fri->FileNameLength / sizeof(WCHAR), fri->FileName);

    fn = fri->FileName;
    fnlen = fri->FileNameLength / sizeof(WCHAR);

    if (!tfo) {
        if (!fileref || !fileref->parent) {
            ERR("no fileref set and no directory given\n");
            return STATUS_INVALID_PARAMETER;
        }
    } else {
        LONG i;

        while (fnlen > 0 && (fri->FileName[fnlen - 1] == '/' || fri->FileName[fnlen - 1] == '\\'))
            fnlen--;

        if (fnlen == 0)
            return STATUS_INVALID_PARAMETER;

        for (i = fnlen - 1; i >= 0; i--) {
            if (fri->FileName[i] == '\\' || fri->FileName[i] == '/') {
                fn = &fri->FileName[i+1];
                fnlen = (fri->FileNameLength / sizeof(WCHAR)) - i - 1;
                break;
            }
        }
    }

    ExAcquireResourceSharedLite(&Vcb->tree_lock, TRUE);
    acquire_fcb_lock_exclusive(Vcb);
    ExAcquireResourceExclusiveLite(fcb->Header.Resource, TRUE);

    if (fcb->ads) {
        // MSDN says that NTFS data streams can be renamed (https://msdn.microsoft.com/en-us/library/windows/hardware/ff540344.aspx),
        // but if you try it always seems to return STATUS_INVALID_PARAMETER. There is a function in ntfs.sys called NtfsStreamRename,
        // but it never seems to get invoked... If you know what's going on here, I'd appreciate it if you let me know.
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    fnus.Buffer = fn;
    fnus.Length = fnus.MaximumLength = (UINT16)(fnlen * sizeof(WCHAR));

    TRACE("fnus = %.*S\n", fnus.Length / sizeof(WCHAR), fnus.Buffer);

    origutf8len = fileref->dc->utf8.Length;

    Status = RtlUnicodeToUTF8N(NULL, 0, &utf8len, fn, (ULONG)fnlen * sizeof(WCHAR));
    if (!NT_SUCCESS(Status))
        goto end;

    utf8.MaximumLength = utf8.Length = (UINT16)utf8len;
    utf8.Buffer = ExAllocatePoolWithTag(PagedPool, utf8.MaximumLength, ALLOC_TAG);
    if (!utf8.Buffer) {
        ERR("out of memory\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }

    Status = RtlUnicodeToUTF8N(utf8.Buffer, utf8len, &utf8len, fn, (ULONG)fnlen * sizeof(WCHAR));
    if (!NT_SUCCESS(Status))
        goto end;

    if (tfo && tfo->FsContext2) {
        struct _ccb* relatedccb = tfo->FsContext2;

        related = relatedccb->fileref;
        increase_fileref_refcount(related);
    } else if (fnus.Length >= sizeof(WCHAR) && fnus.Buffer[0] != '\\') {
        related = fileref->parent;
        increase_fileref_refcount(related);
    }

    Status = open_fileref(Vcb, &oldfileref, &fnus, related, FALSE, NULL, NULL, PagedPool, ccb->case_sensitive,  Irp);

    if (NT_SUCCESS(Status)) {
        TRACE("destination file %S already exists\n", file_desc_fileref(oldfileref));

        if (fileref != oldfileref && !oldfileref->deleted) {
            if (!IrpSp->Parameters.SetFile.ReplaceIfExists) {
                Status = STATUS_OBJECT_NAME_COLLISION;
                goto end;
            } else if ((oldfileref->open_count >= 1 || has_open_children(oldfileref)) && !oldfileref->deleted) {
                WARN("trying to overwrite open file\n");
                Status = STATUS_ACCESS_DENIED;
                goto end;
            }

            if (oldfileref->fcb->type == BTRFS_TYPE_DIRECTORY) {
                WARN("trying to overwrite directory\n");
                Status = STATUS_ACCESS_DENIED;
                goto end;
            }
        }

        if (fileref == oldfileref || oldfileref->deleted) {
            free_fileref(Vcb, oldfileref);
            oldfileref = NULL;
        }
    }

    if (!related) {
        Status = open_fileref(Vcb, &related, &fnus, NULL, TRUE, NULL, NULL, PagedPool, ccb->case_sensitive, Irp);

        if (!NT_SUCCESS(Status)) {
            ERR("open_fileref returned %08x\n", Status);
            goto end;
        }
    }

    if (related->fcb == Vcb->dummy_fcb) {
        Status = STATUS_ACCESS_DENIED;
        goto end;
    }

    SeCaptureSubjectContext(&subjcont);

    if (!SeAccessCheck(related->fcb->sd, &subjcont, FALSE, fcb->type == BTRFS_TYPE_DIRECTORY ? FILE_ADD_SUBDIRECTORY : FILE_ADD_FILE, 0, NULL,
        IoGetFileObjectGenericMapping(), Irp->RequestorMode, &access, &Status)) {
        SeReleaseSubjectContext(&subjcont);
        TRACE("SeAccessCheck failed, returning %08x\n", Status);
        goto end;
    }

    SeReleaseSubjectContext(&subjcont);

    if (has_open_children(fileref)) {
        WARN("trying to rename file with open children\n");
        Status = STATUS_ACCESS_DENIED;
        goto end;
    }

    if (oldfileref) {
        SeCaptureSubjectContext(&subjcont);

        if (!SeAccessCheck(oldfileref->fcb->sd, &subjcont, FALSE, DELETE, 0, NULL,
                           IoGetFileObjectGenericMapping(), Irp->RequestorMode, &access, &Status)) {
            SeReleaseSubjectContext(&subjcont);
            TRACE("SeAccessCheck failed, returning %08x\n", Status);
            goto end;
        }

        SeReleaseSubjectContext(&subjcont);

        Status = delete_fileref(oldfileref, NULL, Irp, &rollback);
        if (!NT_SUCCESS(Status)) {
            ERR("delete_fileref returned %08x\n", Status);
            goto end;
        }
    }

    if (fileref->parent->fcb->subvol != related->fcb->subvol && (fileref->fcb->subvol == fileref->parent->fcb->subvol || fileref->fcb == Vcb->dummy_fcb)) {
        Status = move_across_subvols(fileref, ccb, related, &utf8, &fnus, Irp, &rollback);
        if (!NT_SUCCESS(Status)) {
            ERR("move_across_subvols returned %08x\n", Status);
        }
        goto end;
    }

    if (related == fileref->parent) { // keeping file in same directory
        UNICODE_STRING oldfn, newfn;
        USHORT name_offset;
        ULONG reqlen, oldutf8len;

        oldfn.Length = oldfn.MaximumLength = 0;

        Status = fileref_get_filename(fileref, &oldfn, &name_offset, &reqlen);
        if (Status != STATUS_BUFFER_OVERFLOW) {
            ERR("fileref_get_filename returned %08x\n", Status);
            goto end;
        }

        oldfn.Buffer = ExAllocatePoolWithTag(PagedPool, reqlen, ALLOC_TAG);
        if (!oldfn.Buffer) {
            ERR("out of memory\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }

        oldfn.MaximumLength = (UINT16)reqlen;

        Status = fileref_get_filename(fileref, &oldfn, &name_offset, &reqlen);
        if (!NT_SUCCESS(Status)) {
            ERR("fileref_get_filename returned %08x\n", Status);
            ExFreePool(oldfn.Buffer);
            goto end;
        }

        oldutf8len = fileref->dc->utf8.Length;

        if (!fileref->created && !fileref->oldutf8.Buffer) {
            fileref->oldutf8.Buffer = ExAllocatePoolWithTag(PagedPool, fileref->dc->utf8.Length, ALLOC_TAG);
            if (!fileref->oldutf8.Buffer) {
                ERR("out of memory\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto end;
            }

            fileref->oldutf8.Length = fileref->oldutf8.MaximumLength = fileref->dc->utf8.Length;
            RtlCopyMemory(fileref->oldutf8.Buffer, fileref->dc->utf8.Buffer, fileref->dc->utf8.Length);
        }

        TRACE("renaming %.*S to %.*S\n", fileref->dc->name.Length / sizeof(WCHAR), fileref->dc->name.Buffer, fnus.Length / sizeof(WCHAR), fnus.Buffer);

        mark_fileref_dirty(fileref);

        if (fileref->dc) {
            ExAcquireResourceExclusiveLite(&fileref->parent->fcb->nonpaged->dir_children_lock, TRUE);

            ExFreePool(fileref->dc->utf8.Buffer);
            ExFreePool(fileref->dc->name.Buffer);
            ExFreePool(fileref->dc->name_uc.Buffer);

            fileref->dc->utf8.Buffer = ExAllocatePoolWithTag(PagedPool, utf8.Length, ALLOC_TAG);
            if (!fileref->dc->utf8.Buffer) {
                ERR("out of memory\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                ExReleaseResourceLite(&fileref->parent->fcb->nonpaged->dir_children_lock);
                ExFreePool(oldfn.Buffer);
                goto end;
            }

            fileref->dc->utf8.Length = fileref->dc->utf8.MaximumLength = utf8.Length;
            RtlCopyMemory(fileref->dc->utf8.Buffer, utf8.Buffer, utf8.Length);

            fileref->dc->name.Buffer = ExAllocatePoolWithTag(PagedPool, fnus.Length, ALLOC_TAG);
            if (!fileref->dc->name.Buffer) {
                ERR("out of memory\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                ExReleaseResourceLite(&fileref->parent->fcb->nonpaged->dir_children_lock);
                ExFreePool(oldfn.Buffer);
                goto end;
            }

            fileref->dc->name.Length = fileref->dc->name.MaximumLength = fnus.Length;
            RtlCopyMemory(fileref->dc->name.Buffer, fnus.Buffer, fnus.Length);

            Status = RtlUpcaseUnicodeString(&fileref->dc->name_uc, &fileref->dc->name, TRUE);
            if (!NT_SUCCESS(Status)) {
                ERR("RtlUpcaseUnicodeString returned %08x\n", Status);
                ExReleaseResourceLite(&fileref->parent->fcb->nonpaged->dir_children_lock);
                ExFreePool(oldfn.Buffer);
                goto end;
            }

            remove_dir_child_from_hash_lists(fileref->parent->fcb, fileref->dc);

            fileref->dc->hash = calc_crc32c(0xffffffff, (UINT8*)fileref->dc->name.Buffer, fileref->dc->name.Length);
            fileref->dc->hash_uc = calc_crc32c(0xffffffff, (UINT8*)fileref->dc->name_uc.Buffer, fileref->dc->name_uc.Length);

            insert_dir_child_into_hash_lists(fileref->parent->fcb, fileref->dc);

            ExReleaseResourceLite(&fileref->parent->fcb->nonpaged->dir_children_lock);
        }

        newfn.Length = newfn.MaximumLength = 0;

        Status = fileref_get_filename(fileref, &newfn, &name_offset, &reqlen);
        if (Status != STATUS_BUFFER_OVERFLOW) {
            ERR("fileref_get_filename returned %08x\n", Status);
            ExFreePool(oldfn.Buffer);
            goto end;
        }

        newfn.Buffer = ExAllocatePoolWithTag(PagedPool, reqlen, ALLOC_TAG);
        if (!newfn.Buffer) {
            ERR("out of memory\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            ExFreePool(oldfn.Buffer);
            goto end;
        }

        newfn.MaximumLength = (UINT16)reqlen;

        Status = fileref_get_filename(fileref, &newfn, &name_offset, &reqlen);
        if (!NT_SUCCESS(Status)) {
            ERR("fileref_get_filename returned %08x\n", Status);
            ExFreePool(oldfn.Buffer);
            ExFreePool(newfn.Buffer);
            goto end;
        }

        KeQuerySystemTime(&time);
        win_time_to_unix(time, &now);

        if (fcb != Vcb->dummy_fcb && (fileref->parent->fcb->subvol == fcb->subvol || !is_subvol_readonly(fcb->subvol, Irp))) {
            fcb->inode_item.transid = Vcb->superblock.generation;
            fcb->inode_item.sequence++;

            if (!ccb->user_set_change_time)
                fcb->inode_item.st_ctime = now;

            fcb->inode_item_changed = TRUE;
            mark_fcb_dirty(fcb);
        }

        // update parent's INODE_ITEM

        related->fcb->inode_item.transid = Vcb->superblock.generation;
        TRACE("related->fcb->inode_item.st_size (inode %llx) was %llx\n", related->fcb->inode, related->fcb->inode_item.st_size);
        related->fcb->inode_item.st_size = related->fcb->inode_item.st_size + (2 * utf8.Length) - (2* oldutf8len);
        TRACE("related->fcb->inode_item.st_size (inode %llx) now %llx\n", related->fcb->inode, related->fcb->inode_item.st_size);
        related->fcb->inode_item.sequence++;
        related->fcb->inode_item.st_ctime = now;
        related->fcb->inode_item.st_mtime = now;

        related->fcb->inode_item_changed = TRUE;
        mark_fcb_dirty(related->fcb);
        send_notification_fileref(related, FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_ACTION_MODIFIED, NULL);

        FsRtlNotifyFilterReportChange(fcb->Vcb->NotifySync, &fcb->Vcb->DirNotifyList, (PSTRING)&oldfn, name_offset, NULL, NULL,
                                      fcb->type == BTRFS_TYPE_DIRECTORY ? FILE_NOTIFY_CHANGE_DIR_NAME : FILE_NOTIFY_CHANGE_FILE_NAME, FILE_ACTION_RENAMED_OLD_NAME, NULL, NULL);
        FsRtlNotifyFilterReportChange(fcb->Vcb->NotifySync, &fcb->Vcb->DirNotifyList, (PSTRING)&newfn, name_offset, NULL, NULL,
                                      fcb->type == BTRFS_TYPE_DIRECTORY ? FILE_NOTIFY_CHANGE_DIR_NAME : FILE_NOTIFY_CHANGE_FILE_NAME, FILE_ACTION_RENAMED_NEW_NAME, NULL, NULL);

        ExFreePool(oldfn.Buffer);
        ExFreePool(newfn.Buffer);

        Status = STATUS_SUCCESS;
        goto end;
    }

    // We move files by moving the existing fileref to the new directory, and
    // replacing it with a dummy fileref with the same original values, but marked as deleted.

    send_notification_fileref(fileref, fcb->type == BTRFS_TYPE_DIRECTORY ? FILE_NOTIFY_CHANGE_DIR_NAME : FILE_NOTIFY_CHANGE_FILE_NAME, FILE_ACTION_REMOVED, NULL);

    fr2 = create_fileref(Vcb);

    fr2->fcb = fileref->fcb;
    fr2->fcb->refcount++;

    fr2->oldutf8 = fileref->oldutf8;
    fr2->oldindex = fileref->dc->index;
    fr2->delete_on_close = fileref->delete_on_close;
    fr2->deleted = TRUE;
    fr2->created = fileref->created;
    fr2->parent = fileref->parent;
    fr2->dc = NULL;

    if (!fr2->oldutf8.Buffer) {
        fr2->oldutf8.Buffer = ExAllocatePoolWithTag(PagedPool, fileref->dc->utf8.Length, ALLOC_TAG);
        if (!fr2->oldutf8.Buffer) {
            ERR("out of memory\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }

        RtlCopyMemory(fr2->oldutf8.Buffer, fileref->dc->utf8.Buffer, fileref->dc->utf8.Length);

        fr2->oldutf8.Length = fr2->oldutf8.MaximumLength = fileref->dc->utf8.Length;
    }

    if (fr2->fcb->type == BTRFS_TYPE_DIRECTORY)
        fr2->fcb->fileref = fr2;

    if (fileref->fcb->inode == SUBVOL_ROOT_INODE)
        fileref->fcb->subvol->parent = related->fcb->subvol->id;

    fileref->oldutf8.Length = fileref->oldutf8.MaximumLength = 0;
    fileref->oldutf8.Buffer = NULL;
    fileref->deleted = FALSE;
    fileref->created = TRUE;
    fileref->parent = related;

    ExAcquireResourceExclusiveLite(&fileref->parent->nonpaged->children_lock, TRUE);
    InsertHeadList(&fileref->list_entry, &fr2->list_entry);
    RemoveEntryList(&fileref->list_entry);
    ExReleaseResourceLite(&fileref->parent->nonpaged->children_lock);

    mark_fileref_dirty(fr2);
    mark_fileref_dirty(fileref);

    if (fileref->dc) {
        // remove from old parent
        ExAcquireResourceExclusiveLite(&fr2->parent->fcb->nonpaged->dir_children_lock, TRUE);
        RemoveEntryList(&fileref->dc->list_entry_index);
        remove_dir_child_from_hash_lists(fr2->parent->fcb, fileref->dc);
        ExReleaseResourceLite(&fr2->parent->fcb->nonpaged->dir_children_lock);

        if (fileref->dc->utf8.Length != utf8.Length || RtlCompareMemory(fileref->dc->utf8.Buffer, utf8.Buffer, utf8.Length) != utf8.Length) {
            // handle changed name

            ExFreePool(fileref->dc->utf8.Buffer);
            ExFreePool(fileref->dc->name.Buffer);
            ExFreePool(fileref->dc->name_uc.Buffer);

            fileref->dc->utf8.Buffer = ExAllocatePoolWithTag(PagedPool, utf8.Length, ALLOC_TAG);
            if (!fileref->dc->utf8.Buffer) {
                ERR("out of memory\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto end;
            }

            fileref->dc->utf8.Length = fileref->dc->utf8.MaximumLength = utf8.Length;
            RtlCopyMemory(fileref->dc->utf8.Buffer, utf8.Buffer, utf8.Length);

            fileref->dc->name.Buffer = ExAllocatePoolWithTag(PagedPool, fnus.Length, ALLOC_TAG);
            if (!fileref->dc->name.Buffer) {
                ERR("out of memory\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto end;
            }

            fileref->dc->name.Length = fileref->dc->name.MaximumLength = fnus.Length;
            RtlCopyMemory(fileref->dc->name.Buffer, fnus.Buffer, fnus.Length);

            Status = RtlUpcaseUnicodeString(&fileref->dc->name_uc, &fileref->dc->name, TRUE);
            if (!NT_SUCCESS(Status)) {
                ERR("RtlUpcaseUnicodeString returned %08x\n", Status);
                goto end;
            }

            fileref->dc->hash = calc_crc32c(0xffffffff, (UINT8*)fileref->dc->name.Buffer, fileref->dc->name.Length);
            fileref->dc->hash_uc = calc_crc32c(0xffffffff, (UINT8*)fileref->dc->name_uc.Buffer, fileref->dc->name_uc.Length);
        }

        // add to new parent
        ExAcquireResourceExclusiveLite(&related->fcb->nonpaged->dir_children_lock, TRUE);

        if (IsListEmpty(&related->fcb->dir_children_index))
            fileref->dc->index = 2;
        else {
            dir_child* dc2 = CONTAINING_RECORD(related->fcb->dir_children_index.Blink, dir_child, list_entry_index);

            fileref->dc->index = max(2, dc2->index + 1);
        }

        InsertTailList(&related->fcb->dir_children_index, &fileref->dc->list_entry_index);
        insert_dir_child_into_hash_lists(related->fcb, fileref->dc);
        ExReleaseResourceLite(&related->fcb->nonpaged->dir_children_lock);
    }

    ExAcquireResourceExclusiveLite(&related->nonpaged->children_lock, TRUE);
    InsertTailList(&related->children, &fileref->list_entry);
    ExReleaseResourceLite(&related->nonpaged->children_lock);

    if (fcb->inode_item.st_nlink > 1) {
        // add new hardlink entry to fcb

        hl = ExAllocatePoolWithTag(PagedPool, sizeof(hardlink), ALLOC_TAG);
        if (!hl) {
            ERR("out of memory\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }

        hl->parent = related->fcb->inode;
        hl->index = fileref->dc->index;

        hl->name.Length = hl->name.MaximumLength = fnus.Length;
        hl->name.Buffer = ExAllocatePoolWithTag(PagedPool, hl->name.MaximumLength, ALLOC_TAG);

        if (!hl->name.Buffer) {
            ERR("out of memory\n");
            ExFreePool(hl);
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }

        RtlCopyMemory(hl->name.Buffer, fnus.Buffer, fnus.Length);

        hl->utf8.Length = hl->utf8.MaximumLength = fileref->dc->utf8.Length;
        hl->utf8.Buffer = ExAllocatePoolWithTag(PagedPool, hl->utf8.MaximumLength, ALLOC_TAG);

        if (!hl->utf8.Buffer) {
            ERR("out of memory\n");
            ExFreePool(hl->name.Buffer);
            ExFreePool(hl);
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }

        RtlCopyMemory(hl->utf8.Buffer, fileref->dc->utf8.Buffer, fileref->dc->utf8.Length);

        InsertTailList(&fcb->hardlinks, &hl->list_entry);
    }

    // delete old hardlink entry from fcb

    le = fcb->hardlinks.Flink;
    while (le != &fcb->hardlinks) {
        hl = CONTAINING_RECORD(le, hardlink, list_entry);

        if (hl->parent == fr2->parent->fcb->inode && hl->index == fr2->oldindex) {
            RemoveEntryList(&hl->list_entry);

            if (hl->utf8.Buffer)
                ExFreePool(hl->utf8.Buffer);

            if (hl->name.Buffer)
                ExFreePool(hl->name.Buffer);

            ExFreePool(hl);
            break;
        }

        le = le->Flink;
    }

    // update inode's INODE_ITEM

    KeQuerySystemTime(&time);
    win_time_to_unix(time, &now);

    if (fcb != Vcb->dummy_fcb && (fileref->parent->fcb->subvol == fcb->subvol || !is_subvol_readonly(fcb->subvol, Irp))) {
        fcb->inode_item.transid = Vcb->superblock.generation;
        fcb->inode_item.sequence++;

        if (!ccb->user_set_change_time)
            fcb->inode_item.st_ctime = now;

        fcb->inode_item_changed = TRUE;
        mark_fcb_dirty(fcb);
    }

    // update new parent's INODE_ITEM

    related->fcb->inode_item.transid = Vcb->superblock.generation;
    TRACE("related->fcb->inode_item.st_size (inode %llx) was %llx\n", related->fcb->inode, related->fcb->inode_item.st_size);
    related->fcb->inode_item.st_size += 2 * utf8len;
    TRACE("related->fcb->inode_item.st_size (inode %llx) now %llx\n", related->fcb->inode, related->fcb->inode_item.st_size);
    related->fcb->inode_item.sequence++;
    related->fcb->inode_item.st_ctime = now;
    related->fcb->inode_item.st_mtime = now;

    related->fcb->inode_item_changed = TRUE;
    mark_fcb_dirty(related->fcb);

    // update old parent's INODE_ITEM

    fr2->parent->fcb->inode_item.transid = Vcb->superblock.generation;
    TRACE("fr2->parent->fcb->inode_item.st_size (inode %llx) was %llx\n", fr2->parent->fcb->inode, fr2->parent->fcb->inode_item.st_size);
    fr2->parent->fcb->inode_item.st_size -= 2 * origutf8len;
    TRACE("fr2->parent->fcb->inode_item.st_size (inode %llx) now %llx\n", fr2->parent->fcb->inode, fr2->parent->fcb->inode_item.st_size);
    fr2->parent->fcb->inode_item.sequence++;
    fr2->parent->fcb->inode_item.st_ctime = now;
    fr2->parent->fcb->inode_item.st_mtime = now;

    free_fileref(Vcb, fr2);

    fr2->parent->fcb->inode_item_changed = TRUE;
    mark_fcb_dirty(fr2->parent->fcb);

    send_notification_fileref(fileref, fcb->type == BTRFS_TYPE_DIRECTORY ? FILE_NOTIFY_CHANGE_DIR_NAME : FILE_NOTIFY_CHANGE_FILE_NAME, FILE_ACTION_ADDED, NULL);
    send_notification_fileref(related, FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_ACTION_MODIFIED, NULL);
    send_notification_fileref(fr2->parent, FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_ACTION_MODIFIED, NULL);

    Status = STATUS_SUCCESS;

end:
    if (oldfileref)
        free_fileref(Vcb, oldfileref);

    if (!NT_SUCCESS(Status) && related)
        free_fileref(Vcb, related);

    if (!NT_SUCCESS(Status) && fr2)
        free_fileref(Vcb, fr2);

    if (NT_SUCCESS(Status))
        clear_rollback(&rollback);
    else
        do_rollback(Vcb, &rollback);

    ExReleaseResourceLite(fcb->Header.Resource);
    release_fcb_lock(Vcb);
    ExReleaseResourceLite(&Vcb->tree_lock);

    return Status;
}

NTSTATUS stream_set_end_of_file_information(device_extension* Vcb, UINT16 end, fcb* fcb, file_ref* fileref, BOOL advance_only) {
    LARGE_INTEGER time;
    BTRFS_TIME now;

    TRACE("setting new end to %llx bytes (currently %x)\n", end, fcb->adsdata.Length);

    if (!fileref || !fileref->parent) {
        ERR("no fileref for stream\n");
        return STATUS_INTERNAL_ERROR;
    }

    if (end < fcb->adsdata.Length) {
        if (advance_only)
            return STATUS_SUCCESS;

        TRACE("truncating stream to %llx bytes\n", end);

        fcb->adsdata.Length = end;
    } else if (end > fcb->adsdata.Length) {
        TRACE("extending stream to %llx bytes\n", end);

        if (end > fcb->adsmaxlen) {
            ERR("error - xattr too long (%llu > %u)\n", end, fcb->adsmaxlen);
            return STATUS_DISK_FULL;
        }

        if (end > fcb->adsdata.MaximumLength) {
            char* data = ExAllocatePoolWithTag(PagedPool, end, ALLOC_TAG);
            if (!data) {
                ERR("out of memory\n");
                ExFreePool(data);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            if (fcb->adsdata.Buffer) {
                RtlCopyMemory(data, fcb->adsdata.Buffer, fcb->adsdata.Length);
                ExFreePool(fcb->adsdata.Buffer);
            }

            fcb->adsdata.Buffer = data;
            fcb->adsdata.MaximumLength = end;
        }

        RtlZeroMemory(&fcb->adsdata.Buffer[fcb->adsdata.Length], end - fcb->adsdata.Length);

        fcb->adsdata.Length = end;
    }

    mark_fcb_dirty(fcb);

    fcb->Header.AllocationSize.QuadPart = end;
    fcb->Header.FileSize.QuadPart = end;
    fcb->Header.ValidDataLength.QuadPart = end;

    KeQuerySystemTime(&time);
    win_time_to_unix(time, &now);

    fileref->parent->fcb->inode_item.transid = Vcb->superblock.generation;
    fileref->parent->fcb->inode_item.sequence++;
    fileref->parent->fcb->inode_item.st_ctime = now;

    fileref->parent->fcb->inode_item_changed = TRUE;
    mark_fcb_dirty(fileref->parent->fcb);

    fileref->parent->fcb->subvol->root_item.ctransid = Vcb->superblock.generation;
    fileref->parent->fcb->subvol->root_item.ctime = now;

    return STATUS_SUCCESS;
}

static NTSTATUS set_end_of_file_information(device_extension* Vcb, PIRP Irp, PFILE_OBJECT FileObject, BOOL advance_only, BOOL prealloc) {
    FILE_END_OF_FILE_INFORMATION* feofi = Irp->AssociatedIrp.SystemBuffer;
    fcb* fcb = FileObject->FsContext;
    ccb* ccb = FileObject->FsContext2;
    file_ref* fileref = ccb ? ccb->fileref : NULL;
    NTSTATUS Status;
    LARGE_INTEGER time;
    CC_FILE_SIZES ccfs;
    LIST_ENTRY rollback;
    BOOL set_size = FALSE;
    ULONG filter;

    if (!fileref) {
        ERR("fileref is NULL\n");
        return STATUS_INVALID_PARAMETER;
    }

    InitializeListHead(&rollback);

    ExAcquireResourceSharedLite(&Vcb->tree_lock, TRUE);

    ExAcquireResourceExclusiveLite(fcb->Header.Resource, TRUE);

    if (fileref ? fileref->deleted : fcb->deleted) {
        Status = STATUS_FILE_CLOSED;
        goto end;
    }

    if (fcb->ads) {
        if (feofi->EndOfFile.QuadPart > 0xffff) {
            Status = STATUS_DISK_FULL;
            goto end;
        }

        if (feofi->EndOfFile.QuadPart < 0) {
            Status = STATUS_INVALID_PARAMETER;
            goto end;
        }

        Status = stream_set_end_of_file_information(Vcb, (UINT16)feofi->EndOfFile.QuadPart, fcb, fileref, advance_only);

        if (NT_SUCCESS(Status)) {
            ccfs.AllocationSize = fcb->Header.AllocationSize;
            ccfs.FileSize = fcb->Header.FileSize;
            ccfs.ValidDataLength = fcb->Header.ValidDataLength;
            set_size = TRUE;
        }

        filter = FILE_NOTIFY_CHANGE_SIZE;

        if (!ccb->user_set_write_time) {
            KeQuerySystemTime(&time);
            win_time_to_unix(time, &fileref->parent->fcb->inode_item.st_mtime);
            filter |= FILE_NOTIFY_CHANGE_LAST_WRITE;

            fileref->parent->fcb->inode_item_changed = TRUE;
            mark_fcb_dirty(fileref->parent->fcb);
        }

        send_notification_fcb(fileref->parent, filter, FILE_ACTION_MODIFIED, &fileref->dc->name);

        goto end;
    }

    TRACE("file: %S\n", file_desc(FileObject));
    TRACE("paging IO: %s\n", Irp->Flags & IRP_PAGING_IO ? "TRUE" : "FALSE");
    TRACE("FileObject: AllocationSize = %llx, FileSize = %llx, ValidDataLength = %llx\n",
        fcb->Header.AllocationSize.QuadPart, fcb->Header.FileSize.QuadPart, fcb->Header.ValidDataLength.QuadPart);

    TRACE("setting new end to %llx bytes (currently %llx)\n", feofi->EndOfFile.QuadPart, fcb->inode_item.st_size);

    if ((UINT64)feofi->EndOfFile.QuadPart < fcb->inode_item.st_size) {
        if (advance_only) {
            Status = STATUS_SUCCESS;
            goto end;
        }

        TRACE("truncating file to %llx bytes\n", feofi->EndOfFile.QuadPart);

        if (!MmCanFileBeTruncated(&fcb->nonpaged->segment_object, &feofi->EndOfFile)) {
            Status = STATUS_USER_MAPPED_FILE;
            goto end;
        }

        Status = truncate_file(fcb, feofi->EndOfFile.QuadPart, Irp, &rollback);
        if (!NT_SUCCESS(Status)) {
            ERR("error - truncate_file failed\n");
            goto end;
        }
    } else if ((UINT64)feofi->EndOfFile.QuadPart > fcb->inode_item.st_size) {
        if (Irp->Flags & IRP_PAGING_IO) {
            TRACE("paging IO tried to extend file size\n");
            Status = STATUS_SUCCESS;
            goto end;
        }

        TRACE("extending file to %llx bytes\n", feofi->EndOfFile.QuadPart);

        Status = extend_file(fcb, fileref, feofi->EndOfFile.QuadPart, prealloc, NULL, &rollback);
        if (!NT_SUCCESS(Status)) {
            ERR("error - extend_file failed\n");
            goto end;
        }
    }

    ccfs.AllocationSize = fcb->Header.AllocationSize;
    ccfs.FileSize = fcb->Header.FileSize;
    ccfs.ValidDataLength = fcb->Header.ValidDataLength;
    set_size = TRUE;

    filter = FILE_NOTIFY_CHANGE_SIZE;

    if (!ccb->user_set_write_time) {
        KeQuerySystemTime(&time);
        win_time_to_unix(time, &fcb->inode_item.st_mtime);
        filter |= FILE_NOTIFY_CHANGE_LAST_WRITE;
    }

    fcb->inode_item_changed = TRUE;
    mark_fcb_dirty(fcb);
    send_notification_fcb(fileref, filter, FILE_ACTION_MODIFIED, NULL);

    Status = STATUS_SUCCESS;

end:
    if (NT_SUCCESS(Status))
        clear_rollback(&rollback);
    else
        do_rollback(Vcb, &rollback);

    ExReleaseResourceLite(fcb->Header.Resource);

    if (set_size) {
        try {
            CcSetFileSizes(FileObject, &ccfs);
        } except (EXCEPTION_EXECUTE_HANDLER) {
            Status = GetExceptionCode();
        }

        if (!NT_SUCCESS(Status))
            ERR("CcSetFileSizes threw exception %08x\n", Status);
    }

    ExReleaseResourceLite(&Vcb->tree_lock);

    return Status;
}

static NTSTATUS set_position_information(PFILE_OBJECT FileObject, PIRP Irp) {
    FILE_POSITION_INFORMATION* fpi = (FILE_POSITION_INFORMATION*)Irp->AssociatedIrp.SystemBuffer;

    TRACE("setting the position on %S to %llx\n", file_desc(FileObject), fpi->CurrentByteOffset.QuadPart);

    // FIXME - make sure aligned for FO_NO_INTERMEDIATE_BUFFERING

    FileObject->CurrentByteOffset = fpi->CurrentByteOffset;

    return STATUS_SUCCESS;
}

static NTSTATUS set_link_information(device_extension* Vcb, PIRP Irp, PFILE_OBJECT FileObject, PFILE_OBJECT tfo) {
    FILE_LINK_INFORMATION* fli = Irp->AssociatedIrp.SystemBuffer;
    fcb *fcb = FileObject->FsContext, *tfofcb, *parfcb;
    ccb* ccb = FileObject->FsContext2;
    file_ref *fileref = ccb ? ccb->fileref : NULL, *oldfileref = NULL, *related = NULL, *fr2 = NULL;
    WCHAR* fn;
    ULONG fnlen, utf8len;
    UNICODE_STRING fnus;
    ANSI_STRING utf8;
    NTSTATUS Status;
    LARGE_INTEGER time;
    BTRFS_TIME now;
    LIST_ENTRY rollback;
    hardlink* hl;
    ACCESS_MASK access;
    SECURITY_SUBJECT_CONTEXT subjcont;
    dir_child* dc = NULL;

    InitializeListHead(&rollback);

    // FIXME - check fli length
    // FIXME - don't ignore fli->RootDirectory

    TRACE("ReplaceIfExists = %x\n", fli->ReplaceIfExists);
    TRACE("RootDirectory = %p\n", fli->RootDirectory);
    TRACE("FileNameLength = %x\n", fli->FileNameLength);
    TRACE("FileName = %.*S\n", fli->FileNameLength / sizeof(WCHAR), fli->FileName);

    fn = fli->FileName;
    fnlen = fli->FileNameLength / sizeof(WCHAR);

    if (!tfo) {
        if (!fileref || !fileref->parent) {
            ERR("no fileref set and no directory given\n");
            return STATUS_INVALID_PARAMETER;
        }

        parfcb = fileref->parent->fcb;
        tfofcb = NULL;
    } else {
        LONG i;

        tfofcb = tfo->FsContext;
        parfcb = tfofcb;

        while (fnlen > 0 && (fli->FileName[fnlen - 1] == '/' || fli->FileName[fnlen - 1] == '\\'))
            fnlen--;

        if (fnlen == 0)
            return STATUS_INVALID_PARAMETER;

        for (i = fnlen - 1; i >= 0; i--) {
            if (fli->FileName[i] == '\\' || fli->FileName[i] == '/') {
                fn = &fli->FileName[i+1];
                fnlen = (fli->FileNameLength / sizeof(WCHAR)) - i - 1;
                break;
            }
        }
    }

    ExAcquireResourceSharedLite(&Vcb->tree_lock, TRUE);
    acquire_fcb_lock_exclusive(Vcb);
    ExAcquireResourceExclusiveLite(fcb->Header.Resource, TRUE);

    if (fcb->type == BTRFS_TYPE_DIRECTORY) {
        WARN("tried to create hard link on directory\n");
        Status = STATUS_FILE_IS_A_DIRECTORY;
        goto end;
    }

    if (fcb->ads) {
        WARN("tried to create hard link on stream\n");
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    if (fcb->inode_item.st_nlink >= 65535) {
        Status = STATUS_TOO_MANY_LINKS;
        goto end;
    }

    fnus.Buffer = fn;
    fnus.Length = fnus.MaximumLength = (UINT16)(fnlen * sizeof(WCHAR));

    TRACE("fnus = %.*S\n", fnus.Length / sizeof(WCHAR), fnus.Buffer);

    Status = RtlUnicodeToUTF8N(NULL, 0, &utf8len, fn, (ULONG)fnlen * sizeof(WCHAR));
    if (!NT_SUCCESS(Status))
        goto end;

    utf8.MaximumLength = utf8.Length = (UINT16)utf8len;
    utf8.Buffer = ExAllocatePoolWithTag(PagedPool, utf8.MaximumLength, ALLOC_TAG);
    if (!utf8.Buffer) {
        ERR("out of memory\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }

    Status = RtlUnicodeToUTF8N(utf8.Buffer, utf8len, &utf8len, fn, (ULONG)fnlen * sizeof(WCHAR));
    if (!NT_SUCCESS(Status))
        goto end;

    if (tfo && tfo->FsContext2) {
        struct _ccb* relatedccb = tfo->FsContext2;

        related = relatedccb->fileref;
        increase_fileref_refcount(related);
    }

    Status = open_fileref(Vcb, &oldfileref, &fnus, related, FALSE, NULL, NULL, PagedPool, ccb->case_sensitive, Irp);

    if (NT_SUCCESS(Status)) {
        if (!oldfileref->deleted) {
            WARN("destination file %S already exists\n", file_desc_fileref(oldfileref));

            if (!fli->ReplaceIfExists) {
                Status = STATUS_OBJECT_NAME_COLLISION;
                goto end;
            } else if (oldfileref->open_count >= 1 && !oldfileref->deleted) {
                WARN("trying to overwrite open file\n");
                Status = STATUS_ACCESS_DENIED;
                goto end;
            } else if (fileref == oldfileref) {
                Status = STATUS_ACCESS_DENIED;
                goto end;
            }

            if (oldfileref->fcb->type == BTRFS_TYPE_DIRECTORY) {
                WARN("trying to overwrite directory\n");
                Status = STATUS_ACCESS_DENIED;
                goto end;
            }
        } else {
            free_fileref(Vcb, oldfileref);
            oldfileref = NULL;
        }
    }

    if (!related) {
        Status = open_fileref(Vcb, &related, &fnus, NULL, TRUE, NULL, NULL, PagedPool, ccb->case_sensitive, Irp);

        if (!NT_SUCCESS(Status)) {
            ERR("open_fileref returned %08x\n", Status);
            goto end;
        }
    }

    SeCaptureSubjectContext(&subjcont);

    if (!SeAccessCheck(related->fcb->sd, &subjcont, FALSE, FILE_ADD_FILE, 0, NULL,
                       IoGetFileObjectGenericMapping(), Irp->RequestorMode, &access, &Status)) {
        SeReleaseSubjectContext(&subjcont);
        TRACE("SeAccessCheck failed, returning %08x\n", Status);
        goto end;
    }

    SeReleaseSubjectContext(&subjcont);

    if (fcb->subvol != parfcb->subvol) {
        WARN("can't create hard link over subvolume boundary\n");
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    if (oldfileref) {
        SeCaptureSubjectContext(&subjcont);

        if (!SeAccessCheck(oldfileref->fcb->sd, &subjcont, FALSE, DELETE, 0, NULL,
                           IoGetFileObjectGenericMapping(), Irp->RequestorMode, &access, &Status)) {
            SeReleaseSubjectContext(&subjcont);
            TRACE("SeAccessCheck failed, returning %08x\n", Status);
            goto end;
        }

        SeReleaseSubjectContext(&subjcont);

        Status = delete_fileref(oldfileref, NULL, Irp, &rollback);
        if (!NT_SUCCESS(Status)) {
            ERR("delete_fileref returned %08x\n", Status);
            goto end;
        }
    }

    fr2 = create_fileref(Vcb);

    fr2->fcb = fcb;
    fcb->refcount++;

    fr2->created = TRUE;
    fr2->parent = related;

    Status = add_dir_child(related->fcb, fcb->inode, FALSE, &utf8, &fnus, fcb->type, &dc);
    if (!NT_SUCCESS(Status))
        WARN("add_dir_child returned %08x\n", Status);

    fr2->dc = dc;
    dc->fileref = fr2;

    ExAcquireResourceExclusiveLite(&related->nonpaged->children_lock, TRUE);
    InsertTailList(&related->children, &fr2->list_entry);
    ExReleaseResourceLite(&related->nonpaged->children_lock);

    // add hardlink for existing fileref, if it's not there already
    if (IsListEmpty(&fcb->hardlinks)) {
        hl = ExAllocatePoolWithTag(PagedPool, sizeof(hardlink), ALLOC_TAG);
        if (!hl) {
            ERR("out of memory\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }

        hl->parent = fileref->parent->fcb->inode;
        hl->index = fileref->dc->index;

        hl->name.Length = hl->name.MaximumLength = fnus.Length;
        hl->name.Buffer = ExAllocatePoolWithTag(PagedPool, fnus.Length, ALLOC_TAG);

        if (!hl->name.Buffer) {
            ERR("out of memory\n");
            ExFreePool(hl);
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }

        RtlCopyMemory(hl->name.Buffer, fnus.Buffer, fnus.Length);

        hl->utf8.Length = hl->utf8.MaximumLength = fileref->dc->utf8.Length;
        hl->utf8.Buffer = ExAllocatePoolWithTag(PagedPool, hl->utf8.MaximumLength, ALLOC_TAG);

        if (!hl->utf8.Buffer) {
            ERR("out of memory\n");
            ExFreePool(hl->name.Buffer);
            ExFreePool(hl);
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }

        RtlCopyMemory(hl->utf8.Buffer, fileref->dc->utf8.Buffer, fileref->dc->utf8.Length);

        InsertTailList(&fcb->hardlinks, &hl->list_entry);
    }

    hl = ExAllocatePoolWithTag(PagedPool, sizeof(hardlink), ALLOC_TAG);
    if (!hl) {
        ERR("out of memory\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }

    hl->parent = related->fcb->inode;
    hl->index = dc->index;

    hl->name.Length = hl->name.MaximumLength = fnus.Length;
    hl->name.Buffer = ExAllocatePoolWithTag(PagedPool, hl->name.MaximumLength, ALLOC_TAG);

    if (!hl->name.Buffer) {
        ERR("out of memory\n");
        ExFreePool(hl);
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }

    RtlCopyMemory(hl->name.Buffer, fnus.Buffer, fnus.Length);

    hl->utf8.Length = hl->utf8.MaximumLength = utf8.Length;
    hl->utf8.Buffer = ExAllocatePoolWithTag(PagedPool, hl->utf8.MaximumLength, ALLOC_TAG);

    if (!hl->utf8.Buffer) {
        ERR("out of memory\n");
        ExFreePool(hl->name.Buffer);
        ExFreePool(hl);
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }

    RtlCopyMemory(hl->utf8.Buffer, utf8.Buffer, utf8.Length);
    ExFreePool(utf8.Buffer);

    InsertTailList(&fcb->hardlinks, &hl->list_entry);

    mark_fileref_dirty(fr2);
    free_fileref(Vcb, fr2);

    // update inode's INODE_ITEM

    KeQuerySystemTime(&time);
    win_time_to_unix(time, &now);

    fcb->inode_item.transid = Vcb->superblock.generation;
    fcb->inode_item.sequence++;
    fcb->inode_item.st_nlink++;

    if (!ccb->user_set_change_time)
        fcb->inode_item.st_ctime = now;

    fcb->inode_item_changed = TRUE;
    mark_fcb_dirty(fcb);

    // update parent's INODE_ITEM

    parfcb->inode_item.transid = Vcb->superblock.generation;
    TRACE("parfcb->inode_item.st_size (inode %llx) was %llx\n", parfcb->inode, parfcb->inode_item.st_size);
    parfcb->inode_item.st_size += 2 * utf8len;
    TRACE("parfcb->inode_item.st_size (inode %llx) now %llx\n", parfcb->inode, parfcb->inode_item.st_size);
    parfcb->inode_item.sequence++;
    parfcb->inode_item.st_ctime = now;

    parfcb->inode_item_changed = TRUE;
    mark_fcb_dirty(parfcb);

    send_notification_fileref(fr2, FILE_NOTIFY_CHANGE_FILE_NAME, FILE_ACTION_ADDED, NULL);

    Status = STATUS_SUCCESS;

end:
    if (oldfileref)
        free_fileref(Vcb, oldfileref);

    if (!NT_SUCCESS(Status) && related)
        free_fileref(Vcb, related);

    if (!NT_SUCCESS(Status) && fr2)
        free_fileref(Vcb, fr2);

    if (NT_SUCCESS(Status))
        clear_rollback(&rollback);
    else
        do_rollback(Vcb, &rollback);

    ExReleaseResourceLite(fcb->Header.Resource);
    release_fcb_lock(Vcb);
    ExReleaseResourceLite(&Vcb->tree_lock);

    return Status;
}

static NTSTATUS set_valid_data_length_information(device_extension* Vcb, PIRP Irp, PFILE_OBJECT FileObject) {
    FILE_VALID_DATA_LENGTH_INFORMATION* fvdli = Irp->AssociatedIrp.SystemBuffer;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    fcb* fcb = FileObject->FsContext;
    ccb* ccb = FileObject->FsContext2;
    file_ref* fileref = ccb ? ccb->fileref : NULL;
    NTSTATUS Status;
    LARGE_INTEGER time;
    CC_FILE_SIZES ccfs;
    LIST_ENTRY rollback;
    BOOL set_size = FALSE;
    ULONG filter;

    if (IrpSp->Parameters.SetFile.Length < sizeof(FILE_VALID_DATA_LENGTH_INFORMATION)) {
        ERR("input buffer length was %u, expected %u\n", IrpSp->Parameters.SetFile.Length, sizeof(FILE_VALID_DATA_LENGTH_INFORMATION));
        return STATUS_INVALID_PARAMETER;
    }

    if (!fileref) {
        ERR("fileref is NULL\n");
        return STATUS_INVALID_PARAMETER;
    }

    InitializeListHead(&rollback);

    ExAcquireResourceSharedLite(&Vcb->tree_lock, TRUE);

    ExAcquireResourceExclusiveLite(fcb->Header.Resource, TRUE);

    if (fcb->atts & FILE_ATTRIBUTE_SPARSE_FILE) {
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    if (fvdli->ValidDataLength.QuadPart <= fcb->Header.ValidDataLength.QuadPart || fvdli->ValidDataLength.QuadPart > fcb->Header.FileSize.QuadPart) {
        TRACE("invalid VDL of %llu (current VDL = %llu, file size = %llu)\n", fvdli->ValidDataLength.QuadPart,
              fcb->Header.ValidDataLength.QuadPart, fcb->Header.FileSize.QuadPart);
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    if (fileref ? fileref->deleted : fcb->deleted) {
        Status = STATUS_FILE_CLOSED;
        goto end;
    }

    // This function doesn't really do anything - the fsctl can only increase the value of ValidDataLength,
    // and we set it to the max anyway.

    ccfs.AllocationSize = fcb->Header.AllocationSize;
    ccfs.FileSize = fcb->Header.FileSize;
    ccfs.ValidDataLength = fvdli->ValidDataLength;
    set_size = TRUE;

    filter = FILE_NOTIFY_CHANGE_SIZE;

    if (!ccb->user_set_write_time) {
        KeQuerySystemTime(&time);
        win_time_to_unix(time, &fcb->inode_item.st_mtime);
        filter |= FILE_NOTIFY_CHANGE_LAST_WRITE;
    }

    fcb->inode_item_changed = TRUE;
    mark_fcb_dirty(fcb);

    send_notification_fcb(fileref, filter, FILE_ACTION_MODIFIED, NULL);

    Status = STATUS_SUCCESS;

end:
    if (NT_SUCCESS(Status))
        clear_rollback(&rollback);
    else
        do_rollback(Vcb, &rollback);

    ExReleaseResourceLite(fcb->Header.Resource);

    if (set_size) {
        try {
            CcSetFileSizes(FileObject, &ccfs);
        } except (EXCEPTION_EXECUTE_HANDLER) {
            Status = GetExceptionCode();
        }

        if (!NT_SUCCESS(Status))
            ERR("CcSetFileSizes threw exception %08x\n", Status);
        else
            fcb->Header.AllocationSize = ccfs.AllocationSize;
    }

    ExReleaseResourceLite(&Vcb->tree_lock);

    return Status;
}

_Dispatch_type_(IRP_MJ_SET_INFORMATION)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS drv_set_information(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    NTSTATUS Status;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    device_extension* Vcb = DeviceObject->DeviceExtension;
    fcb* fcb = IrpSp->FileObject->FsContext;
    ccb* ccb = IrpSp->FileObject->FsContext2;
    BOOL top_level;

    FsRtlEnterFileSystem();

    top_level = is_top_level(Irp);

    Irp->IoStatus.Information = 0;

    if (Vcb && Vcb->type == VCB_TYPE_VOLUME) {
        Status = vol_set_information(DeviceObject, Irp);
        goto end;
    } else if (!Vcb || Vcb->type != VCB_TYPE_FS) {
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    if (!(Vcb->Vpb->Flags & VPB_MOUNTED)) {
        Status = STATUS_ACCESS_DENIED;
        goto end;
    }

    if (Vcb->readonly && IrpSp->Parameters.SetFile.FileInformationClass != FilePositionInformation) {
        Status = STATUS_MEDIA_WRITE_PROTECTED;
        goto end;
    }

    if (!fcb) {
        ERR("no fcb\n");
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    if (!ccb) {
        ERR("no ccb\n");
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    if (fcb != Vcb->dummy_fcb && is_subvol_readonly(fcb->subvol, Irp) && IrpSp->Parameters.SetFile.FileInformationClass != FilePositionInformation &&
        (fcb->inode != SUBVOL_ROOT_INODE || (IrpSp->Parameters.SetFile.FileInformationClass != FileBasicInformation && IrpSp->Parameters.SetFile.FileInformationClass != FileRenameInformation))) {
        Status = STATUS_ACCESS_DENIED;
        goto end;
    }

    Status = STATUS_NOT_IMPLEMENTED;

    TRACE("set information\n");

    switch (IrpSp->Parameters.SetFile.FileInformationClass) {
        case FileAllocationInformation:
        {
            TRACE("FileAllocationInformation\n");

            if (Irp->RequestorMode == UserMode && !(ccb->access & FILE_WRITE_DATA)) {
                WARN("insufficient privileges\n");
                Status = STATUS_ACCESS_DENIED;
                break;
            }

            Status = set_end_of_file_information(Vcb, Irp, IrpSp->FileObject, FALSE, TRUE);
            break;
        }

        case FileBasicInformation:
        {
            TRACE("FileBasicInformation\n");

            if (Irp->RequestorMode == UserMode && !(ccb->access & FILE_WRITE_ATTRIBUTES)) {
                WARN("insufficient privileges\n");
                Status = STATUS_ACCESS_DENIED;
                break;
            }

            Status = set_basic_information(Vcb, Irp, IrpSp->FileObject);

            break;
        }

        case FileDispositionInformation:
        {
            TRACE("FileDispositionInformation\n");

            if (Irp->RequestorMode == UserMode && !(ccb->access & DELETE)) {
                WARN("insufficient privileges\n");
                Status = STATUS_ACCESS_DENIED;
                break;
            }

            Status = set_disposition_information(Vcb, Irp, IrpSp->FileObject);

            break;
        }

        case FileEndOfFileInformation:
        {
            TRACE("FileEndOfFileInformation\n");

            if (Irp->RequestorMode == UserMode && !(ccb->access & (FILE_WRITE_DATA | FILE_APPEND_DATA))) {
                WARN("insufficient privileges\n");
                Status = STATUS_ACCESS_DENIED;
                break;
            }

            Status = set_end_of_file_information(Vcb, Irp, IrpSp->FileObject, IrpSp->Parameters.SetFile.AdvanceOnly, FALSE);

            break;
        }

        case FileLinkInformation:
            TRACE("FileLinkInformation\n");
            Status = set_link_information(Vcb, Irp, IrpSp->FileObject, IrpSp->Parameters.SetFile.FileObject);
            break;

        case FilePositionInformation:
            TRACE("FilePositionInformation\n");
            Status = set_position_information(IrpSp->FileObject, Irp);
            break;

        case FileRenameInformation:
            TRACE("FileRenameInformation\n");
            // FIXME - make this work with streams
            Status = set_rename_information(Vcb, Irp, IrpSp->FileObject, IrpSp->Parameters.SetFile.FileObject);
            break;

        case FileValidDataLengthInformation:
        {
            TRACE("FileValidDataLengthInformation\n");

            if (Irp->RequestorMode == UserMode && !(ccb->access & (FILE_WRITE_DATA | FILE_APPEND_DATA))) {
                WARN("insufficient privileges\n");
                Status = STATUS_ACCESS_DENIED;
                break;
            }

            Status = set_valid_data_length_information(Vcb, Irp, IrpSp->FileObject);

            break;
        }

        default:
            WARN("unknown FileInformationClass %u\n", IrpSp->Parameters.SetFile.FileInformationClass);
    }

end:
    Irp->IoStatus.Status = Status;

    TRACE("returning %08x\n", Status);

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    if (top_level)
        IoSetTopLevelIrp(NULL);

    FsRtlExitFileSystem();

    return Status;
}

static NTSTATUS fill_in_file_basic_information(FILE_BASIC_INFORMATION* fbi, INODE_ITEM* ii, LONG* length, fcb* fcb, file_ref* fileref) {
    RtlZeroMemory(fbi, sizeof(FILE_BASIC_INFORMATION));

    *length -= sizeof(FILE_BASIC_INFORMATION);

    if (fcb == fcb->Vcb->dummy_fcb) {
        LARGE_INTEGER time;

        KeQuerySystemTime(&time);
        fbi->CreationTime = fbi->LastAccessTime = fbi->LastWriteTime = fbi->ChangeTime = time;
    } else {
        fbi->CreationTime.QuadPart = unix_time_to_win(&ii->otime);
        fbi->LastAccessTime.QuadPart = unix_time_to_win(&ii->st_atime);
        fbi->LastWriteTime.QuadPart = unix_time_to_win(&ii->st_mtime);
        fbi->ChangeTime.QuadPart = unix_time_to_win(&ii->st_ctime);
    }

    if (fcb->ads) {
        if (!fileref || !fileref->parent) {
            ERR("no fileref for stream\n");
            return STATUS_INTERNAL_ERROR;
        } else
            fbi->FileAttributes = fileref->parent->fcb->atts == 0 ? FILE_ATTRIBUTE_NORMAL : fileref->parent->fcb->atts;
    } else
        fbi->FileAttributes = fcb->atts == 0 ? FILE_ATTRIBUTE_NORMAL : fcb->atts;

    return STATUS_SUCCESS;
}

static NTSTATUS fill_in_file_network_open_information(FILE_NETWORK_OPEN_INFORMATION* fnoi, fcb* fcb, file_ref* fileref, LONG* length) {
    INODE_ITEM* ii;

    if (*length < (LONG)sizeof(FILE_NETWORK_OPEN_INFORMATION)) {
        WARN("overflow\n");
        return STATUS_BUFFER_OVERFLOW;
    }

    RtlZeroMemory(fnoi, sizeof(FILE_NETWORK_OPEN_INFORMATION));

    *length -= sizeof(FILE_NETWORK_OPEN_INFORMATION);

    if (fcb->ads) {
        if (!fileref || !fileref->parent) {
            ERR("no fileref for stream\n");
            return STATUS_INTERNAL_ERROR;
        }

        ii = &fileref->parent->fcb->inode_item;
    } else
        ii = &fcb->inode_item;

    if (fcb == fcb->Vcb->dummy_fcb) {
        LARGE_INTEGER time;

        KeQuerySystemTime(&time);
        fnoi->CreationTime = fnoi->LastAccessTime = fnoi->LastWriteTime = fnoi->ChangeTime = time;
    } else {
        fnoi->CreationTime.QuadPart = unix_time_to_win(&ii->otime);
        fnoi->LastAccessTime.QuadPart = unix_time_to_win(&ii->st_atime);
        fnoi->LastWriteTime.QuadPart = unix_time_to_win(&ii->st_mtime);
        fnoi->ChangeTime.QuadPart = unix_time_to_win(&ii->st_ctime);
    }

    if (fcb->ads) {
        fnoi->AllocationSize.QuadPart = fnoi->EndOfFile.QuadPart = fcb->adsdata.Length;
        fnoi->FileAttributes = fileref->parent->fcb->atts == 0 ? FILE_ATTRIBUTE_NORMAL : fileref->parent->fcb->atts;
    } else {
        fnoi->AllocationSize.QuadPart = fcb_alloc_size(fcb);
        fnoi->EndOfFile.QuadPart = S_ISDIR(fcb->inode_item.st_mode) ? 0 : fcb->inode_item.st_size;
        fnoi->FileAttributes = fcb->atts == 0 ? FILE_ATTRIBUTE_NORMAL : fcb->atts;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS fill_in_file_standard_information(FILE_STANDARD_INFORMATION* fsi, fcb* fcb, file_ref* fileref, LONG* length) {
    RtlZeroMemory(fsi, sizeof(FILE_STANDARD_INFORMATION));

    *length -= sizeof(FILE_STANDARD_INFORMATION);

    if (fcb->ads) {
        if (!fileref || !fileref->parent) {
            ERR("no fileref for stream\n");
            return STATUS_INTERNAL_ERROR;
        }

        fsi->AllocationSize.QuadPart = fsi->EndOfFile.QuadPart = fcb->adsdata.Length;
        fsi->NumberOfLinks = fileref->parent->fcb->inode_item.st_nlink;
        fsi->Directory = FALSE;
    } else {
        fsi->AllocationSize.QuadPart = fcb_alloc_size(fcb);
        fsi->EndOfFile.QuadPart = S_ISDIR(fcb->inode_item.st_mode) ? 0 : fcb->inode_item.st_size;
        fsi->NumberOfLinks = fcb->inode_item.st_nlink;
        fsi->Directory = S_ISDIR(fcb->inode_item.st_mode);
    }

    TRACE("length = %llu\n", fsi->EndOfFile.QuadPart);

    fsi->DeletePending = fileref ? fileref->delete_on_close : FALSE;

    return STATUS_SUCCESS;
}

static NTSTATUS fill_in_file_internal_information(FILE_INTERNAL_INFORMATION* fii, fcb* fcb, LONG* length) {
    *length -= sizeof(FILE_INTERNAL_INFORMATION);

    fii->IndexNumber.QuadPart = make_file_id(fcb->subvol, fcb->inode);

    return STATUS_SUCCESS;
}

static NTSTATUS fill_in_file_ea_information(FILE_EA_INFORMATION* eai, fcb* fcb, LONG* length) {
    *length -= sizeof(FILE_EA_INFORMATION);

    /* This value appears to be the size of the structure NTFS stores on disk, and not,
     * as might be expected, the size of FILE_FULL_EA_INFORMATION (which is what we store).
     * The formula is 4 bytes as a header, followed by 5 + NameLength + ValueLength for each
     * item. */

    eai->EaSize = fcb->ealen;

    return STATUS_SUCCESS;
}

static NTSTATUS fill_in_file_position_information(FILE_POSITION_INFORMATION* fpi, PFILE_OBJECT FileObject, LONG* length) {
    RtlZeroMemory(fpi, sizeof(FILE_POSITION_INFORMATION));

    *length -= sizeof(FILE_POSITION_INFORMATION);

    fpi->CurrentByteOffset = FileObject->CurrentByteOffset;

    return STATUS_SUCCESS;
}

NTSTATUS fileref_get_filename(file_ref* fileref, PUNICODE_STRING fn, USHORT* name_offset, ULONG* preqlen) {
    file_ref* fr;
    NTSTATUS Status;
    ULONG reqlen = 0;
    USHORT offset;
    BOOL overflow = FALSE;

    // FIXME - we need a lock on filerefs' filepart

    if (fileref == fileref->fcb->Vcb->root_fileref) {
        if (fn->MaximumLength >= sizeof(WCHAR)) {
            fn->Buffer[0] = '\\';
            fn->Length = sizeof(WCHAR);

            if (name_offset)
                *name_offset = 0;

            return STATUS_SUCCESS;
        } else {
            if (preqlen)
                *preqlen = sizeof(WCHAR);
            fn->Length = 0;

            return STATUS_BUFFER_OVERFLOW;
        }
    }

    fr = fileref;
    offset = 0;

    while (fr->parent) {
        USHORT movelen;

        if (!fr->dc)
            return STATUS_INTERNAL_ERROR;

        if (!overflow) {
            if (fr->dc->name.Length + sizeof(WCHAR) + fn->Length > fn->MaximumLength)
                overflow = TRUE;
        }

        if (overflow)
            movelen = fn->MaximumLength - fr->dc->name.Length - sizeof(WCHAR);
        else
            movelen = fn->Length;

        if ((!overflow || fn->MaximumLength > fr->dc->name.Length + sizeof(WCHAR)) && movelen > 0) {
            RtlMoveMemory(&fn->Buffer[(fr->dc->name.Length / sizeof(WCHAR)) + 1], fn->Buffer, movelen);
            offset += fr->dc->name.Length + sizeof(WCHAR);
        }

        if (fn->MaximumLength >= sizeof(WCHAR)) {
            fn->Buffer[0] = fr->fcb->ads ? ':' : '\\';
            fn->Length += sizeof(WCHAR);

            if (fn->MaximumLength > sizeof(WCHAR)) {
                RtlCopyMemory(&fn->Buffer[1], fr->dc->name.Buffer, min(fr->dc->name.Length, fn->MaximumLength - sizeof(WCHAR)));
                fn->Length += fr->dc->name.Length;
            }

            if (fn->Length > fn->MaximumLength) {
                fn->Length = fn->MaximumLength;
                overflow = TRUE;
            }
        }

        reqlen += sizeof(WCHAR) + fr->dc->name.Length;

        fr = fr->parent;
    }

    offset += sizeof(WCHAR);

    if (overflow) {
        if (preqlen)
            *preqlen = reqlen;
        Status = STATUS_BUFFER_OVERFLOW;
    } else {
        if (name_offset)
            *name_offset = offset;

        Status = STATUS_SUCCESS;
    }

    return Status;
}

static NTSTATUS fill_in_file_name_information(FILE_NAME_INFORMATION* fni, fcb* fcb, file_ref* fileref, LONG* length) {
    ULONG reqlen;
    UNICODE_STRING fn;
    NTSTATUS Status;
    static WCHAR datasuf[] = {':','$','D','A','T','A',0};
    UINT16 datasuflen = (UINT16)wcslen(datasuf) * sizeof(WCHAR);

    if (!fileref) {
        ERR("called without fileref\n");
        return STATUS_INVALID_PARAMETER;
    }

    *length -= (LONG)offsetof(FILE_NAME_INFORMATION, FileName[0]);

    TRACE("maximum length is %u\n", *length);
    fni->FileNameLength = 0;

    fni->FileName[0] = 0;

    fn.Buffer = fni->FileName;
    fn.Length = 0;
    fn.MaximumLength = (UINT16)*length;

    Status = fileref_get_filename(fileref, &fn, NULL, &reqlen);
    if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_OVERFLOW) {
        ERR("fileref_get_filename returned %08x\n", Status);
        return Status;
    }

    if (fcb->ads) {
        if (Status == STATUS_BUFFER_OVERFLOW)
            reqlen += datasuflen;
        else {
            if (fn.Length + datasuflen > fn.MaximumLength) {
                RtlCopyMemory(&fn.Buffer[fn.Length / sizeof(WCHAR)], datasuf, fn.MaximumLength - fn.Length);
                reqlen += datasuflen;
                Status = STATUS_BUFFER_OVERFLOW;
            } else {
                RtlCopyMemory(&fn.Buffer[fn.Length / sizeof(WCHAR)], datasuf, datasuflen);
                fn.Length += datasuflen;
            }
        }
    }

    if (Status == STATUS_BUFFER_OVERFLOW) {
        *length = -1;
        fni->FileNameLength = reqlen;
        TRACE("%.*S (truncated)\n", fn.Length / sizeof(WCHAR), fn.Buffer);
    } else {
        *length -= fn.Length;
        fni->FileNameLength = fn.Length;
        TRACE("%.*S\n", fn.Length / sizeof(WCHAR), fn.Buffer);
    }

    return Status;
}

static NTSTATUS fill_in_file_attribute_information(FILE_ATTRIBUTE_TAG_INFORMATION* ati, fcb* fcb, ccb* ccb, PIRP Irp, LONG* length) {
    *length -= sizeof(FILE_ATTRIBUTE_TAG_INFORMATION);

    if (fcb->ads) {
        if (!ccb->fileref || !ccb->fileref->parent) {
            ERR("no fileref for stream\n");
            return STATUS_INTERNAL_ERROR;
        }

        ati->FileAttributes = ccb->fileref->parent->fcb->atts;
    } else
        ati->FileAttributes = fcb->atts;

    if (!(ati->FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
        ati->ReparseTag = 0;
    else
        ati->ReparseTag = get_reparse_tag(fcb->Vcb, fcb->subvol, fcb->inode, fcb->type, fcb->atts, ccb->lxss, Irp);

    return STATUS_SUCCESS;
}

static NTSTATUS fill_in_file_stream_information(FILE_STREAM_INFORMATION* fsi, file_ref* fileref, LONG* length) {
    LONG reqsize;
    LIST_ENTRY* le;
    FILE_STREAM_INFORMATION *entry, *lastentry;
    NTSTATUS Status;

    static WCHAR datasuf[] = L":$DATA";
    UNICODE_STRING suf;

    if (!fileref) {
        ERR("fileref was NULL\n");
        return STATUS_INVALID_PARAMETER;
    }

    suf.Buffer = datasuf;
    suf.Length = suf.MaximumLength = (UINT16)wcslen(datasuf) * sizeof(WCHAR);

    if (fileref->fcb->type != BTRFS_TYPE_DIRECTORY)
        reqsize = sizeof(FILE_STREAM_INFORMATION) - sizeof(WCHAR) + suf.Length + sizeof(WCHAR);
    else
        reqsize = 0;

    ExAcquireResourceSharedLite(&fileref->fcb->nonpaged->dir_children_lock, TRUE);

    le = fileref->fcb->dir_children_index.Flink;
    while (le != &fileref->fcb->dir_children_index) {
        dir_child* dc = CONTAINING_RECORD(le, dir_child, list_entry_index);

        if (dc->index == 0) {
            reqsize = (ULONG)sector_align(reqsize, sizeof(LONGLONG));
            reqsize += sizeof(FILE_STREAM_INFORMATION) - sizeof(WCHAR) + suf.Length + sizeof(WCHAR) + dc->name.Length;
        } else
            break;

        le = le->Flink;
    }

    TRACE("length = %i, reqsize = %u\n", *length, reqsize);

    if (reqsize > *length) {
        Status = STATUS_BUFFER_OVERFLOW;
        goto end;
    }

    entry = fsi;
    lastentry = NULL;

    if (fileref->fcb->type != BTRFS_TYPE_DIRECTORY) {
        ULONG off;

        entry->NextEntryOffset = 0;
        entry->StreamNameLength = suf.Length + sizeof(WCHAR);
        entry->StreamSize.QuadPart = fileref->fcb->inode_item.st_size;
        entry->StreamAllocationSize.QuadPart = fcb_alloc_size(fileref->fcb);

        entry->StreamName[0] = ':';
        RtlCopyMemory(&entry->StreamName[1], suf.Buffer, suf.Length);

        off = (ULONG)sector_align(sizeof(FILE_STREAM_INFORMATION) - sizeof(WCHAR) + suf.Length + sizeof(WCHAR), sizeof(LONGLONG));

        lastentry = entry;
        entry = (FILE_STREAM_INFORMATION*)((UINT8*)entry + off);
    }

    le = fileref->fcb->dir_children_index.Flink;
    while (le != &fileref->fcb->dir_children_index) {
        dir_child* dc = CONTAINING_RECORD(le, dir_child, list_entry_index);

        if (dc->index == 0) {
            ULONG off;

            entry->NextEntryOffset = 0;
            entry->StreamNameLength = dc->name.Length + suf.Length + sizeof(WCHAR);

            if (dc->fileref)
                entry->StreamSize.QuadPart = dc->fileref->fcb->adsdata.Length;
            else
                entry->StreamSize.QuadPart = dc->size;

            entry->StreamAllocationSize.QuadPart = entry->StreamSize.QuadPart;

            entry->StreamName[0] = ':';

            RtlCopyMemory(&entry->StreamName[1], dc->name.Buffer, dc->name.Length);
            RtlCopyMemory(&entry->StreamName[1 + (dc->name.Length / sizeof(WCHAR))], suf.Buffer, suf.Length);

            if (lastentry)
                lastentry->NextEntryOffset = (UINT32)((UINT8*)entry - (UINT8*)lastentry);

            off = (ULONG)sector_align(sizeof(FILE_STREAM_INFORMATION) - sizeof(WCHAR) + suf.Length + sizeof(WCHAR) + dc->name.Length, sizeof(LONGLONG));

            lastentry = entry;
            entry = (FILE_STREAM_INFORMATION*)((UINT8*)entry + off);
        } else
            break;

        le = le->Flink;
    }

    *length -= reqsize;

    Status = STATUS_SUCCESS;

end:
    ExReleaseResourceLite(&fileref->fcb->nonpaged->dir_children_lock);

    return Status;
}

static NTSTATUS fill_in_file_standard_link_information(FILE_STANDARD_LINK_INFORMATION* fsli, fcb* fcb, file_ref* fileref, LONG* length) {
    TRACE("FileStandardLinkInformation\n");

    // FIXME - NumberOfAccessibleLinks should subtract open links which have been marked as delete_on_close

    fsli->NumberOfAccessibleLinks = fcb->inode_item.st_nlink;
    fsli->TotalNumberOfLinks = fcb->inode_item.st_nlink;
    fsli->DeletePending = fileref ? fileref->delete_on_close : FALSE;
    fsli->Directory = (!fcb->ads && fcb->type == BTRFS_TYPE_DIRECTORY) ? TRUE : FALSE;

    *length -= sizeof(FILE_STANDARD_LINK_INFORMATION);

    return STATUS_SUCCESS;
}

NTSTATUS open_fileref_by_inode(_Requires_exclusive_lock_held_(_Curr_->fcb_lock) device_extension* Vcb,
                               root* subvol, UINT64 inode, file_ref** pfr, PIRP Irp) {
    NTSTATUS Status;
    fcb* fcb;
    UINT64 parent = 0;
    UNICODE_STRING name;
    BOOL hl_alloc = FALSE;
    file_ref *parfr, *fr;

    Status = open_fcb(Vcb, subvol, inode, 0, NULL, NULL, &fcb, PagedPool, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("open_fcb returned %08x\n", Status);
        return Status;
    }

    if (fcb->fileref) {
        *pfr = fcb->fileref;
        increase_fileref_refcount(fcb->fileref);
        return STATUS_SUCCESS;
    }

    // find hardlink if fcb doesn't have any loaded
    if (IsListEmpty(&fcb->hardlinks)) {
        KEY searchkey;
        traverse_ptr tp;

        searchkey.obj_id = fcb->inode;
        searchkey.obj_type = TYPE_INODE_EXTREF;
        searchkey.offset = 0xffffffffffffffff;

        Status = find_item(Vcb, fcb->subvol, &tp, &searchkey, FALSE, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("find_item returned %08x\n", Status);
            free_fcb(Vcb, fcb);
            return Status;
        }

        if (tp.item->key.obj_id == fcb->inode) {
            if (tp.item->key.obj_type == TYPE_INODE_REF) {
                INODE_REF* ir;
                ULONG stringlen;

                ir = (INODE_REF*)tp.item->data;

                parent = tp.item->key.offset;

                Status = RtlUTF8ToUnicodeN(NULL, 0, &stringlen, ir->name, ir->n);
                if (!NT_SUCCESS(Status)) {
                    ERR("RtlUTF8ToUnicodeN 1 returned %08x\n", Status);
                    free_fcb(Vcb, fcb);
                    return Status;
                }

                name.Length = name.MaximumLength = (UINT16)stringlen;

                if (stringlen == 0)
                    name.Buffer = NULL;
                else {
                    name.Buffer = ExAllocatePoolWithTag(PagedPool, name.MaximumLength, ALLOC_TAG);

                    if (!name.Buffer) {
                        ERR("out of memory\n");
                        free_fcb(Vcb, fcb);
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }

                    Status = RtlUTF8ToUnicodeN(name.Buffer, stringlen, &stringlen, ir->name, ir->n);
                    if (!NT_SUCCESS(Status)) {
                        ERR("RtlUTF8ToUnicodeN 2 returned %08x\n", Status);
                        ExFreePool(name.Buffer);
                        free_fcb(Vcb, fcb);
                        return Status;
                    }

                    hl_alloc = TRUE;
                }
            } else if (tp.item->key.obj_type == TYPE_INODE_EXTREF) {
                INODE_EXTREF* ier;
                ULONG stringlen;

                ier = (INODE_EXTREF*)tp.item->data;

                parent = ier->dir;

                Status = RtlUTF8ToUnicodeN(NULL, 0, &stringlen, ier->name, ier->n);
                if (!NT_SUCCESS(Status)) {
                    ERR("RtlUTF8ToUnicodeN 1 returned %08x\n", Status);
                    free_fcb(Vcb, fcb);
                    return Status;
                }

                name.Length = name.MaximumLength = (UINT16)stringlen;

                if (stringlen == 0)
                    name.Buffer = NULL;
                else {
                    name.Buffer = ExAllocatePoolWithTag(PagedPool, name.MaximumLength, ALLOC_TAG);

                    if (!name.Buffer) {
                        ERR("out of memory\n");
                        free_fcb(Vcb, fcb);
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }

                    Status = RtlUTF8ToUnicodeN(name.Buffer, stringlen, &stringlen, ier->name, ier->n);
                    if (!NT_SUCCESS(Status)) {
                        ERR("RtlUTF8ToUnicodeN 2 returned %08x\n", Status);
                        ExFreePool(name.Buffer);
                        free_fcb(Vcb, fcb);
                        return Status;
                    }

                    hl_alloc = TRUE;
                }

            }
        }
    } else {
        hardlink* hl = CONTAINING_RECORD(fcb->hardlinks.Flink, hardlink, list_entry);

        name = hl->name;
        parent = hl->parent;
    }

    if (parent == 0) {
        ERR("subvol %llx, inode %llx has no hardlinks\n", subvol->id, inode);
        free_fcb(Vcb, fcb);
        if (hl_alloc) ExFreePool(name.Buffer);
        return STATUS_INVALID_PARAMETER;
    }

    if (parent == inode) { // subvolume root
        KEY searchkey;
        traverse_ptr tp;

        searchkey.obj_id = subvol->id;
        searchkey.obj_type = TYPE_ROOT_BACKREF;
        searchkey.offset = 0xffffffffffffffff;

        Status = find_item(Vcb, Vcb->root_root, &tp, &searchkey, FALSE, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("find_item returned %08x\n", Status);
            free_fcb(Vcb, fcb);
            if (hl_alloc) ExFreePool(name.Buffer);
            return Status;
        }

        if (tp.item->key.obj_id == searchkey.obj_id && tp.item->key.obj_type == searchkey.obj_type) {
            ROOT_REF* rr = (ROOT_REF*)tp.item->data;
            LIST_ENTRY* le;
            root* r = NULL;
            ULONG stringlen;

            if (tp.item->size < sizeof(ROOT_REF)) {
                ERR("(%llx,%x,%llx) was %u bytes, expected at least %u\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, tp.item->size, sizeof(ROOT_REF));
                free_fcb(Vcb, fcb);
                if (hl_alloc) ExFreePool(name.Buffer);
                return STATUS_INTERNAL_ERROR;
            }

            if (tp.item->size < offsetof(ROOT_REF, name[0]) + rr->n) {
                ERR("(%llx,%x,%llx) was %u bytes, expected %u\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, tp.item->size, offsetof(ROOT_REF, name[0]) + rr->n);
                free_fcb(Vcb, fcb);
                if (hl_alloc) ExFreePool(name.Buffer);
                return STATUS_INTERNAL_ERROR;
            }

            le = Vcb->roots.Flink;
            while (le != &Vcb->roots) {
                root* r2 = CONTAINING_RECORD(le, root, list_entry);

                if (r2->id == tp.item->key.offset) {
                    r = r2;
                    break;
                }

                le = le->Flink;
            }

            if (!r) {
                ERR("couldn't find subvol %llx\n", tp.item->key.offset);
                free_fcb(Vcb, fcb);
                if (hl_alloc) ExFreePool(name.Buffer);
                return STATUS_INTERNAL_ERROR;
            }

            Status = open_fileref_by_inode(Vcb, r, rr->dir, &parfr, Irp);
            if (!NT_SUCCESS(Status)) {
                ERR("open_fileref_by_inode returned %08x\n", Status);
                free_fcb(Vcb, fcb);
                if (hl_alloc) ExFreePool(name.Buffer);
                return Status;
            }

            if (hl_alloc) {
                ExFreePool(name.Buffer);
                hl_alloc = FALSE;
            }

            Status = RtlUTF8ToUnicodeN(NULL, 0, &stringlen, rr->name, rr->n);
            if (!NT_SUCCESS(Status)) {
                ERR("RtlUTF8ToUnicodeN 1 returned %08x\n", Status);
                free_fcb(Vcb, fcb);
                return Status;
            }

            name.Length = name.MaximumLength = (UINT16)stringlen;

            if (stringlen == 0)
                name.Buffer = NULL;
            else {
                name.Buffer = ExAllocatePoolWithTag(PagedPool, name.MaximumLength, ALLOC_TAG);

                if (!name.Buffer) {
                    ERR("out of memory\n");
                    free_fcb(Vcb, fcb);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                Status = RtlUTF8ToUnicodeN(name.Buffer, stringlen, &stringlen, rr->name, rr->n);
                if (!NT_SUCCESS(Status)) {
                    ERR("RtlUTF8ToUnicodeN 2 returned %08x\n", Status);
                    ExFreePool(name.Buffer);
                    free_fcb(Vcb, fcb);
                    return Status;
                }

                hl_alloc = TRUE;
            }
        } else {
            ERR("couldn't find parent for subvol %llx\n", subvol->id);
            free_fcb(Vcb, fcb);
            if (hl_alloc) ExFreePool(name.Buffer);
            return STATUS_INTERNAL_ERROR;
        }
    } else {
        Status = open_fileref_by_inode(Vcb, subvol, parent, &parfr, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("open_fileref_by_inode returned %08x\n", Status);
            free_fcb(Vcb, fcb);

            if (hl_alloc)
                ExFreePool(name.Buffer);

            return Status;
        }
    }

    Status = open_fileref_child(Vcb, parfr, &name, TRUE, TRUE, FALSE, PagedPool, &fr, Irp);

    if (!NT_SUCCESS(Status)) {
        ERR("open_fileref_child returned %08x\n", Status);

        if (hl_alloc)
            ExFreePool(name.Buffer);

        free_fcb(Vcb, fcb);
        free_fileref(Vcb, parfr);

        return Status;
    }

    *pfr = fr;

    if (hl_alloc)
        ExFreePool(name.Buffer);

    free_fcb(Vcb, fcb);
    free_fileref(Vcb, parfr);

    return STATUS_SUCCESS;
}

static NTSTATUS fill_in_hard_link_information(FILE_LINKS_INFORMATION* fli, file_ref* fileref, PIRP Irp, LONG* length) {
    NTSTATUS Status;
    LIST_ENTRY* le;
    LONG bytes_needed;
    FILE_LINK_ENTRY_INFORMATION* feli;
    BOOL overflow = FALSE;
    fcb* fcb = fileref->fcb;
    ULONG len;

    if (fcb->ads)
        return STATUS_INVALID_PARAMETER;

    if (*length < (LONG)offsetof(FILE_LINKS_INFORMATION, Entry))
        return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(fli, *length);

    bytes_needed = offsetof(FILE_LINKS_INFORMATION, Entry);
    len = bytes_needed;
    feli = NULL;

    ExAcquireResourceSharedLite(fcb->Header.Resource, TRUE);

    if (fcb->inode == SUBVOL_ROOT_INODE) {
        ULONG namelen;

        if (fcb == fcb->Vcb->root_fileref->fcb)
            namelen = sizeof(WCHAR);
        else
            namelen = fileref->dc->name.Length;

        bytes_needed += sizeof(FILE_LINK_ENTRY_INFORMATION) - sizeof(WCHAR) + namelen;

        if (bytes_needed > *length)
            overflow = TRUE;

        if (!overflow) {
            feli = &fli->Entry;

            feli->NextEntryOffset = 0;
            feli->ParentFileId = 0; // we use an inode of 0 to mean the parent of a subvolume

            if (fcb == fcb->Vcb->root_fileref->fcb) {
                feli->FileNameLength = 1;
                feli->FileName[0] = '.';
            } else {
                feli->FileNameLength = fileref->dc->name.Length / sizeof(WCHAR);
                RtlCopyMemory(feli->FileName, fileref->dc->name.Buffer, fileref->dc->name.Length);
            }

            fli->EntriesReturned++;

            len = bytes_needed;
        }
    } else {
        acquire_fcb_lock_exclusive(fcb->Vcb);

        if (IsListEmpty(&fcb->hardlinks)) {
            bytes_needed += sizeof(FILE_LINK_ENTRY_INFORMATION) + fileref->dc->name.Length - sizeof(WCHAR);

            if (bytes_needed > *length)
                overflow = TRUE;

            if (!overflow) {
                feli = &fli->Entry;

                feli->NextEntryOffset = 0;
                feli->ParentFileId = fileref->parent->fcb->inode;
                feli->FileNameLength = fileref->dc->name.Length / sizeof(WCHAR);
                RtlCopyMemory(feli->FileName, fileref->dc->name.Buffer, fileref->dc->name.Length);

                fli->EntriesReturned++;

                len = bytes_needed;
            }
        } else {
            le = fcb->hardlinks.Flink;
            while (le != &fcb->hardlinks) {
                hardlink* hl = CONTAINING_RECORD(le, hardlink, list_entry);
                file_ref* parfr;

                TRACE("parent %llx, index %llx, name %.*S\n", hl->parent, hl->index, hl->name.Length / sizeof(WCHAR), hl->name.Buffer);

                Status = open_fileref_by_inode(fcb->Vcb, fcb->subvol, hl->parent, &parfr, Irp);

                if (!NT_SUCCESS(Status)) {
                    ERR("open_fileref_by_inode returned %08x\n", Status);
                } else if (!parfr->deleted) {
                    LIST_ENTRY* le2;
                    BOOL found = FALSE, deleted = FALSE;
                    UNICODE_STRING* fn = NULL;

                    le2 = parfr->children.Flink;
                    while (le2 != &parfr->children) {
                        file_ref* fr2 = CONTAINING_RECORD(le2, file_ref, list_entry);

                        if (fr2->dc->index == hl->index) {
                            found = TRUE;
                            deleted = fr2->deleted;

                            if (!deleted)
                                fn = &fr2->dc->name;

                            break;
                        }

                        le2 = le2->Flink;
                    }

                    if (!found)
                        fn = &hl->name;

                    if (!deleted) {
                        TRACE("fn = %.*S (found = %u)\n", fn->Length / sizeof(WCHAR), fn->Buffer, found);

                        if (feli)
                            bytes_needed = (LONG)sector_align(bytes_needed, 8);

                        bytes_needed += sizeof(FILE_LINK_ENTRY_INFORMATION) + fn->Length - sizeof(WCHAR);

                        if (bytes_needed > *length)
                            overflow = TRUE;

                        if (!overflow) {
                            if (feli) {
                                feli->NextEntryOffset = (ULONG)sector_align(sizeof(FILE_LINK_ENTRY_INFORMATION) + ((feli->FileNameLength - 1) * sizeof(WCHAR)), 8);
                                feli = (FILE_LINK_ENTRY_INFORMATION*)((UINT8*)feli + feli->NextEntryOffset);
                            } else
                                feli = &fli->Entry;

                            feli->NextEntryOffset = 0;
                            feli->ParentFileId = parfr->fcb->inode;
                            feli->FileNameLength = fn->Length / sizeof(WCHAR);
                            RtlCopyMemory(feli->FileName, fn->Buffer, fn->Length);

                            fli->EntriesReturned++;

                            len = bytes_needed;
                        }
                    }

                    free_fileref(fcb->Vcb, parfr);
                }

                le = le->Flink;
            }
        }

        release_fcb_lock(fcb->Vcb);
    }

    fli->BytesNeeded = bytes_needed;

    *length -= len;

    Status = overflow ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;

    ExReleaseResourceLite(fcb->Header.Resource);

    return Status;
}

#ifdef __MINGW32__
typedef struct _FILE_ID_128 {
    UCHAR Identifier[16];
} FILE_ID_128, *PFILE_ID_128;

typedef struct _FILE_ID_INFORMATION {
    ULONGLONG VolumeSerialNumber;
    FILE_ID_128 FileId;
} FILE_ID_INFORMATION, *PFILE_ID_INFORMATION;
#endif

static NTSTATUS fill_in_file_id_information(FILE_ID_INFORMATION* fii, fcb* fcb, LONG* length) {
    RtlCopyMemory(&fii->VolumeSerialNumber, &fcb->Vcb->superblock.uuid.uuid[8], sizeof(UINT64));
    RtlCopyMemory(&fii->FileId.Identifier[0], &fcb->inode, sizeof(UINT64));
    RtlCopyMemory(&fii->FileId.Identifier[sizeof(UINT64)], &fcb->subvol->id, sizeof(UINT64));

    *length -= sizeof(FILE_ID_INFORMATION);

    return STATUS_SUCCESS;
}

static NTSTATUS query_info(device_extension* Vcb, PFILE_OBJECT FileObject, PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    LONG length = IrpSp->Parameters.QueryFile.Length;
    fcb* fcb = FileObject->FsContext;
    ccb* ccb = FileObject->FsContext2;
    file_ref* fileref = ccb ? ccb->fileref : NULL;
    NTSTATUS Status;

    TRACE("(%p, %p, %p)\n", Vcb, FileObject, Irp);
    TRACE("fcb = %p\n", fcb);

    if (fcb == Vcb->volume_fcb)
        return STATUS_INVALID_PARAMETER;

    if (!ccb) {
        ERR("ccb is NULL\n");
        return STATUS_INVALID_PARAMETER;
    }

    switch (IrpSp->Parameters.QueryFile.FileInformationClass) {
        case FileAllInformation:
        {
            FILE_ALL_INFORMATION* fai = Irp->AssociatedIrp.SystemBuffer;
            INODE_ITEM* ii;

            TRACE("FileAllInformation\n");

            if (Irp->RequestorMode != KernelMode && !(ccb->access & (FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES))) {
                WARN("insufficient privileges\n");
                Status = STATUS_ACCESS_DENIED;
                goto exit;
            }

            if (fcb->ads) {
                if (!fileref || !fileref->parent) {
                    ERR("no fileref for stream\n");
                    Status = STATUS_INTERNAL_ERROR;
                    goto exit;
                }

                ii = &fileref->parent->fcb->inode_item;
            } else
                ii = &fcb->inode_item;

            // Access, mode, and alignment are all filled in by the kernel

            if (length > 0)
                fill_in_file_basic_information(&fai->BasicInformation, ii, &length, fcb, fileref);

            if (length > 0)
                fill_in_file_standard_information(&fai->StandardInformation, fcb, fileref, &length);

            if (length > 0)
                fill_in_file_internal_information(&fai->InternalInformation, fcb, &length);

            if (length > 0)
                fill_in_file_ea_information(&fai->EaInformation, fcb, &length);

            length -= sizeof(FILE_ACCESS_INFORMATION);

            if (length > 0)
                fill_in_file_position_information(&fai->PositionInformation, FileObject, &length);

            length -= sizeof(FILE_MODE_INFORMATION);

            length -= sizeof(FILE_ALIGNMENT_INFORMATION);

            if (length > 0)
                fill_in_file_name_information(&fai->NameInformation, fcb, fileref, &length);

            Status = STATUS_SUCCESS;

            break;
        }

        case FileAttributeTagInformation:
        {
            FILE_ATTRIBUTE_TAG_INFORMATION* ati = Irp->AssociatedIrp.SystemBuffer;

            TRACE("FileAttributeTagInformation\n");

            if (Irp->RequestorMode != KernelMode && !(ccb->access & (FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES))) {
                WARN("insufficient privileges\n");
                Status = STATUS_ACCESS_DENIED;
                goto exit;
            }

            ExAcquireResourceSharedLite(&Vcb->tree_lock, TRUE);
            Status = fill_in_file_attribute_information(ati, fcb, ccb, Irp, &length);
            ExReleaseResourceLite(&Vcb->tree_lock);

            break;
        }

        case FileBasicInformation:
        {
            FILE_BASIC_INFORMATION* fbi = Irp->AssociatedIrp.SystemBuffer;
            INODE_ITEM* ii;

            TRACE("FileBasicInformation\n");

            if (Irp->RequestorMode != KernelMode && !(ccb->access & (FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES))) {
                WARN("insufficient privileges\n");
                Status = STATUS_ACCESS_DENIED;
                goto exit;
            }

            if (IrpSp->Parameters.QueryFile.Length < sizeof(FILE_BASIC_INFORMATION)) {
                WARN("overflow\n");
                Status = STATUS_BUFFER_OVERFLOW;
                goto exit;
            }

            if (fcb->ads) {
                if (!fileref || !fileref->parent) {
                    ERR("no fileref for stream\n");
                    Status = STATUS_INTERNAL_ERROR;
                    goto exit;
                }

                ii = &fileref->parent->fcb->inode_item;
            } else
                ii = &fcb->inode_item;

            Status = fill_in_file_basic_information(fbi, ii, &length, fcb, fileref);
            break;
        }

        case FileCompressionInformation:
            FIXME("STUB: FileCompressionInformation\n");
            Status = STATUS_INVALID_PARAMETER;
            goto exit;

        case FileEaInformation:
        {
            FILE_EA_INFORMATION* eai = Irp->AssociatedIrp.SystemBuffer;

            TRACE("FileEaInformation\n");

            Status = fill_in_file_ea_information(eai, fcb, &length);

            break;
        }

        case FileInternalInformation:
        {
            FILE_INTERNAL_INFORMATION* fii = Irp->AssociatedIrp.SystemBuffer;

            TRACE("FileInternalInformation\n");

            Status = fill_in_file_internal_information(fii, fcb, &length);

            break;
        }

        case FileNameInformation:
        {
            FILE_NAME_INFORMATION* fni = Irp->AssociatedIrp.SystemBuffer;

            TRACE("FileNameInformation\n");

            Status = fill_in_file_name_information(fni, fcb, fileref, &length);

            break;
        }

        case FileNetworkOpenInformation:
        {
            FILE_NETWORK_OPEN_INFORMATION* fnoi = Irp->AssociatedIrp.SystemBuffer;

            TRACE("FileNetworkOpenInformation\n");

            if (Irp->RequestorMode != KernelMode && !(ccb->access & (FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES))) {
                WARN("insufficient privileges\n");
                Status = STATUS_ACCESS_DENIED;
                goto exit;
            }

            Status = fill_in_file_network_open_information(fnoi, fcb, fileref, &length);

            break;
        }

        case FilePositionInformation:
        {
            FILE_POSITION_INFORMATION* fpi = Irp->AssociatedIrp.SystemBuffer;

            TRACE("FilePositionInformation\n");

            Status = fill_in_file_position_information(fpi, FileObject, &length);

            break;
        }

        case FileStandardInformation:
        {
            FILE_STANDARD_INFORMATION* fsi = Irp->AssociatedIrp.SystemBuffer;

            TRACE("FileStandardInformation\n");

            if (IrpSp->Parameters.QueryFile.Length < sizeof(FILE_STANDARD_INFORMATION)) {
                WARN("overflow\n");
                Status = STATUS_BUFFER_OVERFLOW;
                goto exit;
            }

            Status = fill_in_file_standard_information(fsi, fcb, ccb->fileref, &length);

            break;
        }

        case FileStreamInformation:
        {
            FILE_STREAM_INFORMATION* fsi = Irp->AssociatedIrp.SystemBuffer;

            TRACE("FileStreamInformation\n");

            Status = fill_in_file_stream_information(fsi, fileref, &length);

            break;
        }

        case FileHardLinkInformation:
        {
            FILE_LINKS_INFORMATION* fli = Irp->AssociatedIrp.SystemBuffer;

            TRACE("FileHardLinkInformation\n");

            ExAcquireResourceSharedLite(&Vcb->tree_lock, TRUE);
            Status = fill_in_hard_link_information(fli, fileref, Irp, &length);
            ExReleaseResourceLite(&Vcb->tree_lock);

            break;
        }

        case FileNormalizedNameInformation:
        {
            FILE_NAME_INFORMATION* fni = Irp->AssociatedIrp.SystemBuffer;

            TRACE("FileNormalizedNameInformation\n");

            Status = fill_in_file_name_information(fni, fcb, fileref, &length);

            break;
        }

        case FileStandardLinkInformation:
        {
            FILE_STANDARD_LINK_INFORMATION* fsli = Irp->AssociatedIrp.SystemBuffer;

            TRACE("FileStandardLinkInformation\n");

            Status = fill_in_file_standard_link_information(fsli, fcb, ccb->fileref, &length);

            break;
        }

        case FileRemoteProtocolInformation:
            TRACE("FileRemoteProtocolInformation\n");
            Status = STATUS_INVALID_PARAMETER;
            goto exit;

#ifndef _MSC_VER
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wswitch"
#endif
        case FileIdInformation:
        {
            FILE_ID_INFORMATION* fii = Irp->AssociatedIrp.SystemBuffer;

            if (IrpSp->Parameters.QueryFile.Length < sizeof(FILE_ID_INFORMATION)) {
                WARN("overflow\n");
                Status = STATUS_BUFFER_OVERFLOW;
                goto exit;
            }

            TRACE("FileIdInformation\n");

            Status = fill_in_file_id_information(fii, fcb, &length);

            break;
        }
#ifndef _MSC_VER
#pragma GCC diagnostic pop
#endif

        default:
            WARN("unknown FileInformationClass %u\n", IrpSp->Parameters.QueryFile.FileInformationClass);
            Status = STATUS_INVALID_PARAMETER;
            goto exit;
    }

    if (length < 0) {
        length = 0;
        Status = STATUS_BUFFER_OVERFLOW;
    }

    Irp->IoStatus.Information = IrpSp->Parameters.QueryFile.Length - length;

exit:
    TRACE("query_info returning %08x\n", Status);

    return Status;
}

_Dispatch_type_(IRP_MJ_QUERY_INFORMATION)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS drv_query_information(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    PIO_STACK_LOCATION IrpSp;
    NTSTATUS Status;
    fcb* fcb;
    device_extension* Vcb = DeviceObject->DeviceExtension;
    BOOL top_level;

    FsRtlEnterFileSystem();

    top_level = is_top_level(Irp);

    if (Vcb && Vcb->type == VCB_TYPE_VOLUME) {
        Status = vol_query_information(DeviceObject, Irp);
        goto end;
    } else if (!Vcb || Vcb->type != VCB_TYPE_FS) {
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    Irp->IoStatus.Information = 0;

    TRACE("query information\n");

    IrpSp = IoGetCurrentIrpStackLocation(Irp);

    fcb = IrpSp->FileObject->FsContext;
    TRACE("fcb = %p\n", fcb);
    TRACE("fcb->subvol = %p\n", fcb->subvol);

    Status = query_info(fcb->Vcb, IrpSp->FileObject, Irp);

end:
    TRACE("returning %08x\n", Status);

    Irp->IoStatus.Status = Status;

    IoCompleteRequest( Irp, IO_NO_INCREMENT );

    if (top_level)
        IoSetTopLevelIrp(NULL);

    FsRtlExitFileSystem();

    return Status;
}

_Dispatch_type_(IRP_MJ_QUERY_EA)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS drv_query_ea(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    NTSTATUS Status;
    BOOL top_level;
    device_extension* Vcb = DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    fcb* fcb;
    ccb* ccb;
    FILE_FULL_EA_INFORMATION* ffei;
    ULONG retlen = 0;

    FsRtlEnterFileSystem();

    TRACE("(%p, %p)\n", DeviceObject, Irp);

    top_level = is_top_level(Irp);

    if (Vcb && Vcb->type == VCB_TYPE_VOLUME) {
        Status = vol_query_ea(DeviceObject, Irp);
        goto end;
    } else if (!Vcb || Vcb->type != VCB_TYPE_FS) {
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    ffei = map_user_buffer(Irp, NormalPagePriority);
    if (!ffei) {
        ERR("could not get output buffer\n");
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    if (!FileObject) {
        ERR("no file object\n");
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    fcb = FileObject->FsContext;

    if (!fcb) {
        ERR("no fcb\n");
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    ccb = FileObject->FsContext2;

    if (!ccb) {
        ERR("no ccb\n");
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    if (Irp->RequestorMode == UserMode && !(ccb->access & (FILE_READ_EA | FILE_WRITE_EA))) {
        WARN("insufficient privileges\n");
        Status = STATUS_ACCESS_DENIED;
        goto end;
    }

    if (fcb->ads)
        fcb = ccb->fileref->parent->fcb;

    ExAcquireResourceSharedLite(fcb->Header.Resource, TRUE);

    Status = STATUS_SUCCESS;

    if (fcb->ea_xattr.Length == 0)
        goto end2;

    if (IrpSp->Parameters.QueryEa.EaList) {
        FILE_FULL_EA_INFORMATION *ea, *out;
        FILE_GET_EA_INFORMATION* in;

        in = IrpSp->Parameters.QueryEa.EaList;
        do {
            STRING s;

            s.Length = s.MaximumLength = in->EaNameLength;
            s.Buffer = in->EaName;

            RtlUpperString(&s, &s);

            if (in->NextEntryOffset == 0)
                break;

            in = (FILE_GET_EA_INFORMATION*)(((UINT8*)in) + in->NextEntryOffset);
        } while (TRUE);

        ea = (FILE_FULL_EA_INFORMATION*)fcb->ea_xattr.Buffer;
        out = NULL;

        do {
            BOOL found = FALSE;

            in = IrpSp->Parameters.QueryEa.EaList;
            do {
                if (in->EaNameLength == ea->EaNameLength &&
                    RtlCompareMemory(in->EaName, ea->EaName, in->EaNameLength) == in->EaNameLength) {
                    found = TRUE;
                    break;
                }

                if (in->NextEntryOffset == 0)
                    break;

                in = (FILE_GET_EA_INFORMATION*)(((UINT8*)in) + in->NextEntryOffset);
            } while (TRUE);

            if (found) {
                UINT8 padding = retlen % 4 > 0 ? (4 - (retlen % 4)) : 0;

                if (offsetof(FILE_FULL_EA_INFORMATION, EaName[0]) + ea->EaNameLength + 1 + ea->EaValueLength > IrpSp->Parameters.QueryEa.Length - retlen - padding) {
                    Status = STATUS_BUFFER_OVERFLOW;
                    retlen = 0;
                    goto end2;
                }

                retlen += padding;

                if (out) {
                    out->NextEntryOffset = (ULONG)offsetof(FILE_FULL_EA_INFORMATION, EaName[0]) + out->EaNameLength + 1 + out->EaValueLength + padding;
                    out = (FILE_FULL_EA_INFORMATION*)(((UINT8*)out) + out->NextEntryOffset);
                } else
                    out = ffei;

                out->NextEntryOffset = 0;
                out->Flags = ea->Flags;
                out->EaNameLength = ea->EaNameLength;
                out->EaValueLength = ea->EaValueLength;
                RtlCopyMemory(out->EaName, ea->EaName, ea->EaNameLength + ea->EaValueLength + 1);

                retlen += (ULONG)offsetof(FILE_FULL_EA_INFORMATION, EaName[0]) + ea->EaNameLength + 1 + ea->EaValueLength;

                if (IrpSp->Flags & SL_RETURN_SINGLE_ENTRY)
                    break;
            }

            if (ea->NextEntryOffset == 0)
                break;

            ea = (FILE_FULL_EA_INFORMATION*)(((UINT8*)ea) + ea->NextEntryOffset);
        } while (TRUE);
    } else {
        FILE_FULL_EA_INFORMATION *ea, *out;
        ULONG index;

        if (IrpSp->Flags & SL_INDEX_SPECIFIED) {
            // The index is 1-based
            if (IrpSp->Parameters.QueryEa.EaIndex == 0) {
                Status = STATUS_NONEXISTENT_EA_ENTRY;
                goto end2;
            } else
                index = IrpSp->Parameters.QueryEa.EaIndex - 1;
        } else if (IrpSp->Flags & SL_RESTART_SCAN)
            index = ccb->ea_index = 0;
        else
            index = ccb->ea_index;

        ea = (FILE_FULL_EA_INFORMATION*)fcb->ea_xattr.Buffer;

        if (index > 0) {
            ULONG i;

            for (i = 0; i < index; i++) {
                if (ea->NextEntryOffset == 0) // last item
                    goto end2;

                ea = (FILE_FULL_EA_INFORMATION*)(((UINT8*)ea) + ea->NextEntryOffset);
            }
        }

        out = NULL;

        do {
            UINT8 padding = retlen % 4 > 0 ? (4 - (retlen % 4)) : 0;

            if (offsetof(FILE_FULL_EA_INFORMATION, EaName[0]) + ea->EaNameLength + 1 + ea->EaValueLength > IrpSp->Parameters.QueryEa.Length - retlen - padding) {
                Status = retlen == 0 ? STATUS_BUFFER_TOO_SMALL : STATUS_BUFFER_OVERFLOW;
                goto end2;
            }

            retlen += padding;

            if (out) {
                out->NextEntryOffset = (ULONG)offsetof(FILE_FULL_EA_INFORMATION, EaName[0]) + out->EaNameLength + 1 + out->EaValueLength + padding;
                out = (FILE_FULL_EA_INFORMATION*)(((UINT8*)out) + out->NextEntryOffset);
            } else
                out = ffei;

            out->NextEntryOffset = 0;
            out->Flags = ea->Flags;
            out->EaNameLength = ea->EaNameLength;
            out->EaValueLength = ea->EaValueLength;
            RtlCopyMemory(out->EaName, ea->EaName, ea->EaNameLength + ea->EaValueLength + 1);

            retlen += (ULONG)offsetof(FILE_FULL_EA_INFORMATION, EaName[0]) + ea->EaNameLength + 1 + ea->EaValueLength;

            if (!(IrpSp->Flags & SL_INDEX_SPECIFIED))
                ccb->ea_index++;

            if (ea->NextEntryOffset == 0 || IrpSp->Flags & SL_RETURN_SINGLE_ENTRY)
                break;

            ea = (FILE_FULL_EA_INFORMATION*)(((UINT8*)ea) + ea->NextEntryOffset);
        } while (TRUE);
    }

end2:
    ExReleaseResourceLite(fcb->Header.Resource);

end:
    TRACE("returning %08x\n", Status);

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = NT_SUCCESS(Status) || Status == STATUS_BUFFER_OVERFLOW ? retlen : 0;

    IoCompleteRequest( Irp, IO_NO_INCREMENT );

    if (top_level)
        IoSetTopLevelIrp(NULL);

    FsRtlExitFileSystem();

    return Status;
}

typedef struct {
    ANSI_STRING name;
    ANSI_STRING value;
    UCHAR flags;
    LIST_ENTRY list_entry;
} ea_item;

_Dispatch_type_(IRP_MJ_SET_EA)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS drv_set_ea(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    device_extension* Vcb = DeviceObject->DeviceExtension;
    NTSTATUS Status;
    BOOL top_level;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    fcb* fcb;
    ccb* ccb;
    file_ref* fileref;
    FILE_FULL_EA_INFORMATION* ffei;
    ULONG offset;
    LIST_ENTRY ealist;
    ea_item* item;
    FILE_FULL_EA_INFORMATION* ea;
    LIST_ENTRY* le;
    LARGE_INTEGER time;
    BTRFS_TIME now;

    FsRtlEnterFileSystem();

    TRACE("(%p, %p)\n", DeviceObject, Irp);

    top_level = is_top_level(Irp);

    if (Vcb && Vcb->type == VCB_TYPE_VOLUME) {
        Status = vol_set_ea(DeviceObject, Irp);
        goto end;
    } else if (!Vcb || Vcb->type != VCB_TYPE_FS) {
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    if (Vcb->readonly) {
        Status = STATUS_MEDIA_WRITE_PROTECTED;
        goto end;
    }

    ffei = map_user_buffer(Irp, NormalPagePriority);
    if (!ffei) {
        ERR("could not get output buffer\n");
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    Status = IoCheckEaBufferValidity(ffei, IrpSp->Parameters.SetEa.Length, &offset);
    if (!NT_SUCCESS(Status)) {
        ERR("IoCheckEaBufferValidity returned %08x (error at offset %u)\n", Status, offset);
        goto end;
    }

    if (!FileObject) {
        ERR("no file object\n");
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    fcb = FileObject->FsContext;

    if (!fcb) {
        ERR("no fcb\n");
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    ccb = FileObject->FsContext2;

    if (!ccb) {
        ERR("no ccb\n");
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    if (Irp->RequestorMode == UserMode && !(ccb->access & FILE_WRITE_EA)) {
        WARN("insufficient privileges\n");
        Status = STATUS_ACCESS_DENIED;
        goto end;
    }

    if (fcb->ads) {
        fileref = ccb->fileref->parent;
        fcb = fileref->fcb;
    } else
        fileref = ccb->fileref;

    InitializeListHead(&ealist);

    ExAcquireResourceExclusiveLite(fcb->Header.Resource, TRUE);

    if (fcb->ea_xattr.Length > 0) {
        ea = (FILE_FULL_EA_INFORMATION*)fcb->ea_xattr.Buffer;

        do {
            item = ExAllocatePoolWithTag(PagedPool, sizeof(ea_item), ALLOC_TAG);
            if (!item) {
                ERR("out of memory\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto end2;
            }

            item->name.Length = item->name.MaximumLength = ea->EaNameLength;
            item->name.Buffer = ea->EaName;

            item->value.Length = item->value.MaximumLength = ea->EaValueLength;
            item->value.Buffer = &ea->EaName[ea->EaNameLength + 1];

            item->flags = ea->Flags;

            InsertTailList(&ealist, &item->list_entry);

            if (ea->NextEntryOffset == 0)
                break;

            ea = (FILE_FULL_EA_INFORMATION*)(((UINT8*)ea) + ea->NextEntryOffset);
        } while (TRUE);
    }

    ea = ffei;

    do {
        STRING s;
        BOOL found = FALSE;

        s.Length = s.MaximumLength = ea->EaNameLength;
        s.Buffer = ea->EaName;

        RtlUpperString(&s, &s);

        le = ealist.Flink;
        while (le != &ealist) {
            item = CONTAINING_RECORD(le, ea_item, list_entry);

            if (item->name.Length == s.Length &&
                RtlCompareMemory(item->name.Buffer, s.Buffer, s.Length) == s.Length) {
                item->flags = ea->Flags;
                item->value.Length = item->value.MaximumLength = ea->EaValueLength;
                item->value.Buffer = &ea->EaName[ea->EaNameLength + 1];
                found = TRUE;
                break;
            }

            le = le->Flink;
        }

        if (!found) {
            item = ExAllocatePoolWithTag(PagedPool, sizeof(ea_item), ALLOC_TAG);
            if (!item) {
                ERR("out of memory\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto end2;
            }

            item->name.Length = item->name.MaximumLength = ea->EaNameLength;
            item->name.Buffer = ea->EaName;

            item->value.Length = item->value.MaximumLength = ea->EaValueLength;
            item->value.Buffer = &ea->EaName[ea->EaNameLength + 1];

            item->flags = ea->Flags;

            InsertTailList(&ealist, &item->list_entry);
        }

        if (ea->NextEntryOffset == 0)
            break;

        ea = (FILE_FULL_EA_INFORMATION*)(((UINT8*)ea) + ea->NextEntryOffset);
    } while (TRUE);

    // remove entries with zero-length value
    le = ealist.Flink;
    while (le != &ealist) {
        LIST_ENTRY* le2 = le->Flink;

        item = CONTAINING_RECORD(le, ea_item, list_entry);

        if (item->value.Length == 0) {
            RemoveEntryList(&item->list_entry);
            ExFreePool(item);
        }

        le = le2;
    }

    if (IsListEmpty(&ealist)) {
        fcb->ealen = 0;

        if (fcb->ea_xattr.Buffer)
            ExFreePool(fcb->ea_xattr.Buffer);

        fcb->ea_xattr.Length = fcb->ea_xattr.MaximumLength = 0;
        fcb->ea_xattr.Buffer = NULL;
    } else {
        UINT16 size = 0;
        char *buf, *oldbuf;

        le = ealist.Flink;
        while (le != &ealist) {
            item = CONTAINING_RECORD(le, ea_item, list_entry);

            if (size % 4 > 0)
                size += 4 - (size % 4);

            size += (UINT16)offsetof(FILE_FULL_EA_INFORMATION, EaName[0]) + item->name.Length + 1 + item->value.Length;

            le = le->Flink;
        }

        buf = ExAllocatePoolWithTag(PagedPool, size, ALLOC_TAG);
        if (!buf) {
            ERR("out of memory\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end2;
        }

        oldbuf = fcb->ea_xattr.Buffer;

        fcb->ea_xattr.Length = fcb->ea_xattr.MaximumLength = size;
        fcb->ea_xattr.Buffer = buf;

        fcb->ealen = 4;
        ea = NULL;

        le = ealist.Flink;
        while (le != &ealist) {
            item = CONTAINING_RECORD(le, ea_item, list_entry);

            if (ea) {
                ea->NextEntryOffset = (ULONG)offsetof(FILE_FULL_EA_INFORMATION, EaName[0]) + ea->EaNameLength + ea->EaValueLength;

                if (ea->NextEntryOffset % 4 > 0)
                    ea->NextEntryOffset += 4 - (ea->NextEntryOffset % 4);

                ea = (FILE_FULL_EA_INFORMATION*)(((UINT8*)ea) + ea->NextEntryOffset);
            } else
                ea = (FILE_FULL_EA_INFORMATION*)fcb->ea_xattr.Buffer;

            ea->NextEntryOffset = 0;
            ea->Flags = item->flags;
            ea->EaNameLength = (UCHAR)item->name.Length;
            ea->EaValueLength = item->value.Length;

            RtlCopyMemory(ea->EaName, item->name.Buffer, item->name.Length);
            ea->EaName[item->name.Length] = 0;
            RtlCopyMemory(&ea->EaName[item->name.Length + 1], item->value.Buffer, item->value.Length);

            fcb->ealen += 5 + item->name.Length + item->value.Length;

            le = le->Flink;
        }

        if (oldbuf)
            ExFreePool(oldbuf);
    }

    fcb->ea_changed = TRUE;

    KeQuerySystemTime(&time);
    win_time_to_unix(time, &now);

    fcb->inode_item.transid = Vcb->superblock.generation;
    fcb->inode_item.sequence++;

    if (!ccb->user_set_change_time)
        fcb->inode_item.st_ctime = now;

    fcb->inode_item_changed = TRUE;
    mark_fcb_dirty(fcb);

    send_notification_fileref(fileref, FILE_NOTIFY_CHANGE_EA, FILE_ACTION_MODIFIED, NULL);

    Status = STATUS_SUCCESS;

end2:
    ExReleaseResourceLite(fcb->Header.Resource);

    while (!IsListEmpty(&ealist)) {
        le = RemoveHeadList(&ealist);

        item = CONTAINING_RECORD(le, ea_item, list_entry);

        ExFreePool(item);
    }

end:
    TRACE("returning %08x\n", Status);

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    if (top_level)
        IoSetTopLevelIrp(NULL);

    FsRtlExitFileSystem();

    return Status;
}
