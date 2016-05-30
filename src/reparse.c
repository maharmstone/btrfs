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

NTSTATUS get_reparse_point(PDEVICE_OBJECT DeviceObject, PFILE_OBJECT FileObject, void* buffer, DWORD buflen, DWORD* retlen) {
    USHORT subnamelen, printnamelen, i;
    ULONG stringlen;
    DWORD reqlen;
    REPARSE_DATA_BUFFER* rdb = buffer;
    fcb* fcb = FileObject->FsContext;
    char* data;
    NTSTATUS Status;
    
    // FIXME - check permissions
    
    TRACE("(%p, %p, %p, %x, %p)\n", DeviceObject, FileObject, buffer, buflen, retlen);
    
    ExAcquireResourceSharedLite(&fcb->Vcb->tree_lock, TRUE);
    ExAcquireResourceSharedLite(fcb->Header.Resource, TRUE);
    
    if (fcb->type == BTRFS_TYPE_SYMLINK) {
        data = ExAllocatePoolWithTag(PagedPool, fcb->inode_item.st_size, ALLOC_TAG);
        if (!data) {
            ERR("out of memory\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }
        
        TRACE("data = %p, size = %x\n", data, fcb->inode_item.st_size);
        Status = read_file(fcb, (UINT8*)data, 0, fcb->inode_item.st_size, NULL);
        
        if (!NT_SUCCESS(Status)) {
            ERR("read_file returned %08x\n", Status);
            ExFreePool(data);
            goto end;
        }
        
        Status = RtlUTF8ToUnicodeN(NULL, 0, &stringlen, data, fcb->inode_item.st_size);
        if (!NT_SUCCESS(Status)) {
            ERR("RtlUTF8ToUnicodeN 1 returned %08x\n", Status);
            ExFreePool(data);
            goto end;
        }
        
        subnamelen = stringlen;
        printnamelen = stringlen;
        
        reqlen = offsetof(REPARSE_DATA_BUFFER, SymbolicLinkReparseBuffer.PathBuffer) + subnamelen + printnamelen;
        
        if (buflen < reqlen) {
            Status = STATUS_BUFFER_OVERFLOW;
            goto end;
        }
        
        rdb->ReparseTag = IO_REPARSE_TAG_SYMLINK;
        rdb->ReparseDataLength = reqlen - offsetof(REPARSE_DATA_BUFFER, SymbolicLinkReparseBuffer);
        rdb->Reserved = 0;
        
        rdb->SymbolicLinkReparseBuffer.SubstituteNameOffset = 0;
        rdb->SymbolicLinkReparseBuffer.SubstituteNameLength = subnamelen;
        rdb->SymbolicLinkReparseBuffer.PrintNameOffset = subnamelen;
        rdb->SymbolicLinkReparseBuffer.PrintNameLength = printnamelen;
        rdb->SymbolicLinkReparseBuffer.Flags = SYMLINK_FLAG_RELATIVE;
        
        Status = RtlUTF8ToUnicodeN(&rdb->SymbolicLinkReparseBuffer.PathBuffer[rdb->SymbolicLinkReparseBuffer.SubstituteNameOffset / sizeof(WCHAR)],
                                stringlen, &stringlen, data, fcb->inode_item.st_size);

        if (!NT_SUCCESS(Status)) {
            ERR("RtlUTF8ToUnicodeN 2 returned %08x\n", Status);
            ExFreePool(data);
            goto end;
        }
        
        for (i = 0; i < stringlen / sizeof(WCHAR); i++) {
            if (rdb->SymbolicLinkReparseBuffer.PathBuffer[(rdb->SymbolicLinkReparseBuffer.SubstituteNameOffset / sizeof(WCHAR)) + i] == '/')
                rdb->SymbolicLinkReparseBuffer.PathBuffer[(rdb->SymbolicLinkReparseBuffer.SubstituteNameOffset / sizeof(WCHAR)) + i] = '\\';
        }
        
        RtlCopyMemory(&rdb->SymbolicLinkReparseBuffer.PathBuffer[rdb->SymbolicLinkReparseBuffer.PrintNameOffset / sizeof(WCHAR)],
                    &rdb->SymbolicLinkReparseBuffer.PathBuffer[rdb->SymbolicLinkReparseBuffer.SubstituteNameOffset / sizeof(WCHAR)],
                    rdb->SymbolicLinkReparseBuffer.SubstituteNameLength);
        
        *retlen = reqlen;
        
        ExFreePool(data);
        
        Status = STATUS_SUCCESS;
    } else if (fcb->atts & FILE_ATTRIBUTE_REPARSE_POINT) {
        if (fcb->type == BTRFS_TYPE_FILE) {
            Status = read_file(fcb, buffer, 0, buflen, retlen);
            
            if (!NT_SUCCESS(Status)) {
                ERR("read_file returned %08x\n", Status);
            }
        } else if (fcb->type == BTRFS_TYPE_DIRECTORY) {
            if (!fcb->reparse_xattr.Buffer || fcb->reparse_xattr.Length < sizeof(ULONG)) {
                Status = STATUS_NOT_A_REPARSE_POINT;
                goto end;
            }
            
            if (buflen > 0) {
                *retlen = min(buflen, fcb->reparse_xattr.Length);
                RtlCopyMemory(buffer, fcb->reparse_xattr.Buffer, *retlen);
            } else
                *retlen = 0;
        } else
            Status = STATUS_NOT_A_REPARSE_POINT;
    } else {
        Status = STATUS_NOT_A_REPARSE_POINT;
    }
    
end:
    ExReleaseResourceLite(fcb->Header.Resource);
    ExReleaseResourceLite(&fcb->Vcb->tree_lock);

    return Status;
}

static NTSTATUS change_file_type(device_extension* Vcb, UINT64 inode, root* subvol, UINT64 parinode, UINT64 index, PANSI_STRING utf8, UINT8 type, LIST_ENTRY* rollback) {
    KEY searchkey;
    UINT32 crc32;
    traverse_ptr tp;
    NTSTATUS Status;
    
    crc32 = calc_crc32c(0xfffffffe, (UINT8*)utf8->Buffer, (ULONG)utf8->Length);

    searchkey.obj_id = parinode;
    searchkey.obj_type = TYPE_DIR_ITEM;
    searchkey.offset = crc32;

    Status = find_item(Vcb, subvol, &tp, &searchkey, FALSE);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08x\n", Status);
        return Status;
    }

    if (!keycmp(&tp.item->key, &searchkey)) {
        if (tp.item->size < sizeof(DIR_ITEM)) {
            ERR("(%llx,%x,%llx) was %u bytes, expected at least %u\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, tp.item->size, sizeof(DIR_ITEM));
        } else {
            DIR_ITEM *di = ExAllocatePoolWithTag(PagedPool, tp.item->size, ALLOC_TAG), *di2;
            BOOL found = FALSE;
            ULONG len = tp.item->size;
            
            if (!di) {
                ERR("out of memory\n");
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            
            RtlCopyMemory(di, tp.item->data, tp.item->size);
            
            di2 = di;
            do {
                if (len < sizeof(DIR_ITEM) || len < sizeof(DIR_ITEM) - 1 + di2->m + di2->n) {
                    ERR("(%llx,%x,%llx) was truncated\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset);
                    break;
                }
                
                if (di2->n == utf8->Length && RtlCompareMemory(di2->name, utf8->Buffer, utf8->Length) == utf8->Length) {
                    di2->type = type;
                    found = TRUE;
                    break;
                }
                
                if (len > sizeof(DIR_ITEM) - sizeof(char) + di2->m + di2->n) {
                    len -= sizeof(DIR_ITEM) - sizeof(char) + di2->m + di2->n;
                    di2 = (DIR_ITEM*)&di2->name[di2->m + di2->n];
                } else
                    break;
            } while (len > 0);
            
            if (found) {
                delete_tree_item(Vcb, &tp, rollback);
                insert_tree_item(Vcb, subvol, tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, di, tp.item->size, NULL, rollback);
            } else
                ExFreePool(di);
        }
    } else {
        WARN("search for DIR_ITEM by crc32 failed\n");
    }

    searchkey.obj_id = parinode;
    searchkey.obj_type = TYPE_DIR_INDEX;
    searchkey.offset = index;
    
    Status = find_item(Vcb, subvol, &tp, &searchkey, FALSE);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08x\n", Status);
        return Status;
    }
    
    if (!keycmp(&tp.item->key, &searchkey)) {
        if (tp.item->size < sizeof(DIR_ITEM)) {
            ERR("(%llx,%x,%llx) was %u bytes, expected at least %u\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, tp.item->size, sizeof(DIR_ITEM));
        } else {
            DIR_ITEM* di = (DIR_ITEM*)tp.item->data;
            DIR_ITEM* di2 = ExAllocatePoolWithTag(PagedPool, tp.item->size, ALLOC_TAG);
            if (!di2) {
                ERR("out of memory\n");
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            
            RtlCopyMemory(di2, di, tp.item->size);
            di2->type = type;
            
            delete_tree_item(Vcb, &tp, rollback);
            insert_tree_item(Vcb, subvol, tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, di2, tp.item->size, NULL, rollback);
        }
    }
    
    return STATUS_SUCCESS;
}

static NTSTATUS set_symlink(PIRP Irp, file_ref* fileref, REPARSE_DATA_BUFFER* rdb, ULONG buflen, LIST_ENTRY* rollback) {
    NTSTATUS Status;
    ULONG minlen;
    UNICODE_STRING subname;
    ANSI_STRING target;
    LARGE_INTEGER offset;
    USHORT i;
    
    minlen = offsetof(REPARSE_DATA_BUFFER, SymbolicLinkReparseBuffer.PathBuffer) + sizeof(WCHAR);
    if (buflen < minlen) {
        WARN("buffer was less than minimum length (%u < %u)\n", buflen, minlen);
        return STATUS_INVALID_PARAMETER;
    }
    
    subname.Buffer = &rdb->SymbolicLinkReparseBuffer.PathBuffer[rdb->SymbolicLinkReparseBuffer.SubstituteNameOffset / sizeof(WCHAR)];
    subname.MaximumLength = subname.Length = rdb->SymbolicLinkReparseBuffer.SubstituteNameLength;
    
    TRACE("substitute name = %.*S\n", subname.Length / sizeof(WCHAR), subname.Buffer);
    
    fileref->fcb->type = BTRFS_TYPE_SYMLINK;
    
    fileref->fcb->inode_item.st_mode |= __S_IFLNK;
    
    Status = truncate_file(fileref->fcb, 0, rollback);
    if (!NT_SUCCESS(Status)) {
        ERR("truncate_file returned %08x\n", Status);
        return Status;
    }
    
    Status = RtlUnicodeToUTF8N(NULL, 0, (PULONG)&target.Length, subname.Buffer, subname.Length);
    if (!NT_SUCCESS(Status)) {
        ERR("RtlUnicodeToUTF8N 1 failed with error %08x\n", Status);
        return Status;
    }
    
    target.MaximumLength = target.Length;
    target.Buffer = ExAllocatePoolWithTag(PagedPool, target.MaximumLength, ALLOC_TAG);
    if (!target.Buffer) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    Status = RtlUnicodeToUTF8N(target.Buffer, target.Length, (PULONG)&target.Length, subname.Buffer, subname.Length);
    if (!NT_SUCCESS(Status)) {
        ERR("RtlUnicodeToUTF8N 2 failed with error %08x\n", Status);
        ExFreePool(target.Buffer);
        return Status;
    }
    
    for (i = 0; i < target.Length; i++) {
        if (target.Buffer[i] == '\\')
            target.Buffer[i] = '/';
    }
    
    offset.QuadPart = 0;
    Status = write_file2(fileref->fcb->Vcb, Irp, offset, target.Buffer, (ULONG*)&target.Length, FALSE, TRUE,
                         TRUE, FALSE, rollback);
    ExFreePool(target.Buffer);
    
    mark_fcb_dirty(fileref->fcb);
    mark_fileref_dirty(fileref);
    
    return Status;
}

static NTSTATUS delete_symlink(fcb* fcb, LIST_ENTRY* rollback) {
    NTSTATUS Status;
    KEY searchkey;
    traverse_ptr tp, next_tp;
    BOOL b;
    LARGE_INTEGER time;
    BTRFS_TIME now;
    
    searchkey.obj_id = fcb->inode;
    searchkey.obj_type = TYPE_INODE_REF;
    searchkey.offset = 0;
    
    Status = find_item(fcb->Vcb, fcb->subvol, &tp, &searchkey, FALSE);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08x\n", Status);
        return Status;
    }
    
    do {
        if (tp.item->key.obj_id == fcb->inode && tp.item->key.obj_type == TYPE_INODE_REF) {
            if (tp.item->size < sizeof(INODE_REF)) {
                WARN("(%llx,%x,%llx) was %u bytes, expected at least %u\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, tp.item->size, sizeof(INODE_REF));
            } else {
                INODE_REF* ir;
                ULONG size = tp.item->size;
                ANSI_STRING utf8;
                
                ir = (INODE_REF*)tp.item->data;
                
                do {
                    if (size < sizeof(INODE_REF) || size < sizeof(INODE_REF) - 1 + ir->n) {
                        WARN("(%llx,%x,%llx) was truncated\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset);
                        break;
                    }
                    
                    utf8.Buffer = ir->name;
                    utf8.Length = utf8.MaximumLength = ir->n;
                    
                    Status = change_file_type(fcb->Vcb, fcb->inode, fcb->subvol, tp.item->key.offset, ir->index, &utf8, BTRFS_TYPE_FILE, rollback);
                    
                    if (!NT_SUCCESS(Status)) {
                        ERR("error - change_file_type returned %08x\n", Status);
                        return Status;
                    }
                    
                    if (size > sizeof(INODE_REF) - 1 + ir->n) {
                        size -= sizeof(INODE_REF) - 1 + ir->n;
                        
                        ir = (INODE_REF*)&ir->name[ir->n];
                    } else
                        break;
                } while (TRUE);
            }
        }
        
        b = find_next_item(fcb->Vcb, &tp, &next_tp, FALSE);
        if (b) {
            tp = next_tp;
            
            b = tp.item->key.obj_id == fcb->inode && tp.item->key.obj_type == TYPE_INODE_REF;
        }
    } while (b);
    
    if (fcb->Vcb->superblock.incompat_flags & BTRFS_INCOMPAT_FLAGS_EXTENDED_IREF) {
        searchkey.obj_id = fcb->inode;
        searchkey.obj_type = TYPE_INODE_EXTREF;
        searchkey.offset = 0;
        
        Status = find_item(fcb->Vcb, fcb->subvol, &tp, &searchkey, FALSE);
        if (!NT_SUCCESS(Status)) {
            ERR("error - find_item returned %08x\n", Status);
            return Status;
        }
        
        do {
            if (tp.item->key.obj_id == fcb->inode && tp.item->key.obj_type == TYPE_INODE_EXTREF) {
                if (tp.item->size < sizeof(INODE_EXTREF)) {
                    WARN("(%llx,%x,%llx) was %u bytes, expected at least %u\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, tp.item->size, sizeof(INODE_EXTREF));
                } else {
                    INODE_EXTREF* ier;
                    ULONG size = tp.item->size;
                    ANSI_STRING utf8;
                    
                    ier = (INODE_EXTREF*)tp.item->data;
                    
                    do {
                        if (size < sizeof(INODE_EXTREF) || size < sizeof(INODE_EXTREF) - 1 + ier->n) {
                            WARN("(%llx,%x,%llx) was truncated\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset);
                            break;
                        }
                        
                        utf8.Buffer = ier->name;
                        utf8.Length = utf8.MaximumLength = ier->n;
                        
                        Status = change_file_type(fcb->Vcb, fcb->inode, fcb->subvol, ier->dir, ier->index, &utf8, BTRFS_TYPE_FILE, rollback);
                        
                        if (!NT_SUCCESS(Status)) {
                            ERR("error - change_file_type returned %08x\n", Status);
                            return Status;
                        }
                        
                        if (size > sizeof(INODE_EXTREF) - 1 + ier->n) {
                            size -= sizeof(INODE_EXTREF) - 1 + ier->n;
                            
                            ier = (INODE_EXTREF*)&ier->name[ier->n];
                        } else
                            break;
                    } while (TRUE);
                }
            }
            
            b = find_next_item(fcb->Vcb, &tp, &next_tp, FALSE);
            if (b) {
                tp = next_tp;
                
                b = tp.item->key.obj_id == fcb->inode && tp.item->key.obj_type == TYPE_INODE_EXTREF;
            }
        } while (b);
    }   
    
    Status = truncate_file(fcb, 0, rollback);
    if (!NT_SUCCESS(Status)) {
        ERR("truncate_file returned %08x\n", Status);
        return Status;
    }
    
    KeQuerySystemTime(&time);
    
    win_time_to_unix(time, &now);
    
    fcb->type = BTRFS_TYPE_FILE;
    fcb->inode_item.st_mode &= ~__S_IFLNK;
    fcb->inode_item.st_mode |= __S_IFREG;
    fcb->inode_item.transid = fcb->Vcb->superblock.generation;
    fcb->inode_item.sequence++;
    fcb->inode_item.st_ctime = now;
    fcb->inode_item.st_mtime = now;

    mark_fcb_dirty(fcb);

    fcb->subvol->root_item.ctransid = fcb->Vcb->superblock.generation;
    fcb->subvol->root_item.ctime = now;
    
    return Status;
}

NTSTATUS set_reparse_point(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    void* buffer = Irp->AssociatedIrp.SystemBuffer;
    REPARSE_DATA_BUFFER* rdb = buffer;
    DWORD buflen = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
    NTSTATUS Status = STATUS_SUCCESS;
    fcb* fcb;
    ccb* ccb;
    file_ref* fileref;
    ULONG tag;
    LIST_ENTRY rollback;
    
    // FIXME - send notification if this succeeds? The attributes will have changed.
    // FIXME - check permissions
    
    TRACE("(%p, %p)\n", DeviceObject, Irp);
    
    InitializeListHead(&rollback);
    
    if (!FileObject) {
        ERR("FileObject was NULL\n");
        return STATUS_INVALID_PARAMETER;
    }
    
    fcb = FileObject->FsContext;
    ccb = FileObject->FsContext2;
    
    if (!ccb) {
        ERR("ccb was NULL\n");
        return STATUS_INVALID_PARAMETER;
    }
    
    fileref = ccb->fileref;
    
    if (!fileref) {
        ERR("fileref was NULL\n");
        return STATUS_INVALID_PARAMETER;
    }
    
    TRACE("%S\n", file_desc(FileObject));
    
    ExAcquireResourceSharedLite(&fcb->Vcb->tree_lock, TRUE);
    ExAcquireResourceExclusiveLite(fcb->Header.Resource, TRUE);
    
    if (fcb->type == BTRFS_TYPE_SYMLINK) {
        WARN("tried to set a reparse point on an existing symlink\n");
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }
    
    // FIXME - fail if we already have the attribute FILE_ATTRIBUTE_REPARSE_POINT
    
    // FIXME - die if not file or directory
    // FIXME - die if ADS
    
    if (buflen < sizeof(ULONG)) {
        WARN("buffer was not long enough to hold tag\n");
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }
    
    RtlCopyMemory(&tag, buffer, sizeof(ULONG));
    
    if (fcb->type == BTRFS_TYPE_FILE && tag == IO_REPARSE_TAG_SYMLINK && rdb->SymbolicLinkReparseBuffer.Flags & SYMLINK_FLAG_RELATIVE) {
        Status = set_symlink(Irp, fileref, rdb, buflen, &rollback);
        fileref->fcb->atts |= FILE_ATTRIBUTE_REPARSE_POINT;
    } else {
        LARGE_INTEGER offset;
        
        if (fcb->type == BTRFS_TYPE_DIRECTORY) { // for directories, store as xattr
            ANSI_STRING buf;
            
            buf.Buffer = ExAllocatePoolWithTag(PagedPool, buflen, ALLOC_TAG);
            if (!buf.Buffer) {
                ERR("out of memory\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto end;
            }
            buf.Length = buf.MaximumLength = buflen;
            
            if (fcb->reparse_xattr.Buffer)
                ExFreePool(fcb->reparse_xattr.Buffer);
            
            fcb->reparse_xattr = buf;
            RtlCopyMemory(fcb->reparse_xattr.Buffer, buffer, buflen);
            
            fcb->reparse_xattr_changed = TRUE;
            
            Status = STATUS_SUCCESS;
        } else { // otherwise, store as file data
            Status = truncate_file(fcb, 0, &rollback);
            if (!NT_SUCCESS(Status)) {
                ERR("truncate_file returned %08x\n", Status);
                goto end;
            }
            
            offset.QuadPart = 0;
            
            Status = write_file2(fcb->Vcb, Irp, offset, buffer, &buflen, FALSE, TRUE, TRUE, FALSE, &rollback);
            if (!NT_SUCCESS(Status)) {
                ERR("write_file2 returned %08x\n", Status);
                goto end;
            }
        }
            
        fcb->atts |= FILE_ATTRIBUTE_REPARSE_POINT;
        fcb->atts_changed = TRUE;
        
        mark_fcb_dirty(fcb);
    }
    
end:
    // FIXME - do rollback if this failed
    clear_rollback(&rollback);

    ExReleaseResourceLite(fcb->Header.Resource);
    ExReleaseResourceLite(&fcb->Vcb->tree_lock);
    
    return Status;
}

NTSTATUS delete_reparse_point(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    REPARSE_DATA_BUFFER* rdb = Irp->AssociatedIrp.SystemBuffer;
    DWORD buflen = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
    NTSTATUS Status;
    fcb* fcb;
    ccb* ccb;
    file_ref* fileref;
    LIST_ENTRY rollback;
    
    // FIXME - send notification if this succeeds? The attributes will have changed.
    // FIXME - check permissions
    
    TRACE("(%p, %p)\n", DeviceObject, Irp);
    
    InitializeListHead(&rollback);
    
    if (!FileObject) {
        ERR("FileObject was NULL\n");
        return STATUS_INVALID_PARAMETER;
    }
    
    fcb = FileObject->FsContext;
    ccb = FileObject->FsContext2;
    fileref = ccb ? ccb->fileref : NULL;
    
    TRACE("%S\n", file_desc(FileObject));
    
    if (!fileref) {
        ERR("fileref was NULL\n");
        return STATUS_INVALID_PARAMETER;
    }
    
    if (buflen < offsetof(REPARSE_DATA_BUFFER, GenericReparseBuffer.DataBuffer)) {
        ERR("buffer was too short\n");
        return STATUS_INVALID_PARAMETER;
    }
    
    if (rdb->ReparseDataLength > 0) {
        WARN("rdb->ReparseDataLength was not zero\n");
        return STATUS_INVALID_PARAMETER;
    }
    
    ExAcquireResourceExclusiveLite(&fcb->Vcb->tree_lock, TRUE);
    
    if (fcb->ads) {
        WARN("tried to delete reparse point on ADS\n");
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }
    
    if (fcb->type == BTRFS_TYPE_SYMLINK) {
        if (rdb->ReparseTag != IO_REPARSE_TAG_SYMLINK) {
            WARN("reparse tag was not IO_REPARSE_TAG_SYMLINK\n");
            Status = STATUS_INVALID_PARAMETER;
            goto end;
        }
        
        Status = delete_symlink(fcb, &rollback);
        if (!NT_SUCCESS(Status)) {
            ERR("delete_symlink returned %08x\n", Status);
            goto end;
        }
    } else if (fcb->type == BTRFS_TYPE_FILE) {
        LARGE_INTEGER time;
        BTRFS_TIME now;
        ULONG defda;
        
        // FIXME - do we need to check that the reparse tags match?
        
        Status = truncate_file(fcb, 0, &rollback);
        if (!NT_SUCCESS(Status)) {
            ERR("truncate_file returned %08x\n", Status);
            goto end;
        }
        
        fcb->atts &= ~FILE_ATTRIBUTE_REPARSE_POINT;
        
        defda = get_file_attributes(fcb->Vcb, &fcb->inode_item, fcb->subvol, fcb->inode, fcb->type, fileref->filepart.Length > 0 && fileref->filepart.Buffer[0] == '.', TRUE);
        
        if (defda != fcb->atts) {
            char val[64];
            
            sprintf(val, "0x%lx", fcb->atts);
        
            Status = set_xattr(fcb->Vcb, fcb->subvol, fcb->inode, EA_DOSATTRIB, EA_DOSATTRIB_HASH, (UINT8*)val, strlen(val), &rollback);
            if (!NT_SUCCESS(Status)) {
                ERR("set_xattr returned %08x\n", Status);
                goto end;
            }
        } else
            delete_xattr(fcb->Vcb, fcb->subvol, fcb->inode, EA_DOSATTRIB, EA_DOSATTRIB_HASH, &rollback);
        
        KeQuerySystemTime(&time);
        
        win_time_to_unix(time, &now);
        
        fcb->inode_item.transid = fcb->Vcb->superblock.generation;
        fcb->inode_item.sequence++;
        fcb->inode_item.st_ctime = now;
        fcb->inode_item.st_mtime = now;

        mark_fcb_dirty(fcb);

        fcb->subvol->root_item.ctransid = fcb->Vcb->superblock.generation;
        fcb->subvol->root_item.ctime = now;
    } else if (fcb->type == BTRFS_TYPE_DIRECTORY) {
        LARGE_INTEGER time;
        BTRFS_TIME now;
        ULONG defda;
        
        // FIXME - do we need to check that the reparse tags match?
        
        fcb->atts &= ~FILE_ATTRIBUTE_REPARSE_POINT;
        
        defda = get_file_attributes(fcb->Vcb, &fcb->inode_item, fcb->subvol, fcb->inode, fcb->type, fileref->filepart.Length > 0 && fileref->filepart.Buffer[0] == '.', TRUE);
        defda |= FILE_ATTRIBUTE_DIRECTORY;
        
        if (defda != fcb->atts) {
            char val[64];
            
            sprintf(val, "0x%lx", fcb->atts);
        
            Status = set_xattr(fcb->Vcb, fcb->subvol, fcb->inode, EA_DOSATTRIB, EA_DOSATTRIB_HASH, (UINT8*)val, strlen(val), &rollback);
            if (!NT_SUCCESS(Status)) {
                ERR("set_xattr returned %08x\n", Status);
                goto end;
            }
        } else
            delete_xattr(fcb->Vcb, fcb->subvol, fcb->inode, EA_DOSATTRIB, EA_DOSATTRIB_HASH, &rollback);
        
        delete_xattr(fcb->Vcb, fcb->subvol, fcb->inode, EA_REPARSE, EA_REPARSE_HASH, &rollback);
        
        KeQuerySystemTime(&time);
        
        win_time_to_unix(time, &now);
        
        fcb->inode_item.transid = fcb->Vcb->superblock.generation;
        fcb->inode_item.sequence++;
        fcb->inode_item.st_ctime = now;
        fcb->inode_item.st_mtime = now;

        mark_fcb_dirty(fcb);

        fcb->subvol->root_item.ctransid = fcb->Vcb->superblock.generation;
        fcb->subvol->root_item.ctime = now;
    } else {
        ERR("unsupported file type %u\n", fcb->type);
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }
    
    Status = STATUS_SUCCESS;
    
    if (NT_SUCCESS(Status))
        Status = consider_write(fcb->Vcb);
    
end:
    if (NT_SUCCESS(Status))
        clear_rollback(&rollback);
    else
        do_rollback(fcb->Vcb, &rollback);

    ExReleaseResourceLite(&fcb->Vcb->tree_lock);
    
    return Status;
}
