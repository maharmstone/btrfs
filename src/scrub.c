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

#define SCRUB_UNIT 0x100000 // 1 MB

struct _scrub_context;

typedef struct {
    struct _scrub_context* context;
    PIRP Irp;
    UINT64 start;
    UINT32 length;
    IO_STATUS_BLOCK iosb;
    UINT8* buf;
    BOOL csum_error;
    UINT32* bad_csums;
} scrub_context_stripe;

typedef struct _scrub_context {
    KEVENT Event;
    scrub_context_stripe* stripes;
    LONG stripes_left;
} scrub_context;

typedef struct {
    ANSI_STRING name;
    BOOL orig_subvol;
    LIST_ENTRY list_entry;
} path_part;

static void log_file_checksum_error(device_extension* Vcb, UINT64 addr, UINT64 devid, UINT64 subvol, UINT64 inode, UINT64 offset) {
    LIST_ENTRY *le, parts;
    root* r = NULL;
    KEY searchkey;
    traverse_ptr tp;
    UINT64 dir;
    BOOL orig_subvol = TRUE, not_in_tree = FALSE;
    ANSI_STRING fn;
    scrub_error* err;
    NTSTATUS Status;
    ULONG utf16len;

    le = Vcb->roots.Flink;
    while (le != &Vcb->roots) {
        root* r2 = CONTAINING_RECORD(le, root, list_entry);

        if (r2->id == subvol) {
            r = r2;
            break;
        }

        le = le->Flink;
    }

    if (!r) {
        ERR("could not find subvol %llx\n", subvol);
        return;
    }

    InitializeListHead(&parts);

    dir = inode;

    while (TRUE) {
        if (dir == r->root_item.objid) {
            if (r == Vcb->root_fileref->fcb->subvol)
                break;

            searchkey.obj_id = r->id;
            searchkey.obj_type = TYPE_ROOT_BACKREF;
            searchkey.offset = 0xffffffffffffffff;

            Status = find_item(Vcb, Vcb->root_root, &tp, &searchkey, FALSE, NULL);
            if (!NT_SUCCESS(Status)) {
                ERR("find_item returned %08x\n", Status);
                goto end;
            }

            if (tp.item->key.obj_id == searchkey.obj_id && tp.item->key.obj_type == searchkey.obj_type) {
                ROOT_REF* rr = (ROOT_REF*)tp.item->data;
                path_part* pp;

                if (tp.item->size < sizeof(ROOT_REF)) {
                    ERR("(%llx,%x,%llx) was %u bytes, expected at least %u\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, tp.item->size, sizeof(ROOT_REF));
                    goto end;
                }

                if (tp.item->size < offsetof(ROOT_REF, name[0]) + rr->n) {
                    ERR("(%llx,%x,%llx) was %u bytes, expected at least %u\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset,
                        tp.item->size, offsetof(ROOT_REF, name[0]) + rr->n);
                    goto end;
                }

                pp = ExAllocatePoolWithTag(PagedPool, sizeof(path_part), ALLOC_TAG);
                if (!pp) {
                    ERR("out of memory\n");
                    goto end;
                }

                pp->name.Buffer = rr->name;
                pp->name.Length = pp->name.MaximumLength = rr->n;
                pp->orig_subvol = FALSE;

                InsertTailList(&parts, &pp->list_entry);

                r = NULL;

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
                    ERR("could not find subvol %llx\n", tp.item->key.offset);
                    goto end;
                }

                dir = rr->dir;
                orig_subvol = FALSE;
            } else {
                not_in_tree = TRUE;
                break;
            }
        } else {
            searchkey.obj_id = dir;
            searchkey.obj_type = TYPE_INODE_EXTREF;
            searchkey.offset = 0xffffffffffffffff;

            Status = find_item(Vcb, r, &tp, &searchkey, FALSE, NULL);
            if (!NT_SUCCESS(Status)) {
                ERR("find_item returned %08x\n", Status);
                goto end;
            }

            if (tp.item->key.obj_id == searchkey.obj_id && tp.item->key.obj_type == TYPE_INODE_REF) {
                INODE_REF* ir = (INODE_REF*)tp.item->data;
                path_part* pp;

                if (tp.item->size < sizeof(INODE_REF)) {
                    ERR("(%llx,%x,%llx) was %u bytes, expected at least %u\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, tp.item->size, sizeof(INODE_REF));
                    goto end;
                }

                if (tp.item->size < offsetof(INODE_REF, name[0]) + ir->n) {
                    ERR("(%llx,%x,%llx) was %u bytes, expected at least %u\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset,
                        tp.item->size, offsetof(INODE_REF, name[0]) + ir->n);
                    goto end;
                }

                pp = ExAllocatePoolWithTag(PagedPool, sizeof(path_part), ALLOC_TAG);
                if (!pp) {
                    ERR("out of memory\n");
                    goto end;
                }

                pp->name.Buffer = ir->name;
                pp->name.Length = pp->name.MaximumLength = ir->n;
                pp->orig_subvol = orig_subvol;

                InsertTailList(&parts, &pp->list_entry);

                if (dir == tp.item->key.offset)
                    break;

                dir = tp.item->key.offset;
            } else if (tp.item->key.obj_id == searchkey.obj_id && tp.item->key.obj_type == TYPE_INODE_EXTREF) {
                INODE_EXTREF* ier = (INODE_EXTREF*)tp.item->data;
                path_part* pp;

                if (tp.item->size < sizeof(INODE_EXTREF)) {
                    ERR("(%llx,%x,%llx) was %u bytes, expected at least %u\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset,
                                                                               tp.item->size, sizeof(INODE_EXTREF));
                    goto end;
                }

                if (tp.item->size < offsetof(INODE_EXTREF, name[0]) + ier->n) {
                    ERR("(%llx,%x,%llx) was %u bytes, expected at least %u\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset,
                        tp.item->size, offsetof(INODE_EXTREF, name[0]) + ier->n);
                    goto end;
                }

                pp = ExAllocatePoolWithTag(PagedPool, sizeof(path_part), ALLOC_TAG);
                if (!pp) {
                    ERR("out of memory\n");
                    goto end;
                }

                pp->name.Buffer = ier->name;
                pp->name.Length = pp->name.MaximumLength = ier->n;
                pp->orig_subvol = orig_subvol;

                InsertTailList(&parts, &pp->list_entry);

                if (dir == ier->dir)
                    break;

                dir = ier->dir;
            } else {
                ERR("could not find INODE_REF for inode %llx in subvol %llx\n", dir, r->id);
                goto end;
            }
        }
    }

    fn.MaximumLength = 0;

    if (not_in_tree) {
        le = parts.Blink;
        while (le != &parts) {
            path_part* pp = CONTAINING_RECORD(le, path_part, list_entry);
            LIST_ENTRY* le2 = le->Blink;

            if (pp->orig_subvol)
                break;

            RemoveTailList(&parts);
            ExFreePool(pp);

            le = le2;
        }
    }

    le = parts.Flink;
    while (le != &parts) {
        path_part* pp = CONTAINING_RECORD(le, path_part, list_entry);

        fn.MaximumLength += pp->name.Length + 1;

        le = le->Flink;
    }

    fn.Buffer = ExAllocatePoolWithTag(PagedPool, fn.MaximumLength, ALLOC_TAG);
    if (!fn.Buffer) {
        ERR("out of memory\n");
        goto end;
    }

    fn.Length = 0;

    le = parts.Blink;
    while (le != &parts) {
        path_part* pp = CONTAINING_RECORD(le, path_part, list_entry);

        fn.Buffer[fn.Length] = '\\';
        fn.Length++;

        RtlCopyMemory(&fn.Buffer[fn.Length], pp->name.Buffer, pp->name.Length);
        fn.Length += pp->name.Length;

        le = le->Blink;
    }

    if (not_in_tree)
        ERR("subvol %llx, %.*s, offset %llx\n", subvol, fn.Length, fn.Buffer, offset);
    else
        ERR("%.*s, offset %llx\n", fn.Length, fn.Buffer, offset);

    Status = RtlUTF8ToUnicodeN(NULL, 0, &utf16len, fn.Buffer, fn.Length);
    if (!NT_SUCCESS(Status)) {
        ERR("RtlUTF8ToUnicodeN 1 returned %08x\n", Status);
        ExFreePool(fn.Buffer);
        goto end;
    }

    err = ExAllocatePoolWithTag(PagedPool, offsetof(scrub_error, data.filename[0]) + utf16len, ALLOC_TAG);
    if (!err) {
        ERR("out of memory\n");
        ExFreePool(fn.Buffer);
        goto end;
    }

    err->address = addr;
    err->device = devid;
    err->recovered = FALSE;
    err->is_metadata = FALSE;
    err->parity = FALSE;

    err->data.subvol = not_in_tree ? subvol : 0;
    err->data.offset = offset;
    err->data.filename_length = (UINT16)utf16len;

    Status = RtlUTF8ToUnicodeN(err->data.filename, utf16len, &utf16len, fn.Buffer, fn.Length);
    if (!NT_SUCCESS(Status)) {
        ERR("RtlUTF8ToUnicodeN 2 returned %08x\n", Status);
        ExFreePool(fn.Buffer);
        ExFreePool(err);
        goto end;
    }

    ExAcquireResourceExclusiveLite(&Vcb->scrub.stats_lock, TRUE);

    Vcb->scrub.num_errors++;
    InsertTailList(&Vcb->scrub.errors, &err->list_entry);

    ExReleaseResourceLite(&Vcb->scrub.stats_lock);

    ExFreePool(fn.Buffer);

end:
    while (!IsListEmpty(&parts)) {
        path_part* pp = CONTAINING_RECORD(RemoveHeadList(&parts), path_part, list_entry);

        ExFreePool(pp);
    }
}

static void log_file_checksum_error_shared(device_extension* Vcb, UINT64 treeaddr, UINT64 addr, UINT64 devid, UINT64 extent) {
    tree_header* tree;
    NTSTATUS Status;
    leaf_node* ln;
    ULONG i;

    tree = ExAllocatePoolWithTag(PagedPool, Vcb->superblock.node_size, ALLOC_TAG);
    if (!tree) {
        ERR("out of memory\n");
        return;
    }

    Status = read_data(Vcb, treeaddr, Vcb->superblock.node_size, NULL, TRUE, (UINT8*)tree, NULL, NULL, NULL, 0, FALSE, NormalPagePriority);
    if (!NT_SUCCESS(Status)) {
        ERR("read_data returned %08x\n", Status);
        goto end;
    }

    if (tree->level != 0) {
        ERR("tree level was %x, expected 0\n", tree->level);
        goto end;
    }

    ln = (leaf_node*)&tree[1];

    for (i = 0; i < tree->num_items; i++) {
        if (ln[i].key.obj_type == TYPE_EXTENT_DATA && ln[i].size >= sizeof(EXTENT_DATA) - 1 + sizeof(EXTENT_DATA2)) {
            EXTENT_DATA* ed = (EXTENT_DATA*)((UINT8*)tree + sizeof(tree_header) + ln[i].offset);
            EXTENT_DATA2* ed2 = (EXTENT_DATA2*)ed->data;

            if (ed->type == EXTENT_TYPE_REGULAR && ed2->size != 0 && ed2->address == addr)
                log_file_checksum_error(Vcb, addr, devid, tree->tree_id, ln[i].key.obj_id, ln[i].key.offset + addr - extent);
        }
    }

end:
    ExFreePool(tree);
}

static void log_tree_checksum_error(device_extension* Vcb, UINT64 addr, UINT64 devid, UINT64 root, UINT8 level, KEY* firstitem) {
    scrub_error* err;

    err = ExAllocatePoolWithTag(PagedPool, sizeof(scrub_error), ALLOC_TAG);
    if (!err) {
        ERR("out of memory\n");
        return;
    }

    err->address = addr;
    err->device = devid;
    err->recovered = FALSE;
    err->is_metadata = TRUE;
    err->parity = FALSE;

    err->metadata.root = root;
    err->metadata.level = level;

    if (firstitem) {
        ERR("root %llx, level %u, first item (%llx,%x,%llx)\n", root, level, firstitem->obj_id,
                                                                firstitem->obj_type, firstitem->offset);

        err->metadata.firstitem = *firstitem;
    } else {
        ERR("root %llx, level %u\n", root, level);

        RtlZeroMemory(&err->metadata.firstitem, sizeof(KEY));
    }

    ExAcquireResourceExclusiveLite(&Vcb->scrub.stats_lock, TRUE);

    Vcb->scrub.num_errors++;
    InsertTailList(&Vcb->scrub.errors, &err->list_entry);

    ExReleaseResourceLite(&Vcb->scrub.stats_lock);
}

static void log_tree_checksum_error_shared(device_extension* Vcb, UINT64 offset, UINT64 address, UINT64 devid) {
    tree_header* tree;
    NTSTATUS Status;
    internal_node* in;
    ULONG i;

    tree = ExAllocatePoolWithTag(PagedPool, Vcb->superblock.node_size, ALLOC_TAG);
    if (!tree) {
        ERR("out of memory\n");
        return;
    }

    Status = read_data(Vcb, offset, Vcb->superblock.node_size, NULL, TRUE, (UINT8*)tree, NULL, NULL, NULL, 0, FALSE, NormalPagePriority);
    if (!NT_SUCCESS(Status)) {
        ERR("read_data returned %08x\n", Status);
        goto end;
    }

    if (tree->level == 0) {
        ERR("tree level was 0\n");
        goto end;
    }

    in = (internal_node*)&tree[1];

    for (i = 0; i < tree->num_items; i++) {
        if (in[i].address == address) {
            log_tree_checksum_error(Vcb, address, devid, tree->tree_id, tree->level - 1, &in[i].key);
            break;
        }
    }

end:
    ExFreePool(tree);
}

static void log_unrecoverable_error(device_extension* Vcb, UINT64 address, UINT64 devid) {
    KEY searchkey;
    traverse_ptr tp;
    NTSTATUS Status;
    EXTENT_ITEM* ei;
    EXTENT_ITEM2* ei2 = NULL;
    UINT8* ptr;
    ULONG len;
    UINT64 rc;

    // FIXME - still log even if rest of this function fails

    searchkey.obj_id = address;
    searchkey.obj_type = TYPE_METADATA_ITEM;
    searchkey.offset = 0xffffffffffffffff;

    Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, FALSE, NULL);
    if (!NT_SUCCESS(Status)) {
        ERR("find_item returned %08x\n", Status);
        return;
    }

    if ((tp.item->key.obj_type != TYPE_EXTENT_ITEM && tp.item->key.obj_type != TYPE_METADATA_ITEM) ||
        tp.item->key.obj_id >= address + Vcb->superblock.sector_size ||
        (tp.item->key.obj_type == TYPE_EXTENT_ITEM && tp.item->key.obj_id + tp.item->key.offset <= address) ||
        (tp.item->key.obj_type == TYPE_METADATA_ITEM && tp.item->key.obj_id + Vcb->superblock.node_size <= address)
    )
        return;

    if (tp.item->size < sizeof(EXTENT_ITEM)) {
        ERR("(%llx,%x,%llx) was %u bytes, expected at least %u\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, tp.item->size, sizeof(EXTENT_ITEM));
        return;
    }

    ei = (EXTENT_ITEM*)tp.item->data;
    ptr = (UINT8*)&ei[1];
    len = tp.item->size - sizeof(EXTENT_ITEM);

    if (tp.item->key.obj_id == TYPE_EXTENT_ITEM && ei->flags & EXTENT_ITEM_TREE_BLOCK) {
        if (tp.item->size < sizeof(EXTENT_ITEM) + sizeof(EXTENT_ITEM2)) {
            ERR("(%llx,%x,%llx) was %u bytes, expected at least %u\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset,
                                                                       tp.item->size, sizeof(EXTENT_ITEM) + sizeof(EXTENT_ITEM2));
            return;
        }

        ei2 = (EXTENT_ITEM2*)ptr;

        ptr += sizeof(EXTENT_ITEM2);
        len -= sizeof(EXTENT_ITEM2);
    }

    rc = 0;

    while (len > 0) {
        UINT8 type = *ptr;

        ptr++;
        len--;

        if (type == TYPE_TREE_BLOCK_REF) {
            TREE_BLOCK_REF* tbr;

            if (len < sizeof(TREE_BLOCK_REF)) {
                ERR("TREE_BLOCK_REF takes up %u bytes, but only %u remaining\n", sizeof(TREE_BLOCK_REF), len);
                break;
            }

            tbr = (TREE_BLOCK_REF*)ptr;

            log_tree_checksum_error(Vcb, address, devid, tbr->offset, ei2 ? ei2->level : (UINT8)tp.item->key.offset, ei2 ? &ei2->firstitem : NULL);

            rc++;

            ptr += sizeof(TREE_BLOCK_REF);
            len -= sizeof(TREE_BLOCK_REF);
        } else if (type == TYPE_EXTENT_DATA_REF) {
            EXTENT_DATA_REF* edr;

            if (len < sizeof(EXTENT_DATA_REF)) {
                ERR("EXTENT_DATA_REF takes up %u bytes, but only %u remaining\n", sizeof(EXTENT_DATA_REF), len);
                break;
            }

            edr = (EXTENT_DATA_REF*)ptr;

            log_file_checksum_error(Vcb, address, devid, edr->root, edr->objid, edr->offset + address - tp.item->key.obj_id);

            rc += edr->count;

            ptr += sizeof(EXTENT_DATA_REF);
            len -= sizeof(EXTENT_DATA_REF);
        } else if (type == TYPE_SHARED_BLOCK_REF) {
            SHARED_BLOCK_REF* sbr;

            if (len < sizeof(SHARED_BLOCK_REF)) {
                ERR("SHARED_BLOCK_REF takes up %u bytes, but only %u remaining\n", sizeof(SHARED_BLOCK_REF), len);
                break;
            }

            sbr = (SHARED_BLOCK_REF*)ptr;

            log_tree_checksum_error_shared(Vcb, sbr->offset, address, devid);

            rc++;

            ptr += sizeof(SHARED_BLOCK_REF);
            len -= sizeof(SHARED_BLOCK_REF);
        } else if (type == TYPE_SHARED_DATA_REF) {
            SHARED_DATA_REF* sdr;

            if (len < sizeof(SHARED_DATA_REF)) {
                ERR("SHARED_DATA_REF takes up %u bytes, but only %u remaining\n", sizeof(SHARED_DATA_REF), len);
                break;
            }

            sdr = (SHARED_DATA_REF*)ptr;

            log_file_checksum_error_shared(Vcb, sdr->offset, address, devid, tp.item->key.obj_id);

            rc += sdr->count;

            ptr += sizeof(SHARED_DATA_REF);
            len -= sizeof(SHARED_DATA_REF);
        } else {
            ERR("unknown extent type %x\n", type);
            break;
        }
    }

    if (rc < ei->refcount) {
        do {
            traverse_ptr next_tp;

            if (find_next_item(Vcb, &tp, &next_tp, FALSE, NULL))
                tp = next_tp;
            else
                break;

            if (tp.item->key.obj_id == address) {
                if (tp.item->key.obj_type == TYPE_TREE_BLOCK_REF)
                    log_tree_checksum_error(Vcb, address, devid, tp.item->key.offset, ei2 ? ei2->level : (UINT8)tp.item->key.offset, ei2 ? &ei2->firstitem : NULL);
                else if (tp.item->key.obj_type == TYPE_EXTENT_DATA_REF) {
                    EXTENT_DATA_REF* edr;

                    if (tp.item->size < sizeof(EXTENT_DATA_REF)) {
                        ERR("(%llx,%x,%llx) was %u bytes, expected %u\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset,
                                                                          tp.item->size, sizeof(EXTENT_DATA_REF));
                        break;
                    }

                    edr = (EXTENT_DATA_REF*)tp.item->data;

                    log_file_checksum_error(Vcb, address, devid, edr->root, edr->objid, edr->offset + address - tp.item->key.obj_id);
                } else if (tp.item->key.obj_type == TYPE_SHARED_BLOCK_REF)
                    log_tree_checksum_error_shared(Vcb, tp.item->key.offset, address, devid);
                else if (tp.item->key.obj_type == TYPE_SHARED_DATA_REF)
                    log_file_checksum_error_shared(Vcb, tp.item->key.offset, address, devid, tp.item->key.obj_id);
            } else
                break;
        } while (TRUE);
    }
}

static void log_error(device_extension* Vcb, UINT64 addr, UINT64 devid, BOOL metadata, BOOL recoverable, BOOL parity) {
    if (recoverable) {
        scrub_error* err;

        if (parity) {
            ERR("recovering from parity error at %llx on device %llx\n", addr, devid);
        } else {
            if (metadata)
                ERR("recovering from metadata checksum error at %llx on device %llx\n", addr, devid);
            else
                ERR("recovering from data checksum error at %llx on device %llx\n", addr, devid);
        }

        err = ExAllocatePoolWithTag(PagedPool, sizeof(scrub_error), ALLOC_TAG);
        if (!err) {
            ERR("out of memory\n");
            return;
        }

        err->address = addr;
        err->device = devid;
        err->recovered = TRUE;
        err->is_metadata = metadata;
        err->parity = parity;

        if (metadata)
            RtlZeroMemory(&err->metadata, sizeof(err->metadata));
        else
            RtlZeroMemory(&err->data, sizeof(err->data));

        ExAcquireResourceExclusiveLite(&Vcb->scrub.stats_lock, TRUE);

        Vcb->scrub.num_errors++;
        InsertTailList(&Vcb->scrub.errors, &err->list_entry);

        ExReleaseResourceLite(&Vcb->scrub.stats_lock);
    } else {
        if (metadata)
            ERR("unrecoverable metadata checksum error at %llx\n", addr);
        else
            ERR("unrecoverable data checksum error at %llx\n", addr);

        log_unrecoverable_error(Vcb, addr, devid);
    }
}

_Function_class_(IO_COMPLETION_ROUTINE)
static NTSTATUS scrub_read_completion(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID conptr) {
    scrub_context_stripe* stripe = conptr;
    scrub_context* context = (scrub_context*)stripe->context;
    ULONG left = InterlockedDecrement(&context->stripes_left);

    UNUSED(DeviceObject);

    stripe->iosb = Irp->IoStatus;

    if (left == 0)
        KeSetEvent(&context->Event, 0, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS scrub_extent_dup(device_extension* Vcb, chunk* c, UINT64 offset, UINT32* csum, scrub_context* context) {
    NTSTATUS Status;
    BOOL csum_error = FALSE;
    ULONG i;
    CHUNK_ITEM_STRIPE* cis = (CHUNK_ITEM_STRIPE*)&c->chunk_item[1];
    UINT16 present_devices = 0;

    if (csum) {
        ULONG good_stripe = 0xffffffff;

        for (i = 0; i < c->chunk_item->num_stripes; i++) {
            if (c->devices[i]->devobj) {
                present_devices++;

                // if first stripe is okay, we only need to check that the others are identical to it
                if (good_stripe != 0xffffffff) {
                    if (RtlCompareMemory(context->stripes[i].buf, context->stripes[good_stripe].buf,
                                        context->stripes[good_stripe].length) != context->stripes[i].length) {
                        context->stripes[i].csum_error = TRUE;
                        csum_error = TRUE;
                        log_device_error(Vcb, c->devices[i], BTRFS_DEV_STAT_CORRUPTION_ERRORS);
                    }
                } else {
                    Status = check_csum(Vcb, context->stripes[i].buf, context->stripes[i].length / Vcb->superblock.sector_size, csum);
                    if (Status == STATUS_CRC_ERROR) {
                        context->stripes[i].csum_error = TRUE;
                        csum_error = TRUE;
                        log_device_error(Vcb, c->devices[i], BTRFS_DEV_STAT_CORRUPTION_ERRORS);
                    } else if (!NT_SUCCESS(Status)) {
                        ERR("check_csum returned %08x\n", Status);
                        return Status;
                    } else
                        good_stripe = i;
                }
            }
        }
    } else {
        ULONG good_stripe = 0xffffffff;

        for (i = 0; i < c->chunk_item->num_stripes; i++) {
            ULONG j;

            if (c->devices[i]->devobj) {
                // if first stripe is okay, we only need to check that the others are identical to it
                if (good_stripe != 0xffffffff) {
                    if (RtlCompareMemory(context->stripes[i].buf, context->stripes[good_stripe].buf,
                                         context->stripes[good_stripe].length) != context->stripes[i].length) {
                        context->stripes[i].csum_error = TRUE;
                        csum_error = TRUE;
                        log_device_error(Vcb, c->devices[i], BTRFS_DEV_STAT_CORRUPTION_ERRORS);
                    }
                } else {
                    for (j = 0; j < context->stripes[i].length / Vcb->superblock.node_size; j++) {
                        tree_header* th = (tree_header*)&context->stripes[i].buf[j * Vcb->superblock.node_size];
                        UINT32 crc32 = ~calc_crc32c(0xffffffff, (UINT8*)&th->fs_uuid, Vcb->superblock.node_size - sizeof(th->csum));

                        if (crc32 != *((UINT32*)th->csum) || th->address != offset + UInt32x32To64(j, Vcb->superblock.node_size)) {
                            context->stripes[i].csum_error = TRUE;
                            csum_error = TRUE;
                            log_device_error(Vcb, c->devices[i], BTRFS_DEV_STAT_CORRUPTION_ERRORS);
                        }
                    }

                    if (!context->stripes[i].csum_error)
                        good_stripe = i;
                }
            }
        }
    }

    if (!csum_error)
        return STATUS_SUCCESS;

    // handle checksum error

    for (i = 0; i < c->chunk_item->num_stripes; i++) {
        if (context->stripes[i].csum_error) {
            if (csum) {
                context->stripes[i].bad_csums = ExAllocatePoolWithTag(PagedPool, context->stripes[i].length * sizeof(UINT32) / Vcb->superblock.sector_size, ALLOC_TAG);
                if (!context->stripes[i].bad_csums) {
                    ERR("out of memory\n");
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                Status = calc_csum(Vcb, context->stripes[i].buf, context->stripes[i].length / Vcb->superblock.sector_size, context->stripes[i].bad_csums);
                if (!NT_SUCCESS(Status)) {
                    ERR("calc_csum returned %08x\n", Status);
                    return Status;
                }
            } else {
                ULONG j;

                context->stripes[i].bad_csums = ExAllocatePoolWithTag(PagedPool, context->stripes[i].length * sizeof(UINT32) / Vcb->superblock.node_size, ALLOC_TAG);
                if (!context->stripes[i].bad_csums) {
                    ERR("out of memory\n");
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                for (j = 0; j < context->stripes[i].length / Vcb->superblock.node_size; j++) {
                    tree_header* th = (tree_header*)&context->stripes[i].buf[j * Vcb->superblock.node_size];
                    UINT32 crc32 = ~calc_crc32c(0xffffffff, (UINT8*)&th->fs_uuid, Vcb->superblock.node_size - sizeof(th->csum));

                    context->stripes[i].bad_csums[j] = crc32;
                }
            }
        }
    }

    if (present_devices > 1) {
        ULONG good_stripe = 0xffffffff;

        for (i = 0; i < c->chunk_item->num_stripes; i++) {
            if (c->devices[i]->devobj && !context->stripes[i].csum_error) {
                good_stripe = i;
                break;
            }
        }

        if (good_stripe != 0xffffffff) {
            // log

            for (i = 0; i < c->chunk_item->num_stripes; i++) {
                if (context->stripes[i].csum_error) {
                    ULONG j;

                    if (csum) {
                        for (j = 0; j < context->stripes[i].length / Vcb->superblock.sector_size; j++) {
                            if (context->stripes[i].bad_csums[j] != csum[j]) {
                                UINT64 addr = offset + UInt32x32To64(j, Vcb->superblock.sector_size);

                                log_error(Vcb, addr, c->devices[i]->devitem.dev_id, FALSE, TRUE, FALSE);
                                log_device_error(Vcb, c->devices[i], BTRFS_DEV_STAT_CORRUPTION_ERRORS);
                            }
                        }
                    } else {
                        for (j = 0; j < context->stripes[i].length / Vcb->superblock.node_size; j++) {
                            tree_header* th = (tree_header*)&context->stripes[i].buf[j * Vcb->superblock.node_size];
                            UINT64 addr = offset + UInt32x32To64(j, Vcb->superblock.node_size);

                            if (context->stripes[i].bad_csums[j] != *((UINT32*)th->csum) || th->address != addr) {
                                log_error(Vcb, addr, c->devices[i]->devitem.dev_id, TRUE, TRUE, FALSE);
                                log_device_error(Vcb, c->devices[i], BTRFS_DEV_STAT_CORRUPTION_ERRORS);
                            }
                        }
                    }
                }
            }

            // write good data over bad

            for (i = 0; i < c->chunk_item->num_stripes; i++) {
                if (context->stripes[i].csum_error && !c->devices[i]->readonly) {
                    Status = write_data_phys(c->devices[i]->devobj, cis[i].offset + offset - c->offset,
                                             context->stripes[good_stripe].buf, context->stripes[i].length);

                    if (!NT_SUCCESS(Status)) {
                        ERR("write_data_phys returned %08x\n", Status);
                        log_device_error(Vcb, c->devices[i], BTRFS_DEV_STAT_WRITE_ERRORS);
                        return Status;
                    }
                }
            }

            return STATUS_SUCCESS;
        }

        // if csum errors on all stripes, check sector by sector

        for (i = 0; i < c->chunk_item->num_stripes; i++) {
            ULONG j;

            if (c->devices[i]->devobj) {
                if (csum) {
                    for (j = 0; j < context->stripes[i].length / Vcb->superblock.sector_size; j++) {
                        if (context->stripes[i].bad_csums[j] != csum[j]) {
                            ULONG k;
                            UINT64 addr = offset + UInt32x32To64(j, Vcb->superblock.sector_size);
                            BOOL recovered = FALSE;

                            for (k = 0; k < c->chunk_item->num_stripes; k++) {
                                if (i != k && c->devices[k]->devobj && context->stripes[k].bad_csums[j] == csum[j]) {
                                    log_error(Vcb, addr, c->devices[i]->devitem.dev_id, FALSE, TRUE, FALSE);
                                    log_device_error(Vcb, c->devices[i], BTRFS_DEV_STAT_CORRUPTION_ERRORS);

                                    RtlCopyMemory(context->stripes[i].buf + (j * Vcb->superblock.sector_size),
                                                  context->stripes[k].buf + (j * Vcb->superblock.sector_size), Vcb->superblock.sector_size);

                                    recovered = TRUE;
                                    break;
                                }
                            }

                            if (!recovered) {
                                log_error(Vcb, addr, c->devices[i]->devitem.dev_id, FALSE, FALSE, FALSE);
                                log_device_error(Vcb, c->devices[i], BTRFS_DEV_STAT_CORRUPTION_ERRORS);
                            }
                        }
                    }
                } else {
                    for (j = 0; j < context->stripes[i].length / Vcb->superblock.node_size; j++) {
                        tree_header* th = (tree_header*)&context->stripes[i].buf[j * Vcb->superblock.node_size];
                        UINT64 addr = offset + UInt32x32To64(j, Vcb->superblock.node_size);

                        if (context->stripes[i].bad_csums[j] != *((UINT32*)th->csum) || th->address != addr) {
                            ULONG k;
                            BOOL recovered = FALSE;

                            for (k = 0; k < c->chunk_item->num_stripes; k++) {
                                if (i != k && c->devices[k]->devobj) {
                                    tree_header* th2 = (tree_header*)&context->stripes[k].buf[j * Vcb->superblock.node_size];

                                    if (context->stripes[k].bad_csums[j] == *((UINT32*)th2->csum) && th2->address == addr) {
                                        log_error(Vcb, addr, c->devices[i]->devitem.dev_id, TRUE, TRUE, FALSE);
                                        log_device_error(Vcb, c->devices[i], BTRFS_DEV_STAT_CORRUPTION_ERRORS);

                                        RtlCopyMemory(th, th2, Vcb->superblock.node_size);

                                        recovered = TRUE;
                                        break;
                                    }
                                }
                            }

                            if (!recovered) {
                                log_error(Vcb, addr, c->devices[i]->devitem.dev_id, TRUE, FALSE, FALSE);
                                log_device_error(Vcb, c->devices[i], BTRFS_DEV_STAT_CORRUPTION_ERRORS);
                            }
                        }
                    }
                }
            }
        }

        // write good data over bad

        for (i = 0; i < c->chunk_item->num_stripes; i++) {
            if (c->devices[i]->devobj && !c->devices[i]->readonly) {
                Status = write_data_phys(c->devices[i]->devobj, cis[i].offset + offset - c->offset,
                                         context->stripes[i].buf, context->stripes[i].length);
                if (!NT_SUCCESS(Status)) {
                    ERR("write_data_phys returned %08x\n", Status);
                    log_device_error(Vcb, c->devices[i], BTRFS_DEV_STAT_CORRUPTION_ERRORS);
                    return Status;
                }
            }
        }

        return STATUS_SUCCESS;
    }

    for (i = 0; i < c->chunk_item->num_stripes; i++) {
        if (c->devices[i]->devobj) {
            ULONG j;

            if (csum) {
                for (j = 0; j < context->stripes[i].length / Vcb->superblock.sector_size; j++) {
                    if (context->stripes[i].bad_csums[j] != csum[j]) {
                        UINT64 addr = offset + UInt32x32To64(j, Vcb->superblock.sector_size);

                        log_error(Vcb, addr, c->devices[i]->devitem.dev_id, FALSE, FALSE, FALSE);
                    }
                }
            } else {
                for (j = 0; j < context->stripes[i].length / Vcb->superblock.node_size; j++) {
                    tree_header* th = (tree_header*)&context->stripes[i].buf[j * Vcb->superblock.node_size];
                    UINT64 addr = offset + UInt32x32To64(j, Vcb->superblock.node_size);

                    if (context->stripes[i].bad_csums[j] != *((UINT32*)th->csum) || th->address != addr)
                        log_error(Vcb, addr, c->devices[i]->devitem.dev_id, TRUE, FALSE, FALSE);
                }
            }
        }
    }

    return STATUS_SUCCESS;
}

static NTSTATUS scrub_extent_raid0(device_extension* Vcb, chunk* c, UINT64 offset, UINT32 length, UINT16 startoffstripe, UINT32* csum, scrub_context* context) {
    ULONG j;
    UINT16 stripe;
    UINT32 pos, *stripeoff;

    pos = 0;
    stripeoff = ExAllocatePoolWithTag(NonPagedPool, sizeof(UINT32) * c->chunk_item->num_stripes, ALLOC_TAG);
    if (!stripeoff) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(stripeoff, sizeof(UINT32) * c->chunk_item->num_stripes);

    stripe = startoffstripe;
    while (pos < length) {
        UINT32 readlen;

        if (pos == 0)
            readlen = (UINT32)min(context->stripes[stripe].length, c->chunk_item->stripe_length - (context->stripes[stripe].start % c->chunk_item->stripe_length));
        else
            readlen = min(length - pos, (UINT32)c->chunk_item->stripe_length);

        if (csum) {
            for (j = 0; j < readlen; j += Vcb->superblock.sector_size) {
                UINT32 crc32 = ~calc_crc32c(0xffffffff, context->stripes[stripe].buf + stripeoff[stripe], Vcb->superblock.sector_size);

                if (crc32 != csum[pos / Vcb->superblock.sector_size]) {
                    UINT64 addr = offset + pos;

                    log_error(Vcb, addr, c->devices[stripe]->devitem.dev_id, FALSE, FALSE, FALSE);
                    log_device_error(Vcb, c->devices[stripe], BTRFS_DEV_STAT_CORRUPTION_ERRORS);
                }

                pos += Vcb->superblock.sector_size;
                stripeoff[stripe] += Vcb->superblock.sector_size;
            }
        } else {
            for (j = 0; j < readlen; j += Vcb->superblock.node_size) {
                tree_header* th = (tree_header*)(context->stripes[stripe].buf + stripeoff[stripe]);
                UINT32 crc32 = ~calc_crc32c(0xffffffff, (UINT8*)&th->fs_uuid, Vcb->superblock.node_size - sizeof(th->csum));
                UINT64 addr = offset + pos;

                if (crc32 != *((UINT32*)th->csum) || th->address != addr) {
                    log_error(Vcb, addr, c->devices[stripe]->devitem.dev_id, TRUE, FALSE, FALSE);
                    log_device_error(Vcb, c->devices[stripe], BTRFS_DEV_STAT_CORRUPTION_ERRORS);
                }

                pos += Vcb->superblock.node_size;
                stripeoff[stripe] += Vcb->superblock.node_size;
            }
        }

        stripe = (stripe + 1) % c->chunk_item->num_stripes;
    }

    ExFreePool(stripeoff);

    return STATUS_SUCCESS;
}

static NTSTATUS scrub_extent_raid10(device_extension* Vcb, chunk* c, UINT64 offset, UINT32 length, UINT16 startoffstripe, UINT32* csum, scrub_context* context) {
    ULONG j;
    UINT16 stripe, sub_stripes = max(c->chunk_item->sub_stripes, 1);
    UINT32 pos, *stripeoff;
    BOOL csum_error = FALSE;
    NTSTATUS Status;

    pos = 0;
    stripeoff = ExAllocatePoolWithTag(NonPagedPool, sizeof(UINT32) * c->chunk_item->num_stripes / sub_stripes, ALLOC_TAG);
    if (!stripeoff) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(stripeoff, sizeof(UINT32) * c->chunk_item->num_stripes / sub_stripes);

    stripe = startoffstripe;
    while (pos < length) {
        UINT32 readlen;

        if (pos == 0)
            readlen = (UINT32)min(context->stripes[stripe * sub_stripes].length,
                                  c->chunk_item->stripe_length - (context->stripes[stripe * sub_stripes].start % c->chunk_item->stripe_length));
        else
            readlen = min(length - pos, (UINT32)c->chunk_item->stripe_length);

        if (csum) {
            ULONG good_stripe = 0xffffffff;
            UINT16 k;

            for (k = 0; k < sub_stripes; k++) {
                if (c->devices[(stripe * sub_stripes) + k]->devobj) {
                    // if first stripe is okay, we only need to check that the others are identical to it
                    if (good_stripe != 0xffffffff) {
                        if (RtlCompareMemory(context->stripes[(stripe * sub_stripes) + k].buf + stripeoff[stripe],
                                            context->stripes[(stripe * sub_stripes) + good_stripe].buf + stripeoff[stripe],
                                            readlen) != readlen) {
                            context->stripes[(stripe * sub_stripes) + k].csum_error = TRUE;
                            csum_error = TRUE;
                            log_device_error(Vcb, c->devices[(stripe * sub_stripes) + k], BTRFS_DEV_STAT_CORRUPTION_ERRORS);
                        }
                    } else {
                        for (j = 0; j < readlen; j += Vcb->superblock.sector_size) {
                            UINT32 crc32 = ~calc_crc32c(0xffffffff, context->stripes[(stripe * sub_stripes) + k].buf + stripeoff[stripe] + j, Vcb->superblock.sector_size);

                            if (crc32 != csum[(pos + j) / Vcb->superblock.sector_size]) {
                                csum_error = TRUE;
                                context->stripes[(stripe * sub_stripes) + k].csum_error = TRUE;
                                log_device_error(Vcb, c->devices[(stripe * sub_stripes) + k], BTRFS_DEV_STAT_CORRUPTION_ERRORS);
                                break;
                            }
                        }

                        if (!context->stripes[(stripe * sub_stripes) + k].csum_error)
                            good_stripe = k;
                    }
                }
            }

            pos += readlen;
            stripeoff[stripe] += readlen;
        } else {
            ULONG good_stripe = 0xffffffff;
            UINT16 k;

            for (k = 0; k < sub_stripes; k++) {
                if (c->devices[(stripe * sub_stripes) + k]->devobj) {
                    // if first stripe is okay, we only need to check that the others are identical to it
                    if (good_stripe != 0xffffffff) {
                        if (RtlCompareMemory(context->stripes[(stripe * sub_stripes) + k].buf + stripeoff[stripe],
                                            context->stripes[(stripe * sub_stripes) + good_stripe].buf + stripeoff[stripe],
                                            readlen) != readlen) {
                            context->stripes[(stripe * sub_stripes) + k].csum_error = TRUE;
                            csum_error = TRUE;
                            log_device_error(Vcb, c->devices[(stripe * sub_stripes) + k], BTRFS_DEV_STAT_CORRUPTION_ERRORS);
                        }
                    } else {
                        for (j = 0; j < readlen; j += Vcb->superblock.node_size) {
                            tree_header* th = (tree_header*)(context->stripes[(stripe * sub_stripes) + k].buf + stripeoff[stripe] + j);
                            UINT32 crc32 = ~calc_crc32c(0xffffffff, (UINT8*)&th->fs_uuid, Vcb->superblock.node_size - sizeof(th->csum));
                            UINT64 addr = offset + pos + j;

                            if (crc32 != *((UINT32*)th->csum) || th->address != addr) {
                                csum_error = TRUE;
                                context->stripes[(stripe * sub_stripes) + k].csum_error = TRUE;
                                log_device_error(Vcb, c->devices[(stripe * sub_stripes) + k], BTRFS_DEV_STAT_CORRUPTION_ERRORS);
                                break;
                            }
                        }

                        if (!context->stripes[(stripe * sub_stripes) + k].csum_error)
                            good_stripe = k;
                    }
                }
            }

            pos += readlen;
            stripeoff[stripe] += readlen;
        }

        stripe = (stripe + 1) % (c->chunk_item->num_stripes / sub_stripes);
    }

    if (!csum_error) {
        Status = STATUS_SUCCESS;
        goto end;
    }

    for (j = 0; j < c->chunk_item->num_stripes; j += sub_stripes) {
        ULONG goodstripe = 0xffffffff;
        UINT16 k;
        BOOL hasbadstripe = FALSE;

        if (context->stripes[j].length == 0)
            continue;

        for (k = 0; k < sub_stripes; k++) {
            if (c->devices[j + k]->devobj) {
                if (!context->stripes[j + k].csum_error)
                    goodstripe = k;
                else
                    hasbadstripe = TRUE;
            }
        }

        if (hasbadstripe) {
            if (goodstripe != 0xffffffff) {
                for (k = 0; k < sub_stripes; k++) {
                    if (c->devices[j + k]->devobj && context->stripes[j + k].csum_error) {
                        UINT32 so = 0;
                        BOOL recovered = FALSE;

                        pos = 0;

                        stripe = startoffstripe;
                        while (pos < length) {
                            UINT32 readlen;

                            if (pos == 0)
                                readlen = (UINT32)min(context->stripes[stripe * sub_stripes].length,
                                              c->chunk_item->stripe_length - (context->stripes[stripe * sub_stripes].start % c->chunk_item->stripe_length));
                            else
                                readlen = min(length - pos, (UINT32)c->chunk_item->stripe_length);

                            if (stripe == j / sub_stripes) {
                                if (csum) {
                                    ULONG l;

                                    for (l = 0; l < readlen; l += Vcb->superblock.sector_size) {
                                        if (RtlCompareMemory(context->stripes[j + k].buf + so,
                                                             context->stripes[j + goodstripe].buf + so,
                                                             Vcb->superblock.sector_size) != Vcb->superblock.sector_size) {
                                            UINT64 addr = offset + pos;

                                            log_error(Vcb, addr, c->devices[j + k]->devitem.dev_id, FALSE, TRUE, FALSE);

                                            recovered = TRUE;
                                        }

                                        pos += Vcb->superblock.sector_size;
                                        so += Vcb->superblock.sector_size;
                                    }
                                } else {
                                    ULONG l;

                                    for (l = 0; l < readlen; l += Vcb->superblock.node_size) {
                                        if (RtlCompareMemory(context->stripes[j + k].buf + so,
                                                            context->stripes[j + goodstripe].buf + so,
                                                            Vcb->superblock.node_size) != Vcb->superblock.node_size) {
                                            UINT64 addr = offset + pos;

                                            log_error(Vcb, addr, c->devices[j + k]->devitem.dev_id, TRUE, TRUE, FALSE);

                                            recovered = TRUE;
                                        }

                                        pos += Vcb->superblock.node_size;
                                        so += Vcb->superblock.node_size;
                                    }
                                }
                            } else
                                pos += readlen;

                            stripe = (stripe + 1) % (c->chunk_item->num_stripes / sub_stripes);
                        }

                        if (recovered) {
                            // write good data over bad

                            if (!c->devices[j + k]->readonly) {
                                CHUNK_ITEM_STRIPE* cis = (CHUNK_ITEM_STRIPE*)&c->chunk_item[1];

                                Status = write_data_phys(c->devices[j + k]->devobj, cis[j + k].offset + offset - c->offset,
                                                         context->stripes[j + goodstripe].buf, context->stripes[j + goodstripe].length);

                                if (!NT_SUCCESS(Status)) {
                                    ERR("write_data_phys returned %08x\n", Status);
                                    log_device_error(Vcb, c->devices[j + k], BTRFS_DEV_STAT_WRITE_ERRORS);
                                    goto end;
                                }
                            }
                        }
                    }
                }
            } else {
                UINT32 so = 0;
                BOOL recovered = FALSE;

                if (csum) {
                    for (k = 0; k < sub_stripes; k++) {
                        if (c->devices[j + k]->devobj) {
                            context->stripes[j + k].bad_csums = ExAllocatePoolWithTag(PagedPool, context->stripes[j + k].length * sizeof(UINT32) / Vcb->superblock.sector_size, ALLOC_TAG);
                            if (!context->stripes[j + k].bad_csums) {
                                ERR("out of memory\n");
                                Status = STATUS_INSUFFICIENT_RESOURCES;
                                goto end;
                            }

                            Status = calc_csum(Vcb, context->stripes[j + k].buf, context->stripes[j + k].length / Vcb->superblock.sector_size, context->stripes[j + k].bad_csums);
                            if (!NT_SUCCESS(Status)) {
                                ERR("calc_csum returned %08x\n", Status);
                                goto end;
                            }
                        }
                    }
                } else {
                    for (k = 0; k < sub_stripes; k++) {
                        if (c->devices[j + k]->devobj) {
                            ULONG l;

                            context->stripes[j + k].bad_csums = ExAllocatePoolWithTag(PagedPool, context->stripes[j + k].length * sizeof(UINT32) / Vcb->superblock.node_size, ALLOC_TAG);
                            if (!context->stripes[j + k].bad_csums) {
                                ERR("out of memory\n");
                                Status = STATUS_INSUFFICIENT_RESOURCES;
                                goto end;
                            }

                            for (l = 0; l < context->stripes[j + k].length / Vcb->superblock.node_size; l++) {
                                tree_header* th = (tree_header*)&context->stripes[j + k].buf[l * Vcb->superblock.node_size];
                                UINT32 crc32 = ~calc_crc32c(0xffffffff, (UINT8*)&th->fs_uuid, Vcb->superblock.node_size - sizeof(th->csum));

                                context->stripes[j + k].bad_csums[l] = crc32;
                            }
                        }
                    }
                }

                pos = 0;

                stripe = startoffstripe;
                while (pos < length) {
                    UINT32 readlen;

                    if (pos == 0)
                        readlen = (UINT32)min(context->stripes[stripe * sub_stripes].length,
                                      c->chunk_item->stripe_length - (context->stripes[stripe * sub_stripes].start % c->chunk_item->stripe_length));
                    else
                        readlen = min(length - pos, (UINT32)c->chunk_item->stripe_length);

                    if (stripe == j / sub_stripes) {
                        ULONG l;

                        if (csum) {
                            for (l = 0; l < readlen; l += Vcb->superblock.sector_size) {
                                UINT32 crc32 = csum[pos / Vcb->superblock.sector_size];
                                BOOL has_error = FALSE;

                                goodstripe = 0xffffffff;
                                for (k = 0; k < sub_stripes; k++) {
                                    if (c->devices[j + k]->devobj) {
                                        if (context->stripes[j + k].bad_csums[so / Vcb->superblock.sector_size] != crc32)
                                            has_error = TRUE;
                                        else
                                            goodstripe = k;
                                    }
                                }

                                if (has_error) {
                                    if (goodstripe != 0xffffffff) {
                                        for (k = 0; k < sub_stripes; k++) {
                                            if (c->devices[j + k]->devobj && context->stripes[j + k].bad_csums[so / Vcb->superblock.sector_size] != crc32) {
                                                UINT64 addr = offset + pos;

                                                log_error(Vcb, addr, c->devices[j + k]->devitem.dev_id, FALSE, TRUE, FALSE);

                                                recovered = TRUE;

                                                RtlCopyMemory(context->stripes[j + k].buf + so, context->stripes[j + goodstripe].buf + so,
                                                              Vcb->superblock.sector_size);
                                            }
                                        }
                                    } else {
                                        UINT64 addr = offset + pos;

                                        for (k = 0; k < sub_stripes; k++) {
                                            if (c->devices[j + j]->devobj) {
                                                log_error(Vcb, addr, c->devices[j + k]->devitem.dev_id, FALSE, FALSE, FALSE);
                                                log_device_error(Vcb, c->devices[j + k], BTRFS_DEV_STAT_CORRUPTION_ERRORS);
                                            }
                                        }
                                    }
                                }

                                pos += Vcb->superblock.sector_size;
                                so += Vcb->superblock.sector_size;
                            }
                        } else {
                            for (l = 0; l < readlen; l += Vcb->superblock.node_size) {
                                for (k = 0; k < sub_stripes; k++) {
                                    if (c->devices[j + k]->devobj) {
                                        tree_header* th = (tree_header*)&context->stripes[j + k].buf[so];
                                        UINT64 addr = offset + pos;

                                        if (context->stripes[j + k].bad_csums[so / Vcb->superblock.node_size] != *((UINT32*)th->csum) || th->address != addr) {
                                            ULONG m;

                                            recovered = FALSE;

                                            for (m = 0; m < sub_stripes; m++) {
                                                if (m != k) {
                                                    tree_header* th2 = (tree_header*)&context->stripes[j + m].buf[so];

                                                    if (context->stripes[j + m].bad_csums[so / Vcb->superblock.node_size] == *((UINT32*)th2->csum) && th2->address == addr) {
                                                        log_error(Vcb, addr, c->devices[j + k]->devitem.dev_id, TRUE, TRUE, FALSE);

                                                        RtlCopyMemory(th, th2, Vcb->superblock.node_size);

                                                        recovered = TRUE;
                                                        break;
                                                    } else
                                                        log_device_error(Vcb, c->devices[j + m], BTRFS_DEV_STAT_CORRUPTION_ERRORS);
                                                }
                                            }

                                            if (!recovered)
                                                log_error(Vcb, addr, c->devices[j + k]->devitem.dev_id, TRUE, FALSE, FALSE);
                                        }
                                    }
                                }

                                pos += Vcb->superblock.node_size;
                                so += Vcb->superblock.node_size;
                            }
                        }
                    } else
                        pos += readlen;

                    stripe = (stripe + 1) % (c->chunk_item->num_stripes / sub_stripes);
                }

                if (recovered) {
                    // write good data over bad

                    for (k = 0; k < sub_stripes; k++) {
                        if (c->devices[j + k]->devobj && !c->devices[j + k]->readonly) {
                            CHUNK_ITEM_STRIPE* cis = (CHUNK_ITEM_STRIPE*)&c->chunk_item[1];

                            Status = write_data_phys(c->devices[j + k]->devobj, cis[j + k].offset + offset - c->offset,
                                                     context->stripes[j + k].buf, context->stripes[j + k].length);

                            if (!NT_SUCCESS(Status)) {
                                ERR("write_data_phys returned %08x\n", Status);
                                log_device_error(Vcb, c->devices[j + k], BTRFS_DEV_STAT_WRITE_ERRORS);
                                goto end;
                            }
                        }
                    }
                }
            }
        }
    }

    Status = STATUS_SUCCESS;

end:
    ExFreePool(stripeoff);

    return Status;
}

static NTSTATUS scrub_extent(device_extension* Vcb, chunk* c, ULONG type, UINT64 offset, UINT32 size, UINT32* csum) {
    ULONG i;
    scrub_context context;
    CHUNK_ITEM_STRIPE* cis;
    NTSTATUS Status;
    UINT16 startoffstripe, num_missing, allowed_missing;

    TRACE("(%p, %p, %llx, %llx, %p)\n", Vcb, c, offset, size, csum);

    context.stripes = ExAllocatePoolWithTag(NonPagedPool, sizeof(scrub_context_stripe) * c->chunk_item->num_stripes, ALLOC_TAG);
    if (!context.stripes) {
        ERR("out of memory\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }

    RtlZeroMemory(context.stripes, sizeof(scrub_context_stripe) * c->chunk_item->num_stripes);

    context.stripes_left = 0;

    cis = (CHUNK_ITEM_STRIPE*)&c->chunk_item[1];

    if (type == BLOCK_FLAG_RAID0) {
        UINT64 startoff, endoff;
        UINT16 endoffstripe;

        get_raid0_offset(offset - c->offset, c->chunk_item->stripe_length, c->chunk_item->num_stripes, &startoff, &startoffstripe);
        get_raid0_offset(offset + size - c->offset - 1, c->chunk_item->stripe_length, c->chunk_item->num_stripes, &endoff, &endoffstripe);

        for (i = 0; i < c->chunk_item->num_stripes; i++) {
            if (startoffstripe > i)
                context.stripes[i].start = startoff - (startoff % c->chunk_item->stripe_length) + c->chunk_item->stripe_length;
            else if (startoffstripe == i)
                context.stripes[i].start = startoff;
            else
                context.stripes[i].start = startoff - (startoff % c->chunk_item->stripe_length);

            if (endoffstripe > i)
                context.stripes[i].length = (UINT32)(endoff - (endoff % c->chunk_item->stripe_length) + c->chunk_item->stripe_length - context.stripes[i].start);
            else if (endoffstripe == i)
                context.stripes[i].length = (UINT32)(endoff + 1 - context.stripes[i].start);
            else
                context.stripes[i].length = (UINT32)(endoff - (endoff % c->chunk_item->stripe_length) - context.stripes[i].start);
        }

        allowed_missing = 0;
    } else if (type == BLOCK_FLAG_RAID10) {
        UINT64 startoff, endoff;
        UINT16 endoffstripe, j, sub_stripes = max(c->chunk_item->sub_stripes, 1);

        get_raid0_offset(offset - c->offset, c->chunk_item->stripe_length, c->chunk_item->num_stripes / sub_stripes, &startoff, &startoffstripe);
        get_raid0_offset(offset + size - c->offset - 1, c->chunk_item->stripe_length, c->chunk_item->num_stripes / sub_stripes, &endoff, &endoffstripe);

        if ((c->chunk_item->num_stripes % sub_stripes) != 0) {
            ERR("chunk %llx: num_stripes %x was not a multiple of sub_stripes %x!\n", c->offset, c->chunk_item->num_stripes, sub_stripes);
            Status = STATUS_INTERNAL_ERROR;
            goto end;
        }

        startoffstripe *= sub_stripes;
        endoffstripe *= sub_stripes;

        for (i = 0; i < c->chunk_item->num_stripes; i += sub_stripes) {
            if (startoffstripe > i)
                context.stripes[i].start = startoff - (startoff % c->chunk_item->stripe_length) + c->chunk_item->stripe_length;
            else if (startoffstripe == i)
                context.stripes[i].start = startoff;
            else
                context.stripes[i].start = startoff - (startoff % c->chunk_item->stripe_length);

            if (endoffstripe > i)
                context.stripes[i].length = (UINT32)(endoff - (endoff % c->chunk_item->stripe_length) + c->chunk_item->stripe_length - context.stripes[i].start);
            else if (endoffstripe == i)
                context.stripes[i].length = (UINT32)(endoff + 1 - context.stripes[i].start);
            else
                context.stripes[i].length = (UINT32)(endoff - (endoff % c->chunk_item->stripe_length) - context.stripes[i].start);

            for (j = 1; j < sub_stripes; j++) {
                context.stripes[i+j].start = context.stripes[i].start;
                context.stripes[i+j].length = context.stripes[i].length;
            }
        }

        startoffstripe /= sub_stripes;
        allowed_missing = 1;
    } else
        allowed_missing = c->chunk_item->num_stripes - 1;

    num_missing = 0;

    for (i = 0; i < c->chunk_item->num_stripes; i++) {
        PIO_STACK_LOCATION IrpSp;

        context.stripes[i].context = (struct _scrub_context*)&context;

        if (type == BLOCK_FLAG_DUPLICATE) {
            context.stripes[i].start = offset - c->offset;
            context.stripes[i].length = size;
        } else if (type != BLOCK_FLAG_RAID0 && type != BLOCK_FLAG_RAID10) {
            ERR("unexpected chunk type %x\n", type);
            Status = STATUS_INTERNAL_ERROR;
            goto end;
        }

        if (!c->devices[i]->devobj) {
            num_missing++;

            if (num_missing > allowed_missing) {
                ERR("too many missing devices (at least %u, maximum allowed %u)\n", num_missing, allowed_missing);
                Status = STATUS_INTERNAL_ERROR;
                goto end;
            }
        } else if (context.stripes[i].length > 0) {
            context.stripes[i].buf = ExAllocatePoolWithTag(NonPagedPool, context.stripes[i].length, ALLOC_TAG);

            if (!context.stripes[i].buf) {
                ERR("out of memory\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto end;
            }

            context.stripes[i].Irp = IoAllocateIrp(c->devices[i]->devobj->StackSize, FALSE);

            if (!context.stripes[i].Irp) {
                ERR("IoAllocateIrp failed\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto end;
            }

            IrpSp = IoGetNextIrpStackLocation(context.stripes[i].Irp);
            IrpSp->MajorFunction = IRP_MJ_READ;

            if (c->devices[i]->devobj->Flags & DO_BUFFERED_IO) {
                context.stripes[i].Irp->AssociatedIrp.SystemBuffer = ExAllocatePoolWithTag(NonPagedPool, context.stripes[i].length, ALLOC_TAG);
                if (!context.stripes[i].Irp->AssociatedIrp.SystemBuffer) {
                    ERR("out of memory\n");
                    Status = STATUS_INSUFFICIENT_RESOURCES;
                    goto end;
                }

                context.stripes[i].Irp->Flags |= IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER | IRP_INPUT_OPERATION;

                context.stripes[i].Irp->UserBuffer = context.stripes[i].buf;
            } else if (c->devices[i]->devobj->Flags & DO_DIRECT_IO) {
                context.stripes[i].Irp->MdlAddress = IoAllocateMdl(context.stripes[i].buf, context.stripes[i].length, FALSE, FALSE, NULL);
                if (!context.stripes[i].Irp->MdlAddress) {
                    ERR("IoAllocateMdl failed\n");
                    Status = STATUS_INSUFFICIENT_RESOURCES;
                    goto end;
                }

                Status = STATUS_SUCCESS;

                try {
                    MmProbeAndLockPages(context.stripes[i].Irp->MdlAddress, KernelMode, IoWriteAccess);
                } except (EXCEPTION_EXECUTE_HANDLER) {
                    Status = GetExceptionCode();
                }

                if (!NT_SUCCESS(Status)) {
                    ERR("MmProbeAndLockPages threw exception %08x\n", Status);
                    IoFreeMdl(context.stripes[i].Irp->MdlAddress);
                    context.stripes[i].Irp->MdlAddress = NULL;
                    goto end;
                }
            } else
                context.stripes[i].Irp->UserBuffer = context.stripes[i].buf;

            IrpSp->Parameters.Read.Length = context.stripes[i].length;
            IrpSp->Parameters.Read.ByteOffset.QuadPart = context.stripes[i].start + cis[i].offset;

            context.stripes[i].Irp->UserIosb = &context.stripes[i].iosb;

            IoSetCompletionRoutine(context.stripes[i].Irp, scrub_read_completion, &context.stripes[i], TRUE, TRUE, TRUE);

            context.stripes_left++;

            Vcb->scrub.data_scrubbed += context.stripes[i].length;
        }
    }

    if (context.stripes_left == 0) {
        ERR("error - not reading any stripes\n");
        Status = STATUS_INTERNAL_ERROR;
        goto end;
    }

    KeInitializeEvent(&context.Event, NotificationEvent, FALSE);

    for (i = 0; i < c->chunk_item->num_stripes; i++) {
        if (c->devices[i]->devobj && context.stripes[i].length > 0)
            IoCallDriver(c->devices[i]->devobj, context.stripes[i].Irp);
    }

    KeWaitForSingleObject(&context.Event, Executive, KernelMode, FALSE, NULL);

    // return an error if any of the stripes returned an error
    for (i = 0; i < c->chunk_item->num_stripes; i++) {
        if (!NT_SUCCESS(context.stripes[i].iosb.Status)) {
            Status = context.stripes[i].iosb.Status;
            log_device_error(Vcb, c->devices[i], BTRFS_DEV_STAT_READ_ERRORS);
            goto end;
        }
    }

    if (type == BLOCK_FLAG_DUPLICATE) {
        Status = scrub_extent_dup(Vcb, c, offset, csum, &context);
        if (!NT_SUCCESS(Status)) {
            ERR("scrub_extent_dup returned %08x\n", Status);
            goto end;
        }
    } else if (type == BLOCK_FLAG_RAID0) {
        Status = scrub_extent_raid0(Vcb, c, offset, size, startoffstripe, csum, &context);
        if (!NT_SUCCESS(Status)) {
            ERR("scrub_extent_raid0 returned %08x\n", Status);
            goto end;
        }
    } else if (type == BLOCK_FLAG_RAID10) {
        Status = scrub_extent_raid10(Vcb, c, offset, size, startoffstripe, csum, &context);
        if (!NT_SUCCESS(Status)) {
            ERR("scrub_extent_raid10 returned %08x\n", Status);
            goto end;
        }
    }

end:
    if (context.stripes) {
        for (i = 0; i < c->chunk_item->num_stripes; i++) {
            if (context.stripes[i].Irp) {
                if (c->devices[i]->devobj->Flags & DO_DIRECT_IO && context.stripes[i].Irp->MdlAddress) {
                    MmUnlockPages(context.stripes[i].Irp->MdlAddress);
                    IoFreeMdl(context.stripes[i].Irp->MdlAddress);
                }
                IoFreeIrp(context.stripes[i].Irp);
            }

            if (context.stripes[i].buf)
                ExFreePool(context.stripes[i].buf);

            if (context.stripes[i].bad_csums)
                ExFreePool(context.stripes[i].bad_csums);
        }

        ExFreePool(context.stripes);
    }

    return Status;
}

static NTSTATUS scrub_data_extent(device_extension* Vcb, chunk* c, UINT64 offset, ULONG type, UINT32* csum, RTL_BITMAP* bmp) {
    NTSTATUS Status;
    ULONG runlength, index;

    runlength = RtlFindFirstRunClear(bmp, &index);

    while (runlength != 0) {
        do {
            ULONG rl;

            if (runlength * Vcb->superblock.sector_size > SCRUB_UNIT)
                rl = SCRUB_UNIT / Vcb->superblock.sector_size;
            else
                rl = runlength;

            Status = scrub_extent(Vcb, c, type, offset + UInt32x32To64(index, Vcb->superblock.sector_size), rl * Vcb->superblock.sector_size, &csum[index]);
            if (!NT_SUCCESS(Status)) {
                ERR("scrub_data_extent_dup returned %08x\n", Status);
                return Status;
            }

            runlength -= rl;
            index += rl;
        } while (runlength > 0);

        runlength = RtlFindNextForwardRunClear(bmp, index, &index);
    }

    return STATUS_SUCCESS;
}

typedef struct {
    UINT8* buf;
    PIRP Irp;
    void* context;
    IO_STATUS_BLOCK iosb;
    UINT64 offset;
    BOOL rewrite, missing;
    RTL_BITMAP error;
    ULONG* errorarr;
} scrub_context_raid56_stripe;

typedef struct {
    scrub_context_raid56_stripe* stripes;
    LONG stripes_left;
    KEVENT Event;
    RTL_BITMAP alloc;
    RTL_BITMAP has_csum;
    RTL_BITMAP is_tree;
    UINT32* csum;
    UINT8* parity_scratch;
    UINT8* parity_scratch2;
} scrub_context_raid56;

_Function_class_(IO_COMPLETION_ROUTINE)
static NTSTATUS scrub_read_completion_raid56(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID conptr) {
    scrub_context_raid56_stripe* stripe = conptr;
    scrub_context_raid56* context = (scrub_context_raid56*)stripe->context;
    LONG left = InterlockedDecrement(&context->stripes_left);

    UNUSED(DeviceObject);

    stripe->iosb = Irp->IoStatus;

    if (left == 0)
        KeSetEvent(&context->Event, 0, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

static void scrub_raid5_stripe(device_extension* Vcb, chunk* c, scrub_context_raid56* context, UINT64 stripe_start, UINT64 bit_start,
                               UINT64 num, UINT16 missing_devices) {
    ULONG sectors_per_stripe = (ULONG)(c->chunk_item->stripe_length / Vcb->superblock.sector_size), i, off;
    UINT16 stripe, parity = (bit_start + num + c->chunk_item->num_stripes - 1) % c->chunk_item->num_stripes;
    UINT64 stripeoff;

    stripe = (parity + 1) % c->chunk_item->num_stripes;
    off = (ULONG)(bit_start + num - stripe_start) * sectors_per_stripe * (c->chunk_item->num_stripes - 1);
    stripeoff = num * sectors_per_stripe;

    if (missing_devices == 0)
        RtlCopyMemory(context->parity_scratch, &context->stripes[parity].buf[num * c->chunk_item->stripe_length], (ULONG)c->chunk_item->stripe_length);

    while (stripe != parity) {
        RtlClearAllBits(&context->stripes[stripe].error);

        for (i = 0; i < sectors_per_stripe; i++) {
            if (c->devices[stripe]->devobj && RtlCheckBit(&context->alloc, off)) {
                if (RtlCheckBit(&context->is_tree, off)) {
                    tree_header* th = (tree_header*)&context->stripes[stripe].buf[stripeoff * Vcb->superblock.sector_size];
                    UINT64 addr = c->offset + (stripe_start * (c->chunk_item->num_stripes - 1) * c->chunk_item->stripe_length) + (off * Vcb->superblock.sector_size);
                    UINT32 crc32 = ~calc_crc32c(0xffffffff, (UINT8*)&th->fs_uuid, Vcb->superblock.node_size - sizeof(th->csum));

                    if (crc32 != *((UINT32*)th->csum) || th->address != addr) {
                        RtlSetBits(&context->stripes[stripe].error, i, Vcb->superblock.node_size / Vcb->superblock.sector_size);
                        log_device_error(Vcb, c->devices[stripe], BTRFS_DEV_STAT_CORRUPTION_ERRORS);

                        if (missing_devices > 0)
                            log_error(Vcb, addr, c->devices[stripe]->devitem.dev_id, TRUE, FALSE, FALSE);
                    }

                    off += Vcb->superblock.node_size / Vcb->superblock.sector_size;
                    stripeoff += Vcb->superblock.node_size / Vcb->superblock.sector_size;
                    i += (Vcb->superblock.node_size / Vcb->superblock.sector_size) - 1;

                    continue;
                } else if (RtlCheckBit(&context->has_csum, off)) {
                    UINT32 crc32 = ~calc_crc32c(0xffffffff, context->stripes[stripe].buf + (stripeoff * Vcb->superblock.sector_size), Vcb->superblock.sector_size);

                    if (crc32 != context->csum[off]) {
                        RtlSetBit(&context->stripes[stripe].error, i);
                        log_device_error(Vcb, c->devices[stripe], BTRFS_DEV_STAT_CORRUPTION_ERRORS);

                        if (missing_devices > 0) {
                            UINT64 addr = c->offset + (stripe_start * (c->chunk_item->num_stripes - 1) * c->chunk_item->stripe_length) + (off * Vcb->superblock.sector_size);

                            log_error(Vcb, addr, c->devices[stripe]->devitem.dev_id, FALSE, FALSE, FALSE);
                        }
                    }
                }
            }

            off++;
            stripeoff++;
        }

        if (missing_devices == 0)
            do_xor(context->parity_scratch, &context->stripes[stripe].buf[num * c->chunk_item->stripe_length], (ULONG)c->chunk_item->stripe_length);

        stripe = (stripe + 1) % c->chunk_item->num_stripes;
        stripeoff = num * sectors_per_stripe;
    }

    // check parity

    if (missing_devices == 0) {
        RtlClearAllBits(&context->stripes[parity].error);

        for (i = 0; i < sectors_per_stripe; i++) {
            ULONG o, j;

            o = i * Vcb->superblock.sector_size;
            for (j = 0; j < Vcb->superblock.sector_size; j++) { // FIXME - use SSE
                if (context->parity_scratch[o] != 0) {
                    RtlSetBit(&context->stripes[parity].error, i);
                    break;
                }
                o++;
            }
        }
    }

    // log and fix errors

    if (missing_devices > 0)
        return;

    for (i = 0; i < sectors_per_stripe; i++) {
        ULONG num_errors = 0, bad_off;
        UINT64 bad_stripe;
        BOOL alloc = FALSE;

        stripe = (parity + 1) % c->chunk_item->num_stripes;
        off = (ULONG)((bit_start + num - stripe_start) * sectors_per_stripe * (c->chunk_item->num_stripes - 1)) + i;

        while (stripe != parity) {
            if (RtlCheckBit(&context->alloc, off)) {
                alloc = TRUE;

                if (RtlCheckBit(&context->stripes[stripe].error, i)) {
                    bad_stripe = stripe;
                    bad_off = off;
                    num_errors++;
                }
            }

            off += sectors_per_stripe;
            stripe = (stripe + 1) % c->chunk_item->num_stripes;
        }

        if (!alloc)
            continue;

        if (num_errors == 0 && !RtlCheckBit(&context->stripes[parity].error, i)) // everything fine
            continue;

        if (num_errors == 0 && RtlCheckBit(&context->stripes[parity].error, i)) { // parity error
            UINT64 addr;

            do_xor(&context->stripes[parity].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)],
                   &context->parity_scratch[i * Vcb->superblock.sector_size],
                   Vcb->superblock.sector_size);

            bad_off = (ULONG)((bit_start + num - stripe_start) * sectors_per_stripe * (c->chunk_item->num_stripes - 1)) + i;
            addr = c->offset + (stripe_start * (c->chunk_item->num_stripes - 1) * c->chunk_item->stripe_length) + (bad_off * Vcb->superblock.sector_size);

            context->stripes[parity].rewrite = TRUE;

            log_error(Vcb, addr, c->devices[parity]->devitem.dev_id, FALSE, TRUE, TRUE);
            log_device_error(Vcb, c->devices[parity], BTRFS_DEV_STAT_CORRUPTION_ERRORS);
        } else if (num_errors == 1) {
            UINT32 crc32;
            UINT64 addr = c->offset + (stripe_start * (c->chunk_item->num_stripes - 1) * c->chunk_item->stripe_length) + (bad_off * Vcb->superblock.sector_size);

            if (RtlCheckBit(&context->is_tree, bad_off)) {
                tree_header* th;

                do_xor(&context->parity_scratch[i * Vcb->superblock.sector_size],
                       &context->stripes[bad_stripe].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)],
                       Vcb->superblock.node_size);

                th = (tree_header*)&context->parity_scratch[i * Vcb->superblock.sector_size];
                crc32 = ~calc_crc32c(0xffffffff, (UINT8*)&th->fs_uuid, Vcb->superblock.node_size - sizeof(th->csum));

                if (crc32 == *((UINT32*)th->csum) && th->address == addr) {
                    RtlCopyMemory(&context->stripes[bad_stripe].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)],
                                  &context->parity_scratch[i * Vcb->superblock.sector_size], Vcb->superblock.node_size);

                    context->stripes[bad_stripe].rewrite = TRUE;

                    RtlClearBits(&context->stripes[bad_stripe].error, i + 1, (Vcb->superblock.node_size / Vcb->superblock.sector_size) - 1);

                    log_error(Vcb, addr, c->devices[bad_stripe]->devitem.dev_id, TRUE, TRUE, FALSE);
                } else
                    log_error(Vcb, addr, c->devices[bad_stripe]->devitem.dev_id, TRUE, FALSE, FALSE);
            } else {
                do_xor(&context->parity_scratch[i * Vcb->superblock.sector_size],
                       &context->stripes[bad_stripe].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)],
                       Vcb->superblock.sector_size);

                crc32 = ~calc_crc32c(0xffffffff, &context->parity_scratch[i * Vcb->superblock.sector_size], Vcb->superblock.sector_size);

                if (crc32 == context->csum[bad_off]) {
                    RtlCopyMemory(&context->stripes[bad_stripe].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)],
                                  &context->parity_scratch[i * Vcb->superblock.sector_size], Vcb->superblock.sector_size);

                    context->stripes[bad_stripe].rewrite = TRUE;

                    log_error(Vcb, addr, c->devices[bad_stripe]->devitem.dev_id, FALSE, TRUE, FALSE);
                } else
                    log_error(Vcb, addr, c->devices[bad_stripe]->devitem.dev_id, FALSE, FALSE, FALSE);
            }
        } else {
            stripe = (parity + 1) % c->chunk_item->num_stripes;
            off = (ULONG)((bit_start + num - stripe_start) * sectors_per_stripe * (c->chunk_item->num_stripes - 1)) + i;

            while (stripe != parity) {
                if (RtlCheckBit(&context->alloc, off)) {
                    if (RtlCheckBit(&context->stripes[stripe].error, i)) {
                        UINT64 addr = c->offset + (stripe_start * (c->chunk_item->num_stripes - 1) * c->chunk_item->stripe_length) + (off * Vcb->superblock.sector_size);

                        log_error(Vcb, addr, c->devices[stripe]->devitem.dev_id, RtlCheckBit(&context->is_tree, off), FALSE, FALSE);
                    }
                }

                off += sectors_per_stripe;
                stripe = (stripe + 1) % c->chunk_item->num_stripes;
            }
        }
    }
}

static void scrub_raid6_stripe(device_extension* Vcb, chunk* c, scrub_context_raid56* context, UINT64 stripe_start, UINT64 bit_start,
                               UINT64 num, UINT16 missing_devices) {
    ULONG sectors_per_stripe = (ULONG)(c->chunk_item->stripe_length / Vcb->superblock.sector_size), i, off;
    UINT16 stripe, parity1 = (bit_start + num + c->chunk_item->num_stripes - 2) % c->chunk_item->num_stripes;
    UINT16 parity2 = (parity1 + 1) % c->chunk_item->num_stripes;
    UINT64 stripeoff;

    stripe = (parity1 + 2) % c->chunk_item->num_stripes;
    off = (ULONG)(bit_start + num - stripe_start) * sectors_per_stripe * (c->chunk_item->num_stripes - 2);
    stripeoff = num * sectors_per_stripe;

    if (c->devices[parity1]->devobj)
        RtlCopyMemory(context->parity_scratch, &context->stripes[parity1].buf[num * c->chunk_item->stripe_length], (ULONG)c->chunk_item->stripe_length);

    if (c->devices[parity2]->devobj)
        RtlZeroMemory(context->parity_scratch2, (ULONG)c->chunk_item->stripe_length);

    while (stripe != parity1) {
        RtlClearAllBits(&context->stripes[stripe].error);

        for (i = 0; i < sectors_per_stripe; i++) {
            if (c->devices[stripe]->devobj && RtlCheckBit(&context->alloc, off)) {
                if (RtlCheckBit(&context->is_tree, off)) {
                    tree_header* th = (tree_header*)&context->stripes[stripe].buf[stripeoff * Vcb->superblock.sector_size];
                    UINT64 addr = c->offset + (stripe_start * (c->chunk_item->num_stripes - 2) * c->chunk_item->stripe_length) + (off * Vcb->superblock.sector_size);
                    UINT32 crc32 = ~calc_crc32c(0xffffffff, (UINT8*)&th->fs_uuid, Vcb->superblock.node_size - sizeof(th->csum));

                    if (crc32 != *((UINT32*)th->csum) || th->address != addr) {
                        RtlSetBits(&context->stripes[stripe].error, i, Vcb->superblock.node_size / Vcb->superblock.sector_size);
                        log_device_error(Vcb, c->devices[stripe], BTRFS_DEV_STAT_CORRUPTION_ERRORS);

                        if (missing_devices == 2)
                            log_error(Vcb, addr, c->devices[stripe]->devitem.dev_id, TRUE, FALSE, FALSE);
                    }

                    off += Vcb->superblock.node_size / Vcb->superblock.sector_size;
                    stripeoff += Vcb->superblock.node_size / Vcb->superblock.sector_size;
                    i += (Vcb->superblock.node_size / Vcb->superblock.sector_size) - 1;

                    continue;
                } else if (RtlCheckBit(&context->has_csum, off)) {
                    UINT32 crc32 = ~calc_crc32c(0xffffffff, context->stripes[stripe].buf + (stripeoff * Vcb->superblock.sector_size), Vcb->superblock.sector_size);

                    if (crc32 != context->csum[off]) {
                        UINT64 addr = c->offset + (stripe_start * (c->chunk_item->num_stripes - 2) * c->chunk_item->stripe_length) + (off * Vcb->superblock.sector_size);

                        RtlSetBit(&context->stripes[stripe].error, i);
                        log_device_error(Vcb, c->devices[stripe], BTRFS_DEV_STAT_CORRUPTION_ERRORS);

                        if (missing_devices == 2)
                            log_error(Vcb, addr, c->devices[stripe]->devitem.dev_id, FALSE, FALSE, FALSE);
                    }
                }
            }

            off++;
            stripeoff++;
        }

        if (c->devices[parity1]->devobj)
            do_xor(context->parity_scratch, &context->stripes[stripe].buf[num * c->chunk_item->stripe_length], (UINT32)c->chunk_item->stripe_length);

        stripe = (stripe + 1) % c->chunk_item->num_stripes;
        stripeoff = num * sectors_per_stripe;
    }

    RtlClearAllBits(&context->stripes[parity1].error);

    if (missing_devices == 0 || (missing_devices == 1 && !c->devices[parity2]->devobj)) {
        // check parity 1

        for (i = 0; i < sectors_per_stripe; i++) {
            ULONG o, j;

            o = i * Vcb->superblock.sector_size;
            for (j = 0; j < Vcb->superblock.sector_size; j++) { // FIXME - use SSE
                if (context->parity_scratch[o] != 0) {
                    RtlSetBit(&context->stripes[parity1].error, i);
                    break;
                }
                o++;
            }
        }
    }

    RtlClearAllBits(&context->stripes[parity2].error);

    if (missing_devices == 0 || (missing_devices == 1 && !c->devices[parity1]->devobj)) {
        // check parity 2

        stripe = parity1 == 0 ? (c->chunk_item->num_stripes - 1) : (parity1 - 1);

        while (stripe != parity2) {
            galois_double(context->parity_scratch2, (UINT32)c->chunk_item->stripe_length);
            do_xor(context->parity_scratch2, &context->stripes[stripe].buf[num * c->chunk_item->stripe_length], (UINT32)c->chunk_item->stripe_length);

            stripe = stripe == 0 ? (c->chunk_item->num_stripes - 1) : (stripe - 1);
        }

        for (i = 0; i < sectors_per_stripe; i++) {
            if (RtlCompareMemory(&context->stripes[parity2].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)],
                                &context->parity_scratch2[i * Vcb->superblock.sector_size], Vcb->superblock.sector_size) != Vcb->superblock.sector_size)
                RtlSetBit(&context->stripes[parity2].error, i);
        }
    }

    if (missing_devices == 2)
        return;

    // log and fix errors

    for (i = 0; i < sectors_per_stripe; i++) {
        ULONG num_errors = 0;
        UINT64 bad_stripe1, bad_stripe2;
        ULONG bad_off1, bad_off2;
        BOOL alloc = FALSE;

        stripe = (parity1 + 2) % c->chunk_item->num_stripes;
        off = (ULONG)((bit_start + num - stripe_start) * sectors_per_stripe * (c->chunk_item->num_stripes - 2)) + i;

        while (stripe != parity1) {
            if (RtlCheckBit(&context->alloc, off)) {
                alloc = TRUE;

                if (!c->devices[stripe]->devobj || RtlCheckBit(&context->stripes[stripe].error, i)) {
                    if (num_errors == 0) {
                        bad_stripe1 = stripe;
                        bad_off1 = off;
                    } else if (num_errors == 1) {
                        bad_stripe2 = stripe;
                        bad_off2 = off;
                    }
                    num_errors++;
                }
            }

            off += sectors_per_stripe;
            stripe = (stripe + 1) % c->chunk_item->num_stripes;
        }

        if (!alloc)
            continue;

        if (num_errors == 0 && !RtlCheckBit(&context->stripes[parity1].error, i) && !RtlCheckBit(&context->stripes[parity2].error, i)) // everything fine
            continue;

        if (num_errors == 0) { // parity error
            UINT64 addr;

            if (RtlCheckBit(&context->stripes[parity1].error, i)) {
                do_xor(&context->stripes[parity1].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)],
                       &context->parity_scratch[i * Vcb->superblock.sector_size],
                       Vcb->superblock.sector_size);

                bad_off1 = (ULONG)((bit_start + num - stripe_start) * sectors_per_stripe * (c->chunk_item->num_stripes - 2)) + i;
                addr = c->offset + (stripe_start * (c->chunk_item->num_stripes - 2) * c->chunk_item->stripe_length) + (bad_off1 * Vcb->superblock.sector_size);

                context->stripes[parity1].rewrite = TRUE;

                log_error(Vcb, addr, c->devices[parity1]->devitem.dev_id, FALSE, TRUE, TRUE);
                log_device_error(Vcb, c->devices[parity1], BTRFS_DEV_STAT_CORRUPTION_ERRORS);
            }

            if (RtlCheckBit(&context->stripes[parity2].error, i)) {
                RtlCopyMemory(&context->stripes[parity2].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)],
                              &context->parity_scratch2[i * Vcb->superblock.sector_size],
                              Vcb->superblock.sector_size);

                bad_off1 = (ULONG)((bit_start + num - stripe_start) * sectors_per_stripe * (c->chunk_item->num_stripes - 2)) + i;
                addr = c->offset + (stripe_start * (c->chunk_item->num_stripes - 2) * c->chunk_item->stripe_length) + (bad_off1 * Vcb->superblock.sector_size);

                context->stripes[parity2].rewrite = TRUE;

                log_error(Vcb, addr, c->devices[parity2]->devitem.dev_id, FALSE, TRUE, TRUE);
                log_device_error(Vcb, c->devices[parity2], BTRFS_DEV_STAT_CORRUPTION_ERRORS);
            }
        } else if (num_errors == 1) {
            UINT32 crc32a, crc32b, len;
            UINT16 stripe_num, bad_stripe_num = 0;
            UINT64 addr = c->offset + (stripe_start * (c->chunk_item->num_stripes - 2) * c->chunk_item->stripe_length) + (bad_off1 * Vcb->superblock.sector_size);
            UINT8* scratch;

            len = RtlCheckBit(&context->is_tree, bad_off1)? Vcb->superblock.node_size : Vcb->superblock.sector_size;

            scratch = ExAllocatePoolWithTag(PagedPool, len, ALLOC_TAG);
            if (!scratch) {
                ERR("out of memory\n");
                return;
            }

            RtlZeroMemory(scratch, len);

            do_xor(&context->parity_scratch[i * Vcb->superblock.sector_size],
                   &context->stripes[bad_stripe1].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)], len);

            stripe = parity1 == 0 ? (c->chunk_item->num_stripes - 1) : (parity1 - 1);

            if (c->devices[parity2]->devobj) {
                stripe_num = c->chunk_item->num_stripes - 3;
                while (stripe != parity2) {
                    galois_double(scratch, len);

                    if (stripe != bad_stripe1)
                        do_xor(scratch, &context->stripes[stripe].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)], len);
                    else
                        bad_stripe_num = stripe_num;

                    stripe = stripe == 0 ? (c->chunk_item->num_stripes - 1) : (stripe - 1);
                    stripe_num--;
                }

                do_xor(scratch, &context->stripes[parity2].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)], len);
            }

            if (bad_stripe_num != 0)
                galois_divpower(scratch, (UINT8)bad_stripe_num, len);

            if (RtlCheckBit(&context->is_tree, bad_off1)) {
                tree_header *th1 = NULL, *th2 = NULL;

                if (c->devices[parity1]->devobj) {
                    th1 = (tree_header*)&context->parity_scratch[i * Vcb->superblock.sector_size];
                    crc32a = ~calc_crc32c(0xffffffff, (UINT8*)&th1->fs_uuid, Vcb->superblock.node_size - sizeof(th1->csum));
                }

                if (c->devices[parity2]->devobj) {
                    th2 = (tree_header*)scratch;
                    crc32b = ~calc_crc32c(0xffffffff, (UINT8*)&th2->fs_uuid, Vcb->superblock.node_size - sizeof(th2->csum));
                }

                if ((c->devices[parity1]->devobj && crc32a == *((UINT32*)th1->csum) && th1->address == addr) ||
                    (c->devices[parity2]->devobj && crc32b == *((UINT32*)th2->csum) && th2->address == addr)) {
                    if (!c->devices[parity1]->devobj || crc32a != *((UINT32*)th1->csum) || th1->address != addr) {
                        RtlCopyMemory(&context->stripes[bad_stripe1].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)],
                                      scratch, Vcb->superblock.node_size);

                        if (c->devices[parity1]->devobj) {
                            // fix parity 1

                            stripe = (parity1 + 2) % c->chunk_item->num_stripes;

                            RtlCopyMemory(&context->stripes[parity1].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)],
                                          &context->stripes[stripe].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)],
                                          Vcb->superblock.node_size);

                            stripe = (stripe + 1) % c->chunk_item->num_stripes;

                            while (stripe != parity1) {
                                do_xor(&context->stripes[parity1].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)],
                                       &context->stripes[stripe].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)],
                                       Vcb->superblock.node_size);

                                stripe = (stripe + 1) % c->chunk_item->num_stripes;
                            }

                            context->stripes[parity1].rewrite = TRUE;

                            log_error(Vcb, addr, c->devices[parity1]->devitem.dev_id, FALSE, TRUE, TRUE);
                            log_device_error(Vcb, c->devices[parity1], BTRFS_DEV_STAT_CORRUPTION_ERRORS);
                        }
                    } else {
                        RtlCopyMemory(&context->stripes[bad_stripe1].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)],
                                      &context->parity_scratch[i * Vcb->superblock.sector_size], Vcb->superblock.node_size);

                        if (!c->devices[parity2]->devobj || crc32b != *((UINT32*)th2->csum) || th2->address != addr) {
                            // fix parity 2
                            stripe = parity1 == 0 ? (c->chunk_item->num_stripes - 1) : (parity1 - 1);

                            if (c->devices[parity2]->devobj) {
                                RtlCopyMemory(&context->stripes[parity2].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)],
                                            &context->stripes[stripe].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)],
                                            Vcb->superblock.node_size);

                                stripe = stripe == 0 ? (c->chunk_item->num_stripes - 1) : (stripe - 1);

                                while (stripe != parity2) {
                                    galois_double(&context->stripes[parity2].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)], Vcb->superblock.node_size);

                                    do_xor(&context->stripes[parity2].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)],
                                        &context->stripes[stripe].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)],
                                        Vcb->superblock.node_size);

                                    stripe = stripe == 0 ? (c->chunk_item->num_stripes - 1) : (stripe - 1);
                                }

                                context->stripes[parity2].rewrite = TRUE;

                                log_error(Vcb, addr, c->devices[parity2]->devitem.dev_id, FALSE, TRUE, TRUE);
                                log_device_error(Vcb, c->devices[parity2], BTRFS_DEV_STAT_CORRUPTION_ERRORS);
                            }
                        }
                    }

                    context->stripes[bad_stripe1].rewrite = TRUE;

                    RtlClearBits(&context->stripes[bad_stripe1].error, i + 1, (Vcb->superblock.node_size / Vcb->superblock.sector_size) - 1);

                    log_error(Vcb, addr, c->devices[bad_stripe1]->devitem.dev_id, TRUE, TRUE, FALSE);
                } else
                    log_error(Vcb, addr, c->devices[bad_stripe1]->devitem.dev_id, TRUE, FALSE, FALSE);
            } else {
                if (c->devices[parity1]->devobj)
                    crc32a = ~calc_crc32c(0xffffffff, &context->parity_scratch[i * Vcb->superblock.sector_size], Vcb->superblock.sector_size);

                if (c->devices[parity2]->devobj)
                    crc32b = ~calc_crc32c(0xffffffff, scratch, Vcb->superblock.sector_size);

                if ((c->devices[parity1]->devobj && crc32a == context->csum[bad_off1]) || (c->devices[parity2]->devobj && crc32b == context->csum[bad_off1])) {
                    if (c->devices[parity2]->devobj && crc32b == context->csum[bad_off1]) {
                        RtlCopyMemory(&context->stripes[bad_stripe1].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)],
                                      scratch, Vcb->superblock.sector_size);

                        if (c->devices[parity1]->devobj && crc32a != context->csum[bad_off1]) {
                            // fix parity 1

                            stripe = (parity1 + 2) % c->chunk_item->num_stripes;

                            RtlCopyMemory(&context->stripes[parity1].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)],
                                        &context->stripes[stripe].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)],
                                        Vcb->superblock.sector_size);

                            stripe = (stripe + 1) % c->chunk_item->num_stripes;

                            while (stripe != parity1) {
                                do_xor(&context->stripes[parity1].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)],
                                    &context->stripes[stripe].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)],
                                    Vcb->superblock.sector_size);

                                stripe = (stripe + 1) % c->chunk_item->num_stripes;
                            }

                            context->stripes[parity1].rewrite = TRUE;

                            log_error(Vcb, addr, c->devices[parity1]->devitem.dev_id, FALSE, TRUE, TRUE);
                            log_device_error(Vcb, c->devices[parity1], BTRFS_DEV_STAT_CORRUPTION_ERRORS);
                        }
                    } else {
                        RtlCopyMemory(&context->stripes[bad_stripe1].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)],
                                      &context->parity_scratch[i * Vcb->superblock.sector_size], Vcb->superblock.sector_size);

                        if (c->devices[parity2]->devobj && crc32b != context->csum[bad_off1]) {
                            // fix parity 2
                            stripe = parity1 == 0 ? (c->chunk_item->num_stripes - 1) : (parity1 - 1);

                            RtlCopyMemory(&context->stripes[parity2].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)],
                                        &context->stripes[stripe].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)],
                                        Vcb->superblock.sector_size);

                            stripe = stripe == 0 ? (c->chunk_item->num_stripes - 1) : (stripe - 1);

                            while (stripe != parity2) {
                                galois_double(&context->stripes[parity2].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)], Vcb->superblock.sector_size);

                                do_xor(&context->stripes[parity2].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)],
                                       &context->stripes[stripe].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)],
                                       Vcb->superblock.sector_size);

                                stripe = stripe == 0 ? (c->chunk_item->num_stripes - 1) : (stripe - 1);
                            }

                            context->stripes[parity2].rewrite = TRUE;

                            log_error(Vcb, addr, c->devices[parity2]->devitem.dev_id, FALSE, TRUE, TRUE);
                            log_device_error(Vcb, c->devices[parity2], BTRFS_DEV_STAT_CORRUPTION_ERRORS);
                        }
                    }

                    context->stripes[bad_stripe1].rewrite = TRUE;

                    log_error(Vcb, addr, c->devices[bad_stripe1]->devitem.dev_id, FALSE, TRUE, FALSE);
                } else
                    log_error(Vcb, addr, c->devices[bad_stripe1]->devitem.dev_id, FALSE, FALSE, FALSE);
            }

            ExFreePool(scratch);
        } else if (num_errors == 2 && missing_devices == 0) {
            UINT16 x, y, k;
            UINT64 addr;
            UINT32 len = (RtlCheckBit(&context->is_tree, bad_off1) || RtlCheckBit(&context->is_tree, bad_off2)) ? Vcb->superblock.node_size : Vcb->superblock.sector_size;
            UINT8 gyx, gx, denom, a, b, *p, *q, *pxy, *qxy;
            UINT32 j;

            stripe = parity1 == 0 ? (c->chunk_item->num_stripes - 1) : (parity1 - 1);

            // put qxy in parity_scratch
            // put pxy in parity_scratch2

            k = c->chunk_item->num_stripes - 3;
            if (stripe == bad_stripe1 || stripe == bad_stripe2) {
                RtlZeroMemory(&context->parity_scratch[i * Vcb->superblock.sector_size], len);
                RtlZeroMemory(&context->parity_scratch2[i * Vcb->superblock.sector_size], len);

                if (stripe == bad_stripe1)
                    x = k;
                else
                    y = k;
            } else {
                RtlCopyMemory(&context->parity_scratch[i * Vcb->superblock.sector_size],
                              &context->stripes[stripe].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)], len);
                RtlCopyMemory(&context->parity_scratch2[i * Vcb->superblock.sector_size],
                              &context->stripes[stripe].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)], len);
            }

            stripe = stripe == 0 ? (c->chunk_item->num_stripes - 1) : (stripe - 1);

            k--;
            do {
                galois_double(&context->parity_scratch[i * Vcb->superblock.sector_size], len);

                if (stripe != bad_stripe1 && stripe != bad_stripe2) {
                    do_xor(&context->parity_scratch[i * Vcb->superblock.sector_size],
                           &context->stripes[stripe].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)], len);
                    do_xor(&context->parity_scratch2[i * Vcb->superblock.sector_size],
                           &context->stripes[stripe].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)], len);
                } else if (stripe == bad_stripe1)
                    x = k;
                else if (stripe == bad_stripe2)
                    y = k;

                stripe = stripe == 0 ? (c->chunk_item->num_stripes - 1) : (stripe - 1);
                k--;
            } while (stripe != parity2);

            gyx = gpow2(y > x ? (y-x) : (255-x+y));
            gx = gpow2(255-x);

            denom = gdiv(1, gyx ^ 1);
            a = gmul(gyx, denom);
            b = gmul(gx, denom);

            p = &context->stripes[parity1].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)];
            q = &context->stripes[parity2].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)];
            pxy = &context->parity_scratch2[i * Vcb->superblock.sector_size];
            qxy = &context->parity_scratch[i * Vcb->superblock.sector_size];

            for (j = 0; j < len; j++) {
                *qxy = gmul(a, *p ^ *pxy) ^ gmul(b, *q ^ *qxy);

                p++;
                q++;
                pxy++;
                qxy++;
            }

            do_xor(&context->parity_scratch2[i * Vcb->superblock.sector_size], &context->parity_scratch[i * Vcb->superblock.sector_size], len);
            do_xor(&context->parity_scratch2[i * Vcb->superblock.sector_size], &context->stripes[parity1].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)], len);

            addr = c->offset + (stripe_start * (c->chunk_item->num_stripes - 2) * c->chunk_item->stripe_length) + (bad_off1 * Vcb->superblock.sector_size);

            if (RtlCheckBit(&context->is_tree, bad_off1)) {
                tree_header* th = (tree_header*)&context->parity_scratch[i * Vcb->superblock.sector_size];
                UINT32 crc32 = ~calc_crc32c(0xffffffff, (UINT8*)&th->fs_uuid, Vcb->superblock.node_size - sizeof(th->csum));

                if (crc32 == *((UINT32*)th->csum) && th->address == addr) {
                    RtlCopyMemory(&context->stripes[bad_stripe1].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)],
                                  &context->parity_scratch[i * Vcb->superblock.sector_size], Vcb->superblock.node_size);

                    context->stripes[bad_stripe1].rewrite = TRUE;

                    RtlClearBits(&context->stripes[bad_stripe1].error, i + 1, (Vcb->superblock.node_size / Vcb->superblock.sector_size) - 1);

                    log_error(Vcb, addr, c->devices[bad_stripe1]->devitem.dev_id, TRUE, TRUE, FALSE);
                } else
                    log_error(Vcb, addr, c->devices[bad_stripe1]->devitem.dev_id, TRUE, FALSE, FALSE);
            } else {
                UINT32 crc32 = ~calc_crc32c(0xffffffff, &context->parity_scratch[i * Vcb->superblock.sector_size], Vcb->superblock.sector_size);

                if (crc32 == context->csum[bad_off1]) {
                    RtlCopyMemory(&context->stripes[bad_stripe1].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)],
                                  &context->parity_scratch[i * Vcb->superblock.sector_size], Vcb->superblock.sector_size);

                    context->stripes[bad_stripe1].rewrite = TRUE;

                    log_error(Vcb, addr, c->devices[bad_stripe1]->devitem.dev_id, FALSE, TRUE, FALSE);
                } else
                    log_error(Vcb, addr, c->devices[bad_stripe1]->devitem.dev_id, FALSE, FALSE, FALSE);
            }

            addr = c->offset + (stripe_start * (c->chunk_item->num_stripes - 2) * c->chunk_item->stripe_length) + (bad_off2 * Vcb->superblock.sector_size);

            if (RtlCheckBit(&context->is_tree, bad_off2)) {
                tree_header* th = (tree_header*)&context->parity_scratch2[i * Vcb->superblock.sector_size];
                UINT32 crc32 = ~calc_crc32c(0xffffffff, (UINT8*)&th->fs_uuid, Vcb->superblock.node_size - sizeof(th->csum));

                if (crc32 == *((UINT32*)th->csum) && th->address == addr) {
                    RtlCopyMemory(&context->stripes[bad_stripe2].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)],
                                  &context->parity_scratch2[i * Vcb->superblock.sector_size], Vcb->superblock.node_size);

                    context->stripes[bad_stripe2].rewrite = TRUE;

                    RtlClearBits(&context->stripes[bad_stripe2].error, i + 1, (Vcb->superblock.node_size / Vcb->superblock.sector_size) - 1);

                    log_error(Vcb, addr, c->devices[bad_stripe2]->devitem.dev_id, TRUE, TRUE, FALSE);
                } else
                    log_error(Vcb, addr, c->devices[bad_stripe2]->devitem.dev_id, TRUE, FALSE, FALSE);
            } else {
                UINT32 crc32 = ~calc_crc32c(0xffffffff, &context->parity_scratch2[i * Vcb->superblock.sector_size], Vcb->superblock.sector_size);

                if (crc32 == context->csum[bad_off2]) {
                    RtlCopyMemory(&context->stripes[bad_stripe2].buf[(num * c->chunk_item->stripe_length) + (i * Vcb->superblock.sector_size)],
                                  &context->parity_scratch2[i * Vcb->superblock.sector_size], Vcb->superblock.sector_size);

                    context->stripes[bad_stripe2].rewrite = TRUE;

                    log_error(Vcb, addr, c->devices[bad_stripe2]->devitem.dev_id, FALSE, TRUE, FALSE);
                } else
                    log_error(Vcb, addr, c->devices[bad_stripe2]->devitem.dev_id, FALSE, FALSE, FALSE);
            }
        } else {
            stripe = (parity2 + 1) % c->chunk_item->num_stripes;
            off = (ULONG)((bit_start + num - stripe_start) * sectors_per_stripe * (c->chunk_item->num_stripes - 2)) + i;

            while (stripe != parity1) {
                if (c->devices[stripe]->devobj && RtlCheckBit(&context->alloc, off)) {
                    if (RtlCheckBit(&context->stripes[stripe].error, i)) {
                        UINT64 addr = c->offset + (stripe_start * (c->chunk_item->num_stripes - 2) * c->chunk_item->stripe_length) + (off * Vcb->superblock.sector_size);

                        log_error(Vcb, addr, c->devices[stripe]->devitem.dev_id, RtlCheckBit(&context->is_tree, off), FALSE, FALSE);
                    }
                }

                off += sectors_per_stripe;
                stripe = (stripe + 1) % c->chunk_item->num_stripes;
            }
        }
    }
}

static NTSTATUS scrub_chunk_raid56_stripe_run(device_extension* Vcb, chunk* c, UINT64 stripe_start, UINT64 stripe_end) {
    NTSTATUS Status;
    KEY searchkey;
    traverse_ptr tp;
    BOOL b;
    UINT64 run_start, run_end, full_stripe_len, stripe;
    UINT32 max_read, num_sectors;
    ULONG arrlen, *allocarr, *csumarr = NULL, *treearr, num_parity_stripes = c->chunk_item->type & BLOCK_FLAG_RAID6 ? 2 : 1;
    scrub_context_raid56 context;
    UINT16 i;
    CHUNK_ITEM_STRIPE* cis = (CHUNK_ITEM_STRIPE*)&c->chunk_item[1];

    TRACE("(%p, %p, %llx, %llx)\n", Vcb, c, stripe_start, stripe_end);

    full_stripe_len = (c->chunk_item->num_stripes - num_parity_stripes) * c->chunk_item->stripe_length;
    run_start = c->offset + (stripe_start * full_stripe_len);
    run_end = c->offset + ((stripe_end + 1) * full_stripe_len);

    searchkey.obj_id = run_start;
    searchkey.obj_type = TYPE_METADATA_ITEM;
    searchkey.offset = 0xffffffffffffffff;

    Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, FALSE, NULL);
    if (!NT_SUCCESS(Status)) {
        ERR("find_item returned %08x\n", Status);
        return Status;
    }

    num_sectors = (UINT32)((stripe_end - stripe_start + 1) * full_stripe_len / Vcb->superblock.sector_size);
    arrlen = (ULONG)sector_align((num_sectors / 8) + 1, sizeof(ULONG));

    allocarr = ExAllocatePoolWithTag(PagedPool, arrlen, ALLOC_TAG);
    if (!allocarr) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    treearr = ExAllocatePoolWithTag(PagedPool, arrlen, ALLOC_TAG);
    if (!treearr) {
        ERR("out of memory\n");
        ExFreePool(allocarr);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlInitializeBitMap(&context.alloc, allocarr, num_sectors);
    RtlClearAllBits(&context.alloc);

    RtlInitializeBitMap(&context.is_tree, treearr, num_sectors);
    RtlClearAllBits(&context.is_tree);

    context.parity_scratch = ExAllocatePoolWithTag(PagedPool, (ULONG)c->chunk_item->stripe_length, ALLOC_TAG);
    if (!context.parity_scratch) {
        ERR("out of memory\n");
        ExFreePool(allocarr);
        ExFreePool(treearr);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (c->chunk_item->type & BLOCK_FLAG_DATA) {
        csumarr = ExAllocatePoolWithTag(PagedPool, arrlen, ALLOC_TAG);
        if (!csumarr) {
            ERR("out of memory\n");
            ExFreePool(allocarr);
            ExFreePool(treearr);
            ExFreePool(context.parity_scratch);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlInitializeBitMap(&context.has_csum, csumarr, num_sectors);
        RtlClearAllBits(&context.has_csum);

        context.csum = ExAllocatePoolWithTag(PagedPool, num_sectors * sizeof(UINT32), ALLOC_TAG);
        if (!context.csum) {
            ERR("out of memory\n");
            ExFreePool(allocarr);
            ExFreePool(treearr);
            ExFreePool(context.parity_scratch);
            ExFreePool(csumarr);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    if (c->chunk_item->type & BLOCK_FLAG_RAID6) {
        context.parity_scratch2 = ExAllocatePoolWithTag(PagedPool, (ULONG)c->chunk_item->stripe_length, ALLOC_TAG);
        if (!context.parity_scratch2) {
            ERR("out of memory\n");
            ExFreePool(allocarr);
            ExFreePool(treearr);
            ExFreePool(context.parity_scratch);

            if (c->chunk_item->type & BLOCK_FLAG_DATA) {
                ExFreePool(csumarr);
                ExFreePool(context.csum);
            }

            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    do {
        traverse_ptr next_tp;

        if (tp.item->key.obj_id >= run_end)
            break;

        if (tp.item->key.obj_type == TYPE_EXTENT_ITEM || tp.item->key.obj_type == TYPE_METADATA_ITEM) {
            UINT64 size = tp.item->key.obj_type == TYPE_METADATA_ITEM ? Vcb->superblock.node_size : tp.item->key.offset;

            if (tp.item->key.obj_id + size > run_start) {
                UINT64 extent_start = max(run_start, tp.item->key.obj_id);
                UINT64 extent_end = min(tp.item->key.obj_id + size, run_end);
                BOOL extent_is_tree = FALSE;

                RtlSetBits(&context.alloc, (ULONG)((extent_start - run_start) / Vcb->superblock.sector_size), (ULONG)((extent_end - extent_start) / Vcb->superblock.sector_size));

                if (tp.item->key.obj_type == TYPE_METADATA_ITEM)
                    extent_is_tree = TRUE;
                else {
                    EXTENT_ITEM* ei = (EXTENT_ITEM*)tp.item->data;

                    if (tp.item->size < sizeof(EXTENT_ITEM)) {
                        ERR("(%llx,%x,%llx) was %u bytes, expected at least %u\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, tp.item->size, sizeof(EXTENT_ITEM));
                        Status = STATUS_INTERNAL_ERROR;
                        goto end;
                    }

                    if (ei->flags & EXTENT_ITEM_TREE_BLOCK)
                        extent_is_tree = TRUE;
                }

                if (extent_is_tree)
                    RtlSetBits(&context.is_tree, (ULONG)((extent_start - run_start) / Vcb->superblock.sector_size), (ULONG)((extent_end - extent_start) / Vcb->superblock.sector_size));
                else if (c->chunk_item->type & BLOCK_FLAG_DATA) {
                    traverse_ptr tp2;
                    BOOL b2;

                    searchkey.obj_id = EXTENT_CSUM_ID;
                    searchkey.obj_type = TYPE_EXTENT_CSUM;
                    searchkey.offset = extent_start;

                    Status = find_item(Vcb, Vcb->checksum_root, &tp2, &searchkey, FALSE, NULL);
                    if (!NT_SUCCESS(Status) && Status != STATUS_NOT_FOUND) {
                        ERR("find_item returned %08x\n", Status);
                        goto end;
                    }

                    do {
                        traverse_ptr next_tp2;

                        if (tp2.item->key.offset >= extent_end)
                            break;

                        if (tp2.item->key.offset >= extent_start) {
                            UINT64 csum_start = max(extent_start, tp2.item->key.offset);
                            UINT64 csum_end = min(extent_end, tp2.item->key.offset + (tp2.item->size * Vcb->superblock.sector_size / sizeof(UINT32)));

                            RtlSetBits(&context.has_csum, (ULONG)((csum_start - run_start) / Vcb->superblock.sector_size), (ULONG)((csum_end - csum_start) / Vcb->superblock.sector_size));

                            RtlCopyMemory(&context.csum[(csum_start - run_start) / Vcb->superblock.sector_size],
                                          tp2.item->data + ((csum_start - tp2.item->key.offset) * sizeof(UINT32) / Vcb->superblock.sector_size),
                                          (ULONG)((csum_end - csum_start) * sizeof(UINT32) / Vcb->superblock.sector_size));
                        }

                        b2 = find_next_item(Vcb, &tp2, &next_tp2, FALSE, NULL);

                        if (b2)
                            tp2 = next_tp2;
                    } while (b2);
                }
            }
        }

        b = find_next_item(Vcb, &tp, &next_tp, FALSE, NULL);

        if (b)
            tp = next_tp;
    } while (b);

    context.stripes = ExAllocatePoolWithTag(PagedPool, sizeof(scrub_context_raid56_stripe) * c->chunk_item->num_stripes, ALLOC_TAG);
    if (!context.stripes) {
        ERR("out of memory\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }

    max_read = (UINT32)min(1048576 / c->chunk_item->stripe_length, stripe_end - stripe_start + 1); // only process 1 MB of data at a time

    for (i = 0; i < c->chunk_item->num_stripes; i++) {
        context.stripes[i].buf = ExAllocatePoolWithTag(PagedPool, (ULONG)(max_read * c->chunk_item->stripe_length), ALLOC_TAG);
        if (!context.stripes[i].buf) {
            UINT64 j;

            ERR("out of memory\n");

            for (j = 0; j < i; j++) {
                ExFreePool(context.stripes[j].buf);
            }
            ExFreePool(context.stripes);

            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }

        context.stripes[i].errorarr = ExAllocatePoolWithTag(PagedPool, (ULONG)sector_align(((c->chunk_item->stripe_length / Vcb->superblock.sector_size) / 8) + 1, sizeof(ULONG)), ALLOC_TAG);
        if (!context.stripes[i].errorarr) {
            UINT64 j;

            ERR("out of memory\n");

            ExFreePool(context.stripes[i].buf);

            for (j = 0; j < i; j++) {
                ExFreePool(context.stripes[j].buf);
            }
            ExFreePool(context.stripes);

            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }

        RtlInitializeBitMap(&context.stripes[i].error, context.stripes[i].errorarr, (ULONG)(c->chunk_item->stripe_length / Vcb->superblock.sector_size));

        context.stripes[i].context = &context;
        context.stripes[i].rewrite = FALSE;
    }

    stripe = stripe_start;

    Status = STATUS_SUCCESS;

    chunk_lock_range(Vcb, c, run_start, run_end - run_start);

    do {
        ULONG read_stripes;
        UINT16 missing_devices = 0;
        BOOL need_wait = FALSE;

        if (max_read < stripe_end + 1 - stripe)
            read_stripes = max_read;
        else
            read_stripes = (ULONG)(stripe_end + 1 - stripe);

        context.stripes_left = c->chunk_item->num_stripes;

        // read megabyte by megabyte
        for (i = 0; i < c->chunk_item->num_stripes; i++) {
            if (c->devices[i]->devobj) {
                PIO_STACK_LOCATION IrpSp;

                context.stripes[i].Irp = IoAllocateIrp(c->devices[i]->devobj->StackSize, FALSE);

                if (!context.stripes[i].Irp) {
                    ERR("IoAllocateIrp failed\n");
                    Status = STATUS_INSUFFICIENT_RESOURCES;
                    goto end3;
                }

                context.stripes[i].Irp->MdlAddress = NULL;

                IrpSp = IoGetNextIrpStackLocation(context.stripes[i].Irp);
                IrpSp->MajorFunction = IRP_MJ_READ;

                if (c->devices[i]->devobj->Flags & DO_BUFFERED_IO) {
                    context.stripes[i].Irp->AssociatedIrp.SystemBuffer = ExAllocatePoolWithTag(NonPagedPool, (ULONG)(read_stripes * c->chunk_item->stripe_length), ALLOC_TAG);
                    if (!context.stripes[i].Irp->AssociatedIrp.SystemBuffer) {
                        ERR("out of memory\n");
                        Status = STATUS_INSUFFICIENT_RESOURCES;
                        goto end3;
                    }

                    context.stripes[i].Irp->Flags |= IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER | IRP_INPUT_OPERATION;

                    context.stripes[i].Irp->UserBuffer = context.stripes[i].buf;
                } else if (c->devices[i]->devobj->Flags & DO_DIRECT_IO) {
                    context.stripes[i].Irp->MdlAddress = IoAllocateMdl(context.stripes[i].buf, (ULONG)(read_stripes * c->chunk_item->stripe_length), FALSE, FALSE, NULL);
                    if (!context.stripes[i].Irp->MdlAddress) {
                        ERR("IoAllocateMdl failed\n");
                        Status = STATUS_INSUFFICIENT_RESOURCES;
                        goto end3;
                    }

                    Status = STATUS_SUCCESS;

                    try {
                        MmProbeAndLockPages(context.stripes[i].Irp->MdlAddress, KernelMode, IoWriteAccess);
                    } except (EXCEPTION_EXECUTE_HANDLER) {
                        Status = GetExceptionCode();
                    }

                    if (!NT_SUCCESS(Status)) {
                        ERR("MmProbeAndLockPages threw exception %08x\n", Status);
                        IoFreeMdl(context.stripes[i].Irp->MdlAddress);
                        goto end3;
                    }
                } else
                    context.stripes[i].Irp->UserBuffer = context.stripes[i].buf;

                context.stripes[i].offset = stripe * c->chunk_item->stripe_length;

                IrpSp->Parameters.Read.Length = (ULONG)(read_stripes * c->chunk_item->stripe_length);
                IrpSp->Parameters.Read.ByteOffset.QuadPart = cis[i].offset + context.stripes[i].offset;

                context.stripes[i].Irp->UserIosb = &context.stripes[i].iosb;
                context.stripes[i].missing = FALSE;

                IoSetCompletionRoutine(context.stripes[i].Irp, scrub_read_completion_raid56, &context.stripes[i], TRUE, TRUE, TRUE);

                Vcb->scrub.data_scrubbed += read_stripes * c->chunk_item->stripe_length;
                need_wait = TRUE;
            } else {
                context.stripes[i].Irp = NULL;
                context.stripes[i].missing = TRUE;
                missing_devices++;
                InterlockedDecrement(&context.stripes_left);
            }
        }

        if (c->chunk_item->type & BLOCK_FLAG_RAID5 && missing_devices > 1) {
            ERR("too many missing devices (%u, maximum 1)\n", missing_devices);
            Status = STATUS_UNEXPECTED_IO_ERROR;
            goto end3;
        } else if (c->chunk_item->type & BLOCK_FLAG_RAID6 && missing_devices > 2) {
            ERR("too many missing devices (%u, maximum 2)\n", missing_devices);
            Status = STATUS_UNEXPECTED_IO_ERROR;
            goto end3;
        }

        if (need_wait) {
            KeInitializeEvent(&context.Event, NotificationEvent, FALSE);

            for (i = 0; i < c->chunk_item->num_stripes; i++) {
                if (c->devices[i]->devobj)
                    IoCallDriver(c->devices[i]->devobj, context.stripes[i].Irp);
            }

            KeWaitForSingleObject(&context.Event, Executive, KernelMode, FALSE, NULL);
        }

        // return an error if any of the stripes returned an error
        for (i = 0; i < c->chunk_item->num_stripes; i++) {
            if (!context.stripes[i].missing && !NT_SUCCESS(context.stripes[i].iosb.Status)) {
                Status = context.stripes[i].iosb.Status;
                log_device_error(Vcb, c->devices[i], BTRFS_DEV_STAT_READ_ERRORS);
                goto end3;
            }
        }

        if (c->chunk_item->type & BLOCK_FLAG_RAID6) {
            for (i = 0; i < read_stripes; i++) {
                scrub_raid6_stripe(Vcb, c, &context, stripe_start, stripe, i, missing_devices);
            }
        } else {
            for (i = 0; i < read_stripes; i++) {
                scrub_raid5_stripe(Vcb, c, &context, stripe_start, stripe, i, missing_devices);
            }
        }
        stripe += read_stripes;

end3:
        for (i = 0; i < c->chunk_item->num_stripes; i++) {
            if (context.stripes[i].Irp) {
                if (c->devices[i]->devobj->Flags & DO_DIRECT_IO && context.stripes[i].Irp->MdlAddress) {
                    MmUnlockPages(context.stripes[i].Irp->MdlAddress);
                    IoFreeMdl(context.stripes[i].Irp->MdlAddress);
                }
                IoFreeIrp(context.stripes[i].Irp);
                context.stripes[i].Irp = NULL;

                if (context.stripes[i].rewrite) {
                    Status = write_data_phys(c->devices[i]->devobj, cis[i].offset + context.stripes[i].offset,
                                             context.stripes[i].buf, (UINT32)(read_stripes * c->chunk_item->stripe_length));

                    if (!NT_SUCCESS(Status)) {
                        ERR("write_data_phys returned %08x\n", Status);
                        log_device_error(Vcb, c->devices[i], BTRFS_DEV_STAT_WRITE_ERRORS);
                        goto end2;
                    }
                }
            }
        }

        if (!NT_SUCCESS(Status))
            break;
    } while (stripe < stripe_end);

end2:
    chunk_unlock_range(Vcb, c, run_start, run_end - run_start);

    for (i = 0; i < c->chunk_item->num_stripes; i++) {
        ExFreePool(context.stripes[i].buf);
        ExFreePool(context.stripes[i].errorarr);
    }
    ExFreePool(context.stripes);

end:
    ExFreePool(treearr);
    ExFreePool(allocarr);
    ExFreePool(context.parity_scratch);

    if (c->chunk_item->type & BLOCK_FLAG_RAID6)
        ExFreePool(context.parity_scratch2);

    if (c->chunk_item->type & BLOCK_FLAG_DATA) {
        ExFreePool(csumarr);
        ExFreePool(context.csum);
    }

    return Status;
}

static NTSTATUS scrub_chunk_raid56(device_extension* Vcb, chunk* c, UINT64* offset, BOOL* changed) {
    NTSTATUS Status;
    KEY searchkey;
    traverse_ptr tp;
    BOOL b;
    UINT64 full_stripe_len, stripe, stripe_start, stripe_end, total_data = 0;
    ULONG num_extents = 0, num_parity_stripes = c->chunk_item->type & BLOCK_FLAG_RAID6 ? 2 : 1;

    full_stripe_len = (c->chunk_item->num_stripes - num_parity_stripes) * c->chunk_item->stripe_length;
    stripe = (*offset - c->offset) / full_stripe_len;

    *offset = c->offset + (stripe * full_stripe_len);

    searchkey.obj_id = *offset;
    searchkey.obj_type = TYPE_METADATA_ITEM;
    searchkey.offset = 0xffffffffffffffff;

    Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, FALSE, NULL);
    if (!NT_SUCCESS(Status)) {
        ERR("find_item returned %08x\n", Status);
        return Status;
    }

    *changed = FALSE;

    do {
        traverse_ptr next_tp;

        if (tp.item->key.obj_id >= c->offset + c->chunk_item->size)
            break;

        if (tp.item->key.obj_id >= *offset && (tp.item->key.obj_type == TYPE_EXTENT_ITEM || tp.item->key.obj_type == TYPE_METADATA_ITEM)) {
            UINT64 size = tp.item->key.obj_type == TYPE_METADATA_ITEM ? Vcb->superblock.node_size : tp.item->key.offset;

            TRACE("%llx\n", tp.item->key.obj_id);

            if (size < Vcb->superblock.sector_size) {
                ERR("extent %llx has size less than sector_size (%llx < %x)\n", tp.item->key.obj_id, Vcb->superblock.sector_size);
                return STATUS_INTERNAL_ERROR;
            }

            stripe = (tp.item->key.obj_id - c->offset) / full_stripe_len;

            if (*changed) {
                if (stripe > stripe_end + 1) {
                    Status = scrub_chunk_raid56_stripe_run(Vcb, c, stripe_start, stripe_end);
                    if (!NT_SUCCESS(Status)) {
                        ERR("scrub_chunk_raid56_stripe_run returned %08x\n", Status);
                        return Status;
                    }

                    stripe_start = stripe;
                }
            } else
                stripe_start = stripe;

            stripe_end = (tp.item->key.obj_id + size - 1 - c->offset) / full_stripe_len;

            *changed = TRUE;

            total_data += size;
            num_extents++;

            // only do so much at a time
            if (num_extents >= 64 || total_data >= 0x8000000) // 128 MB
                break;
        }

        b = find_next_item(Vcb, &tp, &next_tp, FALSE, NULL);

        if (b)
            tp = next_tp;
    } while (b);

    if (*changed) {
        Status = scrub_chunk_raid56_stripe_run(Vcb, c, stripe_start, stripe_end);
        if (!NT_SUCCESS(Status)) {
            ERR("scrub_chunk_raid56_stripe_run returned %08x\n", Status);
            return Status;
        }

        *offset = c->offset + ((stripe_end + 1) * full_stripe_len);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS scrub_chunk(device_extension* Vcb, chunk* c, UINT64* offset, BOOL* changed) {
    NTSTATUS Status;
    KEY searchkey;
    traverse_ptr tp;
    BOOL b = FALSE, tree_run = FALSE;
    ULONG type, num_extents = 0;
    UINT64 total_data = 0, tree_run_start, tree_run_end;

    TRACE("chunk %llx\n", c->offset);

    ExAcquireResourceSharedLite(&Vcb->tree_lock, TRUE);

    if (c->chunk_item->type & BLOCK_FLAG_DUPLICATE)
        type = BLOCK_FLAG_DUPLICATE;
    else if (c->chunk_item->type & BLOCK_FLAG_RAID0)
        type = BLOCK_FLAG_RAID0;
    else if (c->chunk_item->type & BLOCK_FLAG_RAID1)
        type = BLOCK_FLAG_DUPLICATE;
    else if (c->chunk_item->type & BLOCK_FLAG_RAID10)
        type = BLOCK_FLAG_RAID10;
    else if (c->chunk_item->type & BLOCK_FLAG_RAID5) {
        Status = scrub_chunk_raid56(Vcb, c, offset, changed);
        goto end;
    } else if (c->chunk_item->type & BLOCK_FLAG_RAID6) {
        Status = scrub_chunk_raid56(Vcb, c, offset, changed);
        goto end;
    } else // SINGLE
        type = BLOCK_FLAG_DUPLICATE;

    searchkey.obj_id = *offset;
    searchkey.obj_type = TYPE_METADATA_ITEM;
    searchkey.offset = 0xffffffffffffffff;

    Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, FALSE, NULL);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08x\n", Status);
        goto end;
    }

    do {
        traverse_ptr next_tp;

        if (tp.item->key.obj_id >= c->offset + c->chunk_item->size)
            break;

        if (tp.item->key.obj_id >= *offset && (tp.item->key.obj_type == TYPE_EXTENT_ITEM || tp.item->key.obj_type == TYPE_METADATA_ITEM)) {
            UINT64 size = tp.item->key.obj_type == TYPE_METADATA_ITEM ? Vcb->superblock.node_size : tp.item->key.offset;
            BOOL is_tree;
            UINT32* csum = NULL;
            RTL_BITMAP bmp;
            ULONG* bmparr = NULL;

            TRACE("%llx\n", tp.item->key.obj_id);

            is_tree = FALSE;

            if (tp.item->key.obj_type == TYPE_METADATA_ITEM)
                is_tree = TRUE;
            else {
                EXTENT_ITEM* ei = (EXTENT_ITEM*)tp.item->data;

                if (tp.item->size < sizeof(EXTENT_ITEM)) {
                    ERR("(%llx,%x,%llx) was %u bytes, expected at least %u\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, tp.item->size, sizeof(EXTENT_ITEM));
                    Status = STATUS_INTERNAL_ERROR;
                    goto end;
                }

                if (ei->flags & EXTENT_ITEM_TREE_BLOCK)
                    is_tree = TRUE;
            }

            if (size < Vcb->superblock.sector_size) {
                ERR("extent %llx has size less than sector_size (%llx < %x)\n", tp.item->key.obj_id, Vcb->superblock.sector_size);
                Status = STATUS_INTERNAL_ERROR;
                goto end;
            }

            // load csum
            if (!is_tree) {
                traverse_ptr tp2;

                csum = ExAllocatePoolWithTag(PagedPool, (ULONG)(sizeof(UINT32) * size / Vcb->superblock.sector_size), ALLOC_TAG);
                if (!csum) {
                    ERR("out of memory\n");
                    Status = STATUS_INSUFFICIENT_RESOURCES;
                    goto end;
                }

                bmparr = ExAllocatePoolWithTag(PagedPool, (ULONG)(sector_align(((size / Vcb->superblock.sector_size) >> 3) + 1, sizeof(ULONG))), ALLOC_TAG);
                if (!bmparr) {
                    ERR("out of memory\n");
                    ExFreePool(csum);
                    Status = STATUS_INSUFFICIENT_RESOURCES;
                    goto end;
                }

                RtlInitializeBitMap(&bmp, bmparr, (ULONG)(size / Vcb->superblock.sector_size));
                RtlSetAllBits(&bmp); // 1 = no csum, 0 = csum

                searchkey.obj_id = EXTENT_CSUM_ID;
                searchkey.obj_type = TYPE_EXTENT_CSUM;
                searchkey.offset = tp.item->key.obj_id;

                Status = find_item(Vcb, Vcb->checksum_root, &tp2, &searchkey, FALSE, NULL);
                if (!NT_SUCCESS(Status) && Status != STATUS_NOT_FOUND) {
                    ERR("find_item returned %08x\n", Status);
                    ExFreePool(csum);
                    ExFreePool(bmparr);
                    goto end;
                }

                if (Status != STATUS_NOT_FOUND) {
                    do {
                        traverse_ptr next_tp2;

                        if (tp2.item->key.obj_type == TYPE_EXTENT_CSUM) {
                            if (tp2.item->key.offset >= tp.item->key.obj_id + size)
                                break;
                            else if (tp2.item->size >= sizeof(UINT32) && tp2.item->key.offset + (tp2.item->size * Vcb->superblock.sector_size / sizeof(UINT32)) >= tp.item->key.obj_id) {
                                UINT64 cs = max(tp.item->key.obj_id, tp2.item->key.offset);
                                UINT64 ce = min(tp.item->key.obj_id + size, tp2.item->key.offset + (tp2.item->size * Vcb->superblock.sector_size / sizeof(UINT32)));

                                RtlCopyMemory(csum + ((cs - tp.item->key.obj_id) / Vcb->superblock.sector_size),
                                              tp2.item->data + ((cs - tp2.item->key.offset) * sizeof(UINT32) / Vcb->superblock.sector_size),
                                              (ULONG)((ce - cs) * sizeof(UINT32) / Vcb->superblock.sector_size));

                                RtlClearBits(&bmp, (ULONG)((cs - tp.item->key.obj_id) / Vcb->superblock.sector_size), (ULONG)((ce - cs) / Vcb->superblock.sector_size));

                                if (ce == tp.item->key.obj_id + size)
                                    break;
                            }
                        }

                        if (find_next_item(Vcb, &tp2, &next_tp2, FALSE, NULL))
                            tp2 = next_tp2;
                        else
                            break;
                    } while (TRUE);
                }
            }

            if (tree_run) {
                if (!is_tree || tp.item->key.obj_id > tree_run_end) {
                    Status = scrub_extent(Vcb, c, type, tree_run_start, (UINT32)(tree_run_end - tree_run_start), NULL);
                    if (!NT_SUCCESS(Status)) {
                        ERR("scrub_extent returned %08x\n", Status);
                        goto end;
                    }

                    if (!is_tree)
                        tree_run = FALSE;
                    else {
                        tree_run_start = tp.item->key.obj_id;
                        tree_run_end = tp.item->key.obj_id + Vcb->superblock.node_size;
                    }
                } else
                    tree_run_end = tp.item->key.obj_id + Vcb->superblock.node_size;
            } else if (is_tree) {
                tree_run = TRUE;
                tree_run_start = tp.item->key.obj_id;
                tree_run_end = tp.item->key.obj_id + Vcb->superblock.node_size;
            }

            if (!is_tree) {
                Status = scrub_data_extent(Vcb, c, tp.item->key.obj_id, type, csum, &bmp);
                if (!NT_SUCCESS(Status)) {
                    ERR("scrub_data_extent returned %08x\n", Status);
                    ExFreePool(csum);
                    ExFreePool(bmparr);
                    goto end;
                }

                ExFreePool(csum);
                ExFreePool(bmparr);
            }

            *offset = tp.item->key.obj_id + size;
            *changed = TRUE;

            total_data += size;
            num_extents++;

            // only do so much at a time
            if (num_extents >= 64 || total_data >= 0x8000000) // 128 MB
                break;
        }

        b = find_next_item(Vcb, &tp, &next_tp, FALSE, NULL);

        if (b)
            tp = next_tp;
    } while (b);

    if (tree_run) {
        Status = scrub_extent(Vcb, c, type, tree_run_start, (UINT32)(tree_run_end - tree_run_start), NULL);
        if (!NT_SUCCESS(Status)) {
            ERR("scrub_extent returned %08x\n", Status);
            goto end;
        }
    }

    Status = STATUS_SUCCESS;

end:
    ExReleaseResourceLite(&Vcb->tree_lock);

    return Status;
}

_Function_class_(KSTART_ROUTINE)
static void scrub_thread(void* context) {
    device_extension* Vcb = context;
    LIST_ENTRY chunks, *le;
    NTSTATUS Status;
    LARGE_INTEGER time;

    KeInitializeEvent(&Vcb->scrub.finished, NotificationEvent, FALSE);

    InitializeListHead(&chunks);

    ExAcquireResourceExclusiveLite(&Vcb->tree_lock, TRUE);

    if (Vcb->need_write && !Vcb->readonly)
        Status = do_write(Vcb, NULL);
    else
        Status = STATUS_SUCCESS;

    free_trees(Vcb);

    if (!NT_SUCCESS(Status)) {
        ExReleaseResourceLite(&Vcb->tree_lock);
        ERR("do_write returned %08x\n", Status);
        Vcb->scrub.error = Status;
        goto end;
    }

    ExConvertExclusiveToSharedLite(&Vcb->tree_lock);

    ExAcquireResourceExclusiveLite(&Vcb->scrub.stats_lock, TRUE);

    KeQuerySystemTime(&Vcb->scrub.start_time);
    Vcb->scrub.finish_time.QuadPart = 0;
    Vcb->scrub.resume_time.QuadPart = Vcb->scrub.start_time.QuadPart;
    Vcb->scrub.duration.QuadPart = 0;
    Vcb->scrub.total_chunks = 0;
    Vcb->scrub.chunks_left = 0;
    Vcb->scrub.data_scrubbed = 0;
    Vcb->scrub.num_errors = 0;

    while (!IsListEmpty(&Vcb->scrub.errors)) {
        scrub_error* err = CONTAINING_RECORD(RemoveHeadList(&Vcb->scrub.errors), scrub_error, list_entry);
        ExFreePool(err);
    }

    ExAcquireResourceSharedLite(&Vcb->chunk_lock, TRUE);

    le = Vcb->chunks.Flink;
    while (le != &Vcb->chunks) {
        chunk* c = CONTAINING_RECORD(le, chunk, list_entry);

        ExAcquireResourceExclusiveLite(&c->lock, TRUE);

        if (!c->readonly) {
            InsertTailList(&chunks, &c->list_entry_balance);
            Vcb->scrub.total_chunks++;
            Vcb->scrub.chunks_left++;
        }

        ExReleaseResourceLite(&c->lock);

        le = le->Flink;
    }

    ExReleaseResourceLite(&Vcb->chunk_lock);

    ExReleaseResource(&Vcb->scrub.stats_lock);

    ExReleaseResourceLite(&Vcb->tree_lock);

    while (!IsListEmpty(&chunks)) {
        chunk* c = CONTAINING_RECORD(RemoveHeadList(&chunks), chunk, list_entry_balance);
        UINT64 offset = c->offset;
        BOOL changed;

        c->reloc = TRUE;

        KeWaitForSingleObject(&Vcb->scrub.event, Executive, KernelMode, FALSE, NULL);

        if (!Vcb->scrub.stopping) {
            do {
                changed = FALSE;

                Status = scrub_chunk(Vcb, c, &offset, &changed);
                if (!NT_SUCCESS(Status)) {
                    ERR("scrub_chunk returned %08x\n", Status);
                    Vcb->scrub.stopping = TRUE;
                    Vcb->scrub.error = Status;
                    break;
                }

                if (offset == c->offset + c->chunk_item->size || Vcb->scrub.stopping)
                    break;

                KeWaitForSingleObject(&Vcb->scrub.event, Executive, KernelMode, FALSE, NULL);
            } while (changed);
        }

        ExAcquireResourceExclusiveLite(&Vcb->scrub.stats_lock, TRUE);

        if (!Vcb->scrub.stopping)
            Vcb->scrub.chunks_left--;

        if (IsListEmpty(&chunks))
            KeQuerySystemTime(&Vcb->scrub.finish_time);

        ExReleaseResource(&Vcb->scrub.stats_lock);

        c->reloc = FALSE;
        c->list_entry_balance.Flink = NULL;
    }

    KeQuerySystemTime(&time);
    Vcb->scrub.duration.QuadPart += time.QuadPart - Vcb->scrub.resume_time.QuadPart;

end:
    ZwClose(Vcb->scrub.thread);
    Vcb->scrub.thread = NULL;

    KeSetEvent(&Vcb->scrub.finished, 0, FALSE);
}

NTSTATUS start_scrub(device_extension* Vcb, KPROCESSOR_MODE processor_mode) {
    NTSTATUS Status;

    if (!SeSinglePrivilegeCheck(RtlConvertLongToLuid(SE_MANAGE_VOLUME_PRIVILEGE), processor_mode))
        return STATUS_PRIVILEGE_NOT_HELD;

    if (Vcb->locked) {
        WARN("cannot start scrub while locked\n");
        return STATUS_DEVICE_NOT_READY;
    }

    if (Vcb->balance.thread) {
        WARN("cannot start scrub while balance running\n");
        return STATUS_DEVICE_NOT_READY;
    }

    if (Vcb->scrub.thread) {
        WARN("scrub already running\n");
        return STATUS_DEVICE_NOT_READY;
    }

    if (Vcb->readonly)
        return STATUS_MEDIA_WRITE_PROTECTED;

    Vcb->scrub.stopping = FALSE;
    Vcb->scrub.paused = FALSE;
    Vcb->scrub.error = STATUS_SUCCESS;
    KeInitializeEvent(&Vcb->scrub.event, NotificationEvent, !Vcb->scrub.paused);

    Status = PsCreateSystemThread(&Vcb->scrub.thread, 0, NULL, NULL, NULL, scrub_thread, Vcb);
    if (!NT_SUCCESS(Status)) {
        ERR("PsCreateSystemThread returned %08x\n", Status);
        return Status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS query_scrub(device_extension* Vcb, KPROCESSOR_MODE processor_mode, void* data, ULONG length) {
    btrfs_query_scrub* bqs = (btrfs_query_scrub*)data;
    ULONG len;
    NTSTATUS Status;
    LIST_ENTRY* le;
    btrfs_scrub_error* bse = NULL;

    if (!SeSinglePrivilegeCheck(RtlConvertLongToLuid(SE_MANAGE_VOLUME_PRIVILEGE), processor_mode))
        return STATUS_PRIVILEGE_NOT_HELD;

    if (length < offsetof(btrfs_query_scrub, errors))
        return STATUS_BUFFER_TOO_SMALL;

    ExAcquireResourceSharedLite(&Vcb->scrub.stats_lock, TRUE);

    if (Vcb->scrub.thread && Vcb->scrub.chunks_left > 0)
        bqs->status = Vcb->scrub.paused ? BTRFS_SCRUB_PAUSED : BTRFS_SCRUB_RUNNING;
    else
        bqs->status = BTRFS_SCRUB_STOPPED;

    bqs->start_time.QuadPart = Vcb->scrub.start_time.QuadPart;
    bqs->finish_time.QuadPart = Vcb->scrub.finish_time.QuadPart;
    bqs->chunks_left = Vcb->scrub.chunks_left;
    bqs->total_chunks = Vcb->scrub.total_chunks;
    bqs->data_scrubbed = Vcb->scrub.data_scrubbed;

    bqs->duration = Vcb->scrub.duration.QuadPart;

    if (bqs->status == BTRFS_SCRUB_RUNNING) {
        LARGE_INTEGER time;

        KeQuerySystemTime(&time);
        bqs->duration += time.QuadPart - Vcb->scrub.resume_time.QuadPart;
    }

    bqs->error = Vcb->scrub.error;

    bqs->num_errors = Vcb->scrub.num_errors;

    len = length - offsetof(btrfs_query_scrub, errors);

    le = Vcb->scrub.errors.Flink;
    while (le != &Vcb->scrub.errors) {
        scrub_error* err = CONTAINING_RECORD(le, scrub_error, list_entry);
        ULONG errlen;

        if (err->is_metadata)
            errlen = offsetof(btrfs_scrub_error, metadata.firstitem) + sizeof(KEY);
        else
            errlen = offsetof(btrfs_scrub_error, data.filename) + err->data.filename_length;

        if (len < errlen) {
            Status = STATUS_BUFFER_OVERFLOW;
            goto end;
        }

        if (!bse)
            bse = &bqs->errors;
        else {
            ULONG lastlen;

            if (bse->is_metadata)
                lastlen = offsetof(btrfs_scrub_error, metadata.firstitem) + sizeof(KEY);
            else
                lastlen = offsetof(btrfs_scrub_error, data.filename) + bse->data.filename_length;

            bse->next_entry = lastlen;
            bse = (btrfs_scrub_error*)(((UINT8*)bse) + lastlen);
        }

        bse->next_entry = 0;
        bse->address = err->address;
        bse->device = err->device;
        bse->recovered = err->recovered;
        bse->is_metadata = err->is_metadata;
        bse->parity = err->parity;

        if (err->is_metadata) {
            bse->metadata.root = err->metadata.root;
            bse->metadata.level = err->metadata.level;
            bse->metadata.firstitem = err->metadata.firstitem;
        } else {
            bse->data.subvol = err->data.subvol;
            bse->data.offset = err->data.offset;
            bse->data.filename_length = err->data.filename_length;
            RtlCopyMemory(bse->data.filename, err->data.filename, err->data.filename_length);
        }

        len -= errlen;
        le = le->Flink;
    }

    Status = STATUS_SUCCESS;

end:
    ExReleaseResourceLite(&Vcb->scrub.stats_lock);

    return Status;
}

NTSTATUS pause_scrub(device_extension* Vcb, KPROCESSOR_MODE processor_mode) {
    LARGE_INTEGER time;

    if (!SeSinglePrivilegeCheck(RtlConvertLongToLuid(SE_MANAGE_VOLUME_PRIVILEGE), processor_mode))
        return STATUS_PRIVILEGE_NOT_HELD;

    if (!Vcb->scrub.thread)
        return STATUS_DEVICE_NOT_READY;

    if (Vcb->scrub.paused)
        return STATUS_DEVICE_NOT_READY;

    Vcb->scrub.paused = TRUE;
    KeClearEvent(&Vcb->scrub.event);

    KeQuerySystemTime(&time);
    Vcb->scrub.duration.QuadPart += time.QuadPart - Vcb->scrub.resume_time.QuadPart;

    return STATUS_SUCCESS;
}

NTSTATUS resume_scrub(device_extension* Vcb, KPROCESSOR_MODE processor_mode) {
    if (!SeSinglePrivilegeCheck(RtlConvertLongToLuid(SE_MANAGE_VOLUME_PRIVILEGE), processor_mode))
        return STATUS_PRIVILEGE_NOT_HELD;

    if (!Vcb->scrub.thread)
        return STATUS_DEVICE_NOT_READY;

    if (!Vcb->scrub.paused)
        return STATUS_DEVICE_NOT_READY;

    Vcb->scrub.paused = FALSE;
    KeSetEvent(&Vcb->scrub.event, 0, FALSE);

    KeQuerySystemTime(&Vcb->scrub.resume_time);

    return STATUS_SUCCESS;
}

NTSTATUS stop_scrub(device_extension* Vcb, KPROCESSOR_MODE processor_mode) {
    if (!SeSinglePrivilegeCheck(RtlConvertLongToLuid(SE_MANAGE_VOLUME_PRIVILEGE), processor_mode))
        return STATUS_PRIVILEGE_NOT_HELD;

    if (!Vcb->scrub.thread)
        return STATUS_DEVICE_NOT_READY;

    Vcb->scrub.paused = FALSE;
    Vcb->scrub.stopping = TRUE;
    KeSetEvent(&Vcb->scrub.event, 0, FALSE);

    return STATUS_SUCCESS;
}
