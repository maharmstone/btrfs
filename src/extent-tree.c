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
#include "crc32c.h"

uint64_t get_extent_data_ref_hash2(uint64_t root, uint64_t objid, uint64_t offset) {
    uint32_t high_crc = 0xffffffff, low_crc = 0xffffffff;

    high_crc = calc_crc32c(high_crc, (uint8_t*)&root, sizeof(uint64_t));
    low_crc = calc_crc32c(low_crc, (uint8_t*)&objid, sizeof(uint64_t));
    low_crc = calc_crc32c(low_crc, (uint8_t*)&offset, sizeof(uint64_t));

    return ((uint64_t)high_crc << 31) ^ (uint64_t)low_crc;
}

NTSTATUS increase_extent_refcount_data(device_extension* Vcb, uint64_t address, uint64_t size, uint64_t root, uint64_t inode, uint64_t offset, uint32_t refcount, PIRP Irp) {
    NTSTATUS Status;
    struct btrfs_key searchkey;
    traverse_ptr tp;
    ULONG len, max_extent_item_size;
    struct btrfs_extent_item* ei;
    uint8_t* ptr;
    uint64_t inline_rc, hash;
    struct btrfs_extent_data_ref* data2;
    struct btrfs_extent_item* newei;

    searchkey.objectid = address;
    searchkey.type = BTRFS_EXTENT_ITEM_KEY;
    searchkey.offset = 0xffffffffffffffff;

    Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, false, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08lx\n", Status);
        return Status;
    }

    // If entry doesn't exist yet, create new inline extent item

    if (tp.item->key.objectid != searchkey.objectid || tp.item->key.type != BTRFS_EXTENT_ITEM_KEY) {
        uint16_t eisize;
        struct btrfs_extent_inline_ref* eir;
        struct btrfs_extent_data_ref* edr;

        eisize = sizeof(struct btrfs_extent_item);
        eisize += offsetof(struct btrfs_extent_inline_ref, offset);
        eisize += sizeof(struct btrfs_extent_data_ref);

        ei = ExAllocatePoolWithTag(PagedPool, eisize, ALLOC_TAG);
        if (!ei) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        ei->refs = refcount;
        ei->generation = Vcb->superblock.generation;
        ei->flags = BTRFS_EXTENT_FLAG_DATA;

        eir = (struct btrfs_extent_inline_ref*)&ei[1];
        eir->type = BTRFS_EXTENT_DATA_REF_KEY;

        edr = (struct btrfs_extent_data_ref*)&eir->offset;

        edr->root = root;
        edr->objectid = inode;
        edr->offset = offset;
        edr->count = refcount;

        Status = insert_tree_item(Vcb, Vcb->extent_root, address, BTRFS_EXTENT_ITEM_KEY, size, ei, eisize, NULL, Irp);

        if (!NT_SUCCESS(Status)) {
            ERR("insert_tree_item returned %08lx\n", Status);
            return Status;
        }

        return STATUS_SUCCESS;
    } else if (tp.item->key.objectid == address && tp.item->key.type == BTRFS_EXTENT_ITEM_KEY && tp.item->key.offset != size) {
        ERR("extent %I64x exists, but with size %I64x rather than %I64x as expected\n", tp.item->key.objectid, tp.item->key.offset, size);
        return STATUS_INTERNAL_ERROR;
    }

    if (tp.item->size == sizeof(struct btrfs_extent_item_v0)) {
        ERR("old-style extents no longer supported\n");
        return STATUS_INTERNAL_ERROR;
    }

    if (tp.item->size < sizeof(struct btrfs_extent_item)) {
        ERR("(%I64x,%x,%I64x) was %u bytes, expected at least %Iu\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset, tp.item->size, sizeof(struct btrfs_extent_item));
        return STATUS_INTERNAL_ERROR;
    }

    ei = (struct btrfs_extent_item*)tp.item->data;

    len = tp.item->size - sizeof(struct btrfs_extent_item);
    ptr = (uint8_t*)&ei[1];

    if (ei->flags & BTRFS_EXTENT_FLAG_TREE_BLOCK) {
        ERR("(%I64x,%x,%I64x) had TREE_BLOCK flag set\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset);
        return STATUS_INTERNAL_ERROR;
    }

    inline_rc = 0;

    // Loop through existing inline extent entries

    while (len > 0) {
        struct btrfs_extent_inline_ref* eir = (struct btrfs_extent_inline_ref*)ptr;

        if (len < sizeof(struct btrfs_extent_inline_ref)) {
            ERR("(%I64x,%x,%I64x) was truncated\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset);
            return STATUS_INTERNAL_ERROR;
        }

        ptr += sizeof(struct btrfs_extent_inline_ref);
        len -= sizeof(struct btrfs_extent_inline_ref);

        switch (eir->type) {
            case BTRFS_SHARED_DATA_REF_KEY: {
                struct btrfs_shared_data_ref* sdr;

                if (len < sizeof(struct btrfs_shared_data_ref)) {
                    ERR("(%I64x,%x,%I64x) was truncated\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset);
                    return STATUS_INTERNAL_ERROR;
                }

                sdr = (struct btrfs_shared_data_ref*)ptr;

                ptr += sizeof(struct btrfs_shared_data_ref);
                len -= sizeof(struct btrfs_shared_data_ref);
                inline_rc += sdr->count;

                break;
            }

            case BTRFS_EXTENT_DATA_REF_KEY:
                // If inline extent already present, increase refcount and return

                if (len < sizeof(struct btrfs_extent_data_ref) - sizeof(uint64_t)) {
                    ERR("(%I64x,%x,%I64x) was truncated\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset);
                    return STATUS_INTERNAL_ERROR;
                }

                struct btrfs_extent_data_ref* sectedr = (struct btrfs_extent_data_ref*)&eir->offset;

                if (sectedr->root == root && sectedr->objectid == inode && sectedr->offset == offset) {
                    struct btrfs_extent_data_ref* sectedr2;

                    newei = ExAllocatePoolWithTag(PagedPool, tp.item->size, ALLOC_TAG);
                    if (!newei) {
                        ERR("out of memory\n");
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }

                    RtlCopyMemory(newei, tp.item->data, tp.item->size);

                    newei->refs += refcount;

                    sectedr2 = (struct btrfs_extent_data_ref*)((uint8_t*)newei + ((uint8_t*)sectedr - tp.item->data));
                    sectedr2->count += refcount;

                    Status = delete_tree_item(Vcb, &tp);
                    if (!NT_SUCCESS(Status)) {
                        ERR("delete_tree_item returned %08lx\n", Status);
                        return Status;
                    }

                    Status = insert_tree_item(Vcb, Vcb->extent_root, tp.item->key.objectid, tp.item->key.type, tp.item->key.offset, newei, tp.item->size, NULL, Irp);
                    if (!NT_SUCCESS(Status)) {
                        ERR("insert_tree_item returned %08lx\n", Status);
                        return Status;
                    }

                    return STATUS_SUCCESS;
                }

                ptr += sizeof(struct btrfs_extent_data_ref) - sizeof(uint64_t);
                len -= sizeof(struct btrfs_extent_data_ref) - sizeof(uint64_t);
                inline_rc += sectedr->count;

                break;

            case BTRFS_TREE_BLOCK_REF_KEY:
            case BTRFS_SHARED_BLOCK_REF_KEY:
                inline_rc++;
                break;

            default:
                ERR("unknown extent item type %x\n", eir->type);
                return STATUS_INTERNAL_ERROR;
        }
    }

    hash = get_extent_data_ref_hash2(root, inode, offset);

    max_extent_item_size = (Vcb->superblock.nodesize >> 4) - sizeof(struct btrfs_item);

    // If we can, add entry as inline extent item

    if (inline_rc == ei->refs && tp.item->size + offsetof(struct btrfs_extent_inline_ref, offset) + sizeof(struct btrfs_extent_data_ref) < max_extent_item_size) {
        struct btrfs_extent_inline_ref* eir;
        struct btrfs_extent_data_ref* edr;

        len = tp.item->size - sizeof(struct btrfs_extent_item);
        ptr = (uint8_t*)&ei[1];

        // Confusingly, it appears that references are sorted forward by type (i.e. EXTENT_DATA_REFs before
        // SHARED_DATA_REFs), but then backwards by hash...

        while (len > 0) {
            struct btrfs_extent_inline_ref* eir = (struct btrfs_extent_inline_ref*)ptr;

            if (eir->type == BTRFS_TREE_BLOCK_REF_KEY) {
                len -= sizeof(struct btrfs_extent_inline_ref);
                ptr += sizeof(struct btrfs_extent_inline_ref);
            } else if (eir->type == BTRFS_EXTENT_DATA_REF_KEY) {
                struct btrfs_extent_data_ref* sectedr = (struct btrfs_extent_data_ref*)&eir->offset;
                uint64_t sectoff = get_extent_data_ref_hash2(sectedr->root, sectedr->objectid, sectedr->offset);

                if (sectoff < hash)
                    break;

                len -= offsetof(struct btrfs_extent_inline_ref, offset) + sizeof(struct btrfs_extent_data_ref);
                ptr += offsetof(struct btrfs_extent_inline_ref, offset) + sizeof(struct btrfs_extent_data_ref);
            } else
                break;
        }

        newei = ExAllocatePoolWithTag(PagedPool, tp.item->size + offsetof(struct btrfs_extent_inline_ref, offset) + sizeof(struct btrfs_extent_data_ref), ALLOC_TAG);
        if (!newei) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlCopyMemory(newei, tp.item->data, ptr - tp.item->data);

        newei->refs += refcount;

        if (len > 0)
            RtlCopyMemory((uint8_t*)newei + (ptr - tp.item->data) + offsetof(struct btrfs_extent_inline_ref, offset) + sizeof(struct btrfs_extent_data_ref), ptr, len);

        eir = (struct btrfs_extent_inline_ref*)((ptr - tp.item->data) + (uint8_t*)newei);

        eir->type = BTRFS_EXTENT_DATA_REF_KEY;

        edr = (struct btrfs_extent_data_ref*)&eir->offset;

        edr->root = root;
        edr->objectid = inode;
        edr->offset = offset;
        edr->count = refcount;

        Status = delete_tree_item(Vcb, &tp);
        if (!NT_SUCCESS(Status)) {
            ERR("delete_tree_item returned %08lx\n", Status);
            return Status;
        }

        Status = insert_tree_item(Vcb, Vcb->extent_root, tp.item->key.objectid, tp.item->key.type,
                                  tp.item->key.offset, newei, tp.item->size + offsetof(struct btrfs_extent_inline_ref, offset) + sizeof(struct btrfs_extent_data_ref),
                                  NULL, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("insert_tree_item returned %08lx\n", Status);
            return Status;
        }

        return STATUS_SUCCESS;
    }

    // Look for existing non-inline entry, and increase refcount if found

    if (inline_rc != ei->refs) {
        traverse_ptr tp2;

        searchkey.objectid = address;
        searchkey.type = BTRFS_EXTENT_DATA_REF_KEY;
        searchkey.offset = hash;

        Status = find_item(Vcb, Vcb->extent_root, &tp2, &searchkey, false, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("error - find_item returned %08lx\n", Status);
            return Status;
        }

        if (!keycmp(tp2.item->key, searchkey)) {
            struct btrfs_extent_data_ref* edr2;

            if (tp2.item->size < sizeof(struct btrfs_extent_data_ref)) {
                ERR("(%I64x,%x,%I64x) was %x bytes, expecting %Ix\n", tp2.item->key.objectid, tp2.item->key.type, tp2.item->key.offset, tp2.item->size, sizeof(struct btrfs_extent_data_ref));
                return STATUS_INTERNAL_ERROR;
            }

            data2 = ExAllocatePoolWithTag(PagedPool, tp2.item->size, ALLOC_TAG);
            if (!data2) {
                ERR("out of memory\n");
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            RtlCopyMemory(data2, tp2.item->data, tp2.item->size);

            edr2 = (struct btrfs_extent_data_ref*)data2;

            edr2->count += refcount;

            Status = delete_tree_item(Vcb, &tp2);
            if (!NT_SUCCESS(Status)) {
                ERR("delete_tree_item returned %08lx\n", Status);
                return Status;
            }

            Status = insert_tree_item(Vcb, Vcb->extent_root, tp2.item->key.objectid, tp2.item->key.type, tp2.item->key.offset, data2, tp2.item->size, NULL, Irp);
            if (!NT_SUCCESS(Status)) {
                ERR("insert_tree_item returned %08lx\n", Status);
                return Status;
            }

            newei = ExAllocatePoolWithTag(PagedPool, tp.item->size, ALLOC_TAG);
            if (!newei) {
                ERR("out of memory\n");
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            RtlCopyMemory(newei, tp.item->data, tp.item->size);

            newei->refs += refcount;

            Status = delete_tree_item(Vcb, &tp);
            if (!NT_SUCCESS(Status)) {
                ERR("delete_tree_item returned %08lx\n", Status);
                return Status;
            }

            Status = insert_tree_item(Vcb, Vcb->extent_root, tp.item->key.objectid, tp.item->key.type, tp.item->key.offset, newei, tp.item->size, NULL, Irp);
            if (!NT_SUCCESS(Status)) {
                ERR("insert_tree_item returned %08lx\n", Status);
                return Status;
            }

            return STATUS_SUCCESS;
        }
    }

    // Otherwise, add new non-inline entry

    data2 = ExAllocatePoolWithTag(PagedPool, sizeof(struct btrfs_extent_data_ref), ALLOC_TAG);
    if (!data2) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    data2->root = root;
    data2->objectid = inode;
    data2->offset = offset;
    data2->count = refcount;

    Status = insert_tree_item(Vcb, Vcb->extent_root, address, BTRFS_EXTENT_DATA_REF_KEY,
                              hash, data2, sizeof(struct btrfs_extent_data_ref),
                              NULL, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("insert_tree_item returned %08lx\n", Status);
        return Status;
    }

    newei = ExAllocatePoolWithTag(PagedPool, tp.item->size, ALLOC_TAG);
    if (!newei) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(newei, tp.item->data, tp.item->size);

    newei->refs += refcount;

    Status = delete_tree_item(Vcb, &tp);
    if (!NT_SUCCESS(Status)) {
        ERR("delete_tree_item returned %08lx\n", Status);
        return Status;
    }

    Status = insert_tree_item(Vcb, Vcb->extent_root, tp.item->key.objectid,
                              tp.item->key.type, tp.item->key.offset, newei,
                              tp.item->size, NULL, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("insert_tree_item returned %08lx\n", Status);
        return Status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS increase_extent_refcount_shared_data(device_extension* Vcb, uint64_t address,
                                              uint64_t size, uint64_t offset,
                                              uint32_t count, PIRP Irp) {
    NTSTATUS Status;
    struct btrfs_key searchkey;
    traverse_ptr tp;
    ULONG len, max_extent_item_size;
    struct btrfs_extent_item* ei;
    uint8_t* ptr;
    uint64_t inline_rc;
    struct btrfs_extent_item* newei;
    struct btrfs_shared_data_ref* sdr;

    searchkey.objectid = address;
    searchkey.type = BTRFS_EXTENT_ITEM_KEY;
    searchkey.offset = 0xffffffffffffffff;

    Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, false, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08lx\n", Status);
        return Status;
    }

    // If entry doesn't exist yet, create new inline extent item

    if (tp.item->key.objectid != searchkey.objectid || tp.item->key.type != BTRFS_EXTENT_ITEM_KEY) {
        struct btrfs_extent_inline_ref* eir;
        uint16_t eisize;

        eisize = sizeof(struct btrfs_extent_item);
        eisize += sizeof(struct btrfs_extent_inline_ref);
        eisize += sizeof(struct btrfs_shared_data_ref);

        ei = ExAllocatePoolWithTag(PagedPool, eisize, ALLOC_TAG);
        if (!ei) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        ei->refs = count;
        ei->generation = Vcb->superblock.generation;
        ei->flags = BTRFS_EXTENT_FLAG_DATA;

        eir = (struct btrfs_extent_inline_ref*)&ei[1];

        eir->type = BTRFS_SHARED_DATA_REF_KEY;
        eir->offset = offset;

        sdr = (struct btrfs_shared_data_ref*)&eir[1];
        sdr->count = count;

        Status = insert_tree_item(Vcb, Vcb->extent_root, address, BTRFS_EXTENT_ITEM_KEY,
                                  size, ei, eisize, NULL, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("insert_tree_item returned %08lx\n", Status);
            return Status;
        }

        return STATUS_SUCCESS;
    } else if (tp.item->key.objectid == address && tp.item->key.type == BTRFS_EXTENT_ITEM_KEY && tp.item->key.offset != size) {
        ERR("extent %I64x exists, but with size %I64x rather than %I64x as expected\n",
            tp.item->key.objectid, tp.item->key.offset, size);

        return STATUS_INTERNAL_ERROR;
    }

    if (tp.item->size == sizeof(struct btrfs_extent_item_v0)) {
        ERR("old-style extents no longer supported\n");
        return STATUS_INTERNAL_ERROR;
    }

    if (tp.item->size < sizeof(struct btrfs_extent_item)) {
        ERR("(%I64x,%x,%I64x) was %u bytes, expected at least %Iu\n",
            tp.item->key.objectid, tp.item->key.type, tp.item->key.offset,
            tp.item->size, sizeof(struct btrfs_extent_item));

        return STATUS_INTERNAL_ERROR;
    }

    ei = (struct btrfs_extent_item*)tp.item->data;

    len = tp.item->size - sizeof(struct btrfs_extent_item);
    ptr = (uint8_t*)&ei[1];

    if (ei->flags & BTRFS_EXTENT_FLAG_TREE_BLOCK) {
        ERR("(%I64x,%x,%I64x) had TREE_BLOCK flag set\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset);
        return STATUS_INTERNAL_ERROR;
    }

    inline_rc = 0;

    // Loop through existing inline extent entries

    while (len > 0) {
        struct btrfs_extent_inline_ref* eir = (struct btrfs_extent_inline_ref*)ptr;

        if (len < sizeof(struct btrfs_extent_inline_ref)) {
            ERR("(%I64x,%x,%I64x) was truncated\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset);
            return STATUS_INTERNAL_ERROR;
        }

        ptr += sizeof(struct btrfs_extent_inline_ref);
        len -= sizeof(struct btrfs_extent_inline_ref);

        switch (eir->type) {
            case BTRFS_SHARED_DATA_REF_KEY: {
                struct btrfs_shared_data_ref* sdr;

                if (len < sizeof(struct btrfs_shared_data_ref)) {
                    ERR("(%I64x,%x,%I64x) was truncated\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset);
                    return STATUS_INTERNAL_ERROR;
                }

                sdr = (struct btrfs_shared_data_ref*)ptr;

                // If inline extent already present, increase refcount and return

                if (eir->offset == offset) {
                    newei = ExAllocatePoolWithTag(PagedPool, tp.item->size, ALLOC_TAG);
                    if (!newei) {
                        ERR("out of memory\n");
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }

                    RtlCopyMemory(newei, tp.item->data, tp.item->size);

                    newei->refs += count;

                    sdr = (struct btrfs_shared_data_ref*)((uint8_t*)newei + ((uint8_t*)ptr - tp.item->data));
                    sdr->count += count;

                    Status = delete_tree_item(Vcb, &tp);
                    if (!NT_SUCCESS(Status)) {
                        ERR("delete_tree_item returned %08lx\n", Status);
                        return Status;
                    }

                    Status = insert_tree_item(Vcb, Vcb->extent_root, tp.item->key.objectid,
                                              tp.item->key.type, tp.item->key.offset,
                                              newei, tp.item->size, NULL, Irp);
                    if (!NT_SUCCESS(Status)) {
                        ERR("insert_tree_item returned %08lx\n", Status);
                        return Status;
                    }

                    return STATUS_SUCCESS;
                }

                ptr += sizeof(struct btrfs_shared_data_ref);
                len -= sizeof(struct btrfs_shared_data_ref);
                inline_rc += sdr->count;

                break;
            }

            case BTRFS_EXTENT_DATA_REF_KEY:
                if (len < sizeof(struct btrfs_extent_data_ref) - sizeof(uint64_t)) {
                    ERR("(%I64x,%x,%I64x) was truncated\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset);
                    return STATUS_INTERNAL_ERROR;
                }

                struct btrfs_extent_data_ref* sectedr = (struct btrfs_extent_data_ref*)&eir->offset;

                ptr += sizeof(struct btrfs_extent_data_ref) - sizeof(uint64_t);
                len -= sizeof(struct btrfs_extent_data_ref) - sizeof(uint64_t);
                inline_rc += sectedr->count;

                break;

            case BTRFS_TREE_BLOCK_REF_KEY:
            case BTRFS_SHARED_BLOCK_REF_KEY:
                inline_rc++;
                break;

            default:
                ERR("unknown extent item type %x\n", eir->type);
                return STATUS_INTERNAL_ERROR;
        }
    }

    max_extent_item_size = (Vcb->superblock.nodesize >> 4) - sizeof(struct btrfs_item);

    // If we can, add entry as inline extent item

    if (inline_rc == ei->refs && tp.item->size + sizeof(struct btrfs_extent_inline_ref) + sizeof(struct btrfs_shared_data_ref) < max_extent_item_size) {
        struct btrfs_extent_inline_ref* eir;

        len = tp.item->size - sizeof(struct btrfs_extent_item);
        ptr = (uint8_t*)&ei[1];

        // Confusingly, it appears that references are sorted forward by type (i.e. EXTENT_DATA_REFs before
        // SHARED_DATA_REFs), but then backwards by hash...

        while (len > 0) {
            eir = (struct btrfs_extent_inline_ref*)ptr;

            if (eir->type == BTRFS_TREE_BLOCK_REF_KEY) {
                len -= sizeof(struct btrfs_extent_inline_ref);
                ptr += sizeof(struct btrfs_extent_inline_ref);
            } else if (eir->type == BTRFS_EXTENT_DATA_REF_KEY) {
                len -= offsetof(struct btrfs_extent_inline_ref, offset) + sizeof(struct btrfs_extent_data_ref);
                ptr += offsetof(struct btrfs_extent_inline_ref, offset) + sizeof(struct btrfs_extent_data_ref);
            } else if (eir->type == BTRFS_SHARED_BLOCK_REF_KEY) {
                len -= sizeof(struct btrfs_extent_inline_ref);
                ptr += sizeof(struct btrfs_extent_inline_ref);
            } else if (eir->type == BTRFS_SHARED_DATA_REF_KEY) {
                if (eir->offset < offset)
                    break;

                len -= sizeof(struct btrfs_extent_inline_ref) + sizeof(struct btrfs_shared_data_ref);
                ptr += sizeof(struct btrfs_extent_inline_ref) + sizeof(struct btrfs_shared_data_ref);
            } else
                break;
        }

        newei = ExAllocatePoolWithTag(PagedPool, tp.item->size + sizeof(struct btrfs_extent_inline_ref) + sizeof(struct btrfs_shared_data_ref),
                                      ALLOC_TAG);
        if (!newei) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlCopyMemory(newei, tp.item->data, ptr - tp.item->data);

        newei->refs += count;

        if (len > 0)
            RtlCopyMemory((uint8_t*)newei + (ptr - tp.item->data) + sizeof(struct btrfs_extent_inline_ref) + sizeof(struct btrfs_shared_data_ref), ptr, len);

        eir = (struct btrfs_extent_inline_ref*)((ptr - tp.item->data) + (uint8_t*)newei);

        eir->type = BTRFS_SHARED_DATA_REF_KEY;
        eir->offset = offset;

        sdr = (struct btrfs_shared_data_ref*)&eir[1];

        sdr->count = count;

        Status = delete_tree_item(Vcb, &tp);
        if (!NT_SUCCESS(Status)) {
            ERR("delete_tree_item returned %08lx\n", Status);
            return Status;
        }

        Status = insert_tree_item(Vcb, Vcb->extent_root, tp.item->key.objectid,
                                  tp.item->key.type, tp.item->key.offset, newei,
                                  tp.item->size + sizeof(struct btrfs_extent_inline_ref) + sizeof(struct btrfs_shared_data_ref),
                                  NULL, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("insert_tree_item returned %08lx\n", Status);
            return Status;
        }

        return STATUS_SUCCESS;
    }

    // Look for existing non-inline entry, and increase refcount if found

    if (inline_rc != ei->refs) {
        traverse_ptr tp2;

        searchkey.objectid = address;
        searchkey.type = BTRFS_SHARED_DATA_REF_KEY;
        searchkey.offset = offset;

        Status = find_item(Vcb, Vcb->extent_root, &tp2, &searchkey, false, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("error - find_item returned %08lx\n", Status);
            return Status;
        }

        if (!keycmp(tp2.item->key, searchkey)) {
            if (tp2.item->size < sizeof(struct btrfs_shared_data_ref)) {
                ERR("(%I64x,%x,%I64x) was %x bytes, expecting %Ix\n",
                    tp2.item->key.objectid, tp2.item->key.type, tp2.item->key.offset,
                    tp2.item->size, sizeof(struct btrfs_shared_data_ref));
                return STATUS_INTERNAL_ERROR;
            }

            sdr = ExAllocatePoolWithTag(PagedPool, tp2.item->size, ALLOC_TAG);
            if (!sdr) {
                ERR("out of memory\n");
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            RtlCopyMemory(sdr, tp2.item->data, tp2.item->size);

            sdr->count += count;

            Status = delete_tree_item(Vcb, &tp2);
            if (!NT_SUCCESS(Status)) {
                ERR("delete_tree_item returned %08lx\n", Status);
                return Status;
            }

            Status = insert_tree_item(Vcb, Vcb->extent_root, tp2.item->key.objectid,
                                      tp2.item->key.type, tp2.item->key.offset,
                                      sdr, tp2.item->size, NULL, Irp);
            if (!NT_SUCCESS(Status)) {
                ERR("insert_tree_item returned %08lx\n", Status);
                return Status;
            }

            newei = ExAllocatePoolWithTag(PagedPool, tp.item->size, ALLOC_TAG);
            if (!newei) {
                ERR("out of memory\n");
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            RtlCopyMemory(newei, tp.item->data, tp.item->size);

            newei->refs += count;

            Status = delete_tree_item(Vcb, &tp);
            if (!NT_SUCCESS(Status)) {
                ERR("delete_tree_item returned %08lx\n", Status);
                return Status;
            }

            Status = insert_tree_item(Vcb, Vcb->extent_root, tp.item->key.objectid,
                                      tp.item->key.type, tp.item->key.offset,
                                      newei, tp.item->size, NULL, Irp);
            if (!NT_SUCCESS(Status)) {
                ERR("insert_tree_item returned %08lx\n", Status);
                return Status;
            }

            return STATUS_SUCCESS;
        }
    }

    // Otherwise, add new non-inline entry

    sdr = ExAllocatePoolWithTag(PagedPool, sizeof(struct btrfs_shared_data_ref),
                                ALLOC_TAG);
    if (!sdr) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    sdr->count = count;

    Status = insert_tree_item(Vcb, Vcb->extent_root, address, BTRFS_SHARED_DATA_REF_KEY,
                              offset, sdr, sizeof(struct btrfs_shared_data_ref),
                              NULL, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("insert_tree_item returned %08lx\n", Status);
        return Status;
    }

    newei = ExAllocatePoolWithTag(PagedPool, tp.item->size, ALLOC_TAG);
    if (!newei) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(newei, tp.item->data, tp.item->size);

    newei->refs += count;

    Status = delete_tree_item(Vcb, &tp);
    if (!NT_SUCCESS(Status)) {
        ERR("delete_tree_item returned %08lx\n", Status);
        return Status;
    }

    Status = insert_tree_item(Vcb, Vcb->extent_root, tp.item->key.objectid,
                              tp.item->key.type, tp.item->key.offset, newei,
                              tp.item->size, NULL, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("insert_tree_item returned %08lx\n", Status);
        return Status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS increase_extent_refcount_tree(device_extension* Vcb, uint64_t address,
                                       uint64_t offset, struct btrfs_key* firstitem,
                                       uint8_t level, PIRP Irp) {
    uint64_t size = Vcb->superblock.nodesize;
    NTSTATUS Status;
    struct btrfs_key searchkey;
    traverse_ptr tp;
    ULONG len, max_extent_item_size;
    struct btrfs_extent_item* ei;
    uint8_t* ptr;
    uint64_t inline_rc;
    struct btrfs_extent_item* newei;
    bool skinny;

    searchkey.objectid = address;
    searchkey.type = Vcb->superblock.incompat_flags & BTRFS_FEATURE_INCOMPAT_SKINNY_METADATA ? BTRFS_METADATA_ITEM_KEY : BTRFS_EXTENT_ITEM_KEY;
    searchkey.offset = 0xffffffffffffffff;

    Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, false, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08lx\n", Status);
        return Status;
    }

    // If entry doesn't exist yet, create new inline extent item

    if (tp.item->key.objectid != searchkey.objectid || (tp.item->key.type != BTRFS_EXTENT_ITEM_KEY && tp.item->key.type != BTRFS_METADATA_ITEM_KEY)) {
        struct btrfs_extent_inline_ref* eir;
        uint16_t eisize;

        eisize = sizeof(struct btrfs_extent_item);

        if (!(Vcb->superblock.incompat_flags & BTRFS_FEATURE_INCOMPAT_SKINNY_METADATA))
            eisize += sizeof(struct btrfs_tree_block_info);

        eisize += sizeof(struct btrfs_extent_inline_ref);

        ei = ExAllocatePoolWithTag(PagedPool, eisize, ALLOC_TAG);
        if (!ei) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        ei->refs = 1;
        ei->generation = Vcb->superblock.generation;
        ei->flags = BTRFS_EXTENT_FLAG_TREE_BLOCK;
        ptr = (uint8_t*)&ei[1];

        if (!(Vcb->superblock.incompat_flags & BTRFS_FEATURE_INCOMPAT_SKINNY_METADATA)) {
            struct btrfs_tree_block_info* ei2 = (struct btrfs_tree_block_info*)ptr;
            ei2->key = *firstitem;
            ei2->level = level;
            ptr = (uint8_t*)&ei2[1];
        }

        eir = (struct btrfs_extent_inline_ref*)ptr;
        eir->type = BTRFS_TREE_BLOCK_REF_KEY;
        eir->offset = offset;

        if (Vcb->superblock.incompat_flags & BTRFS_FEATURE_INCOMPAT_SKINNY_METADATA)
            Status = insert_tree_item(Vcb, Vcb->extent_root, address, BTRFS_METADATA_ITEM_KEY, level, ei, eisize, NULL, Irp);
        else
            Status = insert_tree_item(Vcb, Vcb->extent_root, address, BTRFS_EXTENT_ITEM_KEY, size, ei, eisize, NULL, Irp);

        if (!NT_SUCCESS(Status)) {
            ERR("insert_tree_item returned %08lx\n", Status);
            return Status;
        }

        return STATUS_SUCCESS;
    } else if (tp.item->key.objectid == address && tp.item->key.type == BTRFS_EXTENT_ITEM_KEY && tp.item->key.offset != size) {
        ERR("extent %I64x exists, but with size %I64x rather than %I64x expected\n", tp.item->key.objectid, tp.item->key.offset, size);
        return STATUS_INTERNAL_ERROR;
    }

    skinny = tp.item->key.type == BTRFS_METADATA_ITEM_KEY;

    if (tp.item->size == sizeof(struct btrfs_extent_item_v0) && !skinny) {
        ERR("old-style extents no longer supported\n");
        return STATUS_INTERNAL_ERROR;
    }

    if (tp.item->size < sizeof(struct btrfs_extent_item)) {
        ERR("(%I64x,%x,%I64x) was %u bytes, expected at least %Iu\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset, tp.item->size, sizeof(struct btrfs_extent_item));
        return STATUS_INTERNAL_ERROR;
    }

    ei = (struct btrfs_extent_item*)tp.item->data;

    len = tp.item->size - sizeof(struct btrfs_extent_item);
    ptr = (uint8_t*)&ei[1];

    if (ei->flags & BTRFS_EXTENT_FLAG_TREE_BLOCK && !skinny) {
        if (tp.item->size < sizeof(struct btrfs_extent_item) + sizeof(struct btrfs_tree_block_info)) {
            ERR("(%I64x,%x,%I64x) was %u bytes, expected at least %Iu\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset, tp.item->size, sizeof(struct btrfs_extent_item) + sizeof(struct btrfs_tree_block_info));
            return STATUS_INTERNAL_ERROR;
        }

        len -= sizeof(struct btrfs_tree_block_info);
        ptr += sizeof(struct btrfs_tree_block_info);
    }

    inline_rc = 0;

    // Loop through existing inline extent entries

    while (len > 0) {
        struct btrfs_extent_inline_ref* eir = (struct btrfs_extent_inline_ref*)ptr;

        if (len < sizeof(struct btrfs_extent_inline_ref)) {
            ERR("(%I64x,%x,%I64x) was truncated\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset);
            return STATUS_INTERNAL_ERROR;
        }

        ptr += sizeof(struct btrfs_extent_inline_ref);
        len -= sizeof(struct btrfs_extent_inline_ref);

        switch (eir->type) {
            case BTRFS_SHARED_DATA_REF_KEY: {
                struct btrfs_shared_data_ref* sdr;

                if (len < sizeof(struct btrfs_shared_data_ref)) {
                    ERR("(%I64x,%x,%I64x) was truncated\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset);
                    return STATUS_INTERNAL_ERROR;
                }

                sdr = (struct btrfs_shared_data_ref*)ptr;

                ptr += sizeof(struct btrfs_shared_data_ref);
                len -= sizeof(struct btrfs_shared_data_ref);
                inline_rc += sdr->count;

                break;
            }

            case BTRFS_EXTENT_DATA_REF_KEY: {
                if (len < sizeof(struct btrfs_extent_data_ref) - sizeof(uint64_t)) {
                    ERR("(%I64x,%x,%I64x) was truncated\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset);
                    return STATUS_INTERNAL_ERROR;
                }

                struct btrfs_extent_data_ref* sectedr = (struct btrfs_extent_data_ref*)&eir->offset;

                ptr += sizeof(struct btrfs_extent_data_ref) - sizeof(uint64_t);
                len -= sizeof(struct btrfs_extent_data_ref) - sizeof(uint64_t);
                inline_rc += sectedr->count;

                break;
            }

            case BTRFS_TREE_BLOCK_REF_KEY: {
                if (eir->offset == offset) {
                    TRACE("trying to increase refcount of non-shared tree extent\n");
                    return STATUS_SUCCESS;
                }

                inline_rc++;
                break;
            }

            case BTRFS_SHARED_BLOCK_REF_KEY:
                inline_rc++;
                break;

            default:
                ERR("unknown extent item type %x\n", eir->type);
                return STATUS_INTERNAL_ERROR;
        }
    }

    max_extent_item_size = (Vcb->superblock.nodesize >> 4) - sizeof(struct btrfs_item);

    // If we can, add entry as inline extent item

    if (inline_rc == ei->refs && tp.item->size + sizeof(struct btrfs_extent_inline_ref) < max_extent_item_size) {
        struct btrfs_extent_inline_ref* eir;

        len = tp.item->size - sizeof(struct btrfs_extent_item);
        ptr = (uint8_t*)&ei[1];

        if (ei->flags & BTRFS_EXTENT_FLAG_TREE_BLOCK && !skinny) {
            len -= sizeof(struct btrfs_tree_block_info);
            ptr += sizeof(struct btrfs_tree_block_info);
        }

        // Confusingly, it appears that references are sorted forward by type (i.e. EXTENT_DATA_REFs before
        // SHARED_DATA_REFs), but then backwards by hash...

        while (len > 0) {
            eir = (struct btrfs_extent_inline_ref*)ptr;

            if (eir->type == BTRFS_TREE_BLOCK_REF_KEY) {
                if (eir->offset < offset)
                    break;

                len -= sizeof(struct btrfs_extent_inline_ref);
                ptr += sizeof(struct btrfs_extent_inline_ref);
            } else
                break;
        }

        newei = ExAllocatePoolWithTag(PagedPool, tp.item->size + sizeof(struct btrfs_extent_inline_ref), ALLOC_TAG);
        if (!newei) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlCopyMemory(newei, tp.item->data, ptr - tp.item->data);

        newei->refs++;

        if (len > 0)
            RtlCopyMemory((uint8_t*)newei + (ptr - tp.item->data) + sizeof(struct btrfs_extent_inline_ref), ptr, len);

        eir = (struct btrfs_extent_inline_ref*)((ptr - tp.item->data) + (uint8_t*)newei);

        eir->type = BTRFS_TREE_BLOCK_REF_KEY;
        eir->offset = offset;

        Status = delete_tree_item(Vcb, &tp);
        if (!NT_SUCCESS(Status)) {
            ERR("delete_tree_item returned %08lx\n", Status);
            return Status;
        }

        Status = insert_tree_item(Vcb, Vcb->extent_root, tp.item->key.objectid,
                                  tp.item->key.type, tp.item->key.offset, newei,
                                  tp.item->size + sizeof(struct btrfs_extent_inline_ref), NULL, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("insert_tree_item returned %08lx\n", Status);
            return Status;
        }

        return STATUS_SUCCESS;
    }

    // Look for existing non-inline entry, and increase refcount if found

    if (inline_rc != ei->refs) {
        traverse_ptr tp2;

        searchkey.objectid = address;
        searchkey.type = BTRFS_TREE_BLOCK_REF_KEY;
        searchkey.offset = offset;

        Status = find_item(Vcb, Vcb->extent_root, &tp2, &searchkey, false, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("error - find_item returned %08lx\n", Status);
            return Status;
        }

        if (!keycmp(tp2.item->key, searchkey)) {
            TRACE("trying to increase refcount of non-shared tree extent\n");
            return STATUS_SUCCESS;
        }
    }

    // Otherwise, add new non-inline entry

    Status = insert_tree_item(Vcb, Vcb->extent_root, address, BTRFS_TREE_BLOCK_REF_KEY,
                              offset, NULL, 0, NULL, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("insert_tree_item returned %08lx\n", Status);
        return Status;
    }

    newei = ExAllocatePoolWithTag(PagedPool, tp.item->size, ALLOC_TAG);
    if (!newei) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(newei, tp.item->data, tp.item->size);

    newei->refs++;

    Status = delete_tree_item(Vcb, &tp);
    if (!NT_SUCCESS(Status)) {
        ERR("delete_tree_item returned %08lx\n", Status);
        return Status;
    }

    Status = insert_tree_item(Vcb, Vcb->extent_root, tp.item->key.objectid,
                              tp.item->key.type, tp.item->key.offset, newei,
                              tp.item->size, NULL, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("insert_tree_item returned %08lx\n", Status);
        return Status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS increase_extent_refcount_shared_block(device_extension* Vcb, uint64_t address,
                                               uint64_t offset, struct btrfs_key* firstitem,
                                               uint8_t level, PIRP Irp) {
    NTSTATUS Status;
    struct btrfs_key searchkey;
    traverse_ptr tp;
    ULONG len, max_extent_item_size;
    struct btrfs_extent_item* ei;
    uint8_t* ptr;
    uint64_t inline_rc;
    struct btrfs_extent_item* newei;
    bool skinny;

    searchkey.objectid = address;
    searchkey.type = Vcb->superblock.incompat_flags & BTRFS_FEATURE_INCOMPAT_SKINNY_METADATA ? BTRFS_METADATA_ITEM_KEY : BTRFS_EXTENT_ITEM_KEY;
    searchkey.offset = 0xffffffffffffffff;

    Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, false, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08lx\n", Status);
        return Status;
    }

    // If entry doesn't exist yet, create new inline extent item

    if (tp.item->key.objectid != searchkey.objectid || (tp.item->key.type != BTRFS_EXTENT_ITEM_KEY && tp.item->key.type != BTRFS_METADATA_ITEM_KEY)) {
        struct btrfs_extent_inline_ref* eir;
        uint16_t eisize;

        eisize = sizeof(struct btrfs_extent_item);

        if (!(Vcb->superblock.incompat_flags & BTRFS_FEATURE_INCOMPAT_SKINNY_METADATA))
            eisize += sizeof(struct btrfs_tree_block_info);

        eisize += sizeof(struct btrfs_extent_inline_ref);

        ei = ExAllocatePoolWithTag(PagedPool, eisize, ALLOC_TAG);
        if (!ei) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        ei->refs = 1;
        ei->generation = Vcb->superblock.generation;
        ei->flags = BTRFS_EXTENT_FLAG_TREE_BLOCK;
        ptr = (uint8_t*)&ei[1];

        if (!(Vcb->superblock.incompat_flags & BTRFS_FEATURE_INCOMPAT_SKINNY_METADATA)) {
            struct btrfs_tree_block_info* ei2 = (struct btrfs_tree_block_info*)ptr;
            ei2->key = *firstitem;
            ei2->level = level;
            ptr = (uint8_t*)&ei2[1];
        }

        eir = (struct btrfs_extent_inline_ref*)ptr;
        eir->type = BTRFS_SHARED_BLOCK_REF_KEY;
        eir->offset = offset;

        if (Vcb->superblock.incompat_flags & BTRFS_FEATURE_INCOMPAT_SKINNY_METADATA) {
            Status = insert_tree_item(Vcb, Vcb->extent_root, address, BTRFS_METADATA_ITEM_KEY,
                                      level, ei, eisize, NULL, Irp);
        } else {
            Status = insert_tree_item(Vcb, Vcb->extent_root, address, BTRFS_EXTENT_ITEM_KEY,
                                      Vcb->superblock.nodesize, ei, eisize, NULL, Irp);
        }

        if (!NT_SUCCESS(Status)) {
            ERR("insert_tree_item returned %08lx\n", Status);
            return Status;
        }

        return STATUS_SUCCESS;
    } else if (tp.item->key.objectid == address && tp.item->key.type == BTRFS_EXTENT_ITEM_KEY && tp.item->key.offset != Vcb->superblock.nodesize) {
        ERR("extent %I64x exists, but with size %I64x rather than %x as expected\n",
            tp.item->key.objectid, tp.item->key.offset, Vcb->superblock.nodesize);

        return STATUS_INTERNAL_ERROR;
    }

    skinny = tp.item->key.type == BTRFS_METADATA_ITEM_KEY;

    if (tp.item->size == sizeof(struct btrfs_extent_item_v0) && !skinny) {
        ERR("old-style extents no longer supported\n");
        return STATUS_INTERNAL_ERROR;
    }

    if (tp.item->size < sizeof(struct btrfs_extent_item)) {
        ERR("(%I64x,%x,%I64x) was %u bytes, expected at least %Iu\n",
            tp.item->key.objectid, tp.item->key.type, tp.item->key.offset,
            tp.item->size, sizeof(struct btrfs_extent_item));

        return STATUS_INTERNAL_ERROR;
    }

    ei = (struct btrfs_extent_item*)tp.item->data;

    len = tp.item->size - sizeof(struct btrfs_extent_item);
    ptr = (uint8_t*)&ei[1];

    if (ei->flags & BTRFS_EXTENT_FLAG_TREE_BLOCK && !skinny) {
        if (tp.item->size < sizeof(struct btrfs_extent_item) + sizeof(struct btrfs_tree_block_info)) {
            ERR("(%I64x,%x,%I64x) was %u bytes, expected at least %Iu\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset, tp.item->size, sizeof(struct btrfs_extent_item) + sizeof(struct btrfs_tree_block_info));
            return STATUS_INTERNAL_ERROR;
        }

        len -= sizeof(struct btrfs_tree_block_info);
        ptr += sizeof(struct btrfs_tree_block_info);
    }

    inline_rc = 0;

    // Loop through existing inline extent entries

    while (len > 0) {
        struct btrfs_extent_inline_ref* eir = (struct btrfs_extent_inline_ref*)ptr;

        if (len < sizeof(struct btrfs_extent_inline_ref)) {
            ERR("(%I64x,%x,%I64x) was truncated\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset);
            return STATUS_INTERNAL_ERROR;
        }

        ptr += sizeof(struct btrfs_extent_inline_ref);
        len -= sizeof(struct btrfs_extent_inline_ref);

        switch (eir->type) {
            case BTRFS_EXTENT_DATA_REF_KEY: {
                if (len < sizeof(struct btrfs_extent_data_ref) - sizeof(uint64_t)) {
                    ERR("(%I64x,%x,%I64x) was truncated\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset);
                    return STATUS_INTERNAL_ERROR;
                }

                struct btrfs_extent_data_ref* sectedr = (struct btrfs_extent_data_ref*)&eir->offset;

                ptr += sizeof(struct btrfs_extent_data_ref) - sizeof(uint64_t);
                len -= sizeof(struct btrfs_extent_data_ref) - sizeof(uint64_t);
                inline_rc += sectedr->count;

                break;
            }

            case BTRFS_TREE_BLOCK_REF_KEY:
                inline_rc++;
                break;

            case BTRFS_SHARED_BLOCK_REF_KEY:
                if (eir->offset == offset) {
                    TRACE("trying to increase refcount of shared block ref\n");
                    return STATUS_SUCCESS;
                }

                inline_rc++;
                break;

            case BTRFS_SHARED_DATA_REF_KEY: {
                struct btrfs_shared_data_ref* sdr;

                if (len < sizeof(struct btrfs_shared_data_ref)) {
                    ERR("(%I64x,%x,%I64x) was truncated\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset);
                    return STATUS_INTERNAL_ERROR;
                }

                sdr = (struct btrfs_shared_data_ref*)ptr;

                ptr += sizeof(struct btrfs_shared_data_ref);
                len -= sizeof(struct btrfs_shared_data_ref);
                inline_rc += sdr->count;

                break;
            }

            default:
                ERR("unknown extent item type %x\n", eir->type);
                return STATUS_INTERNAL_ERROR;
        }
    }

    max_extent_item_size = (Vcb->superblock.nodesize >> 4) - sizeof(struct btrfs_item);

    // If we can, add entry as inline extent item

    if (inline_rc == ei->refs && tp.item->size + sizeof(struct btrfs_extent_inline_ref) < max_extent_item_size) {
        struct btrfs_extent_inline_ref* eir;

        len = tp.item->size - sizeof(struct btrfs_extent_item);
        ptr = (uint8_t*)&ei[1];

        if (ei->flags & BTRFS_EXTENT_FLAG_TREE_BLOCK && !skinny) {
            len -= sizeof(struct btrfs_tree_block_info);
            ptr += sizeof(struct btrfs_tree_block_info);
        }

        // Confusingly, it appears that references are sorted forward by type (i.e. EXTENT_DATA_REFs before
        // SHARED_DATA_REFs), but then backwards by hash...

        while (len > 0) {
            struct btrfs_extent_inline_ref* eir = (struct btrfs_extent_inline_ref*)ptr;

            if (eir->type == BTRFS_TREE_BLOCK_REF_KEY) {
                len -= sizeof(struct btrfs_extent_inline_ref);
                ptr += sizeof(struct btrfs_extent_inline_ref);
            } else if (eir->type == BTRFS_EXTENT_DATA_REF_KEY) {
                len -= offsetof(struct btrfs_extent_inline_ref, offset) + sizeof(struct btrfs_extent_data_ref);
                ptr += offsetof(struct btrfs_extent_inline_ref, offset) + sizeof(struct btrfs_extent_data_ref);
            } else if (eir->type == BTRFS_SHARED_BLOCK_REF_KEY) {
                if (eir->offset < offset)
                    break;

                len -= sizeof(struct btrfs_extent_inline_ref);
                ptr += sizeof(struct btrfs_extent_inline_ref);
            } else
                break;
        }

        newei = ExAllocatePoolWithTag(PagedPool, tp.item->size + sizeof(struct btrfs_extent_inline_ref),
                                      ALLOC_TAG);
        if (!newei) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlCopyMemory(newei, tp.item->data, ptr - tp.item->data);

        newei->refs++;

        if (len > 0)
            RtlCopyMemory((uint8_t*)newei + (ptr - tp.item->data) + sizeof(struct btrfs_extent_inline_ref), ptr, len);

        eir = (struct btrfs_extent_inline_ref*)((ptr - tp.item->data) + (uint8_t*)newei);

        eir->type = BTRFS_SHARED_BLOCK_REF_KEY;
        eir->offset = offset;

        Status = delete_tree_item(Vcb, &tp);
        if (!NT_SUCCESS(Status)) {
            ERR("delete_tree_item returned %08lx\n", Status);
            return Status;
        }

        Status = insert_tree_item(Vcb, Vcb->extent_root, tp.item->key.objectid,
                                  tp.item->key.type, tp.item->key.offset, newei,
                                  tp.item->size + sizeof(struct btrfs_extent_inline_ref),
                                  NULL, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("insert_tree_item returned %08lx\n", Status);
            return Status;
        }

        return STATUS_SUCCESS;
    }

    // Look for existing non-inline entry, and increase refcount if found

    if (inline_rc != ei->refs) {
        traverse_ptr tp2;

        searchkey.objectid = address;
        searchkey.type = BTRFS_SHARED_BLOCK_REF_KEY;
        searchkey.offset = offset;

        Status = find_item(Vcb, Vcb->extent_root, &tp2, &searchkey, false, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("error - find_item returned %08lx\n", Status);
            return Status;
        }

        if (!keycmp(tp2.item->key, searchkey)) {
            TRACE("trying to increase refcount of shared block ref\n");
            return STATUS_SUCCESS;
        }
    }

    // Otherwise, add new non-inline entry

    Status = insert_tree_item(Vcb, Vcb->extent_root, address, BTRFS_SHARED_BLOCK_REF_KEY,
                              offset, NULL, 0, NULL, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("insert_tree_item returned %08lx\n", Status);
        return Status;
    }

    newei = ExAllocatePoolWithTag(PagedPool, tp.item->size, ALLOC_TAG);
    if (!newei) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(newei, tp.item->data, tp.item->size);

    newei->refs++;

    Status = delete_tree_item(Vcb, &tp);
    if (!NT_SUCCESS(Status)) {
        ERR("delete_tree_item returned %08lx\n", Status);
        return Status;
    }

    Status = insert_tree_item(Vcb, Vcb->extent_root, tp.item->key.objectid,
                              tp.item->key.type, tp.item->key.offset, newei,
                              tp.item->size, NULL, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("insert_tree_item returned %08lx\n", Status);
        return Status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS decrease_extent_refcount_data(device_extension* Vcb, uint64_t address,
                                       uint64_t size, uint64_t root, uint64_t inode,
                                       uint64_t offset, uint32_t refcount,
                                       bool superseded, PIRP Irp) {
    struct btrfs_key searchkey;
    NTSTATUS Status;
    traverse_ptr tp, tp2;
    struct btrfs_extent_item* ei;
    ULONG len;
    uint64_t inline_rc;
    uint8_t* ptr;
    struct btrfs_extent_data_ref* sectedr;

    searchkey.objectid = address;
    searchkey.type = BTRFS_EXTENT_ITEM_KEY;
    searchkey.offset = 0xffffffffffffffff;

    Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, false, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08lx\n", Status);
        return Status;
    }

    if (tp.item->key.objectid != searchkey.objectid || tp.item->key.type != searchkey.type) {
        ERR("could not find EXTENT_ITEM for address %I64x\n", address);
        return STATUS_INTERNAL_ERROR;
    }

    if (tp.item->key.offset != size) {
        ERR("extent %I64x had length %I64x, not %I64x as expected\n", address,
            tp.item->key.offset, size);

        return STATUS_INTERNAL_ERROR;
    }

    if (tp.item->size == sizeof(struct btrfs_extent_item_v0)) {
        ERR("old-style extents no longer supported\n");
        return STATUS_INTERNAL_ERROR;
    }

    if (tp.item->size < sizeof(struct btrfs_extent_item)) {
        ERR("(%I64x,%x,%I64x) was %u bytes, expected at least %Iu\n",
            tp.item->key.objectid, tp.item->key.type, tp.item->key.offset,
            tp.item->size, sizeof(struct btrfs_extent_item));

        return STATUS_INTERNAL_ERROR;
    }

    ei = (struct btrfs_extent_item*)tp.item->data;

    len = tp.item->size - sizeof(struct btrfs_extent_item);
    ptr = (uint8_t*)&ei[1];

    if (ei->flags & BTRFS_EXTENT_FLAG_TREE_BLOCK) {
        ERR("(%I64x,%x,%I64x) had TREE_BLOCK flag set\n", tp.item->key.objectid,
            tp.item->key.type, tp.item->key.offset);

        return STATUS_INTERNAL_ERROR;
    }

    if (ei->refs < refcount) {
        ERR("error - extent has refcount %I64x, trying to reduce by %x\n",
            ei->refs, refcount);

        return STATUS_INTERNAL_ERROR;
    }

    inline_rc = 0;

    // Loop through inline extent entries

    while (len > 0) {
        struct btrfs_extent_inline_ref* eir = (struct btrfs_extent_inline_ref*)ptr;

        if (len < sizeof(struct btrfs_extent_inline_ref)) {
            ERR("(%I64x,%x,%I64x) was truncated\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset);
            return STATUS_INTERNAL_ERROR;
        }

        ptr += sizeof(struct btrfs_extent_inline_ref);
        len -= sizeof(struct btrfs_extent_inline_ref);

        switch (eir->type) {
            case BTRFS_SHARED_DATA_REF_KEY: {
                struct btrfs_shared_data_ref* sdr;

                if (len < sizeof(struct btrfs_shared_data_ref)) {
                    ERR("(%I64x,%x,%I64x) was truncated\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset);
                    return STATUS_INTERNAL_ERROR;
                }

                sdr = (struct btrfs_shared_data_ref*)ptr;

                ptr += sizeof(struct btrfs_shared_data_ref);
                len -= sizeof(struct btrfs_shared_data_ref);
                inline_rc += sdr->count;

                break;
            }

            case BTRFS_EXTENT_DATA_REF_KEY:
                // If inline extent already present, decrease refcount and return

                if (len < sizeof(struct btrfs_extent_data_ref) - sizeof(uint64_t)) {
                    ERR("(%I64x,%x,%I64x) was truncated\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset);
                    return STATUS_INTERNAL_ERROR;
                }

                sectedr = (struct btrfs_extent_data_ref*)&eir->offset;

                if (sectedr->root == root && sectedr->objectid == inode && sectedr->offset == offset) {
                    uint16_t neweilen;
                    struct btrfs_extent_item* newei;

                    if (ei->refs == refcount) {
                        Status = delete_tree_item(Vcb, &tp);
                        if (!NT_SUCCESS(Status)) {
                            ERR("delete_tree_item returned %08lx\n", Status);
                            return Status;
                        }

                        if (!superseded) {
                            Status = add_checksum_entry(Vcb, address,
                                                        (ULONG)(size >> Vcb->sector_shift),
                                                        NULL, Irp);
                            if (!NT_SUCCESS(Status))
                                return Status;
                        }

                        return STATUS_SUCCESS;
                    }

                    if (sectedr->count < refcount) {
                        ERR("error - extent section has refcount %x, trying to reduce by %x\n",
                            sectedr->count, refcount);

                        return STATUS_INTERNAL_ERROR;
                    }

                    if (sectedr->count > refcount)    // reduce section refcount
                        neweilen = tp.item->size;
                    else                              // remove section entirely
                        neweilen = tp.item->size - offsetof(struct btrfs_extent_inline_ref, offset) - sizeof(struct btrfs_extent_data_ref);

                    newei = ExAllocatePoolWithTag(PagedPool, neweilen, ALLOC_TAG);
                    if (!newei) {
                        ERR("out of memory\n");
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }

                    if (sectedr->count > refcount) {
                        struct btrfs_extent_data_ref* newedr = (struct btrfs_extent_data_ref*)((uint8_t*)newei + ((uint8_t*)sectedr - tp.item->data));

                        RtlCopyMemory(newei, ei, neweilen);

                        newedr->count -= refcount;
                    } else {
                        RtlCopyMemory(newei, ei, (uint8_t*)eir - tp.item->data);

                        if (len > sizeof(struct btrfs_extent_data_ref) - sizeof(uint64_t)) {
                            RtlCopyMemory((uint8_t*)newei + ((uint8_t*)eir - tp.item->data),
                                          ptr + sizeof(struct btrfs_extent_data_ref) - sizeof(uint64_t),
                                          len - sizeof(struct btrfs_extent_data_ref) + sizeof(uint64_t));
                        }
                    }

                    newei->refs -= refcount;

                    Status = delete_tree_item(Vcb, &tp);
                    if (!NT_SUCCESS(Status)) {
                        ERR("delete_tree_item returned %08lx\n", Status);
                        return Status;
                    }

                    Status = insert_tree_item(Vcb, Vcb->extent_root, tp.item->key.objectid,
                                              tp.item->key.type, tp.item->key.offset,
                                              newei, neweilen, NULL, Irp);
                    if (!NT_SUCCESS(Status)) {
                        ERR("insert_tree_item returned %08lx\n", Status);
                        return Status;
                    }

                    return STATUS_SUCCESS;
                }

                ptr += sizeof(struct btrfs_extent_data_ref) - sizeof(uint64_t);
                len -= sizeof(struct btrfs_extent_data_ref) - sizeof(uint64_t);
                inline_rc += sectedr->count;
                break;

            case BTRFS_TREE_BLOCK_REF_KEY:
            case BTRFS_SHARED_BLOCK_REF_KEY:
                inline_rc++;
                break;

            default:
                ERR("unknown extent item type %x\n", eir->type);
                return STATUS_INTERNAL_ERROR;
        }
    }

    if (inline_rc == ei->refs) {
        ERR("entry not found in inline extent item for address %I64x\n",
            address);
        return STATUS_INTERNAL_ERROR;
    }

    searchkey.objectid = address;
    searchkey.type = BTRFS_EXTENT_DATA_REF_KEY;
    searchkey.offset = get_extent_data_ref_hash2(root, inode, offset);

    Status = find_item(Vcb, Vcb->extent_root, &tp2, &searchkey, false, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08lx\n", Status);
        return Status;
    }

    if (keycmp(tp2.item->key, searchkey)) {
        ERR("(%I64x,%x,%I64x) not found\n", tp2.item->key.objectid,
            tp2.item->key.type, tp2.item->key.offset);
        return STATUS_INTERNAL_ERROR;
    }

    if (tp2.item->size < sizeof(struct btrfs_extent_data_ref)) {
        ERR("(%I64x,%x,%I64x) was %u bytes, expected at least %Iu\n",
            tp2.item->key.objectid, tp2.item->key.type, tp2.item->key.offset,
            tp2.item->size, sizeof(struct btrfs_extent_data_ref));

        return STATUS_INTERNAL_ERROR;
    }

    sectedr = (struct btrfs_extent_data_ref*)tp2.item->data;

    if (sectedr->root == root && sectedr->objectid == inode && sectedr->offset == offset) {
        struct btrfs_extent_item* newei;

        if (ei->refs == refcount) {
            Status = delete_tree_item(Vcb, &tp);
            if (!NT_SUCCESS(Status)) {
                ERR("delete_tree_item returned %08lx\n", Status);
                return Status;
            }

            Status = delete_tree_item(Vcb, &tp2);
            if (!NT_SUCCESS(Status)) {
                ERR("delete_tree_item returned %08lx\n", Status);
                return Status;
            }

            if (!superseded) {
                Status = add_checksum_entry(Vcb, address,
                                            (ULONG)(size >> Vcb->sector_shift),
                                            NULL, Irp);
                if (!NT_SUCCESS(Status))
                    return Status;
            }

            return STATUS_SUCCESS;
        }

        if (sectedr->count < refcount) {
            ERR("error - extent section has refcount %x, trying to reduce by %x\n",
                sectedr->count, refcount);

            return STATUS_INTERNAL_ERROR;
        }

        Status = delete_tree_item(Vcb, &tp2);
        if (!NT_SUCCESS(Status)) {
            ERR("delete_tree_item returned %08lx\n", Status);
            return Status;
        }

        if (sectedr->count > refcount) {
            struct btrfs_extent_data_ref* newedr = ExAllocatePoolWithTag(PagedPool, tp2.item->size, ALLOC_TAG);
            if (!newedr) {
                ERR("out of memory\n");
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            RtlCopyMemory(newedr, sectedr, tp2.item->size);

            newedr->count -= refcount;

            Status = insert_tree_item(Vcb, Vcb->extent_root, tp2.item->key.objectid,
                                      tp2.item->key.type, tp2.item->key.offset,
                                      newedr, tp2.item->size, NULL, Irp);
            if (!NT_SUCCESS(Status)) {
                ERR("insert_tree_item returned %08lx\n", Status);
                return Status;
            }
        }

        newei = ExAllocatePoolWithTag(PagedPool, tp.item->size, ALLOC_TAG);
        if (!newei) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlCopyMemory(newei, tp.item->data, tp.item->size);

        newei->refs -= refcount;

        Status = delete_tree_item(Vcb, &tp);
        if (!NT_SUCCESS(Status)) {
            ERR("delete_tree_item returned %08lx\n", Status);
            return Status;
        }

        Status = insert_tree_item(Vcb, Vcb->extent_root, tp.item->key.objectid,
                                  tp.item->key.type, tp.item->key.offset, newei,
                                  tp.item->size, NULL, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("insert_tree_item returned %08lx\n", Status);
            return Status;
        }

        return STATUS_SUCCESS;
    } else {
        ERR("error - hash collision?\n");
        return STATUS_INTERNAL_ERROR;
    }
}

NTSTATUS decrease_extent_refcount_shared_data(device_extension* Vcb, uint64_t address,
                                              uint64_t size, uint64_t offset,
                                              uint32_t count, bool superseded,
                                              PIRP Irp) {
    struct btrfs_key searchkey;
    NTSTATUS Status;
    traverse_ptr tp, tp2;
    struct btrfs_extent_item* ei;
    ULONG len;
    uint64_t inline_rc;
    uint8_t* ptr;
    struct btrfs_extent_item* newei;
    struct btrfs_shared_data_ref* sdr;

    searchkey.objectid = address;
    searchkey.type = BTRFS_EXTENT_ITEM_KEY;
    searchkey.offset = 0xffffffffffffffff;

    Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, false, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08lx\n", Status);
        return Status;
    }

    if (tp.item->key.objectid != searchkey.objectid || tp.item->key.type != searchkey.type) {
        ERR("could not find EXTENT_ITEM for address %I64x\n", address);
        return STATUS_INTERNAL_ERROR;
    }

    if (tp.item->key.offset != size) {
        ERR("extent %I64x had length %I64x, not %I64x as expected\n", address, tp.item->key.offset, size);
        return STATUS_INTERNAL_ERROR;
    }

    if (tp.item->size == sizeof(struct btrfs_extent_item_v0)) {
        ERR("old-style extents no longer supported\n");
        return STATUS_INTERNAL_ERROR;
    }

    if (tp.item->size < sizeof(struct btrfs_extent_item)) {
        ERR("(%I64x,%x,%I64x) was %u bytes, expected at least %Iu\n",
            tp.item->key.objectid, tp.item->key.type, tp.item->key.offset,
            tp.item->size, sizeof(struct btrfs_extent_item));

        return STATUS_INTERNAL_ERROR;
    }

    ei = (struct btrfs_extent_item*)tp.item->data;

    len = tp.item->size - sizeof(struct btrfs_extent_item);
    ptr = (uint8_t*)&ei[1];

    if (ei->flags & BTRFS_EXTENT_FLAG_TREE_BLOCK) {
        ERR("(%I64x,%x,%I64x) had TREE_BLOCK flag set\n", tp.item->key.objectid,
            tp.item->key.type, tp.item->key.offset);

        return STATUS_INTERNAL_ERROR;
    }

    if (ei->refs < count) {
        ERR("error - extent has refcount %I64x, trying to reduce by %x\n",
            ei->refs, count);

        return STATUS_INTERNAL_ERROR;
    }

    inline_rc = 0;

    // Loop through inline extent entries

    while (len > 0) {
        struct btrfs_extent_inline_ref* eir = (struct btrfs_extent_inline_ref*)ptr;

        if (len < sizeof(struct btrfs_extent_inline_ref)) {
            ERR("(%I64x,%x,%I64x) was truncated\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset);
            return STATUS_INTERNAL_ERROR;
        }

        ptr += sizeof(struct btrfs_extent_inline_ref);
        len -= sizeof(struct btrfs_extent_inline_ref);

        switch (eir->type) {
            case BTRFS_SHARED_DATA_REF_KEY: {
                if (len < sizeof(struct btrfs_shared_data_ref)) {
                    ERR("(%I64x,%x,%I64x) was truncated\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset);
                    return STATUS_INTERNAL_ERROR;
                }

                // If inline extent already present, decrease refcount and return

                if (eir->offset == offset) {
                    uint16_t neweilen;

                    if (ei->refs == count) {
                        Status = delete_tree_item(Vcb, &tp);
                        if (!NT_SUCCESS(Status)) {
                            ERR("delete_tree_item returned %08lx\n", Status);
                            return Status;
                        }

                        if (!superseded) {
                            Status = add_checksum_entry(Vcb, address,
                                                        (ULONG)(size >> Vcb->sector_shift),
                                                        NULL, Irp);
                            if (!NT_SUCCESS(Status))
                                return Status;
                        }

                        return STATUS_SUCCESS;
                    }

                    sdr = (struct btrfs_shared_data_ref*)ptr;

                    if (sdr->count < count) {
                        ERR("error - SHARED_DATA_REF has refcount %x, trying to reduce by %x\n",
                            sdr->count, count);

                        return STATUS_INTERNAL_ERROR;
                    }

                    if (sdr->count > count)    // reduce section refcount
                        neweilen = tp.item->size;
                    else                           // remove section entirely
                        neweilen = tp.item->size - sizeof(struct btrfs_extent_inline_ref) - sizeof(struct btrfs_shared_data_ref);

                    newei = ExAllocatePoolWithTag(PagedPool, neweilen, ALLOC_TAG);
                    if (!newei) {
                        ERR("out of memory\n");
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }

                    if (sdr->count > count) {
                        struct btrfs_shared_data_ref* newsdr = (struct btrfs_shared_data_ref*)((uint8_t*)newei + ((uint8_t*)sdr - tp.item->data));

                        RtlCopyMemory(newei, ei, neweilen);

                        newsdr->count -= count;
                    } else {
                        RtlCopyMemory(newei, ei, (uint8_t*)eir - tp.item->data);

                        if (len > sizeof(struct btrfs_shared_data_ref)) {
                            RtlCopyMemory((uint8_t*)newei + ((uint8_t*)eir - tp.item->data),
                                          ptr + sizeof(struct btrfs_shared_data_ref),
                                          len - sizeof(struct btrfs_shared_data_ref));
                        }
                    }

                    newei->refs -= count;

                    Status = delete_tree_item(Vcb, &tp);
                    if (!NT_SUCCESS(Status)) {
                        ERR("delete_tree_item returned %08lx\n", Status);
                        return Status;
                    }

                    Status = insert_tree_item(Vcb, Vcb->extent_root, tp.item->key.objectid,
                                              tp.item->key.type, tp.item->key.offset,
                                              newei, neweilen, NULL, Irp);
                    if (!NT_SUCCESS(Status)) {
                        ERR("insert_tree_item returned %08lx\n", Status);
                        return Status;
                    }

                    return STATUS_SUCCESS;
                }

                sdr = (struct btrfs_shared_data_ref*)ptr;

                ptr += sizeof(struct btrfs_shared_data_ref);
                len -= sizeof(struct btrfs_shared_data_ref);
                inline_rc += sdr->count;

                break;
            }

            case BTRFS_EXTENT_DATA_REF_KEY: {
                struct btrfs_extent_data_ref* sectedr;

                if (len < sizeof(struct btrfs_extent_data_ref) - sizeof(uint64_t)) {
                    ERR("(%I64x,%x,%I64x) was truncated\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset);
                    return STATUS_INTERNAL_ERROR;
                }

                sectedr = (struct btrfs_extent_data_ref*)&eir->offset;

                ptr += sizeof(struct btrfs_extent_data_ref) - sizeof(uint64_t);
                len -= sizeof(struct btrfs_extent_data_ref) - sizeof(uint64_t);
                inline_rc += sectedr->count;

                break;
            }

            case BTRFS_TREE_BLOCK_REF_KEY:
            case BTRFS_SHARED_BLOCK_REF_KEY:
                inline_rc++;
                break;

            default:
                ERR("unknown extent item type %x\n", eir->type);
                return STATUS_INTERNAL_ERROR;
        }
    }

    if (inline_rc == ei->refs) {
        ERR("entry not found in inline extent item for address %I64x\n", address);
        return STATUS_INTERNAL_ERROR;
    }

    searchkey.objectid = address;
    searchkey.type = BTRFS_SHARED_DATA_REF_KEY;
    searchkey.offset = offset;

    Status = find_item(Vcb, Vcb->extent_root, &tp2, &searchkey, false, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08lx\n", Status);
        return Status;
    }

    if (keycmp(tp2.item->key, searchkey)) {
        ERR("(%I64x,%x,%I64x) not found\n", tp2.item->key.objectid, tp2.item->key.type, tp2.item->key.offset);
        return STATUS_INTERNAL_ERROR;
    }

    if (tp2.item->size < sizeof(struct btrfs_shared_data_ref)) {
        ERR("(%I64x,%x,%I64x) was %u bytes, expected %Iu\n",
            tp2.item->key.objectid, tp2.item->key.type, tp2.item->key.offset,
            tp2.item->size, sizeof(struct btrfs_shared_data_ref));

        return STATUS_INTERNAL_ERROR;
    }

    sdr = (struct btrfs_shared_data_ref*)tp2.item->data;

    if (ei->refs == count) {
        Status = delete_tree_item(Vcb, &tp);
        if (!NT_SUCCESS(Status)) {
            ERR("delete_tree_item returned %08lx\n", Status);
            return Status;
        }

        Status = delete_tree_item(Vcb, &tp2);
        if (!NT_SUCCESS(Status)) {
            ERR("delete_tree_item returned %08lx\n", Status);
            return Status;
        }

        if (!superseded) {
            Status = add_checksum_entry(Vcb, address, (ULONG)(size >> Vcb->sector_shift),
                                        NULL, Irp);
            if (!NT_SUCCESS(Status))
                return Status;
        }

        return STATUS_SUCCESS;
    }

    if (sdr->count < count) {
        ERR("error - extent section has refcount %x, trying to reduce by %x\n",
            sdr->count, count);

        return STATUS_INTERNAL_ERROR;
    }

    Status = delete_tree_item(Vcb, &tp2);
    if (!NT_SUCCESS(Status)) {
        ERR("delete_tree_item returned %08lx\n", Status);
        return Status;
    }

    if (sdr->count > count) {
        struct btrfs_shared_data_ref* newsdr = ExAllocatePoolWithTag(PagedPool, sizeof(struct btrfs_shared_data_ref), ALLOC_TAG);

        if (!newsdr) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        newsdr->count = sdr->count - count;

        Status = insert_tree_item(Vcb, Vcb->extent_root, address,
                                  BTRFS_SHARED_DATA_REF_KEY, offset, newsdr,
                                  sizeof(struct btrfs_shared_data_ref), NULL,
                                  Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("insert_tree_item returned %08lx\n", Status);
            return Status;
        }
    }

    newei = ExAllocatePoolWithTag(PagedPool, tp.item->size, ALLOC_TAG);
    if (!newei) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(newei, tp.item->data, tp.item->size);

    newei->refs -= count;

    Status = delete_tree_item(Vcb, &tp);
    if (!NT_SUCCESS(Status)) {
        ERR("delete_tree_item returned %08lx\n", Status);
        return Status;
    }

    Status = insert_tree_item(Vcb, Vcb->extent_root, tp.item->key.objectid,
                              tp.item->key.type, tp.item->key.offset, newei,
                              tp.item->size, NULL, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("insert_tree_item returned %08lx\n", Status);
        return Status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS decrease_extent_refcount_tree(device_extension* Vcb, uint64_t address,
                                       uint64_t root, PIRP Irp) {
    struct btrfs_key searchkey;
    NTSTATUS Status;
    traverse_ptr tp, tp2;
    struct btrfs_extent_item* ei;
    ULONG len;
    uint64_t inline_rc;
    uint8_t* ptr;
    struct btrfs_extent_item* newei;
    bool skinny = false;

    if (Vcb->superblock.incompat_flags & BTRFS_FEATURE_INCOMPAT_SKINNY_METADATA) {
        searchkey.objectid = address;
        searchkey.type = BTRFS_METADATA_ITEM_KEY;
        searchkey.offset = 0xffffffffffffffff;

        Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, false, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("error - find_item returned %08lx\n", Status);
            return Status;
        }

        if (tp.item->key.objectid == searchkey.objectid && tp.item->key.type == searchkey.type)
            skinny = true;
    }

    if (!skinny) {
        searchkey.objectid = address;
        searchkey.type = BTRFS_EXTENT_ITEM_KEY;
        searchkey.offset = 0xffffffffffffffff;

        Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, false, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("error - find_item returned %08lx\n", Status);
            return Status;
        }

        if (tp.item->key.objectid != searchkey.objectid || tp.item->key.type != searchkey.type) {
            ERR("could not find EXTENT_ITEM for address %I64x\n", address);
            return STATUS_INTERNAL_ERROR;
        }

        if (tp.item->key.offset != Vcb->superblock.nodesize) {
            ERR("extent %I64x had length %I64x, not %x as expected\n",
                address, tp.item->key.offset, Vcb->superblock.nodesize);

            return STATUS_INTERNAL_ERROR;
        }

        if (tp.item->size == sizeof(struct btrfs_extent_item_v0)) {
            ERR("old-style extents no longer supported\n");
            return STATUS_INTERNAL_ERROR;
        }
    }

    if (tp.item->size < sizeof(struct btrfs_extent_item)) {
        ERR("(%I64x,%x,%I64x) was %u bytes, expected at least %Iu\n",
            tp.item->key.objectid, tp.item->key.type, tp.item->key.offset,
            tp.item->size, sizeof(struct btrfs_extent_item));

        return STATUS_INTERNAL_ERROR;
    }

    ei = (struct btrfs_extent_item*)tp.item->data;

    len = tp.item->size - sizeof(struct btrfs_extent_item);
    ptr = (uint8_t*)&ei[1];

    if (ei->flags & BTRFS_EXTENT_FLAG_TREE_BLOCK && !skinny) {
        if (tp.item->size < sizeof(struct btrfs_extent_item) + sizeof(struct btrfs_tree_block_info)) {
            ERR("(%I64x,%x,%I64x) was %u bytes, expected at least %Iu\n",
                tp.item->key.objectid, tp.item->key.type, tp.item->key.offset,
                tp.item->size, sizeof(struct btrfs_extent_item) + sizeof(struct btrfs_tree_block_info));

            return STATUS_INTERNAL_ERROR;
        }

        len -= sizeof(struct btrfs_tree_block_info);
        ptr += sizeof(struct btrfs_tree_block_info);
    }

    if (ei->refs == 0) {
        ERR("error - extent has refcount of 0\n");
        return STATUS_INTERNAL_ERROR;
    }

    inline_rc = 0;

    // Loop through inline extent entries

    while (len > 0) {
        struct btrfs_extent_inline_ref* eir = (struct btrfs_extent_inline_ref*)ptr;

        if (len < sizeof(struct btrfs_extent_inline_ref)) {
            ERR("(%I64x,%x,%I64x) was truncated\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset);
            return STATUS_INTERNAL_ERROR;
        }

        ptr += sizeof(struct btrfs_extent_inline_ref);
        len -= sizeof(struct btrfs_extent_inline_ref);

        switch (eir->type) {
            case BTRFS_SHARED_DATA_REF_KEY: {
                struct btrfs_shared_data_ref* sdr;

                if (len < sizeof(struct btrfs_shared_data_ref)) {
                    ERR("(%I64x,%x,%I64x) was truncated\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset);
                    return STATUS_INTERNAL_ERROR;
                }

                sdr = (struct btrfs_shared_data_ref*)ptr;

                ptr += sizeof(struct btrfs_shared_data_ref);
                len -= sizeof(struct btrfs_shared_data_ref);
                inline_rc += sdr->count;

                break;
            }

            case BTRFS_EXTENT_DATA_REF_KEY: {
                struct btrfs_extent_data_ref* edr;

                if (len < sizeof(struct btrfs_extent_data_ref) - sizeof(uint64_t)) {
                    ERR("(%I64x,%x,%I64x) was truncated\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset);
                    return STATUS_INTERNAL_ERROR;
                }

                edr = (struct btrfs_extent_data_ref*)&eir->offset;

                ptr += sizeof(struct btrfs_extent_data_ref) - sizeof(uint64_t);
                len -= sizeof(struct btrfs_extent_data_ref) - sizeof(uint64_t);
                inline_rc += edr->count;

                break;
            }

            case BTRFS_TREE_BLOCK_REF_KEY:
                // If inline extent already present, decrease refcount and return

                if (eir->offset == root) {
                    uint16_t neweilen;

                    if (ei->refs == 1) {
                        Status = delete_tree_item(Vcb, &tp);
                        if (!NT_SUCCESS(Status)) {
                            ERR("delete_tree_item returned %08lx\n", Status);
                            return Status;
                        }

                        return STATUS_SUCCESS;
                    }

                    neweilen = tp.item->size - sizeof(struct btrfs_extent_inline_ref);

                    newei = ExAllocatePoolWithTag(PagedPool, neweilen, ALLOC_TAG);
                    if (!newei) {
                        ERR("out of memory\n");
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }

                    RtlCopyMemory(newei, ei, (uint8_t*)eir - tp.item->data);

                    if (len > 0) {
                        RtlCopyMemory((uint8_t*)newei + ((uint8_t*)eir - tp.item->data),
                                      ptr, len);
                    }

                    newei->refs--;

                    Status = delete_tree_item(Vcb, &tp);
                    if (!NT_SUCCESS(Status)) {
                        ERR("delete_tree_item returned %08lx\n", Status);
                        return Status;
                    }

                    Status = insert_tree_item(Vcb, Vcb->extent_root, tp.item->key.objectid,
                                              tp.item->key.type, tp.item->key.offset,
                                              newei, neweilen, NULL, Irp);
                    if (!NT_SUCCESS(Status)) {
                        ERR("insert_tree_item returned %08lx\n", Status);
                        return Status;
                    }

                    return STATUS_SUCCESS;
                }

                inline_rc++;
                break;

            case BTRFS_SHARED_BLOCK_REF_KEY:
                inline_rc++;
                break;

            default:
                ERR("unknown extent item type %x\n", eir->type);
                return STATUS_INTERNAL_ERROR;
        }
    }

    if (inline_rc == ei->refs) {
        ERR("entry not found in inline extent item for address %I64x\n", address);
        return STATUS_INTERNAL_ERROR;
    }

    searchkey.objectid = address;
    searchkey.type = BTRFS_TREE_BLOCK_REF_KEY;
    searchkey.offset = root;

    Status = find_item(Vcb, Vcb->extent_root, &tp2, &searchkey, false, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08lx\n", Status);
        return Status;
    }

    if (keycmp(tp2.item->key, searchkey)) {
        ERR("(%I64x,%x,%I64x) not found\n", tp2.item->key.objectid,
            tp2.item->key.type, tp2.item->key.offset);

        return STATUS_INTERNAL_ERROR;
    }

    if (ei->refs == 1) {
        Status = delete_tree_item(Vcb, &tp);
        if (!NT_SUCCESS(Status)) {
            ERR("delete_tree_item returned %08lx\n", Status);
            return Status;
        }

        Status = delete_tree_item(Vcb, &tp2);
        if (!NT_SUCCESS(Status)) {
            ERR("delete_tree_item returned %08lx\n", Status);
            return Status;
        }

        return STATUS_SUCCESS;
    }

    Status = delete_tree_item(Vcb, &tp2);
    if (!NT_SUCCESS(Status)) {
        ERR("delete_tree_item returned %08lx\n", Status);
        return Status;
    }

    newei = ExAllocatePoolWithTag(PagedPool, tp.item->size, ALLOC_TAG);
    if (!newei) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(newei, tp.item->data, tp.item->size);

    newei->refs--;

    Status = delete_tree_item(Vcb, &tp);
    if (!NT_SUCCESS(Status)) {
        ERR("delete_tree_item returned %08lx\n", Status);
        return Status;
    }

    Status = insert_tree_item(Vcb, Vcb->extent_root, tp.item->key.objectid,
                              tp.item->key.type, tp.item->key.offset, newei,
                              tp.item->size, NULL, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("insert_tree_item returned %08lx\n", Status);
        return Status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS decrease_extent_refcount_shared_block(device_extension* Vcb, uint64_t address,
                                               uint64_t offset, PIRP Irp) {
    struct btrfs_key searchkey;
    NTSTATUS Status;
    traverse_ptr tp, tp2;
    struct btrfs_extent_item* ei;
    ULONG len;
    uint64_t inline_rc;
    uint8_t* ptr;
    bool skinny = false;
    struct btrfs_extent_item* newei;

    if (Vcb->superblock.incompat_flags & BTRFS_FEATURE_INCOMPAT_SKINNY_METADATA) {
        searchkey.objectid = address;
        searchkey.type = BTRFS_METADATA_ITEM_KEY;
        searchkey.offset = 0xffffffffffffffff;

        Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, false, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("error - find_item returned %08lx\n", Status);
            return Status;
        }

        if (tp.item->key.objectid == searchkey.objectid && tp.item->key.type == searchkey.type)
            skinny = true;
    }

    if (!skinny) {
        searchkey.objectid = address;
        searchkey.type = BTRFS_EXTENT_ITEM_KEY;
        searchkey.offset = 0xffffffffffffffff;

        Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, false, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("error - find_item returned %08lx\n", Status);
            return Status;
        }

        if (tp.item->key.objectid != searchkey.objectid || tp.item->key.type != searchkey.type) {
            ERR("could not find EXTENT_ITEM for address %I64x\n", address);
            return STATUS_INTERNAL_ERROR;
        }

        if (tp.item->key.offset != Vcb->superblock.nodesize) {
            ERR("extent %I64x had length %I64x, not %x as expected\n",
                address, tp.item->key.offset, Vcb->superblock.nodesize);
            return STATUS_INTERNAL_ERROR;
        }

        if (tp.item->size == sizeof(struct btrfs_extent_item_v0)) {
            ERR("old-style extents no longer supported\n");
            return STATUS_INTERNAL_ERROR;
        }
    }

    if (tp.item->size < sizeof(struct btrfs_extent_item)) {
        ERR("(%I64x,%x,%I64x) was %u bytes, expected at least %Iu\n",
            tp.item->key.objectid, tp.item->key.type, tp.item->key.offset,
            tp.item->size, sizeof(struct btrfs_extent_item));

        return STATUS_INTERNAL_ERROR;
    }

    ei = (struct btrfs_extent_item*)tp.item->data;

    len = tp.item->size - sizeof(struct btrfs_extent_item);
    ptr = (uint8_t*)&ei[1];

    if (ei->flags & BTRFS_EXTENT_FLAG_TREE_BLOCK && !skinny) {
        if (tp.item->size < sizeof(struct btrfs_extent_item) + sizeof(struct btrfs_tree_block_info)) {
            ERR("(%I64x,%x,%I64x) was %u bytes, expected at least %Iu\n",
                tp.item->key.objectid, tp.item->key.type, tp.item->key.offset,
                tp.item->size, sizeof(struct btrfs_extent_item) + sizeof(struct btrfs_tree_block_info));

            return STATUS_INTERNAL_ERROR;
        }

        len -= sizeof(struct btrfs_tree_block_info);
        ptr += sizeof(struct btrfs_tree_block_info);
    }

    if (ei->refs == 0) {
        ERR("error - extent has refcount of 0\n");
        return STATUS_INTERNAL_ERROR;
    }

    inline_rc = 0;

    // Loop through inline extent entries

    while (len > 0) {
        struct btrfs_extent_inline_ref* eir = (struct btrfs_extent_inline_ref*)ptr;

        if (len < sizeof(struct btrfs_extent_inline_ref)) {
            ERR("(%I64x,%x,%I64x) was truncated\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset);
            return STATUS_INTERNAL_ERROR;
        }

        ptr += sizeof(struct btrfs_extent_inline_ref);
        len -= sizeof(struct btrfs_extent_inline_ref);

        switch (eir->type) {
            case BTRFS_SHARED_DATA_REF_KEY: {
                struct btrfs_shared_data_ref* sdr;

                if (len < sizeof(struct btrfs_shared_data_ref)) {
                    ERR("(%I64x,%x,%I64x) was truncated\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset);
                    return STATUS_INTERNAL_ERROR;
                }

                sdr = (struct btrfs_shared_data_ref*)ptr;

                ptr += sizeof(struct btrfs_shared_data_ref);
                len -= sizeof(struct btrfs_shared_data_ref);
                inline_rc += sdr->count;

                break;
            }

            case BTRFS_EXTENT_DATA_REF_KEY: {
                struct btrfs_extent_data_ref* edr;

                if (len < sizeof(struct btrfs_extent_data_ref) - sizeof(uint64_t)) {
                    ERR("(%I64x,%x,%I64x) was truncated\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset);
                    return STATUS_INTERNAL_ERROR;
                }

                edr = (struct btrfs_extent_data_ref*)&eir->offset;

                ptr += sizeof(struct btrfs_extent_data_ref) - sizeof(uint64_t);
                len -= sizeof(struct btrfs_extent_data_ref) - sizeof(uint64_t);
                inline_rc += edr->count;

                break;
            }

            case BTRFS_TREE_BLOCK_REF_KEY:
                inline_rc++;
                break;

            case BTRFS_SHARED_BLOCK_REF_KEY:
                // If inline extent already present, decrease refcount and return

                if (eir->offset == offset) {
                    uint16_t neweilen;

                    if (ei->refs == 1) {
                        Status = delete_tree_item(Vcb, &tp);
                        if (!NT_SUCCESS(Status)) {
                            ERR("delete_tree_item returned %08lx\n", Status);
                            return Status;
                        }

                        return STATUS_SUCCESS;
                    }

                    neweilen = tp.item->size - sizeof(struct btrfs_extent_inline_ref);

                    newei = ExAllocatePoolWithTag(PagedPool, neweilen, ALLOC_TAG);
                    if (!newei) {
                        ERR("out of memory\n");
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }

                    RtlCopyMemory(newei, ei, (uint8_t*)eir - tp.item->data);

                    if (len > 0) {
                        RtlCopyMemory((uint8_t*)newei + ((uint8_t*)eir - tp.item->data),
                                      ptr, len);
                    }

                    newei->refs--;

                    Status = delete_tree_item(Vcb, &tp);
                    if (!NT_SUCCESS(Status)) {
                        ERR("delete_tree_item returned %08lx\n", Status);
                        return Status;
                    }

                    Status = insert_tree_item(Vcb, Vcb->extent_root, tp.item->key.objectid,
                                              tp.item->key.type, tp.item->key.offset,
                                              newei, neweilen, NULL, Irp);
                    if (!NT_SUCCESS(Status)) {
                        ERR("insert_tree_item returned %08lx\n", Status);
                        return Status;
                    }

                    return STATUS_SUCCESS;
                }

                inline_rc++;
                break;

            default:
                ERR("unknown extent item type %x\n", eir->type);
                return STATUS_INTERNAL_ERROR;
        }
    }

    if (inline_rc == ei->refs) {
        ERR("entry not found in inline extent item for address %I64x\n", address);
        return STATUS_INTERNAL_ERROR;
    }

    searchkey.objectid = address;
    searchkey.type = BTRFS_SHARED_BLOCK_REF_KEY;
    searchkey.offset = offset;

    Status = find_item(Vcb, Vcb->extent_root, &tp2, &searchkey, false, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08lx\n", Status);
        return Status;
    }

    if (keycmp(tp2.item->key, searchkey)) {
        ERR("(%I64x,%x,%I64x) not found\n", tp2.item->key.objectid, tp2.item->key.type, tp2.item->key.offset);
        return STATUS_INTERNAL_ERROR;
    }

    if (ei->refs == 1) {
        Status = delete_tree_item(Vcb, &tp);
        if (!NT_SUCCESS(Status)) {
            ERR("delete_tree_item returned %08lx\n", Status);
            return Status;
        }

        Status = delete_tree_item(Vcb, &tp2);
        if (!NT_SUCCESS(Status)) {
            ERR("delete_tree_item returned %08lx\n", Status);
            return Status;
        }

        return STATUS_SUCCESS;
    }

    Status = delete_tree_item(Vcb, &tp2);
    if (!NT_SUCCESS(Status)) {
        ERR("delete_tree_item returned %08lx\n", Status);
        return Status;
    }

    newei = ExAllocatePoolWithTag(PagedPool, tp.item->size, ALLOC_TAG);
    if (!newei) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(newei, tp.item->data, tp.item->size);

    newei->refs--;

    Status = delete_tree_item(Vcb, &tp);
    if (!NT_SUCCESS(Status)) {
        ERR("delete_tree_item returned %08lx\n", Status);
        return Status;
    }

    Status = insert_tree_item(Vcb, Vcb->extent_root, tp.item->key.objectid,
                              tp.item->key.type, tp.item->key.offset, newei,
                              tp.item->size, NULL, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("insert_tree_item returned %08lx\n", Status);
        return Status;
    }

    return STATUS_SUCCESS;
}

static uint32_t find_extent_data_refcount(device_extension* Vcb, uint64_t address, uint64_t size, uint64_t root, uint64_t objid, uint64_t offset, PIRP Irp) {
    NTSTATUS Status;
    struct btrfs_key searchkey;
    traverse_ptr tp;
    uint64_t inline_rc;

    searchkey.objectid = address;
    searchkey.type = BTRFS_EXTENT_ITEM_KEY;
    searchkey.offset = 0xffffffffffffffff;

    Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, false, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08lx\n", Status);
        return 0;
    }

    if (tp.item->key.objectid != searchkey.objectid || tp.item->key.type != searchkey.type) {
        TRACE("could not find address %I64x in extent tree\n", address);
        return 0;
    }

    if (tp.item->key.offset != size) {
        ERR("extent %I64x had size %I64x, not %I64x as expected\n", address, tp.item->key.offset, size);
        return 0;
    }

    inline_rc = 0;

    if (tp.item->size >= sizeof(struct btrfs_extent_item)) {
        struct btrfs_extent_item* ei = (struct btrfs_extent_item*)tp.item->data;
        uint32_t len = tp.item->size - sizeof(struct btrfs_extent_item);
        uint8_t* ptr = (uint8_t*)&ei[1];

        while (len > 0) {
            struct btrfs_extent_inline_ref* eir = (struct btrfs_extent_inline_ref*)ptr;

            if (len < sizeof(struct btrfs_extent_inline_ref)) {
                ERR("(%I64x,%x,%I64x) was truncated\n", tp.item->key.objectid,
                    tp.item->key.type, tp.item->key.offset);

                return 0;
            }

            ptr += sizeof(struct btrfs_extent_inline_ref);
            len -= sizeof(struct btrfs_extent_inline_ref);

            switch (eir->type) {
                case BTRFS_EXTENT_DATA_REF_KEY: {
                    struct btrfs_extent_data_ref* sectedr = (struct btrfs_extent_data_ref*)(ptr - sizeof(uint64_t));

                    if (len < sizeof(struct btrfs_extent_data_ref) - sizeof(uint64_t)) {
                        ERR("(%I64x,%x,%I64x) was truncated\n", tp.item->key.objectid,
                            tp.item->key.type, tp.item->key.offset);
                        return 0;
                    }

                    ptr += sizeof(struct btrfs_extent_data_ref) - sizeof(uint64_t);
                    len -= sizeof(struct btrfs_extent_data_ref) - sizeof(uint64_t);
                    inline_rc += sectedr->count;

                    if (sectedr->root == root && sectedr->objectid == objid && sectedr->offset == offset)
                        return sectedr->count;

                    break;
                }

                case BTRFS_SHARED_DATA_REF_KEY: {
                    struct btrfs_shared_data_ref* sdr = (struct btrfs_shared_data_ref*)ptr;

                    if (len < sizeof(struct btrfs_shared_data_ref)) {
                        ERR("(%I64x,%x,%I64x) was truncated\n", tp.item->key.objectid,
                            tp.item->key.type, tp.item->key.offset);
                        return 0;
                    }

                    ptr += sizeof(struct btrfs_shared_data_ref);
                    len -= sizeof(struct btrfs_shared_data_ref);
                    inline_rc += sdr->count;

                    break;
                }

                default:
                    ERR("(%I64x,%x,%I64x): unexpected type %x\n",
                        tp.item->key.objectid, tp.item->key.type,
                        tp.item->key.offset, eir->type);
                    return 0;
            }
        }

        if (inline_rc == ei->refs)
            return 0;
    }

    searchkey.objectid = address;
    searchkey.type = BTRFS_EXTENT_DATA_REF_KEY;
    searchkey.offset = get_extent_data_ref_hash2(root, objid, offset);

    Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, false, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08lx\n", Status);
        return 0;
    }

    if (!keycmp(searchkey, tp.item->key)) {
        if (tp.item->size < sizeof(struct btrfs_extent_data_ref))
            ERR("(%I64x,%x,%I64x) has size %u, not %Iu as expected\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset, tp.item->size, sizeof(struct btrfs_extent_data_ref));
        else {
            struct btrfs_extent_data_ref* edr = (struct btrfs_extent_data_ref*)tp.item->data;

            return edr->count;
        }
    }

    return 0;
}

uint64_t get_extent_refcount(device_extension* Vcb, uint64_t address, uint64_t size, PIRP Irp) {
    struct btrfs_key searchkey;
    traverse_ptr tp;
    NTSTATUS Status;
    struct btrfs_extent_item* ei;

    searchkey.objectid = address;
    searchkey.type = Vcb->superblock.incompat_flags & BTRFS_FEATURE_INCOMPAT_SKINNY_METADATA ? BTRFS_METADATA_ITEM_KEY : BTRFS_EXTENT_ITEM_KEY;
    searchkey.offset = 0xffffffffffffffff;

    Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, false, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08lx\n", Status);
        return 0;
    }

    if (Vcb->superblock.incompat_flags & BTRFS_FEATURE_INCOMPAT_SKINNY_METADATA && tp.item->key.objectid == address &&
        tp.item->key.type == BTRFS_METADATA_ITEM_KEY && tp.item->size >= sizeof(struct btrfs_extent_item)) {
        ei = (struct btrfs_extent_item*)tp.item->data;

        return ei->refs;
    }

    if (tp.item->key.objectid != address || tp.item->key.type != BTRFS_EXTENT_ITEM_KEY) {
        ERR("couldn't find (%I64x,%x,%I64x) in extent tree\n", address, BTRFS_EXTENT_ITEM_KEY, size);
        return 0;
    } else if (tp.item->key.offset != size) {
        ERR("extent %I64x had size %I64x, not %I64x as expected\n", address, tp.item->key.offset, size);
        return 0;
    }

    if (tp.item->size == sizeof(struct btrfs_extent_item_v0)) {
        struct btrfs_extent_item_v0* eiv0 = (struct btrfs_extent_item_v0*)tp.item->data;

        return eiv0->refs;
    } else if (tp.item->size < sizeof(struct btrfs_extent_item)) {
        ERR("(%I64x,%x,%I64x) was %x bytes, expected at least %Ix\n", tp.item->key.objectid, tp.item->key.type,
                                                                      tp.item->key.offset, tp.item->size, sizeof(struct btrfs_extent_item));
        return 0;
    }

    ei = (struct btrfs_extent_item*)tp.item->data;

    return ei->refs;
}

bool is_extent_unique(device_extension* Vcb, uint64_t address, uint64_t size, PIRP Irp) {
    struct btrfs_key searchkey;
    traverse_ptr tp, next_tp;
    NTSTATUS Status;
    uint64_t rc, rcrun, root = 0, inode = 0, offset = 0;
    uint32_t len;
    struct btrfs_extent_item* ei;
    uint8_t* ptr;
    bool b;

    rc = get_extent_refcount(Vcb, address, size, Irp);

    if (rc == 1)
        return true;

    if (rc == 0)
        return false;

    searchkey.objectid = address;
    searchkey.type = BTRFS_EXTENT_ITEM_KEY;
    searchkey.offset = size;

    Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, false, Irp);
    if (!NT_SUCCESS(Status)) {
        WARN("error - find_item returned %08lx\n", Status);
        return false;
    }

    if (keycmp(tp.item->key, searchkey)) {
        WARN("could not find (%I64x,%x,%I64x)\n", searchkey.objectid, searchkey.type, searchkey.offset);
        return false;
    }

    if (tp.item->size == sizeof(struct btrfs_extent_item_v0))
        return false;

    if (tp.item->size < sizeof(struct btrfs_extent_item)) {
        WARN("(%I64x,%x,%I64x) was %u bytes, expected at least %Iu\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset, tp.item->size, sizeof(struct btrfs_extent_item));
        return false;
    }

    ei = (struct btrfs_extent_item*)tp.item->data;

    len = tp.item->size - sizeof(struct btrfs_extent_item);
    ptr = (uint8_t*)&ei[1];

    if (ei->flags & BTRFS_EXTENT_FLAG_TREE_BLOCK) {
        if (tp.item->size < sizeof(struct btrfs_extent_item) + sizeof(struct btrfs_tree_block_info)) {
            WARN("(%I64x,%x,%I64x) was %u bytes, expected at least %Iu\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset, tp.item->size, sizeof(struct btrfs_extent_item) + sizeof(struct btrfs_tree_block_info));
            return false;
        }

        len -= sizeof(struct btrfs_tree_block_info);
        ptr += sizeof(struct btrfs_tree_block_info);
    }

    rcrun = 0;

    // Loop through inline extent entries

    while (len > 0) {
        struct btrfs_extent_inline_ref* eir = (struct btrfs_extent_inline_ref*)ptr;
        struct btrfs_extent_data_ref* edr;

        if (len < sizeof(struct btrfs_extent_inline_ref)) {
            ERR("%I64x,%x,%I64x was truncated\n", tp.item->key.objectid,
                tp.item->key.type, tp.item->key.offset);

            return false;
        }

        ptr += sizeof(struct btrfs_extent_inline_ref);
        len -= sizeof(struct btrfs_extent_inline_ref);

        if (eir->type != BTRFS_EXTENT_DATA_REF_KEY)
            return false;

        if (len < sizeof(struct btrfs_extent_data_ref) - sizeof(uint64_t)) {
            ERR("%I64x,%x,%I64x was truncated\n", tp.item->key.objectid,
                tp.item->key.type, tp.item->key.offset);

            return false;
        }

        edr = (struct btrfs_extent_data_ref*)(ptr - sizeof(uint64_t));

        ptr += sizeof(struct btrfs_extent_data_ref) - sizeof(uint64_t);
        len -= sizeof(struct btrfs_extent_data_ref) - sizeof(uint64_t);
        rcrun += edr->count;

        if (root == 0 && inode == 0) {
            root = edr->root;
            inode = edr->objectid;
            offset = edr->offset;
        } else if (root != edr->root || inode != edr->objectid || offset != edr->offset)
            return false;
    }

    if (rcrun == rc)
        return true;

    // Loop through non-inlines if some refs still unaccounted for

    do {
        b = find_next_item(Vcb, &tp, &next_tp, false, Irp);

        if (tp.item->key.objectid == searchkey.objectid && tp.item->key.type == BTRFS_EXTENT_DATA_REF_KEY) {
            struct btrfs_extent_data_ref* edr = (struct btrfs_extent_data_ref*)tp.item->data;

            if (tp.item->size < sizeof(struct btrfs_extent_data_ref)) {
                WARN("(%I64x,%x,%I64x) was %u bytes, expected at least %Iu\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset,
                     tp.item->size, sizeof(struct btrfs_extent_data_ref));
                return false;
            }

            if (root == 0 && inode == 0) {
                root = edr->root;
                inode = edr->objectid;
                offset = edr->offset;
            } else if (root != edr->root || inode != edr->objectid || offset != edr->offset)
                return false;

            rcrun += edr->count;
        }

        if (rcrun == rc)
            return true;

        if (b) {
            tp = next_tp;

            if (tp.item->key.objectid > searchkey.objectid)
                break;
        }
    } while (b);

    // If we reach this point, there's still some refs unaccounted for somewhere.
    // Return false in case we mess things up elsewhere.

    return false;
}

uint64_t get_extent_flags(device_extension* Vcb, uint64_t address, PIRP Irp) {
    struct btrfs_key searchkey;
    traverse_ptr tp;
    NTSTATUS Status;
    struct btrfs_extent_item* ei;

    searchkey.objectid = address;
    searchkey.type = Vcb->superblock.incompat_flags & BTRFS_FEATURE_INCOMPAT_SKINNY_METADATA ? BTRFS_METADATA_ITEM_KEY : BTRFS_EXTENT_ITEM_KEY;
    searchkey.offset = 0xffffffffffffffff;

    Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, false, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08lx\n", Status);
        return 0;
    }

    if (Vcb->superblock.incompat_flags & BTRFS_FEATURE_INCOMPAT_SKINNY_METADATA && tp.item->key.objectid == address &&
        tp.item->key.type == BTRFS_METADATA_ITEM_KEY && tp.item->size >= sizeof(struct btrfs_extent_item)) {
        ei = (struct btrfs_extent_item*)tp.item->data;

        return ei->flags;
    }

    if (tp.item->key.objectid != address || tp.item->key.type != BTRFS_EXTENT_ITEM_KEY) {
        ERR("couldn't find %I64x in extent tree\n", address);
        return 0;
    }

    if (tp.item->size == sizeof(struct btrfs_extent_item_v0))
        return 0;
    else if (tp.item->size < sizeof(struct btrfs_extent_item)) {
        ERR("(%I64x,%x,%I64x) was %x bytes, expected at least %Ix\n", tp.item->key.objectid, tp.item->key.type,
                                                                      tp.item->key.offset, tp.item->size, sizeof(struct btrfs_extent_item));
        return 0;
    }

    ei = (struct btrfs_extent_item*)tp.item->data;

    return ei->flags;
}

void update_extent_flags(device_extension* Vcb, uint64_t address, uint64_t flags, PIRP Irp) {
    struct btrfs_key searchkey;
    traverse_ptr tp;
    NTSTATUS Status;
    struct btrfs_extent_item* ei;

    searchkey.objectid = address;
    searchkey.type = Vcb->superblock.incompat_flags & BTRFS_FEATURE_INCOMPAT_SKINNY_METADATA ? BTRFS_METADATA_ITEM_KEY : BTRFS_EXTENT_ITEM_KEY;
    searchkey.offset = 0xffffffffffffffff;

    Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, false, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08lx\n", Status);
        return;
    }

    if (Vcb->superblock.incompat_flags & BTRFS_FEATURE_INCOMPAT_SKINNY_METADATA && tp.item->key.objectid == address &&
        tp.item->key.type == BTRFS_METADATA_ITEM_KEY && tp.item->size >= sizeof(struct btrfs_extent_item)) {
        ei = (struct btrfs_extent_item*)tp.item->data;
        ei->flags = flags;
        return;
    }

    if (tp.item->key.objectid != address || tp.item->key.type != BTRFS_EXTENT_ITEM_KEY) {
        ERR("couldn't find %I64x in extent tree\n", address);
        return;
    }

    if (tp.item->size == sizeof(struct btrfs_extent_item_v0))
        return;
    else if (tp.item->size < sizeof(struct btrfs_extent_item)) {
        ERR("(%I64x,%x,%I64x) was %x bytes, expected at least %Ix\n", tp.item->key.objectid, tp.item->key.type,
                                                                      tp.item->key.offset, tp.item->size, sizeof(struct btrfs_extent_item));
        return;
    }

    ei = (struct btrfs_extent_item*)tp.item->data;
    ei->flags = flags;
}

static changed_extent* get_changed_extent_item(chunk* c, uint64_t address, uint64_t size, bool no_csum) {
    LIST_ENTRY* le;
    changed_extent* ce;

    le = c->changed_extents.Flink;
    while (le != &c->changed_extents) {
        ce = CONTAINING_RECORD(le, changed_extent, list_entry);

        if (ce->address == address && ce->size == size)
            return ce;

        le = le->Flink;
    }

    ce = ExAllocatePoolWithTag(PagedPool, sizeof(changed_extent), ALLOC_TAG);
    if (!ce) {
        ERR("out of memory\n");
        return NULL;
    }

    ce->address = address;
    ce->size = size;
    ce->old_size = size;
    ce->count = 0;
    ce->old_count = 0;
    ce->no_csum = no_csum;
    ce->superseded = false;
    InitializeListHead(&ce->refs);
    InitializeListHead(&ce->old_refs);

    InsertTailList(&c->changed_extents, &ce->list_entry);

    return ce;
}

NTSTATUS update_changed_extent_ref(device_extension* Vcb, chunk* c, uint64_t address,
                                   uint64_t size, uint64_t root, uint64_t objid,
                                   uint64_t offset, int32_t count, bool no_csum,
                                   bool superseded, PIRP Irp, LIST_ENTRY* rollback) {
    LIST_ENTRY* le;
    changed_extent* ce;
    changed_extent_ref* cer;
    NTSTATUS Status;
    struct btrfs_key searchkey;
    traverse_ptr tp;
    uint32_t old_count;
    rollback_item* ri;

    ExAcquireResourceExclusiveLite(&c->changed_extents_lock, true);

    ce = get_changed_extent_item(c, address, size, no_csum);

    if (!ce) {
        ERR("get_changed_extent_item failed\n");
        Status = STATUS_INTERNAL_ERROR;
        goto end;
    }

    if (IsListEmpty(&ce->refs) && IsListEmpty(&ce->old_refs)) { // new entry
        searchkey.objectid = address;
        searchkey.type = BTRFS_EXTENT_ITEM_KEY;
        searchkey.offset = 0xffffffffffffffff;

        Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, false, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("error - find_item returned %08lx\n", Status);
            goto end;
        }

        if (tp.item->key.objectid != searchkey.objectid || tp.item->key.type != searchkey.type) {
            ERR("could not find address %I64x in extent tree\n", address);
            Status = STATUS_INTERNAL_ERROR;
            goto end;
        }

        if (tp.item->key.offset != size) {
            ERR("extent %I64x had size %I64x, not %I64x as expected\n", address, tp.item->key.offset, size);
            Status = STATUS_INTERNAL_ERROR;
            goto end;
        }

        if (tp.item->size == sizeof(struct btrfs_extent_item_v0)) {
            struct btrfs_extent_item_v0* eiv0 = (struct btrfs_extent_item_v0*)tp.item->data;

            ce->count = ce->old_count = eiv0->refs;
        } else if (tp.item->size >= sizeof(struct btrfs_extent_item)) {
            struct btrfs_extent_item* ei = (struct btrfs_extent_item*)tp.item->data;

            ce->count = ce->old_count = ei->refs;
        } else {
            ERR("(%I64x,%x,%I64x) was %u bytes, expected at least %Iu\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset, tp.item->size, sizeof(struct btrfs_extent_item));
            Status = STATUS_INTERNAL_ERROR;
            goto end;
        }
    }

    if (rollback) {
        ri = ExAllocatePoolWithTag(PagedPool, sizeof(rollback_item), ALLOC_TAG);
        if (!ri) {
            ERR("out of memory\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }

        ri->type = ROLLBACK_UPDATE_CHANGED_EXTENT_REF;
        ri->changed_extent_ref.address = address;
        ri->changed_extent_ref.size = size;
        ri->changed_extent_ref.root = root;
        ri->changed_extent_ref.objid = objid;
        ri->changed_extent_ref.offset = offset;
        ri->changed_extent_ref.count = count;
    }

    le = ce->refs.Flink;
    while (le != &ce->refs) {
        cer = CONTAINING_RECORD(le, changed_extent_ref, list_entry);

        if (cer->type == BTRFS_EXTENT_DATA_REF_KEY && cer->edr.root == root && cer->edr.objectid == objid && cer->edr.offset == offset) {
            ce->count += count;
            cer->edr.count += count;
            Status = STATUS_SUCCESS;

            if (superseded)
                ce->superseded = true;

            if (rollback)
                InsertTailList(rollback, &ri->list_entry);

            goto end;
        }

        le = le->Flink;
    }

    old_count = find_extent_data_refcount(Vcb, address, size, root, objid, offset, Irp);

    if (old_count > 0) {
        cer = ExAllocatePoolWithTag(PagedPool, sizeof(changed_extent_ref), ALLOC_TAG);

        if (!cer) {
            ERR("out of memory\n");

            if (rollback)
                ExFreePool(ri);

            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }

        cer->type = BTRFS_EXTENT_DATA_REF_KEY;
        cer->edr.root = root;
        cer->edr.objectid = objid;
        cer->edr.offset = offset;
        cer->edr.count = old_count;

        InsertTailList(&ce->old_refs, &cer->list_entry);
    }

    cer = ExAllocatePoolWithTag(PagedPool, sizeof(changed_extent_ref), ALLOC_TAG);

    if (!cer) {
        ERR("out of memory\n");

        if (rollback)
            ExFreePool(ri);

        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }

    cer->type = BTRFS_EXTENT_DATA_REF_KEY;
    cer->edr.root = root;
    cer->edr.objectid = objid;
    cer->edr.offset = offset;
    cer->edr.count = old_count + count;

    InsertTailList(&ce->refs, &cer->list_entry);

    ce->count += count;

    if (superseded)
        ce->superseded = true;

    if (rollback)
        InsertTailList(rollback, &ri->list_entry);

    Status = STATUS_SUCCESS;

end:
    ExReleaseResourceLite(&c->changed_extents_lock);

    return Status;
}

NTSTATUS add_changed_extent_ref(chunk* c, uint64_t address, uint64_t size,
                                uint64_t root, uint64_t objid, uint64_t offset,
                                uint32_t count, bool no_csum, LIST_ENTRY* rollback) {
    changed_extent* ce;
    changed_extent_ref* cer;
    rollback_item* ri;
    LIST_ENTRY* le;

    ce = get_changed_extent_item(c, address, size, no_csum);
    if (!ce) {
        ERR("get_changed_extent_item failed\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (rollback) {
        ri = ExAllocatePoolWithTag(PagedPool, sizeof(rollback_item), ALLOC_TAG);
        if (!ri) {
            ERR("out of memory\n");

            if (IsListEmpty(&ce->refs) && ce->count == 0) {
                RemoveEntryList(&ce->list_entry);
                ExFreePool(ce);
            }

            return STATUS_INSUFFICIENT_RESOURCES;
        }

        ri->type = ROLLBACK_UPDATE_CHANGED_EXTENT_REF;
        ri->changed_extent_ref.address = address;
        ri->changed_extent_ref.size = size;
        ri->changed_extent_ref.root = root;
        ri->changed_extent_ref.objid = objid;
        ri->changed_extent_ref.offset = offset;
        ri->changed_extent_ref.count = count;
    }

    le = ce->refs.Flink;
    while (le != &ce->refs) {
        cer = CONTAINING_RECORD(le, changed_extent_ref, list_entry);

        if (cer->type == BTRFS_EXTENT_DATA_REF_KEY && cer->edr.root == root && cer->edr.objectid == objid && cer->edr.offset == offset) {
            ce->count += count;
            cer->edr.count += count;

            if (rollback)
                InsertTailList(rollback, &ri->list_entry);

            return STATUS_SUCCESS;
        }

        le = le->Flink;
    }

    cer = ExAllocatePoolWithTag(PagedPool, sizeof(changed_extent_ref), ALLOC_TAG);

    if (!cer) {
        ERR("out of memory\n");

        if (IsListEmpty(&ce->refs) && ce->count == 0) {
            RemoveEntryList(&ce->list_entry);
            ExFreePool(ce);
        }

        if (rollback)
            ExFreePool(ri);

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    cer->type = BTRFS_EXTENT_DATA_REF_KEY;
    cer->edr.root = root;
    cer->edr.objectid = objid;
    cer->edr.offset = offset;
    cer->edr.count = count;

    InsertTailList(&ce->refs, &cer->list_entry);

    ce->count += count;

    if (rollback)
        InsertTailList(rollback, &ri->list_entry);

    return STATUS_SUCCESS;
}

uint64_t find_extent_shared_tree_refcount(device_extension* Vcb, uint64_t address, uint64_t parent, PIRP Irp) {
    NTSTATUS Status;
    struct btrfs_key searchkey;
    traverse_ptr tp;
    uint64_t inline_rc;
    struct btrfs_extent_item* ei;
    uint32_t len;
    uint8_t* ptr;

    searchkey.objectid = address;
    searchkey.type = Vcb->superblock.incompat_flags & BTRFS_FEATURE_INCOMPAT_SKINNY_METADATA ? BTRFS_METADATA_ITEM_KEY : BTRFS_EXTENT_ITEM_KEY;
    searchkey.offset = 0xffffffffffffffff;

    Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, false, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08lx\n", Status);
        return 0;
    }

    if (tp.item->key.objectid != searchkey.objectid || (tp.item->key.type != BTRFS_EXTENT_ITEM_KEY && tp.item->key.type != BTRFS_METADATA_ITEM_KEY)) {
        TRACE("could not find address %I64x in extent tree\n", address);
        return 0;
    }

    if (tp.item->key.type == BTRFS_EXTENT_ITEM_KEY && tp.item->key.offset != Vcb->superblock.nodesize) {
        ERR("extent %I64x had size %I64x, not %x as expected\n", address, tp.item->key.offset, Vcb->superblock.nodesize);
        return 0;
    }

    if (tp.item->size < sizeof(struct btrfs_extent_item)) {
        ERR("(%I64x,%x,%I64x): size was %u, expected at least %Iu\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset, tp.item->size, sizeof(struct btrfs_extent_item));
        return 0;
    }

    ei = (struct btrfs_extent_item*)tp.item->data;
    inline_rc = 0;

    len = tp.item->size - sizeof(struct btrfs_extent_item);
    ptr = (uint8_t*)&ei[1];

    if (tp.item->key.type == BTRFS_EXTENT_ITEM_KEY && ei->flags & BTRFS_EXTENT_FLAG_TREE_BLOCK) {
        if (tp.item->size < sizeof(struct btrfs_extent_item) + sizeof(struct btrfs_tree_block_info)) {
            ERR("(%I64x,%x,%I64x): size was %u, expected at least %Iu\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset,
                                                                          tp.item->size, sizeof(struct btrfs_extent_item) + sizeof(struct btrfs_tree_block_info));
            return 0;
        }

        len -= sizeof(struct btrfs_tree_block_info);
        ptr += sizeof(struct btrfs_tree_block_info);
    }

    while (len > 0) {
        struct btrfs_extent_inline_ref* eir = (struct btrfs_extent_inline_ref*)ptr;

        if (len < sizeof(struct btrfs_extent_inline_ref)) {
            ERR("(%I64x,%x,%I64x) was truncated\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset);
            return 0;
        }

        ptr += sizeof(struct btrfs_extent_inline_ref);
        len -= sizeof(struct btrfs_extent_inline_ref);

        switch (eir->type) {
            case BTRFS_SHARED_DATA_REF_KEY: {
                struct btrfs_shared_data_ref* sdr;

                if (len < sizeof(struct btrfs_shared_data_ref)) {
                    ERR("(%I64x,%x,%I64x) was truncated\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset);
                    return 0;
                }

                sdr = (struct btrfs_shared_data_ref*)ptr;

                ptr += sizeof(struct btrfs_shared_data_ref);
                len -= sizeof(struct btrfs_shared_data_ref);
                inline_rc += sdr->count;

                break;
            }

            case BTRFS_EXTENT_DATA_REF_KEY: {
                struct btrfs_extent_data_ref* edr;

                if (len < sizeof(struct btrfs_extent_data_ref) - sizeof(uint64_t)) {
                    ERR("(%I64x,%x,%I64x) was truncated\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset);
                    return 0;
                }

                edr = (struct btrfs_extent_data_ref*)&eir->offset;

                ptr += sizeof(struct btrfs_extent_data_ref) - sizeof(uint64_t);
                len -= sizeof(struct btrfs_extent_data_ref) - sizeof(uint64_t);
                inline_rc += edr->count;

                break;
            }

            case BTRFS_TREE_BLOCK_REF_KEY:
                inline_rc++;
                break;

            case BTRFS_SHARED_BLOCK_REF_KEY: {
                if (eir->offset == parent)
                    return 1;

                inline_rc++;
                break;
            }

            default:
                ERR("unknown extent item type %x\n", eir->type);
                return 0;
        }
    }

    if (inline_rc == ei->refs)
        return 0;

    searchkey.objectid = address;
    searchkey.type = BTRFS_SHARED_BLOCK_REF_KEY;
    searchkey.offset = parent;

    Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, false, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08lx\n", Status);
        return 0;
    }

    if (!keycmp(searchkey, tp.item->key))
        return 1;

    return 0;
}

uint32_t find_extent_shared_data_refcount(device_extension* Vcb, uint64_t address, uint64_t parent, PIRP Irp) {
    NTSTATUS Status;
    struct btrfs_key searchkey;
    traverse_ptr tp;
    uint64_t inline_rc;
    struct btrfs_extent_item* ei;
    uint32_t len;
    uint8_t* ptr;

    searchkey.objectid = address;
    searchkey.type = Vcb->superblock.incompat_flags & BTRFS_FEATURE_INCOMPAT_SKINNY_METADATA ? BTRFS_METADATA_ITEM_KEY : BTRFS_EXTENT_ITEM_KEY;
    searchkey.offset = 0xffffffffffffffff;

    Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, false, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08lx\n", Status);
        return 0;
    }

    if (tp.item->key.objectid != searchkey.objectid || (tp.item->key.type != BTRFS_EXTENT_ITEM_KEY && tp.item->key.type != BTRFS_METADATA_ITEM_KEY)) {
        TRACE("could not find address %I64x in extent tree\n", address);
        return 0;
    }

    if (tp.item->size < sizeof(struct btrfs_extent_item)) {
        ERR("(%I64x,%x,%I64x): size was %u, expected at least %Iu\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset, tp.item->size, sizeof(struct btrfs_extent_item));
        return 0;
    }

    ei = (struct btrfs_extent_item*)tp.item->data;
    inline_rc = 0;

    len = tp.item->size - sizeof(struct btrfs_extent_item);
    ptr = (uint8_t*)&ei[1];

    while (len > 0) {
        struct btrfs_extent_inline_ref* eir = (struct btrfs_extent_inline_ref*)ptr;

        if (len < sizeof(struct btrfs_extent_inline_ref)) {
            ERR("(%I64x,%x,%I64x) was truncated\n", tp.item->key.objectid,
                tp.item->key.type, tp.item->key.offset);

            return 0;
        }

        ptr += sizeof(struct btrfs_extent_inline_ref);
        len -= sizeof(struct btrfs_extent_inline_ref);

        switch (eir->type) {
            case BTRFS_EXTENT_DATA_REF_KEY: {
                struct btrfs_extent_data_ref* edr = (struct btrfs_extent_data_ref*)(ptr - sizeof(uint64_t));

                if (len < sizeof(struct btrfs_extent_data_ref) - sizeof(uint64_t)) {
                    ERR("(%I64x,%x,%I64x) was truncated\n", tp.item->key.objectid,
                        tp.item->key.type, tp.item->key.offset);
                    return 0;
                }

                ptr += sizeof(struct btrfs_extent_data_ref) - sizeof(uint64_t);
                len -= sizeof(struct btrfs_extent_data_ref) - sizeof(uint64_t);
                inline_rc += edr->count;

                break;
            }

            case BTRFS_SHARED_DATA_REF_KEY: {
                struct btrfs_shared_data_ref* sdr = (struct btrfs_shared_data_ref*)ptr;

                if (len < sizeof(struct btrfs_shared_data_ref)) {
                    ERR("(%I64x,%x,%I64x) was truncated\n", tp.item->key.objectid,
                        tp.item->key.type, tp.item->key.offset);
                    return 0;
                }

                ptr += sizeof(struct btrfs_shared_data_ref);
                len -= sizeof(struct btrfs_shared_data_ref);
                inline_rc += sdr->count;

                if (eir->offset == parent)
                    return sdr->count;

                break;
            }

            default:
                ERR("(%I64x,%x,%I64x): unexpected type %x\n",
                    tp.item->key.objectid, tp.item->key.type,
                    tp.item->key.offset, eir->type);
                return 0;
        }
    }

    // FIXME - what if old?

    if (inline_rc == ei->refs)
        return 0;

    searchkey.objectid = address;
    searchkey.type = BTRFS_SHARED_DATA_REF_KEY;
    searchkey.offset = parent;

    Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, false, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08lx\n", Status);
        return 0;
    }

    if (!keycmp(searchkey, tp.item->key)) {
        if (tp.item->size < sizeof(struct btrfs_shared_data_ref)) {
            ERR("(%I64x,%x,%I64x) has size %u, not %Iu as expected\n",
                tp.item->key.objectid, tp.item->key.type, tp.item->key.offset,
                tp.item->size, sizeof(struct btrfs_shared_data_ref));
        } else {
            struct btrfs_shared_data_ref* sdr = (struct btrfs_shared_data_ref*)tp.item->data;

            return sdr->count;
        }
    }

    return 0;
}
