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

static __inline ULONG get_extent_data_len(UINT8 type) {
    switch (type) {
        case TYPE_TREE_BLOCK_REF:
            return sizeof(TREE_BLOCK_REF);
            
        case TYPE_EXTENT_DATA_REF:
            return sizeof(EXTENT_DATA_REF);
            
        // FIXME - TYPE_EXTENT_REF_V0
        // FIXME - TYPE_SHARED_BLOCK_REF
            
        case TYPE_SHARED_DATA_REF:
            return sizeof(SHARED_DATA_REF);
            
        default:
            return 0;
    }
}

static __inline UINT64 get_extent_data_refcount(UINT8 type, void* data) {
    switch (type) {
        case TYPE_TREE_BLOCK_REF:
            return 1;
            
        case TYPE_EXTENT_DATA_REF:
        {
            EXTENT_DATA_REF* edr = (EXTENT_DATA_REF*)data;
            return edr->count;
        }
        
        // FIXME - TYPE_EXTENT_REF_V0
        // FIXME - TYPE_SHARED_BLOCK_REF
        
        case TYPE_SHARED_DATA_REF:
        {
            SHARED_DATA_REF* sdr = (SHARED_DATA_REF*)data;
            return sdr->count;
        }
            
        default:
            return 0;
    }
}

static UINT64 get_extent_data_ref_hash(EXTENT_DATA_REF* edr) {
    UINT32 high_crc = 0xffffffff, low_crc = 0xffffffff;

    high_crc = calc_crc32c(high_crc, (UINT8*)&edr->root, sizeof(UINT64));
    low_crc = calc_crc32c(low_crc, (UINT8*)&edr->objid, sizeof(UINT64));
    low_crc = calc_crc32c(low_crc, (UINT8*)&edr->offset, sizeof(UINT64));
    
    return ((UINT64)high_crc << 31) ^ (UINT64)low_crc;
}

static UINT64 get_extent_hash(UINT8 type, void* data) {
    if (type == TYPE_EXTENT_DATA_REF) {
        return get_extent_data_ref_hash((EXTENT_DATA_REF*)data);
    } else {
        ERR("unhandled extent type %x\n", type);
        return 0;
    }
}

static NTSTATUS increase_extent_refcount(device_extension* Vcb, UINT64 address, UINT64 size, UINT8 type, void* data, KEY* firstitem, UINT8 level, LIST_ENTRY* rollback) {
    NTSTATUS Status;
    KEY searchkey;
    traverse_ptr tp;
    ULONG datalen = get_extent_data_len(type), len, max_extent_item_size;
    EXTENT_ITEM* ei;
    UINT8* ptr;
    UINT64 inline_rc, offset;
    UINT8* data2;
    EXTENT_ITEM* newei;
    
    // FIXME - handle A9s
    // FIXME - handle shared extents
    // FIXME - handle old-style extents
    
    if (datalen == 0) {
        ERR("unrecognized extent type %x\n", type);
        return STATUS_INTERNAL_ERROR;
    }
    
    searchkey.obj_id = address;
    searchkey.obj_type = TYPE_EXTENT_ITEM;
    searchkey.offset = 0xffffffffffffffff;
    
    Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, FALSE);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08x\n", Status);
        return Status;
    }
    
    // If entry doesn't exist yet, create new inline extent item
    
    if (tp.item->key.obj_id != searchkey.obj_id || tp.item->key.obj_type != searchkey.obj_type) {
        ULONG eisize;
        EXTENT_ITEM* ei;
        BOOL is_tree = type == TYPE_TREE_BLOCK_REF;
        UINT8* ptr;
        
        eisize = sizeof(EXTENT_ITEM);
        if (is_tree) eisize += sizeof(EXTENT_ITEM2);
        eisize += sizeof(UINT8);
        eisize += datalen;
        
        ei = ExAllocatePoolWithTag(PagedPool, eisize, ALLOC_TAG);
        if (!ei) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        
        ei->refcount = get_extent_data_refcount(type, data);
        ei->generation = Vcb->superblock.generation;
        ei->flags = is_tree ? EXTENT_ITEM_TREE_BLOCK : EXTENT_ITEM_DATA;
        ptr = (UINT8*)&ei[1];
        
        if (is_tree) {
            EXTENT_ITEM2* ei2 = (EXTENT_ITEM2*)ptr;
            ei2->firstitem = *firstitem;
            ei2->level = level;
            ptr = (UINT8*)&ei2[1];
        }
        
        *ptr = type;
        RtlCopyMemory(ptr + 1, data, datalen);
        
        if (!insert_tree_item(Vcb, Vcb->extent_root, address, TYPE_EXTENT_ITEM, size, ei, eisize, NULL, rollback)) {
            ERR("insert_tree_item failed\n");
            return STATUS_INTERNAL_ERROR;
        }
        
        // FIXME - add to space list?

        return STATUS_SUCCESS;
    } else if (tp.item->key.offset != size) {
        ERR("extent %llx exists, but with size %llx rather than %llx expected\n", tp.item->key.obj_id, tp.item->key.offset, size);
        return STATUS_INTERNAL_ERROR;
    } else if (tp.item->size < sizeof(EXTENT_ITEM)) {
        ERR("(%llx,%x,%llx) was %u bytes, expected at least %u\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, tp.item->size, sizeof(EXTENT_ITEM));
        return STATUS_INTERNAL_ERROR;
    }
    
    ei = (EXTENT_ITEM*)tp.item->data;
    
    len = tp.item->size - sizeof(EXTENT_ITEM);
    ptr = (UINT8*)&ei[1];
    
    if (ei->flags & EXTENT_ITEM_TREE_BLOCK) {
        if (tp.item->size < sizeof(EXTENT_ITEM) + sizeof(EXTENT_ITEM2)) {
            ERR("(%llx,%x,%llx) was %u bytes, expected at least %u\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, tp.item->size, sizeof(EXTENT_ITEM) + sizeof(EXTENT_ITEM2));
            return STATUS_INTERNAL_ERROR;
        }
        
        len -= sizeof(EXTENT_ITEM2);
        ptr += sizeof(EXTENT_ITEM2);
    }
    
    inline_rc = 0;
    
    // Loop through existing inline extent entries
    
    while (len > 0) {
        UINT8 secttype = *ptr;
        ULONG sectlen = get_extent_data_len(secttype);
        UINT64 sectcount = get_extent_data_refcount(secttype, ptr + sizeof(UINT8));
        
        len--;
        
        if (sectlen > len) {
            ERR("(%llx,%x,%llx): %x bytes left, expecting at least %x\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, len, sectlen);
            return STATUS_INTERNAL_ERROR;
        }

        if (sectlen == 0) {
            ERR("(%llx,%x,%llx): unrecognized extent type %x\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, secttype);
            return STATUS_INTERNAL_ERROR;
        }
        
        // If inline extent already present, increase refcount and return
        
        if (secttype == type) {
            if (type == TYPE_EXTENT_DATA_REF) {
                EXTENT_DATA_REF* sectedr = (EXTENT_DATA_REF*)(ptr + sizeof(UINT8));
                EXTENT_DATA_REF* edr = (EXTENT_DATA_REF*)data;
                
                if (sectedr->root == edr->root && sectedr->objid == edr->objid && sectedr->offset == edr->offset) {
                    UINT32 rc = get_extent_data_refcount(type, data);
                    EXTENT_DATA_REF* sectedr2;
                    
                    newei = ExAllocatePoolWithTag(PagedPool, tp.item->size, ALLOC_TAG);
                    if (!newei) {
                        ERR("out of memory\n");
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }
                    
                    RtlCopyMemory(newei, tp.item->data, tp.item->size);
                    
                    newei->generation = Vcb->superblock.generation;
                    newei->refcount += rc;
                    
                    sectedr2 = (EXTENT_DATA_REF*)((UINT8*)newei + ((UINT8*)sectedr - tp.item->data));
                    sectedr2->count += rc;
                    
                    delete_tree_item(Vcb, &tp, rollback);
                    
                    if (!insert_tree_item(Vcb, Vcb->extent_root, tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, newei, tp.item->size, NULL, rollback)) {
                        ERR("insert_tree_item failed\n");
                        return STATUS_INTERNAL_ERROR;
                    }
                    
                    return STATUS_SUCCESS;
                }
            } else if (type == TYPE_TREE_BLOCK_REF) {
                ERR("trying to increase refcount of tree extent\n");
                return STATUS_INTERNAL_ERROR;
            } else {
                ERR("unhandled extent type %x\n", type);
                return STATUS_INTERNAL_ERROR;
            }
        }
        
        len -= sectlen;
        ptr += sizeof(UINT8) + sectlen;
        inline_rc += sectcount;
    }
    
    offset = get_extent_hash(type, data);
    
    max_extent_item_size = (Vcb->superblock.node_size >> 4) - sizeof(leaf_node);
    
    // If we can, add entry as inline extent item
    
    if (inline_rc == ei->refcount && tp.item->size + sizeof(UINT8) + datalen < max_extent_item_size) {
        len = tp.item->size - sizeof(EXTENT_ITEM);
        ptr = (UINT8*)&ei[1];
        
        if (ei->flags & EXTENT_ITEM_TREE_BLOCK) {
            len -= sizeof(EXTENT_ITEM2);
            ptr += sizeof(EXTENT_ITEM2);
        }

        while (len > 0) {
            UINT8 secttype = *ptr;
            ULONG sectlen = get_extent_data_len(secttype);
            
            if (secttype > type)
                break;
            
            len--;
            
            if (secttype == type) {
                UINT64 sectoff = get_extent_hash(secttype, ptr + 1);
                
                if (sectoff > offset)
                    break;
            }
            
            len -= sectlen;
            ptr += sizeof(UINT8) + sectlen;
        }
        
        newei = ExAllocatePoolWithTag(PagedPool, tp.item->size + sizeof(UINT8) + datalen, ALLOC_TAG);
        RtlCopyMemory(newei, tp.item->data, ptr - tp.item->data);
        
        newei->generation = Vcb->superblock.generation;
        newei->refcount += get_extent_data_refcount(type, data);
        
        if (len > 0)
            RtlCopyMemory((UINT8*)newei + (ptr - tp.item->data) + sizeof(UINT8) + datalen, ptr, len + 1);
        
        ptr = (ptr - tp.item->data) + (UINT8*)newei;
        
        *ptr = type;
        RtlCopyMemory(ptr + 1, data, datalen);
        
        delete_tree_item(Vcb, &tp, rollback);
        
        if (!insert_tree_item(Vcb, Vcb->extent_root, tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, newei, tp.item->size + sizeof(UINT8) + datalen, NULL, rollback)) {
            ERR("insert_tree_item failed\n");
            return STATUS_INTERNAL_ERROR;
        }
        
        return STATUS_SUCCESS;
    }
    
    // Look for existing non-inline entry, and increase refcount if found
    
    if (inline_rc != ei->refcount) {
        traverse_ptr tp2;
        
        searchkey.obj_id = address;
        searchkey.obj_type = type;
        searchkey.offset = offset;
        
        Status = find_item(Vcb, Vcb->extent_root, &tp2, &searchkey, FALSE);
        if (!NT_SUCCESS(Status)) {
            ERR("error - find_item returned %08x\n", Status);
            return Status;
        }
        
        if (!keycmp(&tp.item->key, &searchkey)) {
            if (tp.item->size < datalen) {
                ERR("(%llx,%x,%llx) was %x bytes, expecting %x\n", tp2.item->key.obj_id, tp2.item->key.obj_type, tp2.item->key.offset, tp.item->size, datalen);
                return STATUS_INTERNAL_ERROR;
            }
            
            data2 = ExAllocatePoolWithTag(PagedPool, tp2.item->size, ALLOC_TAG);
            RtlCopyMemory(data2, tp2.item->data, tp2.item->size);
            
            if (type == TYPE_EXTENT_DATA_REF) {
                EXTENT_DATA_REF* edr = (EXTENT_DATA_REF*)data2;
                
                edr->count += get_extent_data_refcount(type, data);
            } else if (type == TYPE_TREE_BLOCK_REF) {
                ERR("trying to increase refcount of tree extent\n");
                return STATUS_INTERNAL_ERROR;
            } else {
                ERR("unhandled extent type %x\n", type);
                return STATUS_INTERNAL_ERROR;
            }
            
            delete_tree_item(Vcb, &tp2, rollback);
            
            if (!insert_tree_item(Vcb, Vcb->extent_root, tp2.item->key.obj_id, tp2.item->key.obj_type, tp2.item->key.offset, data2, tp2.item->size, NULL, rollback)) {
                ERR("insert_tree_item failed\n");
                return STATUS_INTERNAL_ERROR;
            }
            
            newei = ExAllocatePoolWithTag(PagedPool, tp.item->size, ALLOC_TAG);
            RtlCopyMemory(newei, tp.item->data, tp.item->size);
            
            newei->generation = Vcb->superblock.generation;
            newei->refcount += get_extent_data_refcount(type, data);
            
            delete_tree_item(Vcb, &tp, rollback);
            
            if (!insert_tree_item(Vcb, Vcb->extent_root, tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, newei, tp.item->size, NULL, rollback)) {
                ERR("insert_tree_item failed\n");
                return STATUS_INTERNAL_ERROR;
            }
            
            return STATUS_SUCCESS;
        }
    }
    
    // Otherwise, add new non-inline entry
    
    data2 = ExAllocatePoolWithTag(PagedPool, datalen, ALLOC_TAG);
    RtlCopyMemory(data2, data, datalen);
    
    if (!insert_tree_item(Vcb, Vcb->extent_root, address, type, offset, data2, datalen, NULL, rollback)) {
        ERR("insert_tree_item failed\n");
        return STATUS_INTERNAL_ERROR;
    }
    
    newei = ExAllocatePoolWithTag(PagedPool, tp.item->size, ALLOC_TAG);
    RtlCopyMemory(newei, tp.item->data, tp.item->size);
    
    newei->generation = Vcb->superblock.generation;
    newei->refcount += get_extent_data_refcount(type, data);
    
    delete_tree_item(Vcb, &tp, rollback);
    
    if (!insert_tree_item(Vcb, Vcb->extent_root, tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, newei, tp.item->size, NULL, rollback)) {
        ERR("insert_tree_item failed\n");
        return STATUS_INTERNAL_ERROR;
    }
    
    return STATUS_SUCCESS;
}

NTSTATUS increase_extent_refcount_data(device_extension* Vcb, UINT64 address, UINT64 size, root* subvol, UINT64 inode, UINT64 offset, UINT32 refcount, LIST_ENTRY* rollback) {
    EXTENT_DATA_REF edr;
    
    edr.root = subvol->id;
    edr.objid = inode;
    edr.offset = offset;
    edr.count = refcount;
    
    return increase_extent_refcount(Vcb, address, size, TYPE_EXTENT_DATA_REF, &edr, NULL, 0, rollback);
}

void decrease_chunk_usage(chunk* c, UINT64 delta) {
    c->used -= delta;
    
    TRACE("decreasing size of chunk %llx by %llx\n", c->offset, delta);
}

static NTSTATUS remove_extent(device_extension* Vcb, UINT64 address, UINT64 size, LIST_ENTRY* changed_sector_list) {
    chunk* c;
    LIST_ENTRY* le;
    
    if (changed_sector_list) {
        changed_sector* sc = ExAllocatePoolWithTag(PagedPool, sizeof(changed_sector), ALLOC_TAG);
        if (!sc) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        
        sc->ol.key = address;
        sc->checksums = NULL;
        sc->length = size / Vcb->superblock.sector_size;

        sc->deleted = TRUE;
        
        insert_into_ordered_list(changed_sector_list, &sc->ol);
    }
    
    c = NULL;
    le = Vcb->chunks.Flink;
    while (le != &Vcb->chunks) {
        c = CONTAINING_RECORD(le, chunk, list_entry);
        
        if (address >= c->offset && address + size < c->offset + c->chunk_item->size)
            break;
        
        le = le->Flink;
    }
    if (le == &Vcb->chunks) c = NULL;
    
    if (c) {
        decrease_chunk_usage(c, size);
        
        add_to_space_list(c, address, size, SPACE_TYPE_DELETING);
    }
    
    return STATUS_SUCCESS;
}

static NTSTATUS decrease_extent_refcount(device_extension* Vcb, UINT64 address, UINT64 size, UINT8 type, void* data, KEY* firstitem,
                                         UINT8 level, LIST_ENTRY* changed_sector_list, LIST_ENTRY* rollback) {
    KEY searchkey;
    NTSTATUS Status;
    traverse_ptr tp, tp2;
    EXTENT_ITEM* ei;
    ULONG len;
    UINT64 inline_rc, offset;
    UINT8* ptr;
    UINT32 rc = get_extent_data_refcount(type, data);
    ULONG datalen = get_extent_data_len(type);
    
    // FIXME - handle trees
    // FIXME - handle shared extents
    // FIXME - handle old-style extents
    
    searchkey.obj_id = address;
    searchkey.obj_type = TYPE_EXTENT_ITEM;
    searchkey.offset = 0xffffffffffffffff;
    
    Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, FALSE);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08x\n", Status);
        return Status;
    }
    
    if (tp.item->key.obj_id != searchkey.obj_id || tp.item->key.obj_type != searchkey.obj_type) {
        ERR("could not find EXTENT_ITEM for address %llx\n", address);
        return STATUS_INTERNAL_ERROR;
    }
    
    if (tp.item->key.offset != size) {
        ERR("extent %llx had length %llx, not %llx as expected\n", address, tp.item->key.offset, size);
        return STATUS_INTERNAL_ERROR;
    }
    
    if (tp.item->size < sizeof(EXTENT_ITEM)) {
        ERR("(%llx,%x,%llx) was %u bytes, expected at least %u\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, tp.item->size, sizeof(EXTENT_ITEM));
        return STATUS_INTERNAL_ERROR;
    }
    
    ei = (EXTENT_ITEM*)tp.item->data;
    
    len = tp.item->size - sizeof(EXTENT_ITEM);
    ptr = (UINT8*)&ei[1];
    
    if (ei->flags & EXTENT_ITEM_TREE_BLOCK) {
        if (tp.item->size < sizeof(EXTENT_ITEM) + sizeof(EXTENT_ITEM2)) {
            ERR("(%llx,%x,%llx) was %u bytes, expected at least %u\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, tp.item->size, sizeof(EXTENT_ITEM) + sizeof(EXTENT_ITEM2));
            return STATUS_INTERNAL_ERROR;
        }
        
        len -= sizeof(EXTENT_ITEM2);
        ptr += sizeof(EXTENT_ITEM2);
    }
    
    if (ei->refcount < rc) {
        ERR("error - extent has refcount %llx, trying to reduce by %x\n", ei->refcount, rc);
        return STATUS_INTERNAL_ERROR;
    }
    
    inline_rc = 0;
    
    // Loop through inline extent entries
    
    while (len > 0) {
        UINT8 secttype = *ptr;
        ULONG sectlen = get_extent_data_len(secttype);
        UINT64 sectcount = get_extent_data_refcount(secttype, ptr + sizeof(UINT8));
        
        len--;
        
        if (sectlen > len) {
            ERR("(%llx,%x,%llx): %x bytes left, expecting at least %x\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, len, sectlen);
            return STATUS_INTERNAL_ERROR;
        }

        if (sectlen == 0) {
            ERR("(%llx,%x,%llx): unrecognized extent type %x\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, secttype);
            return STATUS_INTERNAL_ERROR;
        }
        
        if (secttype == type) {
            if (type == TYPE_EXTENT_DATA_REF) {
                EXTENT_DATA_REF* sectedr = (EXTENT_DATA_REF*)(ptr + sizeof(UINT8));
                EXTENT_DATA_REF* edr = (EXTENT_DATA_REF*)data;
                ULONG neweilen;
                EXTENT_ITEM* newei;
                
                if (sectedr->root == edr->root && sectedr->objid == edr->objid && sectedr->offset == edr->offset) {
                    if (ei->refcount == edr->count) {
                        Status = remove_extent(Vcb, address, size, changed_sector_list);
                        if (!NT_SUCCESS(Status)) {
                            ERR("remove_extent returned %08x\n", Status);
                            return Status;
                        }
                        
                        delete_tree_item(Vcb, &tp, rollback);
                        return STATUS_SUCCESS;
                    }
                    
                    if (sectedr->count < edr->count) {
                        ERR("error - extent section has refcount %x, trying to reduce by %x\n", sectedr->count, edr->count);
                        return STATUS_INTERNAL_ERROR;
                    }
                    
                    if (sectedr->count > edr->count)    // reduce section refcount
                        neweilen = tp.item->size;
                    else                                // remove section entirely
                        neweilen = tp.item->size - sizeof(UINT8) - sectlen;
                    
                    newei = ExAllocatePoolWithTag(PagedPool, neweilen, ALLOC_TAG);
                    if (!newei) {
                        ERR("out of memory\n");
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }
                    
                    if (sectedr->count > edr->count) {
                        EXTENT_DATA_REF* newedr = (EXTENT_DATA_REF*)((UINT8*)newei + ((UINT8*)sectedr - tp.item->data));
                        
                        RtlCopyMemory(newei, ei, neweilen);
                        
                        newedr->count -= rc;
                    } else {
                        RtlCopyMemory(newei, ei, ptr - tp.item->data);
                        
                        if (len > sectlen)
                            RtlCopyMemory((UINT8*)newei + (ptr - tp.item->data), ptr + sectlen + sizeof(UINT8), len - sectlen);
                    }
                    
                    newei->generation = Vcb->superblock.generation;
                    newei->refcount -= rc;
                    
                    delete_tree_item(Vcb, &tp, rollback);
                    
                    if (!insert_tree_item(Vcb, Vcb->extent_root, tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, newei, neweilen, NULL, rollback)) {
                        ERR("insert_tree_item failed\n");
                        return STATUS_INTERNAL_ERROR;
                    }
                    
                    return STATUS_SUCCESS;
                }
//             } else if (type == TYPE_TREE_BLOCK_REF) {
//                 ERR("trying to increase refcount of tree extent\n");
//                 return STATUS_INTERNAL_ERROR;
            } else {
                ERR("unhandled extent type %x\n", type);
                return STATUS_INTERNAL_ERROR;
            }
        }
        
        len -= sectlen;
        ptr += sizeof(UINT8) + sectlen;
        inline_rc += sectcount;
    }
    
    if (inline_rc == ei->refcount) {
        ERR("entry not found in inline extent item for address %llx\n", address);
        return STATUS_INTERNAL_ERROR;
    }
    
    offset = get_extent_hash(type, data);
    
    searchkey.obj_id = address;
    searchkey.obj_type = type;
    searchkey.offset = offset;
    
    Status = find_item(Vcb, Vcb->extent_root, &tp2, &searchkey, FALSE);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08x\n", Status);
        return Status;
    }
    
    if (keycmp(&tp2.item->key, &searchkey)) {
        ERR("(%llx,%x,%llx) not found\n", tp2.item->key.obj_id, tp2.item->key.obj_type, tp2.item->key.offset);
        return STATUS_INTERNAL_ERROR;
    }
    
    if (tp2.item->size < datalen) {
        ERR("(%llx,%x,%llx) was %u bytes, expected at least %u\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, tp.item->size, datalen);
        return STATUS_INTERNAL_ERROR;
    }
    
    if (type == TYPE_EXTENT_DATA_REF) {
        EXTENT_DATA_REF* sectedr = (EXTENT_DATA_REF*)tp2.item->data;
        EXTENT_DATA_REF* edr = (EXTENT_DATA_REF*)data;
        EXTENT_ITEM* newei;
        
        if (sectedr->root == edr->root && sectedr->objid == edr->objid && sectedr->offset == edr->offset) {
            if (ei->refcount == edr->count) {
                Status = remove_extent(Vcb, address, size, changed_sector_list);
                if (!NT_SUCCESS(Status)) {
                    ERR("remove_extent returned %08x\n", Status);
                    return Status;
                }
                
                delete_tree_item(Vcb, &tp, rollback);
                delete_tree_item(Vcb, &tp2, rollback);
                return STATUS_SUCCESS;
            }
            
            if (sectedr->count < edr->count) {
                ERR("error - extent section has refcount %x, trying to reduce by %x\n", sectedr->count, edr->count);
                return STATUS_INTERNAL_ERROR;
            }
            
            delete_tree_item(Vcb, &tp2, rollback);
            
            if (sectedr->count > edr->count) {
                EXTENT_DATA_REF* newedr = ExAllocatePoolWithTag(PagedPool, tp2.item->size, ALLOC_TAG);
                
                if (!newedr) {
                    ERR("out of memory\n");
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                
                RtlCopyMemory(newedr, sectedr, tp2.item->size);
                
                newedr->count -= edr->count;
                
                if (!insert_tree_item(Vcb, Vcb->extent_root, tp2.item->key.obj_id, tp2.item->key.obj_type, tp2.item->key.offset, newedr, tp2.item->size, NULL, rollback)) {
                    ERR("insert_tree_item failed\n");
                    return STATUS_INTERNAL_ERROR;
                }
            }
            
            newei = ExAllocatePoolWithTag(PagedPool, tp.item->size, ALLOC_TAG);
            if (!newei) {
                ERR("out of memory\n");
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            
            RtlCopyMemory(newei, tp.item->data, tp.item->size);

            newei->generation = Vcb->superblock.generation;
            newei->refcount -= rc;
            
            delete_tree_item(Vcb, &tp, rollback);
            
            if (!insert_tree_item(Vcb, Vcb->extent_root, tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, newei, tp.item->size, NULL, rollback)) {
                ERR("insert_tree_item failed\n");
                return STATUS_INTERNAL_ERROR;
            }
            
            return STATUS_SUCCESS;
        } else {
            ERR("error - hash collision?\n");
            return STATUS_INTERNAL_ERROR;
        }
//     } else if (type == TYPE_TREE_BLOCK_REF) {
//         ERR("trying to increase refcount of tree extent\n");
//         return STATUS_INTERNAL_ERROR;
    } else {
        ERR("unhandled extent type %x\n", type);
        return STATUS_INTERNAL_ERROR;
    }
}

NTSTATUS decrease_extent_refcount_data(device_extension* Vcb, UINT64 address, UINT64 size, root* subvol, UINT64 inode,
                                       UINT64 offset, UINT32 refcount, LIST_ENTRY* changed_sector_list, LIST_ENTRY* rollback) {
    EXTENT_DATA_REF edr;
    
    edr.root = subvol->id;
    edr.objid = inode;
    edr.offset = offset;
    edr.count = refcount;
    
    return decrease_extent_refcount(Vcb, address, size, TYPE_EXTENT_DATA_REF, &edr, NULL, 0, changed_sector_list, rollback);
}

typedef struct {
    UINT8 type;
    void* data;
    BOOL allocated;
    LIST_ENTRY list_entry;
} extent_ref;

static void free_extent_refs(LIST_ENTRY* extent_refs) {
    while (!IsListEmpty(extent_refs)) {
        LIST_ENTRY* le = RemoveHeadList(extent_refs);
        extent_ref* er = CONTAINING_RECORD(le, extent_ref, list_entry);
        
        if (er->allocated)
            ExFreePool(er->data);
        
        ExFreePool(er);
    }
}

typedef struct {
    EXTENT_DATA_REF edr;
    LIST_ENTRY list_entry;
} data_ref;

static void add_data_ref(LIST_ENTRY* data_refs, UINT64 root, UINT64 objid, UINT64 offset) {
    data_ref* dr = ExAllocatePoolWithTag(PagedPool, sizeof(data_ref), ALLOC_TAG);
    
    if (!dr) {
        ERR("out of memory\n");
        return;
    }
    
    // FIXME - increase count if entry there already
    // FIXME - put in order?
    
    dr->edr.root = root;
    dr->edr.objid = objid;
    dr->edr.offset = offset;
    dr->edr.count = 1;
    
    InsertTailList(data_refs, &dr->list_entry);
}

static void free_data_refs(LIST_ENTRY* data_refs) {
    while (!IsListEmpty(data_refs)) {
        LIST_ENTRY* le = RemoveHeadList(data_refs);
        data_ref* dr = CONTAINING_RECORD(le, data_ref, list_entry);
        
        ExFreePool(dr);
    }
}

NTSTATUS convert_shared_data_extent(device_extension* Vcb, UINT64 address, UINT64 size, LIST_ENTRY* rollback) {
    KEY searchkey;
    traverse_ptr tp;
    LIST_ENTRY extent_refs;
    LIST_ENTRY *le, *next_le;
    EXTENT_ITEM *ei, *newei;
    UINT8* siptr;
    ULONG len;
    UINT64 count;
    NTSTATUS Status;
    
    searchkey.obj_id = address;
    searchkey.obj_type = TYPE_EXTENT_ITEM;
    searchkey.offset = size;
    
    Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, FALSE);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08x\n", Status);
        return Status;
    }
    
    if (keycmp(&tp.item->key, &searchkey)) {
        WARN("extent item not found for address %llx, size %llx\n", address, size);
        return STATUS_SUCCESS;
    }
    
    if (tp.item->size < sizeof(EXTENT_ITEM)) {
        ERR("(%llx,%x,%llx) was %u bytes, expected at least %u\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, tp.item->size, sizeof(EXTENT_ITEM));
        return STATUS_INTERNAL_ERROR;
    }
    
    ei = (EXTENT_ITEM*)tp.item->data;
    len = tp.item->size - sizeof(EXTENT_ITEM);
    
    InitializeListHead(&extent_refs);
    
    siptr = (UINT8*)&ei[1];
    
    do {
        extent_ref* er = ExAllocatePoolWithTag(PagedPool, sizeof(extent_ref), ALLOC_TAG);
        if (!er) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        er->type = *siptr;
        er->data = siptr+1;
        er->allocated = FALSE;
        
        InsertTailList(&extent_refs, &er->list_entry);
        
        if (*siptr == TYPE_TREE_BLOCK_REF) {
            siptr += sizeof(TREE_BLOCK_REF);
            len -= sizeof(TREE_BLOCK_REF) + 1;
        } else if (*siptr == TYPE_EXTENT_DATA_REF) {
            siptr += sizeof(EXTENT_DATA_REF);
            len -= sizeof(EXTENT_DATA_REF) + 1;
        } else if (*siptr == TYPE_SHARED_BLOCK_REF) {
            siptr += sizeof(SHARED_BLOCK_REF);
            len -= sizeof(SHARED_BLOCK_REF) + 1;
        } else if (*siptr == TYPE_SHARED_DATA_REF) {
            siptr += sizeof(SHARED_DATA_REF);
            len -= sizeof(SHARED_DATA_REF) + 1;
        } else {
            ERR("unrecognized extent subitem %x\n", *siptr);
            free_extent_refs(&extent_refs);
            return STATUS_INTERNAL_ERROR;
        }
    } while (len > 0);
    
    le = extent_refs.Flink;
    while (le != &extent_refs) {
        extent_ref* er = CONTAINING_RECORD(le, extent_ref, list_entry);
        next_le = le->Flink;
        
        if (er->type == TYPE_SHARED_DATA_REF) {
            // normally we'd need to acquire load_tree_lock here, but we're protected by the write tree lock
            SHARED_DATA_REF* sdr = er->data;
            tree* t;
            
            Status = load_tree(Vcb, sdr->offset, NULL, &t);
            if (!NT_SUCCESS(Status)) {
                ERR("load_tree for address %llx returned %08x\n", sdr->offset, Status);
                free_data_refs(&extent_refs);
                return Status;
            }
            
            if (t->header.level == 0) {
                LIST_ENTRY* le2 = t->itemlist.Flink;
                while (le2 != &t->itemlist) {
                    tree_data* td = CONTAINING_RECORD(le2, tree_data, list_entry);
                    
                    if (!td->ignore && td->key.obj_type == TYPE_EXTENT_DATA) {
                        EXTENT_DATA* ed = (EXTENT_DATA*)td->data;
                        
                        if (ed->type == EXTENT_TYPE_REGULAR || ed->type == EXTENT_TYPE_PREALLOC) {
                            EXTENT_DATA2* ed2 = (EXTENT_DATA2*)ed->data;
                            
                            if (ed2->address == address) {
                                extent_ref* er2;
                                EXTENT_DATA_REF* edr;
                                
                                er2 = ExAllocatePoolWithTag(PagedPool, sizeof(extent_ref), ALLOC_TAG);
                                if (!er2) {
                                    ERR("out of memory\n");
                                    return STATUS_INSUFFICIENT_RESOURCES;
                                }
                                
                                edr = ExAllocatePoolWithTag(PagedPool, sizeof(EXTENT_DATA_REF), ALLOC_TAG);
                                if (!edr) {
                                    ERR("out of memory\n");
                                    ExFreePool(er2);
                                    return STATUS_INSUFFICIENT_RESOURCES;
                                }
                                
                                edr->root = t->header.tree_id;
                                edr->objid = td->key.obj_id;
                                edr->offset = td->key.offset;
                                edr->count = 1;
                                
                                er2->type = TYPE_EXTENT_DATA_REF;
                                er2->data = edr;
                                er2->allocated = TRUE;
                                
                                InsertTailList(&extent_refs, &er2->list_entry); // FIXME - list should be in order
                            }
                        }
                    }
                    
                    le2 = le2->Flink;
                }
            }

            RemoveEntryList(&er->list_entry);
            
            if (er->allocated)
                ExFreePool(er->data);
            
            ExFreePool(er);
        }
        // FIXME - also do for SHARED_BLOCK_REF?

        le = next_le;
    }
    
    if (IsListEmpty(&extent_refs)) {
        WARN("no extent refs found\n");
        delete_tree_item(Vcb, &tp, rollback);
        return STATUS_SUCCESS;
    }
    
    len = 0;
    count = 0;
    le = extent_refs.Flink;
    while (le != &extent_refs) {
        extent_ref* er = CONTAINING_RECORD(le, extent_ref, list_entry);
        
        len++;
        if (er->type == TYPE_TREE_BLOCK_REF) {
            len += sizeof(TREE_BLOCK_REF);
        } else if (er->type == TYPE_EXTENT_DATA_REF) {
            len += sizeof(EXTENT_DATA_REF);
        } else {
            ERR("unexpected extent subitem %x\n", er->type);
        }
        
        count++;
        
        le = le->Flink;
    }
    
    newei = ExAllocatePoolWithTag(PagedPool, sizeof(EXTENT_ITEM) + len, ALLOC_TAG);
    if (!newei) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    RtlCopyMemory(newei, ei, sizeof(EXTENT_ITEM));
    newei->refcount = count;
    
    siptr = (UINT8*)&newei[1];
    le = extent_refs.Flink;
    while (le != &extent_refs) {
        extent_ref* er = CONTAINING_RECORD(le, extent_ref, list_entry);
        
        *siptr = er->type;
        siptr++;
        
        if (er->type == TYPE_TREE_BLOCK_REF) {
            RtlCopyMemory(siptr, er->data, sizeof(TREE_BLOCK_REF));
        } else if (er->type == TYPE_EXTENT_DATA_REF) {
            RtlCopyMemory(siptr, er->data, sizeof(EXTENT_DATA_REF));
        } else {
            ERR("unexpected extent subitem %x\n", er->type);
        }
        
        le = le->Flink;
    }
    
    delete_tree_item(Vcb, &tp, rollback);
    
    if (!insert_tree_item(Vcb, Vcb->extent_root, address, TYPE_EXTENT_ITEM, size, newei, sizeof(EXTENT_ITEM) + len, NULL, rollback)) {
        ERR("error - failed to insert item\n");
        ExFreePool(newei);
        free_extent_refs(&extent_refs);
        return STATUS_INTERNAL_ERROR;
    }
    
    free_extent_refs(&extent_refs);
    
    return STATUS_SUCCESS;
}

NTSTATUS convert_old_data_extent(device_extension* Vcb, UINT64 address, UINT64 size, LIST_ENTRY* rollback) {
    KEY searchkey;
    traverse_ptr tp, next_tp;
    BOOL b;
    LIST_ENTRY data_refs;
    LIST_ENTRY* le;
    UINT64 refcount;
    EXTENT_ITEM* ei;
    ULONG eisize;
    UINT8* type;
    NTSTATUS Status;
    
    searchkey.obj_id = address;
    searchkey.obj_type = TYPE_EXTENT_ITEM;
    searchkey.offset = size;
    
    Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, FALSE);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08x\n", Status);
        return Status;
    }
    
    if (keycmp(&tp.item->key, &searchkey)) {
        WARN("extent item not found for address %llx, size %llx\n", address, size);
        return STATUS_SUCCESS;
    }
    
    if (tp.item->size != sizeof(EXTENT_ITEM_V0)) {
        TRACE("extent does not appear to be old - returning STATUS_SUCCESS\n");
        return STATUS_SUCCESS;
    }
    
    delete_tree_item(Vcb, &tp, rollback);
    
    searchkey.obj_id = address;
    searchkey.obj_type = TYPE_EXTENT_REF_V0;
    searchkey.offset = 0;
    
    Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, FALSE);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08x\n", Status);
        return Status;
    }
    
    InitializeListHead(&data_refs);
    
    do {
        b = find_next_item(Vcb, &tp, &next_tp, FALSE);
        
        if (tp.item->key.obj_id == searchkey.obj_id && tp.item->key.obj_type == searchkey.obj_type) {
            tree* t;
            
            // normally we'd need to acquire load_tree_lock here, but we're protected by the write tree lock
    
            Status = load_tree(Vcb, tp.item->key.offset, NULL, &t);
            
            if (!NT_SUCCESS(Status)) {
                ERR("load tree for address %llx returned %08x\n", tp.item->key.offset, Status);
                free_data_refs(&data_refs);
                return Status;
            }
            
            if (t->header.level == 0) {
                le = t->itemlist.Flink;
                while (le != &t->itemlist) {
                    tree_data* td = CONTAINING_RECORD(le, tree_data, list_entry);
                    
                    if (!td->ignore && td->key.obj_type == TYPE_EXTENT_DATA) {
                        EXTENT_DATA* ed = (EXTENT_DATA*)td->data;
                        
                        if (ed->type == EXTENT_TYPE_REGULAR || ed->type == EXTENT_TYPE_PREALLOC) {
                            EXTENT_DATA2* ed2 = (EXTENT_DATA2*)ed->data;
                            
                            if (ed2->address == address)
                                add_data_ref(&data_refs, t->header.tree_id, td->key.obj_id, td->key.offset);
                        }
                    }
                    
                    le = le->Flink;
                }
            }
            
            delete_tree_item(Vcb, &tp, rollback);
        }
        
        if (b) {
            tp = next_tp;
            
            if (tp.item->key.obj_id > searchkey.obj_id || tp.item->key.obj_type > searchkey.obj_type)
                break;
        }
    } while (b);
    
    if (IsListEmpty(&data_refs)) {
        WARN("no data refs found\n");
        return STATUS_SUCCESS;
    }
    
    // create new entry
    
    refcount = 0;
    
    le = data_refs.Flink;
    while (le != &data_refs) {
        refcount++;
        le = le->Flink;
    }
    
    eisize = sizeof(EXTENT_ITEM) + ((sizeof(char) + sizeof(EXTENT_DATA_REF)) * refcount);
    ei = ExAllocatePoolWithTag(PagedPool, eisize, ALLOC_TAG);
    if (!ei) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    ei->refcount = refcount;
    ei->generation = Vcb->superblock.generation;
    ei->flags = EXTENT_ITEM_DATA;
    
    type = (UINT8*)&ei[1];
    
    le = data_refs.Flink;
    while (le != &data_refs) {
        data_ref* dr = CONTAINING_RECORD(le, data_ref, list_entry);
        
        type[0] = TYPE_EXTENT_DATA_REF;
        RtlCopyMemory(&type[1], &dr->edr, sizeof(EXTENT_DATA_REF));
        
        type = &type[1 + sizeof(EXTENT_DATA_REF)];
        
        le = le->Flink;
    }
    
    if (!insert_tree_item(Vcb, Vcb->extent_root, address, TYPE_EXTENT_ITEM, size, ei, eisize, NULL, rollback)) {
        ERR("error - failed to insert item\n");
        ExFreePool(ei);
        return STATUS_INTERNAL_ERROR;
    }
    
    free_data_refs(&data_refs);
    
    return STATUS_SUCCESS;
}
