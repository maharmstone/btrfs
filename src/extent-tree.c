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
        // FIXME - TYPE_SHARED_DATA_REF
            
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
        // FIXME - TYPE_SHARED_DATA_REF
            
        default:
            return 0;
    }
}

// static UINT64 get_extent_data_ref_hash(UINT64 root, UINT64 objid, UINT64 offset) {
//     UINT32 high_crc = 0xffffffff, low_crc = 0xffffffff;
//     
//     // FIXME - can we test this?
// 
//     // FIXME - make sure numbers here are little-endian
//     high_crc = calc_crc32c(high_crc, (UINT8*)&root, sizeof(UINT64));
//     low_crc = calc_crc32c(low_crc, (UINT8*)&objid, sizeof(UINT64));
//     low_crc = calc_crc32c(low_crc, (UINT8*)&offset, sizeof(UINT64));
//     
//     return ((UINT64)high_crc << 31) ^ (UINT64)low_crc;
// }

static NTSTATUS increase_extent_refcount(device_extension* Vcb, UINT64 address, UINT64 size, UINT8 type, void* data, KEY* firstitem, UINT8 level, LIST_ENTRY* rollback) {
    NTSTATUS Status;
    KEY searchkey;
    traverse_ptr tp;
    ULONG datalen = get_extent_data_len(type), len;
    EXTENT_ITEM* ei;
    UINT8* ptr;
    UINT64 inline_rc;
    
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
    
    if (tp.item->key.obj_id != searchkey.obj_id && tp.item->key.obj_type != searchkey.obj_type) {
        ULONG eisize;
        EXTENT_ITEM* ei;
        BOOL is_tree = type == TYPE_TREE_BLOCK_REF;
        UINT8* ptr;
        
        eisize = sizeof(EXTENT_ITEM);
        if (is_tree) eisize += sizeof(EXTENT_ITEM2);
        eisize += sizeof(UINT8);
        eisize += datalen;
        
        ei = ExAllocatePool(PagedPool, sizeof(EXTENT_ITEM));
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
                    EXTENT_ITEM* newei = ExAllocatePoolWithTag(PagedPool, tp.item->size, ALLOC_TAG);
                    UINT32 rc = get_extent_data_refcount(type, data);
                    EXTENT_DATA_REF* sectedr2;
                    
                    if (!newei) {
                        ERR("out of memory\n");
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }
                    
                    RtlCopyMemory(newei, tp.item->data, tp.item->size);
                    
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
    
    int3;
    
    // FIXME - calculate hash
    // FIXME - if refcount was what was expected and entry not too long, add to appropriate place and increase refcount
    // FIXME - otherwise, increase refcount and add entry as separate item
    
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS increase_extent_refcount_data(device_extension* Vcb, UINT64 address, UINT64 size, root* subvol, UINT64 inode, UINT64 offset, UINT32 refcount, LIST_ENTRY* rollback) {
    EXTENT_DATA_REF edr;
    
    edr.root = subvol->id;
    edr.objid = inode;
    edr.offset = offset;
    edr.count = refcount;
    
    return increase_extent_refcount(Vcb, address, size, TYPE_EXTENT_DATA_REF, &edr, NULL, 0, rollback);
}
