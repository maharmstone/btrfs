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

static NTSTATUS remove_free_space_inode(device_extension* Vcb, KEY* key, LIST_ENTRY* rollback) {
    NTSTATUS Status;
    traverse_ptr tp;
    INODE_ITEM* ii;
    
    Status = find_item(Vcb, Vcb->root_root, &tp, key, FALSE);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08x\n", Status);
        return Status;
    }
    
    if (keycmp(key, &tp.item->key)) {
        ERR("could not find (%llx,%x,%llx) in root_root\n", key->obj_id, key->obj_type, key->offset);
        free_traverse_ptr(&tp);
        return STATUS_NOT_FOUND;
    }
    
    if (tp.item->size < offsetof(INODE_ITEM, st_blocks)) {
        ERR("(%llx,%x,%llx) was %u bytes, expected at least %u\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, tp.item->size, offsetof(INODE_ITEM, st_blocks));
        return STATUS_INTERNAL_ERROR;
    }
    
    ii = (INODE_ITEM*)tp.item->data;
    
    Status = excise_extents_inode(Vcb, Vcb->root_root, key->obj_id, NULL, 0, ii->st_size, NULL, rollback);
    if (!NT_SUCCESS(Status)) {
        ERR("excise_extents returned %08x\n", Status);
        return Status;
    }
    
    delete_tree_item(Vcb, &tp, rollback);
    
    free_traverse_ptr(&tp);
    
    return STATUS_SUCCESS;
}

NTSTATUS clear_free_space_cache(device_extension* Vcb) {
    KEY searchkey;
    traverse_ptr tp, next_tp;
    NTSTATUS Status;
    BOOL b;
    LIST_ENTRY rollback;
    
    InitializeListHead(&rollback);
    
    searchkey.obj_id = FREE_SPACE_CACHE_ID;
    searchkey.obj_type = 0;
    searchkey.offset = 0;
    
    Status = find_item(Vcb, Vcb->root_root, &tp, &searchkey, FALSE);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08x\n", Status);
        return Status;
    }
    
    do {
        if (tp.item->key.obj_id > searchkey.obj_id || (tp.item->key.obj_id == searchkey.obj_id && tp.item->key.obj_type > searchkey.obj_type))
            break;
        
        if (tp.item->key.obj_id == searchkey.obj_id && tp.item->key.obj_type == searchkey.obj_type) {
            delete_tree_item(Vcb, &tp, &rollback);
            
            if (tp.item->size >= sizeof(FREE_SPACE_ITEM)) {
                FREE_SPACE_ITEM* fsi = (FREE_SPACE_ITEM*)tp.item->data;
                
                if (fsi->key.obj_type != TYPE_INODE_ITEM)
                    WARN("key (%llx,%x,%llx) does not point to an INODE_ITEM\n", fsi->key.obj_id, fsi->key.obj_type, fsi->key.offset);
                else {
                    Status = remove_free_space_inode(Vcb, &fsi->key, &rollback);
                    
                    if (!NT_SUCCESS(Status)) {
                        ERR("remove_free_space_inode for (%llx,%x,%llx) returned %08x\n", fsi->key.obj_id, fsi->key.obj_type, fsi->key.offset, Status);
                        goto end;
                    }
                }
            } else
                WARN("(%llx,%x,%llx) was %u bytes, expected %u\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, tp.item->size, sizeof(FREE_SPACE_ITEM));
        }
        
        b = find_next_item(Vcb, &tp, &next_tp, FALSE);
        if (b) {
            free_traverse_ptr(&tp);
            tp = next_tp;
        }
    } while (b);
    
    free_traverse_ptr(&tp);
    
    Status = STATUS_SUCCESS;
    
end:
    if (NT_SUCCESS(Status))
        clear_rollback(&rollback);
    else
        do_rollback(Vcb, &rollback);
    
    return Status;
}

static NTSTATUS add_space_entry(chunk* c, UINT64 offset, UINT64 size) {
    space* s;
    
    s = ExAllocatePoolWithTag(PagedPool, sizeof(space), ALLOC_TAG);

    if (!s) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    s->offset = offset;
    s->size = size;
    s->type = SPACE_TYPE_FREE;
    
    if (IsListEmpty(&c->space))
        InsertTailList(&c->space, &s->list_entry);
    else {
        space* s2 = CONTAINING_RECORD(c->space.Blink, space, list_entry);
        
        if (s2->offset < offset)
            InsertTailList(&c->space, &s->list_entry);
        else {
            LIST_ENTRY* le;
            
            le = c->space.Flink;
            while (le != &c->space) {
                s2 = CONTAINING_RECORD(le, space, list_entry);
                
                if (s2->offset > offset) {
                    InsertTailList(le, &s->list_entry);
                    return STATUS_SUCCESS;
                }
                
                le = le->Flink;
            }
        }
    }
    
    return STATUS_SUCCESS;
}

static void load_free_space_bitmap(device_extension* Vcb, chunk* c, UINT64 offset, void* data) {
    RTL_BITMAP bmph;
    UINT32 i, *dwords = data;
    ULONG runlength, index;
    
    // flip bits
    for (i = 0; i < Vcb->superblock.sector_size / sizeof(UINT32); i++) {
        dwords[i] = ~dwords[i];
    }

    RtlInitializeBitMap(&bmph, data, Vcb->superblock.sector_size * 8);

    index = 0;
    runlength = RtlFindFirstRunClear(&bmph, &index);
            
    while (runlength != 0) {
        UINT64 addr, length;
        
        addr = offset + (index * Vcb->superblock.sector_size);
        length = Vcb->superblock.sector_size * runlength;
        
        add_space_entry(c, addr, length);
        index += runlength;
       
        runlength = RtlFindNextForwardRunClear(&bmph, index, &index);
    }
}

static NTSTATUS load_stored_free_space_cache(device_extension* Vcb, chunk* c) {
    KEY searchkey;
    traverse_ptr tp, tp2;
    FREE_SPACE_ITEM* fsi;
    UINT64 inode, num_sectors, num_valid_sectors, i, generation;
    INODE_ITEM* ii;
    UINT8* data;
    NTSTATUS Status;
    UINT32 *checksums, crc32;
    FREE_SPACE_ENTRY* fse;
    UINT64 size, num_entries, num_bitmaps, extent_length, bmpnum;
    LIST_ENTRY* le;
    
    // FIXME - does this break if Vcb->superblock.sector_size is not 4096?
    
    TRACE("(%p, %llx)\n", Vcb, c->offset);
    
    searchkey.obj_id = FREE_SPACE_CACHE_ID;
    searchkey.obj_type = 0;
    searchkey.offset = c->offset;
    
    Status = find_item(Vcb, Vcb->root_root, &tp, &searchkey, FALSE);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08x\n", Status);
        return Status;
    }
    
    if (keycmp(&tp.item->key, &searchkey)) {
        TRACE("(%llx,%x,%llx) not found\n", searchkey.obj_id, searchkey.obj_type, searchkey.offset);
        free_traverse_ptr(&tp);
        return STATUS_NOT_FOUND;
    }
    
    if (tp.item->size < sizeof(FREE_SPACE_ITEM)) {
        WARN("(%llx,%x,%llx) was %u bytes, expected %u\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, tp.item->size, sizeof(FREE_SPACE_ITEM));
        free_traverse_ptr(&tp);
        return STATUS_NOT_FOUND;
    }
    
    fsi = (FREE_SPACE_ITEM*)tp.item->data;
    
    if (fsi->key.obj_type != TYPE_INODE_ITEM) {
        WARN("cache pointed to something other than an INODE_ITEM\n");
        free_traverse_ptr(&tp);
        return STATUS_NOT_FOUND;
    }
    
    inode = fsi->key.obj_id;
    
    searchkey = fsi->key;

    num_entries = fsi->num_entries;
    num_bitmaps = fsi->num_bitmaps;
    
    Status = find_item(Vcb, Vcb->root_root, &tp2, &searchkey, FALSE);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08x\n", Status);
        free_traverse_ptr(&tp);
        return Status;
    }
    
    if (keycmp(&tp2.item->key, &searchkey)) {
        WARN("(%llx,%x,%llx) not found\n", searchkey.obj_id, searchkey.obj_type, searchkey.offset);
        free_traverse_ptr(&tp);
        free_traverse_ptr(&tp2);
        return STATUS_NOT_FOUND;
    }
    
    if (tp2.item->size < sizeof(INODE_ITEM)) {
        WARN("(%llx,%x,%llx) was %u bytes, expected %u\n", tp2.item->key.obj_id, tp2.item->key.obj_type, tp2.item->key.offset, tp2.item->size, sizeof(INODE_ITEM));
        free_traverse_ptr(&tp);
        free_traverse_ptr(&tp2);
        return STATUS_NOT_FOUND;
    }
    
    ii = (INODE_ITEM*)tp2.item->data;
    
    if (ii->st_size == 0) {
        ERR("inode %llx had a length of 0\n", inode);
        free_traverse_ptr(&tp);
        free_traverse_ptr(&tp2);
        return STATUS_NOT_FOUND;
    }
    
    size = sector_align(ii->st_size, Vcb->superblock.sector_size);
    
    data = ExAllocatePoolWithTag(PagedPool, size, ALLOC_TAG);
    
    if (!data) {
        ERR("out of memory\n");
        free_traverse_ptr(&tp);
        free_traverse_ptr(&tp2);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    Status = read_file(Vcb, Vcb->root_root, inode, data, 0, ii->st_size, NULL);
    if (!NT_SUCCESS(Status)) {
        ERR("read_file returned %08x\n", Status);
        ExFreePool(data);
        free_traverse_ptr(&tp);
        free_traverse_ptr(&tp2);
        return Status;
    }
    
    if (size > ii->st_size)
        RtlZeroMemory(&data[ii->st_size], size - ii->st_size);
    
    num_sectors = size / Vcb->superblock.sector_size;
    
    generation = *(data + (num_sectors * sizeof(UINT32)));
    
    if (generation != fsi->generation) {
        WARN("free space cache generation for %llx was %llx, expected %llx\n", c->offset, generation, fsi->generation);
        ExFreePool(data);
        free_traverse_ptr(&tp);
        free_traverse_ptr(&tp2);
        return STATUS_NOT_FOUND;
    }
    
    free_traverse_ptr(&tp);
    
    extent_length = (num_sectors * sizeof(UINT32)) + sizeof(UINT64) + (num_entries * sizeof(FREE_SPACE_ENTRY));
    
    num_valid_sectors = (sector_align(extent_length, Vcb->superblock.sector_size) / Vcb->superblock.sector_size) + num_bitmaps;
    
    if (num_valid_sectors > num_sectors) {
        ERR("free space cache for %llx was %llx sectors, expected at least %llx\n", c->offset, num_sectors, num_valid_sectors);
        ExFreePool(data);
        free_traverse_ptr(&tp2);
        return STATUS_NOT_FOUND;
    }
    
    checksums = (UINT32*)data;
    
    for (i = 0; i < num_valid_sectors; i++) {
        if (i * Vcb->superblock.sector_size > sizeof(UINT32) * num_sectors)
            crc32 = ~calc_crc32c(0xffffffff, &data[i * Vcb->superblock.sector_size], Vcb->superblock.sector_size);
        else if ((i + 1) * Vcb->superblock.sector_size < sizeof(UINT32) * num_sectors)
            crc32 = 0; // FIXME - test this
        else
            crc32 = ~calc_crc32c(0xffffffff, &data[sizeof(UINT32) * num_sectors], ((i + 1) * Vcb->superblock.sector_size) - (sizeof(UINT32) * num_sectors));
        
        if (crc32 != checksums[i]) {
            WARN("checksum %llu was %08x, expected %08x\n", i, crc32, checksums[i]);
            ExFreePool(data);
            free_traverse_ptr(&tp2);
            return STATUS_NOT_FOUND;
        }
    }
    
    fse = (FREE_SPACE_ENTRY*)&data[(sizeof(UINT32) * num_sectors) + sizeof(UINT64)];

    bmpnum = 0;
    for (i = 0; i < num_entries; i++) {
        if (fse[i].type == 1) {
            Status = add_space_entry(c, fse[i].offset, fse[i].size);
            if (!NT_SUCCESS(Status)) {
                ERR("add_space_entry returned %08x\n", Status);
                ExFreePool(data);
                free_traverse_ptr(&tp2);
                return Status;
            }
        } else if (fse[i].type == FREE_SPACE_BITMAP) {
            // FIXME - make sure we don't overflow the buffer here
            load_free_space_bitmap(Vcb, c, fse[i].offset, &data[(bmpnum + 1) * Vcb->superblock.sector_size]);
            bmpnum++;
        }
    }
    
    le = c->space.Flink;
    while (le != &c->space) {
        space* s = CONTAINING_RECORD(le, space, list_entry);
        LIST_ENTRY* le2 = le->Flink;
        
        if (le2 != &c->space) {
            space* s2 = CONTAINING_RECORD(le2, space, list_entry);
            
            if (s2->offset == s->offset + s->size) {
                s->size += s2->size;
                
                RemoveEntryList(&s2->list_entry);
                ExFreePool(s2);
                
                le2 = le;
            }
        }
        
        le = le2;
    }
    
    ExFreePool(data);
    free_traverse_ptr(&tp2);
    
    return STATUS_SUCCESS;
}

NTSTATUS load_free_space_cache(device_extension* Vcb, chunk* c) {
    traverse_ptr tp, next_tp;
    KEY searchkey;
    UINT64 lastaddr;
    BOOL b;
    space *s, *s2;
    LIST_ENTRY* le;
    NTSTATUS Status;
    
    if (Vcb->superblock.generation - 1 == Vcb->superblock.cache_generation) {
        Status = load_stored_free_space_cache(Vcb, c);
        
        if (!NT_SUCCESS(Status) && Status != STATUS_NOT_FOUND) {
            ERR("load_stored_free_space_cache returned %08x\n", Status);
            return Status;
        }
    } else
        Status = STATUS_NOT_FOUND;
     
    if (Status == STATUS_NOT_FOUND) {
        TRACE("generating free space cache for chunk %llx\n", c->offset);
        
        searchkey.obj_id = c->offset;
        searchkey.obj_type = TYPE_EXTENT_ITEM;
        searchkey.offset = 0;
        
        Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, FALSE);
        if (!NT_SUCCESS(Status)) {
            ERR("error - find_item returned %08x\n", Status);
            return Status;
        }
        
        lastaddr = c->offset;
        
        do {
            if (tp.item->key.obj_id >= c->offset + c->chunk_item->size)
                break;
            
            if (tp.item->key.obj_id >= c->offset && (tp.item->key.obj_type == TYPE_EXTENT_ITEM || tp.item->key.obj_type == TYPE_METADATA_ITEM)) {
                if (tp.item->key.obj_id > lastaddr) {
                    s = ExAllocatePoolWithTag(PagedPool, sizeof(space), ALLOC_TAG);
                    
                    if (!s) {
                        ERR("out of memory\n");
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }
                    
                    s->offset = lastaddr;
                    s->size = tp.item->key.obj_id - lastaddr;
                    s->type = SPACE_TYPE_FREE;
                    InsertTailList(&c->space, &s->list_entry);
                    
                    TRACE("(%llx,%llx)\n", s->offset, s->size);
                }
                
                if (tp.item->key.obj_type == TYPE_METADATA_ITEM)
                    lastaddr = tp.item->key.obj_id + Vcb->superblock.node_size;
                else
                    lastaddr = tp.item->key.obj_id + tp.item->key.offset;
            }
            
            b = find_next_item(Vcb, &tp, &next_tp, FALSE);
            if (b) {
                free_traverse_ptr(&tp);
                tp = next_tp;
            }
        } while (b);
        
        if (lastaddr < c->offset + c->chunk_item->size) {
            s = ExAllocatePoolWithTag(PagedPool, sizeof(space), ALLOC_TAG);
            
            if (!s) {
                ERR("out of memory\n");
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            
            s->offset = lastaddr;
            s->size = c->offset + c->chunk_item->size - lastaddr;
            s->type = SPACE_TYPE_FREE;
            InsertTailList(&c->space, &s->list_entry);
            
            TRACE("(%llx,%llx)\n", s->offset, s->size);
        }
        
        free_traverse_ptr(&tp);
    }
    
    // add allocated space
    
    lastaddr = c->offset;
    
    le = c->space.Flink;
    while (le != &c->space) {
        s = CONTAINING_RECORD(le, space, list_entry);
        
        if (s->offset > lastaddr) {
            s2 = ExAllocatePoolWithTag(PagedPool, sizeof(space), ALLOC_TAG);
            
            if (!s2) {
                ERR("out of memory\n");
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            
            s2->offset = lastaddr;
            s2->size = s->offset - lastaddr;
            s2->type = SPACE_TYPE_USED;
            
            InsertTailList(&s->list_entry, &s2->list_entry);
        }
        
        lastaddr = s->offset + s->size;
        
        le = le->Flink;
    }
    
    if (lastaddr < c->offset + c->chunk_item->size) {
        s = ExAllocatePoolWithTag(PagedPool, sizeof(space), ALLOC_TAG);
        
        if (!s) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        
        s->offset = lastaddr;
        s->size = c->offset + c->chunk_item->size - lastaddr;
        s->type = SPACE_TYPE_USED;
        InsertTailList(&c->space, &s->list_entry);
    }
    
    le = c->space.Flink;
    while (le != &c->space) {
        s = CONTAINING_RECORD(le, space, list_entry);
        
        TRACE("%llx,%llx,%u\n", s->offset, s->size, s->type);
        
        le = le->Flink;
    }
    
    return STATUS_SUCCESS;
}
