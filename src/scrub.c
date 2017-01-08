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

static NTSTATUS scrub_data_extent_dup(device_extension* Vcb, chunk* c, UINT64 offset, UINT64 size, UINT32* csum) {
    ERR("(%p, %p, %llx, %llx, %p)\n", Vcb, c, offset, size, csum);
    
    // FIXME
    
    return STATUS_SUCCESS;
}

static NTSTATUS scrub_data_extent(device_extension* Vcb, chunk* c, UINT64 offset, UINT64 size, ULONG type, UINT32* csum, RTL_BITMAP* bmp) {
    NTSTATUS Status;
    ULONG runlength, index;
    
    if (!csum) {
        FIXME("FIXME - scrub trees\n");
        return STATUS_SUCCESS;
    }
    
    runlength = RtlFindFirstRunClear(bmp, &index);
        
    while (runlength != 0) {
        do {
            ULONG rl;
            
            if (runlength * Vcb->superblock.sector_size > SCRUB_UNIT)
                rl = SCRUB_UNIT / Vcb->superblock.sector_size;
            else
                rl = runlength;
            
            if (type == BLOCK_FLAG_DUPLICATE) {
                Status = scrub_data_extent_dup(Vcb, c, offset + UInt32x32To64(index, Vcb->superblock.sector_size), rl * Vcb->superblock.sector_size, &csum[index]);
                if (!NT_SUCCESS(Status)) {
                    ERR("scrub_data_extent_dup returned %08x\n", Status);
                    return Status;
                }
            }

            runlength -= rl;
            index += rl;
        } while (runlength > 0);
        
        runlength = RtlFindNextForwardRunClear(bmp, index, &index);
    }
    
    return STATUS_SUCCESS;
}

static NTSTATUS scrub_chunk(device_extension* Vcb, chunk* c, UINT64* offset, BOOL* changed) {
    NTSTATUS Status;
    KEY searchkey;
    traverse_ptr tp;
    BOOL b = FALSE;
    ULONG type, num_extents = 0;
    UINT64 total_data = 0;
    
    TRACE("chunk %llx\n", c->offset);
    
    ExAcquireResourceSharedLite(&Vcb->tree_lock, TRUE);
    
    if (c->chunk_item->type & BLOCK_FLAG_DUPLICATE)
        type = BLOCK_FLAG_DUPLICATE;
    else if (c->chunk_item->type & BLOCK_FLAG_RAID0) {
        type = BLOCK_FLAG_RAID0;
        ERR("RAID0 not yet supported\n");
        goto end;
    } else if (c->chunk_item->type & BLOCK_FLAG_RAID1)
        type = BLOCK_FLAG_DUPLICATE;
    else if (c->chunk_item->type & BLOCK_FLAG_RAID10) {
        type = BLOCK_FLAG_RAID10;
        ERR("RAID10 not yet supported\n");
        goto end;
    } else if (c->chunk_item->type & BLOCK_FLAG_RAID5) {
        type = BLOCK_FLAG_RAID5;
        ERR("RAID5 not yet supported\n");
        goto end;
    } else if (c->chunk_item->type & BLOCK_FLAG_RAID6) {
        type = BLOCK_FLAG_RAID6;
        ERR("RAID6 not yet supported\n");
        goto end;
    } else // SINGLE
        type = BLOCK_FLAG_DUPLICATE;
    
    searchkey.obj_id = *offset;
    searchkey.obj_type = TYPE_METADATA_ITEM;
    searchkey.offset = 0xffffffffffffffff;
    
    Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, FALSE, NULL);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_tree returned %08x\n", Status);
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
                
                csum = ExAllocatePoolWithTag(PagedPool, sizeof(UINT32) * size / Vcb->superblock.sector_size, ALLOC_TAG);
                if (!csum) {
                    ERR("out of memory\n");
                    Status = STATUS_INSUFFICIENT_RESOURCES;
                    goto end;
                }
                
                bmparr = ExAllocatePoolWithTag(PagedPool, sector_align(((size / Vcb->superblock.sector_size) >> 3) + 1, sizeof(ULONG)), ALLOC_TAG);
                if (!bmparr) {
                    ERR("out of memory\n");
                    ExFreePool(csum);
                    Status = STATUS_INSUFFICIENT_RESOURCES;
                    goto end;
                }
                    
                RtlInitializeBitMap(&bmp, bmparr, size / Vcb->superblock.sector_size);
                RtlSetAllBits(&bmp); // 1 = no csum, 0 = csum
                
                searchkey.obj_id = EXTENT_CSUM_ID;
                searchkey.obj_type = TYPE_EXTENT_CSUM;
                searchkey.offset = tp.item->key.obj_id;
                
                Status = find_item(Vcb, Vcb->checksum_root, &tp2, &searchkey, FALSE, NULL);
                if (!NT_SUCCESS(Status) && Status != STATUS_NOT_FOUND) {
                    ERR("find_tree returned %08x\n", Status);
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
                                              (ce - cs) * sizeof(UINT32) / Vcb->superblock.sector_size);
                                
                                RtlClearBits(&bmp, (cs - tp.item->key.obj_id) / Vcb->superblock.sector_size, (ce - cs) / Vcb->superblock.sector_size);
                                
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
            
            if (is_tree) {
                FIXME("FIXME - scrub trees\n");
            } else {
                Status = scrub_data_extent(Vcb, c, tp.item->key.obj_id, size, type, csum, &bmp);
                if (!NT_SUCCESS(Status)) {
                    ERR("scrub_data_extent returned %08x\n", Status);
                    goto end;
                }
            }
            
            if (!is_tree) {
                ExFreePool(csum);
                ExFreePool(bmparr);
            }
            
            *offset += size;
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
    
    Status = STATUS_SUCCESS;
    
end:
    ExReleaseResourceLite(&Vcb->tree_lock);
    
    return Status;
}

static void scrub_thread(void* context) {
    device_extension* Vcb = context;
    LIST_ENTRY rollback, chunks, *le;
    NTSTATUS Status;
    
    InitializeListHead(&rollback);
    InitializeListHead(&chunks);
    
    ExAcquireResourceExclusiveLite(&Vcb->tree_lock, TRUE);

    if (Vcb->need_write && !Vcb->readonly)
        do_write(Vcb, NULL, &rollback);
    
    free_trees(Vcb);
    
    clear_rollback(Vcb, &rollback);
    
    ExConvertExclusiveToSharedLite(&Vcb->tree_lock);
    
    ExAcquireResourceSharedLite(&Vcb->chunk_lock, TRUE);
    
    le = Vcb->chunks.Flink;
    while (le != &Vcb->chunks) {
        chunk* c = CONTAINING_RECORD(le, chunk, list_entry);
        
        ExAcquireResourceExclusiveLite(&c->lock, TRUE);
               
        if (!c->readonly)
            InsertTailList(&chunks, &c->list_entry_balance);

        ExReleaseResourceLite(&c->lock);
        
        le = le->Flink;
    }
    
    ExReleaseResourceLite(&Vcb->chunk_lock);

    ExReleaseResourceLite(&Vcb->tree_lock);
    
    while (!IsListEmpty(&chunks)) {
        chunk* c = CONTAINING_RECORD(RemoveHeadList(&chunks), chunk, list_entry_balance);
        UINT64 offset = c->offset;
        BOOL changed;
        
        c->reloc = TRUE;
        
        if (!Vcb->scrub.stopping) {
            do {
                changed = FALSE;
                
                Status = scrub_chunk(Vcb, c, &offset, &changed);
                if (!NT_SUCCESS(Status)) {
                    ERR("scrub_chunk returned %08x\n", Status);
                    Vcb->scrub.stopping = TRUE;
                    break;
                }
                
                if (offset == c->offset + c->chunk_item->size)
                    break;
            } while (changed);
        }
        
        c->reloc = FALSE;
        c->list_entry_balance.Flink = NULL;
    }
    
    ZwClose(Vcb->scrub.thread);
    Vcb->scrub.thread = NULL;
}

NTSTATUS start_scrub(device_extension* Vcb) {
    NTSTATUS Status;
    
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
    
    Status = PsCreateSystemThread(&Vcb->scrub.thread, 0, NULL, NULL, NULL, scrub_thread, Vcb);
    if (!NT_SUCCESS(Status)) {
        ERR("PsCreateSystemThread returned %08x\n", Status);
        return Status;
    }
    
    return STATUS_SUCCESS;
}
