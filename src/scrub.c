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

static NTSTATUS scrub_chunk(device_extension* Vcb, chunk* c, UINT64* offset, BOOL* changed) {
    NTSTATUS Status;
    KEY searchkey;
    traverse_ptr tp;
    BOOL b = FALSE;
    ULONG num_extents = 0;
    UINT64 total_data = 0;
    
    FIXME("FIXME - scrub chunk %llx\n", c->offset);
    
    ExAcquireResourceSharedLite(&Vcb->tree_lock, TRUE);
    
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
            
            // FIXME
            ERR("%llx\n", tp.item->key.obj_id);
            
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
