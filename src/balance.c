#include "btrfs_drv.h"

typedef struct {
    UINT64 address;
    UINT64 new_address;
    tree_header* data;
    EXTENT_ITEM* ei;
    LIST_ENTRY refs;
    LIST_ENTRY list_entry;
} metadata_reloc;

typedef struct {
    UINT8 type;
    
    union {
        TREE_BLOCK_REF tbr;
        SHARED_BLOCK_REF sbr;
    };
    
    metadata_reloc* parent;
    LIST_ENTRY list_entry;
} metadata_reloc_ref;

static NTSTATUS add_metadata_reloc(device_extension* Vcb, LIST_ENTRY* items, traverse_ptr* tp, BOOL skinny) {
    metadata_reloc* mr;
    EXTENT_ITEM* ei;
    UINT16 len;
    UINT64 inline_rc;
    UINT8* ptr;
    
    mr = ExAllocatePoolWithTag(PagedPool, sizeof(metadata_reloc), ALLOC_TAG);
    if (!mr) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    mr->address = tp->item->key.obj_id;
    mr->data = NULL;
    mr->ei = (EXTENT_ITEM*)tp->item->data;
    InitializeListHead(&mr->refs);
    
    // FIXME - remove EXTENT_ITEM
    
    ei = (EXTENT_ITEM*)tp->item->data;
    inline_rc = 0;
    
    len = tp->item->size - sizeof(EXTENT_ITEM);
    ptr = (UINT8*)tp->item->data + sizeof(EXTENT_ITEM);
    if (!skinny) {
        len -= sizeof(EXTENT_ITEM2);
        ptr += sizeof(EXTENT_ITEM2);
    }
    
    while (len > 0) {
        UINT8 secttype = *ptr;
        ULONG sectlen = secttype == TYPE_TREE_BLOCK_REF ? sizeof(TREE_BLOCK_REF) : (secttype == TYPE_SHARED_BLOCK_REF ? sizeof(SHARED_BLOCK_REF) : 0);
        metadata_reloc_ref* ref;
        
        len--;
        
        if (sectlen > len) {
            ERR("(%llx,%x,%llx): %x bytes left, expecting at least %x\n", tp->item->key.obj_id, tp->item->key.obj_type, tp->item->key.offset, len, sectlen);
            return STATUS_INTERNAL_ERROR;
        }

        if (sectlen == 0) {
            ERR("(%llx,%x,%llx): unrecognized extent type %x\n", tp->item->key.obj_id, tp->item->key.obj_type, tp->item->key.offset, secttype);
            return STATUS_INTERNAL_ERROR;
        }
        
        ref = ExAllocatePoolWithTag(PagedPool, sizeof(metadata_reloc_ref), ALLOC_TAG);
        if (!ref) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        
        if (secttype == TYPE_TREE_BLOCK_REF) {
            ref->type = TYPE_TREE_BLOCK_REF;
            RtlCopyMemory(&ref->tbr, ptr + sizeof(UINT8), sizeof(TREE_BLOCK_REF));
            inline_rc++;
        } else if (secttype == TYPE_SHARED_BLOCK_REF) {
            ref->type = TYPE_SHARED_BLOCK_REF;
            RtlCopyMemory(&ref->sbr, ptr + sizeof(UINT8), sizeof(SHARED_BLOCK_REF));
            inline_rc++;
        } else {
            ERR("unexpected tree type %x\n", secttype);
            ExFreePool(ref);
            return STATUS_INTERNAL_ERROR;
        }
        
        ref->parent = NULL;
        InsertTailList(&mr->refs, &ref->list_entry);
        
        len -= sectlen;
        ptr += sizeof(UINT8) + sectlen;
    }
    
    if (inline_rc < ei->refcount) { // look for non-inline entries
        traverse_ptr tp2 = *tp, next_tp;
        
        while (find_next_item(Vcb, &tp2, &next_tp, FALSE, NULL)) {
            tp2 = next_tp;
            
            if (tp2.item->key.obj_id == tp->item->key.obj_id) {
                if (tp2.item->key.obj_type == TYPE_TREE_BLOCK_REF && tp2.item->size >= sizeof(TREE_BLOCK_REF)) {
                    metadata_reloc_ref* ref = ExAllocatePoolWithTag(PagedPool, sizeof(metadata_reloc_ref), ALLOC_TAG);
                    if (!ref) {
                        ERR("out of memory\n");
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }
                    
                    ref->type = TYPE_TREE_BLOCK_REF;
                    RtlCopyMemory(&ref->tbr, tp2.item->data, sizeof(TREE_BLOCK_REF));
                    ref->parent = NULL;
                    InsertTailList(&mr->refs, &ref->list_entry);
                } else if (tp2.item->key.obj_type == TYPE_SHARED_BLOCK_REF && tp2.item->size >= sizeof(SHARED_BLOCK_REF)) {
                    metadata_reloc_ref* ref = ExAllocatePoolWithTag(PagedPool, sizeof(metadata_reloc_ref), ALLOC_TAG);
                    if (!ref) {
                        ERR("out of memory\n");
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }
                    
                    ref->type = TYPE_TREE_BLOCK_REF;
                    RtlCopyMemory(&ref->sbr, tp2.item->data, sizeof(SHARED_BLOCK_REF));
                    ref->parent = NULL;
                    InsertTailList(&mr->refs, &ref->list_entry);
                }
            } else
                break;
        }
    }
    
    InsertTailList(items, &mr->list_entry);
    
    return STATUS_SUCCESS;
}

static NTSTATUS balance_chunk(device_extension* Vcb, chunk* c, BOOL* changed) {
    KEY searchkey;
    traverse_ptr tp;
    NTSTATUS Status;
    BOOL b;
    LIST_ENTRY items, *le;
    UINT32 loaded = 0;
    
    ERR("chunk %llx\n", c->offset);
    
    InitializeListHead(&items);
    
    ExAcquireResourceExclusiveLite(&Vcb->tree_lock, TRUE);
    
    searchkey.obj_id = c->offset;
    searchkey.obj_type = TYPE_METADATA_ITEM;
    searchkey.offset = 0xffffffffffffffff;
    
    Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, FALSE, NULL);
    if (!NT_SUCCESS(Status)) {
        ERR("find_item returned %08x\n", Status);
        goto end;
    }
    
    do {
        traverse_ptr next_tp;
        
        if (tp.item->key.obj_id >= c->offset + c->chunk_item->size)
            break;
        
        if (tp.item->key.obj_type == TYPE_EXTENT_ITEM || tp.item->key.obj_type == TYPE_METADATA_ITEM) {
            BOOL tree = FALSE, skinny = FALSE;
            
            if (tp.item->key.obj_type == TYPE_METADATA_ITEM && tp.item->size >= sizeof(EXTENT_ITEM)) {
                tree = TRUE;
                skinny = TRUE;
            } else if (tp.item->key.obj_type == TYPE_EXTENT_ITEM && tp.item->key.offset == Vcb->superblock.node_size &&
                       tp.item->size >= sizeof(EXTENT_ITEM)) {
                EXTENT_ITEM* ei = (EXTENT_ITEM*)tp.item->data;
                
                if (ei->flags & EXTENT_ITEM_TREE_BLOCK)
                    tree = TRUE;
            }
            
            if (tree) {
                Status = add_metadata_reloc(Vcb, &items, &tp, skinny);
                
                if (!NT_SUCCESS(Status)) {
                    ERR("add_metadata_reloc returned %08x\n", Status);
                    goto end;
                }
                
                loaded++;
                
                if (loaded >= 64) // only do 64 at a time
                    break;
            }
        }
    
        b = find_next_item(Vcb, &tp, &next_tp, FALSE, NULL);
        
        if (b)
            tp = next_tp;
    } while (b);
    
    if (IsListEmpty(&items)) {
        *changed = FALSE;
        return STATUS_SUCCESS;
    } else
        *changed = TRUE;
    
    le = items.Flink;
    while (le != &items) {
        metadata_reloc* mr = CONTAINING_RECORD(le, metadata_reloc, list_entry);
        LIST_ENTRY* le2;
        
        ERR("address %llx\n", mr->address);
        
        // FIXME
        
        mr->data = ExAllocatePoolWithTag(PagedPool, Vcb->superblock.node_size, ALLOC_TAG);
        if (!mr->data) {
            ERR("out of memory\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }
        
        // FIXME - pass in c if address is within chunk
        Status = read_data(Vcb, mr->address, Vcb->superblock.node_size, NULL, TRUE, (UINT8*)mr->data, NULL, NULL, NULL);
        if (!NT_SUCCESS(Status)) {
            ERR("read_data returned %08x\n", Status);
            goto end;
        }
        
        le2 = mr->refs.Flink;
        while (le2 != &mr->refs) {
            metadata_reloc_ref* ref = CONTAINING_RECORD(le2, metadata_reloc_ref, list_entry);
            
            if (ref->type == TYPE_TREE_BLOCK_REF) {
                ERR("tree_block_ref root=%llx\n", ref->tbr.offset);
            } else if (ref->type == TYPE_SHARED_BLOCK_REF) {
                ERR("shared_block_ref root=%llx\n", ref->sbr.offset);
            }
            
            // FIXME - add parent
            
            le2 = le2->Flink;
        }
        
        le = le->Flink;
    }
    
    Status = STATUS_SUCCESS;
    
end:
    ExReleaseResourceLite(&Vcb->tree_lock);
    
    while (!IsListEmpty(&items)) {
        metadata_reloc* mr = CONTAINING_RECORD(RemoveHeadList(&items), metadata_reloc, list_entry);
        
        if (mr->data)
            ExFreePool(mr->data);
        
        while (!IsListEmpty(&mr->refs)) {
            metadata_reloc_ref* ref = CONTAINING_RECORD(RemoveHeadList(&mr->refs), metadata_reloc_ref, list_entry);
            
            ExFreePool(ref);
        }
        
        ExFreePool(mr);
    }
    
    return Status;
}

static void balance_thread(void* context) {
    device_extension* Vcb = (device_extension*)context;
    LIST_ENTRY chunks;
    LIST_ENTRY* le;
    
    // FIXME - handle data and system chunks
    
    InitializeListHead(&chunks);
    
    ExAcquireResourceSharedLite(&Vcb->chunk_lock, TRUE);
    
    le = Vcb->chunks.Flink;
    while (le != &Vcb->chunks) {
        chunk* c = CONTAINING_RECORD(le, chunk, list_entry);
        
        ExAcquireResourceExclusiveLite(&c->lock, TRUE);
        
        if (c->chunk_item->type & BLOCK_FLAG_METADATA) { // FIXME
            c->reloc = TRUE;
            
            InsertTailList(&chunks, &c->list_entry_balance);
            
            // only do one chunk for now
            ExReleaseResourceLite(&c->lock);
            break;
        }
        
        ExReleaseResourceLite(&c->lock);
        
        le = le->Flink;
    }
    
    ExReleaseResourceLite(&Vcb->chunk_lock);
    
    while (!IsListEmpty(&chunks)) {
        chunk* c;
        NTSTATUS Status;
        BOOL changed;
        
        le = RemoveHeadList(&chunks);
        c = CONTAINING_RECORD(le, chunk, list_entry_balance);
        
        do {
            Status = balance_chunk(Vcb, c, &changed);
            if (!NT_SUCCESS(Status)) {
                ERR("balance_chunk returned %08x\n", Status);
                // FIXME - store failure status, so we can show this on propsheet
                break;
            }
        } while (FALSE); // FIXME - loop until changed is FALSE
    }
    
    ZwClose(Vcb->balance.thread);
    Vcb->balance.thread = NULL;
}

NTSTATUS start_balance(device_extension* Vcb) {
    NTSTATUS Status;
    
    if (Vcb->balance.thread) {
        WARN("balance already running\n");
        return STATUS_DEVICE_NOT_READY;
    }
    
    if (Vcb->readonly)
        return STATUS_MEDIA_WRITE_PROTECTED;
    
    Status = PsCreateSystemThread(&Vcb->balance.thread, 0, NULL, NULL, NULL, balance_thread, Vcb);
    if (!NT_SUCCESS(Status)) {
        ERR("PsCreateSystemThread returned %08x\n", Status);
        return Status;
    }
    
    return STATUS_SUCCESS;
}
