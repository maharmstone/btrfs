#include "btrfs_drv.h"

typedef struct {
    UINT64 address;
    UINT64 new_address;
    tree_header* data;
    EXTENT_ITEM* ei;
    tree* t;
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
    BOOL top;
    LIST_ENTRY list_entry;
} metadata_reloc_ref;

typedef struct {
    UINT64 address;
    UINT64 size;
    UINT64 new_address;
    EXTENT_ITEM* ei;
    LIST_ENTRY refs;
    LIST_ENTRY list_entry;
} data_reloc;

typedef struct {
    UINT8 type;
    
    union {
        EXTENT_DATA_REF edr;
        SHARED_DATA_REF sdr;
    };
    
//     data_reloc* parent;
    LIST_ENTRY list_entry;
} data_reloc_ref;

static NTSTATUS add_metadata_reloc(device_extension* Vcb, LIST_ENTRY* items, traverse_ptr* tp, BOOL skinny, metadata_reloc** mr2, chunk* c, LIST_ENTRY* rollback) {
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
    
    delete_tree_item(Vcb, tp, rollback);
    
    if (!c)
        c = get_chunk_from_address(Vcb, tp->item->key.obj_id);
        
    if (c) {
        ExAcquireResourceExclusiveLite(&c->lock, TRUE);
        
        decrease_chunk_usage(c, Vcb->superblock.node_size);
        
        space_list_add(Vcb, c, TRUE, tp->item->key.obj_id, Vcb->superblock.node_size, rollback);
        
        ExReleaseResourceLite(&c->lock);
    }
    
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
        ref->top = FALSE;
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
                    ref->top = FALSE;
                    InsertTailList(&mr->refs, &ref->list_entry);
                    
                    delete_tree_item(Vcb, &tp2, rollback);
                } else if (tp2.item->key.obj_type == TYPE_SHARED_BLOCK_REF && tp2.item->size >= sizeof(SHARED_BLOCK_REF)) {
                    metadata_reloc_ref* ref = ExAllocatePoolWithTag(PagedPool, sizeof(metadata_reloc_ref), ALLOC_TAG);
                    if (!ref) {
                        ERR("out of memory\n");
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }
                    
                    ref->type = TYPE_SHARED_BLOCK_REF;
                    RtlCopyMemory(&ref->sbr, tp2.item->data, sizeof(SHARED_BLOCK_REF));
                    ref->parent = NULL;
                    ref->top = FALSE;
                    InsertTailList(&mr->refs, &ref->list_entry);
                    
                    delete_tree_item(Vcb, &tp2, rollback);
                }
            } else
                break;
        }
    }
    
    InsertTailList(items, &mr->list_entry);
    
    if (mr2)
        *mr2 = mr;
    
    return STATUS_SUCCESS;
}

static NTSTATUS add_metadata_reloc_parent(device_extension* Vcb, LIST_ENTRY* items, UINT64 address, metadata_reloc** mr2, LIST_ENTRY* rollback) {
    LIST_ENTRY* le;
    KEY searchkey;
    traverse_ptr tp;
    BOOL skinny = FALSE;
    NTSTATUS Status;
    
    le = items->Flink;
    while (le != items) {
        metadata_reloc* mr = CONTAINING_RECORD(le, metadata_reloc, list_entry);
        
        if (mr->address == address) {
            *mr2 = mr;
            return STATUS_SUCCESS;
        }
        
        le = le->Flink;
    }
    
    searchkey.obj_id = address;
    searchkey.obj_type = TYPE_METADATA_ITEM;
    searchkey.offset = 0xffffffffffffffff;
    
    Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, FALSE, NULL);
    if (!NT_SUCCESS(Status)) {
        ERR("find_item returned %08x\n", Status);
        return Status;
    }
    
    if (tp.item->key.obj_id == address && tp.item->key.obj_type == TYPE_METADATA_ITEM && tp.item->size >= sizeof(EXTENT_ITEM))
        skinny = TRUE;
    else if (tp.item->key.obj_id == address && tp.item->key.obj_type == TYPE_EXTENT_ITEM && tp.item->key.offset == Vcb->superblock.node_size &&
             tp.item->size >= sizeof(EXTENT_ITEM)) {
        EXTENT_ITEM* ei = (EXTENT_ITEM*)tp.item->data;
        
        if (!(ei->flags & EXTENT_ITEM_TREE_BLOCK)) {
            ERR("EXTENT_ITEM for %llx found, but tree flag not set\n", address);
            return STATUS_INTERNAL_ERROR;
        }
    } else {
        ERR("could not find valid EXTENT_ITEM for address %llx\n", address);
        return STATUS_INTERNAL_ERROR;
    }
    
    Status = add_metadata_reloc(Vcb, items, &tp, skinny, mr2, NULL, rollback);
    if (!NT_SUCCESS(Status)) {
        ERR("add_metadata_reloc returned %08x\n", Status);
        return Status;
    }
    
    return STATUS_SUCCESS;
}

static NTSTATUS add_metadata_reloc_extent_item(device_extension* Vcb, metadata_reloc* mr, LIST_ENTRY* rollback) {
    LIST_ENTRY* le;
    UINT64 rc = 0;
    UINT16 inline_len;
    BOOL all_inline = TRUE;
    metadata_reloc_ref* first_noninline = NULL;
    EXTENT_ITEM* ei;
    UINT8* ptr;
    
    inline_len = sizeof(EXTENT_ITEM);
    if (!(Vcb->superblock.incompat_flags & BTRFS_INCOMPAT_FLAGS_SKINNY_METADATA))
        inline_len += sizeof(EXTENT_ITEM2);
    
    le = mr->refs.Flink;
    while (le != &mr->refs) {
        metadata_reloc_ref* ref = CONTAINING_RECORD(le, metadata_reloc_ref, list_entry);
        ULONG extlen = 0;
        
        rc++;
        
        if (ref->type == TYPE_TREE_BLOCK_REF)
            extlen += sizeof(TREE_BLOCK_REF);
        else if (ref->type == TYPE_SHARED_BLOCK_REF)
            extlen += sizeof(SHARED_BLOCK_REF);

        if (all_inline) {
            if (inline_len + 1 + extlen > Vcb->superblock.node_size / 4) {
                all_inline = FALSE;
                first_noninline = ref;
            } else
                inline_len += extlen + 1;
        }
        
        le = le->Flink;
    }
    
    ei = ExAllocatePoolWithTag(PagedPool, inline_len, ALLOC_TAG);
    if (!ei) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    ei->refcount = rc;
    ei->generation = mr->ei->generation;
    ei->flags = mr->ei->flags;
    ptr = (UINT8*)&ei[1];
    
    if (!(Vcb->superblock.incompat_flags & BTRFS_INCOMPAT_FLAGS_SKINNY_METADATA)) {
        EXTENT_ITEM2* ei2 = (EXTENT_ITEM2*)ptr;
        
        ei2->firstitem = *(KEY*)&mr->data[1];
        ei2->level = mr->data->level;
        
        ptr += sizeof(EXTENT_ITEM2);
    }
    
    le = mr->refs.Flink;
    while (le != &mr->refs) {
        metadata_reloc_ref* ref = CONTAINING_RECORD(le, metadata_reloc_ref, list_entry);
        
        if (ref == first_noninline)
            break;
        
        *ptr = ref->type;
        ptr++;
        
        if (ref->type == TYPE_TREE_BLOCK_REF) {
            TREE_BLOCK_REF* tbr = (TREE_BLOCK_REF*)ptr;
            
            tbr->offset = ref->tbr.offset;
            
            ptr += sizeof(TREE_BLOCK_REF);
        } else if (ref->type == TYPE_SHARED_BLOCK_REF) {
            SHARED_BLOCK_REF* sbr = (SHARED_BLOCK_REF*)ptr;
            
            sbr->offset = ref->parent->new_address;
            
            ptr += sizeof(SHARED_BLOCK_REF);
        }
        
        le = le->Flink;
    }
    
    if (Vcb->superblock.incompat_flags & BTRFS_INCOMPAT_FLAGS_SKINNY_METADATA) {
        if (!insert_tree_item(Vcb, Vcb->extent_root, mr->new_address, TYPE_METADATA_ITEM, mr->data->level, ei, inline_len, NULL, NULL, rollback)) {
            ERR("insert_tree_item failed\n");
            return STATUS_INTERNAL_ERROR;
        }
    } else {
        if (!insert_tree_item(Vcb, Vcb->extent_root, mr->new_address, TYPE_EXTENT_ITEM, Vcb->superblock.node_size, ei, inline_len, NULL, NULL, rollback)) {
            ERR("insert_tree_item failed\n");
            return STATUS_INTERNAL_ERROR;
        }
    }
    
    if (!all_inline) {
        le = &first_noninline->list_entry;
        
        while (le != &mr->refs) {
            metadata_reloc_ref* ref = CONTAINING_RECORD(le, metadata_reloc_ref, list_entry);
            
            if (ref->type == TYPE_TREE_BLOCK_REF) {
                TREE_BLOCK_REF* tbr;
                
                tbr = ExAllocatePoolWithTag(PagedPool, sizeof(TREE_BLOCK_REF), ALLOC_TAG);
                if (!tbr) {
                    ERR("out of memory\n");
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                
                tbr->offset = ref->tbr.offset;
                
                if (!insert_tree_item(Vcb, Vcb->extent_root, mr->new_address, TYPE_TREE_BLOCK_REF, tbr->offset, tbr, sizeof(TREE_BLOCK_REF), NULL, NULL, rollback)) {
                    ERR("insert_tree_item failed\n");
                    return STATUS_INTERNAL_ERROR;
                }
            } else if (ref->type == TYPE_SHARED_BLOCK_REF) {
                SHARED_BLOCK_REF* sbr;
                
                sbr = ExAllocatePoolWithTag(PagedPool, sizeof(SHARED_BLOCK_REF), ALLOC_TAG);
                if (!sbr) {
                    ERR("out of memory\n");
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                
                sbr->offset = ref->parent->new_address;
                
                if (!insert_tree_item(Vcb, Vcb->extent_root, mr->new_address, TYPE_SHARED_BLOCK_REF, sbr->offset, sbr, sizeof(SHARED_BLOCK_REF), NULL, NULL, rollback)) {
                    ERR("insert_tree_item failed\n");
                    return STATUS_INTERNAL_ERROR;
                }
            }
            
            le = le->Flink;
        }
    }
    
    if (ei->flags & EXTENT_ITEM_SHARED_BACKREFS || mr->data->flags & HEADER_FLAG_SHARED_BACKREF || !(mr->data->flags & HEADER_FLAG_MIXED_BACKREF)) {
        if (mr->data->level > 0) {
            UINT16 i;
            internal_node* in = (internal_node*)&mr->data[1];
                        
            for (i = 0; i < mr->data->num_items; i++) {
                UINT64 sbrrc = find_extent_shared_tree_refcount(Vcb, in[i].address, mr->address, NULL);

                if (sbrrc > 0) {
                    NTSTATUS Status;
                    SHARED_BLOCK_REF sbr;
                    
                    sbr.offset = mr->new_address;
                    
                    Status = increase_extent_refcount(Vcb, in[i].address, Vcb->superblock.node_size, TYPE_SHARED_BLOCK_REF, &sbr, NULL, 0,
                                                      NULL, rollback);
                    if (!NT_SUCCESS(Status)) {
                        ERR("increase_extent_refcount returned %08x\n", Status);
                        return Status;
                    }
        
                    sbr.offset = mr->address;
                    
                    Status = decrease_extent_refcount(Vcb, in[i].address, Vcb->superblock.node_size, TYPE_SHARED_BLOCK_REF, &sbr, NULL, 0,
                                                      sbr.offset, NULL, rollback);
                    if (!NT_SUCCESS(Status)) {
                        ERR("decrease_extent_refcount returned %08x\n", Status);
                        return Status;
                    }
                }
            }
        } else {
            UINT16 i;
            leaf_node* ln = (leaf_node*)&mr->data[1];
            
            for (i = 0; i < mr->data->num_items; i++) {
                if (ln[i].key.obj_type == TYPE_EXTENT_DATA && ln[i].size >= sizeof(EXTENT_DATA) - 1 + sizeof(EXTENT_DATA2)) {
                    EXTENT_DATA* ed = (EXTENT_DATA*)((UINT8*)mr->data + sizeof(tree_header) + ln[i].offset);
                    
                    if (ed->type == EXTENT_TYPE_REGULAR || ed->type == EXTENT_TYPE_PREALLOC) {
                        EXTENT_DATA2* ed2 = (EXTENT_DATA2*)ed->data;
                        
                        if (ed2->size > 0) { // not sparse
                            UINT64 sdrrc = find_extent_shared_data_refcount(Vcb, ed2->address, mr->address, NULL);
                            
                            if (sdrrc > 0) {
                                NTSTATUS Status;
                                SHARED_DATA_REF sdr;
                                
                                sdr.offset = mr->new_address;
                                sdr.count = sdrrc;
                                
                                Status = increase_extent_refcount(Vcb, ed2->address, ed2->size, TYPE_SHARED_DATA_REF, &sdr, NULL, 0,
                                                                  NULL, rollback);
                                if (!NT_SUCCESS(Status)) {
                                    ERR("increase_extent_refcount returned %08x\n", Status);
                                    return Status;
                                }
                                
                                sdr.offset = mr->address;
                                
                                Status = decrease_extent_refcount(Vcb, ed2->address, ed2->size, TYPE_SHARED_DATA_REF, &sdr, NULL, 0,
                                                                  sdr.offset, NULL, rollback);
                                if (!NT_SUCCESS(Status)) {
                                    ERR("decrease_extent_refcount returned %08x\n", Status);
                                    return Status;
                                }
                                
                                // FIXME - check changed_extent_ref
                            }
                        }
                    }
                }
            }
        }
    }

    return STATUS_SUCCESS;
}

static NTSTATUS balance_metadata_chunk(device_extension* Vcb, chunk* c, BOOL* changed) {
    KEY searchkey;
    traverse_ptr tp;
    NTSTATUS Status;
    BOOL b;
    LIST_ENTRY items, rollback, tree_writes, *le;
    UINT32 loaded = 0;
    UINT8 max_level = 0, level;
    chunk* newchunk = NULL;
    UINT64 flags = BLOCK_FLAG_DUPLICATE | BLOCK_FLAG_METADATA; // FIXME
    
    TRACE("chunk %llx\n", c->offset);
    
    InitializeListHead(&rollback);
    InitializeListHead(&items);
    InitializeListHead(&tree_writes);
    
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
        
        if (tp.item->key.obj_id >= c->offset && (tp.item->key.obj_type == TYPE_EXTENT_ITEM || tp.item->key.obj_type == TYPE_METADATA_ITEM)) {
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
                Status = add_metadata_reloc(Vcb, &items, &tp, skinny, NULL, c, &rollback);
                
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
        Status = STATUS_SUCCESS;
        goto end;
    } else
        *changed = TRUE;
    
    le = items.Flink;
    while (le != &items) {
        metadata_reloc* mr = CONTAINING_RECORD(le, metadata_reloc, list_entry);
        LIST_ENTRY* le2;
        
//         ERR("address %llx\n", mr->address);
        
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
        
        if (mr->data->level > max_level)
            max_level = mr->data->level;
        
        le2 = mr->refs.Flink;
        while (le2 != &mr->refs) {
            metadata_reloc_ref* ref = CONTAINING_RECORD(le2, metadata_reloc_ref, list_entry);
            
            if (ref->type == TYPE_TREE_BLOCK_REF) {
                KEY* firstitem;
                root* r = NULL;
                LIST_ENTRY* le3;
                tree* t;
                
                firstitem = (KEY*)&mr->data[1];
                
                le3 = Vcb->roots.Flink;
                while (le3 != &Vcb->roots) {
                    root* r2 = CONTAINING_RECORD(le3, root, list_entry);
                    
                    if (r2->id == ref->tbr.offset) {
                        r = r2;
                        break;
                    }
                    
                    le3 = le3->Flink;
                }
                
                if (!r) {
                    ERR("could not find subvol with id %llx\n", ref->tbr.offset);
                    Status = STATUS_INTERNAL_ERROR;
                    goto end;
                }
                
                Status = find_item_to_level(Vcb, r, &tp, firstitem, FALSE, mr->data->level + 1, NULL);
                if (!NT_SUCCESS(Status)) {
                    ERR("find_item returned %08x\n", Status);
                    goto end;
                }
                
                t = tp.tree;
                while (t && t->header.level < mr->data->level + 1) {
                    t = t->parent;
                }
                
                if (!t)
                    ref->top = TRUE;
                else {
                    metadata_reloc* mr2;
                    
                    Status = add_metadata_reloc_parent(Vcb, &items, t->header.address, &mr2, &rollback);
                    if (!NT_SUCCESS(Status)) {
                        ERR("add_metadata_reloc_parent returned %08x\n", Status);
                        goto end;
                    }
                    
                    ref->parent = mr2;
                }
            } else if (ref->type == TYPE_SHARED_BLOCK_REF) {
                metadata_reloc* mr2;
                
                Status = add_metadata_reloc_parent(Vcb, &items, ref->sbr.offset, &mr2, &rollback);
                if (!NT_SUCCESS(Status)) {
                    ERR("add_metadata_reloc_parent returned %08x\n", Status);
                    goto end;
                }
                
                ref->parent = mr2;
            }
            
            le2 = le2->Flink;
        }
        
        le = le->Flink;
    }
    
    le = items.Flink;
    while (le != &items) {
        metadata_reloc* mr = CONTAINING_RECORD(le, metadata_reloc, list_entry);
        LIST_ENTRY* le2;
        UINT32 hash;
        
        mr->t = NULL;
        
        hash = calc_crc32c(0xffffffff, (UINT8*)&mr->address, sizeof(UINT64));
        
        le2 = Vcb->trees_ptrs[hash >> 24];
        
        if (le2) {
            while (le2 != &Vcb->trees_hash) {
                tree* t = CONTAINING_RECORD(le2, tree, list_entry_hash);
                
                if (t->header.address == mr->address) {
                    mr->t = t;
                    break;
                } else if (t->hash > hash)
                    break;
                
                le2 = le2->Flink;
            }
        }
        
        le = le->Flink;
    }
    
    for (level = 0; level <= max_level; level++) {
        le = items.Flink;
        while (le != &items) {
            metadata_reloc* mr = CONTAINING_RECORD(le, metadata_reloc, list_entry);
            
            if (mr->data->level == level) {
                BOOL done = FALSE;
                LIST_ENTRY* le2;
                tree_write* tw;
                
                if (newchunk) {
                    ExAcquireResourceExclusiveLite(&newchunk->lock, TRUE);
                    
                    if (find_address_in_chunk(Vcb, newchunk, Vcb->superblock.node_size, &mr->new_address)) {
                        increase_chunk_usage(newchunk, Vcb->superblock.node_size);
                        space_list_subtract(Vcb, newchunk, FALSE, mr->new_address, Vcb->superblock.node_size, &rollback);
                        done = TRUE;
                    }
                    
                    ExReleaseResourceLite(&newchunk->lock);
                }
                
                if (!done) {
                    ExAcquireResourceExclusiveLite(&Vcb->chunk_lock, TRUE);
    
                    le2 = Vcb->chunks.Flink;
                    while (le2 != &Vcb->chunks) {
                        chunk* c2 = CONTAINING_RECORD(le2, chunk, list_entry);
                        
                        if (!c2->readonly && !c2->reloc && c2 != newchunk && c2->chunk_item->type == flags) {
                            ExAcquireResourceExclusiveLite(&c2->lock, TRUE);
                            
                            if ((c2->chunk_item->size - c2->used) >= Vcb->superblock.node_size) {
                                if (find_address_in_chunk(Vcb, c2, Vcb->superblock.node_size, &mr->new_address)) {
                                    increase_chunk_usage(c2, Vcb->superblock.node_size);
                                    space_list_subtract(Vcb, c2, FALSE, mr->new_address, Vcb->superblock.node_size, &rollback);
                                    ExReleaseResourceLite(&c2->lock);
                                    newchunk = c2;
                                    done = TRUE;
                                    break;
                                }
                            }
                            
                            ExReleaseResourceLite(&c2->lock);
                        }

                        le2 = le2->Flink;
                    }
                    
                    // allocate new chunk if necessary
                    if (!done) {
                        newchunk = alloc_chunk(Vcb, flags);
                        
                        if (!newchunk) {
                            ERR("could not allocate new chunk\n");
                            ExReleaseResourceLite(&Vcb->chunk_lock);
                            Status = STATUS_DISK_FULL;
                            goto end;
                        }
                        
                        ExAcquireResourceExclusiveLite(&newchunk->lock, TRUE);
                        
                        if (!find_address_in_chunk(Vcb, newchunk, Vcb->superblock.node_size, &mr->new_address)) {
                            ExReleaseResourceLite(&newchunk->lock);
                            ERR("could not find address in new chunk\n");
                            Status = STATUS_DISK_FULL;
                            goto end;
                        } else {
                            increase_chunk_usage(newchunk, Vcb->superblock.node_size);
                            space_list_subtract(Vcb, newchunk, FALSE, mr->new_address, Vcb->superblock.node_size, &rollback);
                        }
                        
                        ExReleaseResourceLite(&newchunk->lock);
                    }
                    
                    ExReleaseResourceLite(&Vcb->chunk_lock);
                }
                
                // update parents
                le2 = mr->refs.Flink;
                while (le2 != &mr->refs) {
                    metadata_reloc_ref* ref = CONTAINING_RECORD(le2, metadata_reloc_ref, list_entry);
                    
                    if (ref->parent) {
                        UINT16 i;
                        internal_node* in = (internal_node*)&ref->parent->data[1];
                        
                        for (i = 0; i < ref->parent->data->num_items; i++) {
                            if (in[i].address == mr->address) {
                                in[i].address = mr->new_address;
                                break;
                            }
                        }
                        
                        if (ref->parent->t) {
                            LIST_ENTRY* le3;
                            
                            le3 = ref->parent->t->itemlist.Flink;
                            while (le3 != &ref->parent->t->itemlist) {
                                tree_data* td = CONTAINING_RECORD(le3, tree_data, list_entry);
                                
                                if (!td->inserted && td->treeholder.address == mr->address)
                                    td->treeholder.address = mr->new_address;
                                
                                le3 = le3->Flink;
                            }
                        }
                    } else if (ref->top && ref->type == TYPE_TREE_BLOCK_REF) {
                        LIST_ENTRY* le3;
                        root* r = NULL;
                        
                        // alter ROOT_ITEM
                        
                        le3 = Vcb->roots.Flink;
                        while (le3 != &Vcb->roots) {
                            root* r2 = CONTAINING_RECORD(le3, root, list_entry);
                            
                            if (r2->id == ref->tbr.offset) {
                                r = r2;
                                break;
                            }
                            
                            le3 = le3->Flink;
                        }
                        
                        if (r) {
                            r->treeholder.address = mr->new_address;
                            
                            if (r == Vcb->root_root)
                                Vcb->superblock.root_tree_addr = mr->new_address;
                            else if (r == Vcb->chunk_root)
                                Vcb->superblock.chunk_tree_addr = mr->new_address;
                            else if (r->root_item.block_number == mr->address) {
                                KEY searchkey;
                                ROOT_ITEM* ri;
                                
                                r->root_item.block_number = mr->new_address;
                                
                                searchkey.obj_id = r->id;
                                searchkey.obj_type = TYPE_ROOT_ITEM;
                                searchkey.offset = 0xffffffffffffffff;
                                
                                Status = find_item(Vcb, Vcb->root_root, &tp, &searchkey, FALSE, NULL);
                                if (!NT_SUCCESS(Status)) {
                                    ERR("find_item returned %08x\n", Status);
                                    goto end;
                                }
                                
                                if (tp.item->key.obj_id != searchkey.obj_id || tp.item->key.obj_type != searchkey.obj_type) {
                                    ERR("could not find ROOT_ITEM for tree %llx\n", searchkey.obj_id);
                                    Status = STATUS_INTERNAL_ERROR;
                                    goto end;
                                }
                                
                                ri = ExAllocatePoolWithTag(PagedPool, sizeof(ROOT_ITEM), ALLOC_TAG);
                                if (!ri) {
                                    ERR("out of memory\n");
                                    Status = STATUS_INSUFFICIENT_RESOURCES;
                                    goto end;
                                }
                                
                                RtlCopyMemory(ri, &r->root_item, sizeof(ROOT_ITEM));
                                
                                delete_tree_item(Vcb, &tp, &rollback);
                                
                                if (!insert_tree_item(Vcb, Vcb->root_root, tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, ri, sizeof(ROOT_ITEM), NULL, NULL, &rollback)) {
                                    ERR("insert_tree_item failed\n");
                                    Status = STATUS_INTERNAL_ERROR;
                                    goto end;
                                }
                            }
                        }
                    }
                    
                    le2 = le2->Flink;
                }
                
                mr->data->address = mr->new_address;
                
                if (mr->t) {
                    UINT8 h;
                    BOOL inserted;
                    
                    mr->t->header.address = mr->new_address;
                    
                    h = mr->t->hash >> 24;
                    
                    if (Vcb->trees_ptrs[h] == &mr->t->list_entry_hash) {
                        if (mr->t->list_entry_hash.Flink == &Vcb->trees_hash)
                            Vcb->trees_ptrs[h] = NULL;
                        else {
                            tree* t2 = CONTAINING_RECORD(mr->t->list_entry_hash.Flink, tree, list_entry_hash);
                            
                            if (t2->hash >> 24 == h)
                                Vcb->trees_ptrs[h] = &t2->list_entry_hash;
                            else
                                Vcb->trees_ptrs[h] = NULL;
                        }
                    }
                        
                    RemoveEntryList(&mr->t->list_entry_hash);
                    
                    mr->t->hash = calc_crc32c(0xffffffff, (UINT8*)&mr->t->header.address, sizeof(UINT64));
                    h = mr->t->hash >> 24;
                    
                    if (!Vcb->trees_ptrs[h]) {
                        UINT8 h2 = h;
                        
                        le2 = Vcb->trees_hash.Flink;
                        
                        if (h2 > 0) {
                            h2--;
                            do {
                                if (Vcb->trees_ptrs[h2]) {
                                    le2 = Vcb->trees_ptrs[h2];
                                    break;
                                }
                                    
                                h2--;
                            } while (h2 > 0);
                        }
                    } else
                        le2 = Vcb->trees_ptrs[h];
                    
                    inserted = FALSE;
                    while (le2 != &Vcb->trees_hash) {
                        tree* t2 = CONTAINING_RECORD(le2, tree, list_entry_hash);
                        
                        if (t2->hash >= mr->t->hash) {
                            InsertHeadList(le2->Blink, &mr->t->list_entry_hash);
                            inserted = TRUE;
                            break;
                        }
                        
                        le2 = le2->Flink;
                    }

                    if (!inserted)
                        InsertTailList(&Vcb->trees_hash, &mr->t->list_entry_hash);

                    if (!Vcb->trees_ptrs[h] || mr->t->list_entry_hash.Flink == Vcb->trees_ptrs[h])
                        Vcb->trees_ptrs[h] = &mr->t->list_entry_hash;
                    
                    // FIXME - check if tree loaded more than once
                }

                *((UINT32*)mr->data) = ~calc_crc32c(0xffffffff, (UINT8*)&mr->data->fs_uuid, Vcb->superblock.node_size - sizeof(mr->data->csum));
                
                tw = ExAllocatePoolWithTag(PagedPool, sizeof(tree_write), ALLOC_TAG);
                if (!tw) {
                    ERR("out of memory\n");
                    Status = STATUS_INSUFFICIENT_RESOURCES;
                    goto end;
                }
                
                tw->address = mr->new_address;
                tw->length = Vcb->superblock.node_size;
                tw->data = (UINT8*)mr->data;
                tw->overlap = FALSE;
                
                if (IsListEmpty(&tree_writes))
                    InsertTailList(&tree_writes, &tw->list_entry);
                else {
                    BOOL inserted = FALSE;
                    
                    le2 = tree_writes.Flink;
                    while (le2 != &tree_writes) {
                        tree_write* tw2 = CONTAINING_RECORD(le2, tree_write, list_entry);
                        
                        if (tw2->address > tw->address) {
                            InsertHeadList(le2->Blink, &tw->list_entry);
                            inserted = TRUE;
                            break;
                        }
                        
                        le2 = le2->Flink;
                    }
                    
                    if (!inserted)
                        InsertTailList(&tree_writes, &tw->list_entry);
                }
            }
            
            le = le->Flink;
        }
    }
    
    le = items.Flink;
    while (le != &items) {
        metadata_reloc* mr = CONTAINING_RECORD(le, metadata_reloc, list_entry);
        
        Status = add_metadata_reloc_extent_item(Vcb, mr, &rollback);
        if (!NT_SUCCESS(Status)) {
            ERR("add_metadata_reloc_extent_item returned %08x\n", Status);
            goto end;
        }
        
        le = le->Flink;
    }
    
    Status = do_tree_writes(Vcb, &tree_writes, NULL);
    if (!NT_SUCCESS(Status)) {
        ERR("do_tree_writes returned %08x\n", Status);
        goto end;
    }
    
    Status = STATUS_SUCCESS;
    
    Vcb->need_write = TRUE;
    
end:
    if (NT_SUCCESS(Status))
        clear_rollback(Vcb, &rollback);
    else
        do_rollback(Vcb, &rollback);
    
    ExReleaseResourceLite(&Vcb->tree_lock);
    
    while (!IsListEmpty(&tree_writes)) {
        tree_write* tw = CONTAINING_RECORD(RemoveHeadList(&tree_writes), tree_write, list_entry);
        ExFreePool(tw);
    }
    
    while (!IsListEmpty(&items)) {
        metadata_reloc* mr = CONTAINING_RECORD(RemoveHeadList(&items), metadata_reloc, list_entry);
        
        while (!IsListEmpty(&mr->refs)) {
            metadata_reloc_ref* ref = CONTAINING_RECORD(RemoveHeadList(&mr->refs), metadata_reloc_ref, list_entry);
            
            ExFreePool(ref);
        }
        
        ExFreePool(mr);
    }
    
    return Status;
}

static NTSTATUS add_data_reloc(device_extension* Vcb, LIST_ENTRY* items, traverse_ptr* tp, chunk* c, LIST_ENTRY* rollback) {
    data_reloc* dr;
    EXTENT_ITEM* ei;
    UINT16 len;
    UINT64 inline_rc;
    UINT8* ptr;
    
    dr = ExAllocatePoolWithTag(PagedPool, sizeof(data_reloc), ALLOC_TAG);
    if (!dr) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    dr->address = tp->item->key.obj_id;
    dr->size = tp->item->key.offset;
//     mr->data = NULL;
    dr->ei = (EXTENT_ITEM*)tp->item->data;
    InitializeListHead(&dr->refs);
    
    delete_tree_item(Vcb, tp, rollback);
    
    if (!c)
        c = get_chunk_from_address(Vcb, tp->item->key.obj_id);
        
    if (c) {
        ExAcquireResourceExclusiveLite(&c->lock, TRUE);
        
        decrease_chunk_usage(c, tp->item->key.offset);
        
        space_list_add(Vcb, c, TRUE, tp->item->key.obj_id, tp->item->key.offset, rollback);
        
        ExReleaseResourceLite(&c->lock);
    }
    
    ei = (EXTENT_ITEM*)tp->item->data;
    inline_rc = 0;
    
    len = tp->item->size - sizeof(EXTENT_ITEM);
    ptr = (UINT8*)tp->item->data + sizeof(EXTENT_ITEM);
    
    while (len > 0) {
        UINT8 secttype = *ptr;
        ULONG sectlen = secttype == TYPE_EXTENT_DATA_REF ? sizeof(EXTENT_DATA_REF) : (secttype == TYPE_SHARED_DATA_REF ? sizeof(SHARED_DATA_REF) : 0);
        data_reloc_ref* ref;
        
        len--;
        
        if (sectlen > len) {
            ERR("(%llx,%x,%llx): %x bytes left, expecting at least %x\n", tp->item->key.obj_id, tp->item->key.obj_type, tp->item->key.offset, len, sectlen);
            return STATUS_INTERNAL_ERROR;
        }

        if (sectlen == 0) {
            ERR("(%llx,%x,%llx): unrecognized extent type %x\n", tp->item->key.obj_id, tp->item->key.obj_type, tp->item->key.offset, secttype);
            return STATUS_INTERNAL_ERROR;
        }
        
        ref = ExAllocatePoolWithTag(PagedPool, sizeof(data_reloc_ref), ALLOC_TAG);
        if (!ref) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        
        if (secttype == TYPE_EXTENT_DATA_REF) {
            ref->type = TYPE_EXTENT_DATA_REF;
            RtlCopyMemory(&ref->edr, ptr + sizeof(UINT8), sizeof(EXTENT_DATA_REF));
            inline_rc += ref->edr.count;
        } else if (secttype == TYPE_SHARED_DATA_REF) {
            ref->type = TYPE_SHARED_DATA_REF;
            RtlCopyMemory(&ref->sdr, ptr + sizeof(UINT8), sizeof(SHARED_DATA_REF));
            inline_rc += ref->sdr.count;
        } else {
            ERR("unexpected tree type %x\n", secttype);
            ExFreePool(ref);
            return STATUS_INTERNAL_ERROR;
        }
        
//         ref->parent = NULL;
        InsertTailList(&dr->refs, &ref->list_entry);
        
        len -= sectlen;
        ptr += sizeof(UINT8) + sectlen;
    }
    
    if (inline_rc < ei->refcount) { // look for non-inline entries
        traverse_ptr tp2 = *tp, next_tp;
        
        while (find_next_item(Vcb, &tp2, &next_tp, FALSE, NULL)) {
            tp2 = next_tp;
            
            if (tp2.item->key.obj_id == tp->item->key.obj_id) {
                if (tp2.item->key.obj_type == TYPE_EXTENT_DATA_REF && tp2.item->size >= sizeof(EXTENT_DATA_REF)) {
                    data_reloc_ref* ref = ExAllocatePoolWithTag(PagedPool, sizeof(data_reloc_ref), ALLOC_TAG);
                    if (!ref) {
                        ERR("out of memory\n");
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }
                    
                    ref->type = TYPE_EXTENT_DATA_REF;
                    RtlCopyMemory(&ref->edr, tp2.item->data, sizeof(EXTENT_DATA_REF));
//                     ref->parent = NULL;
                    InsertTailList(&dr->refs, &ref->list_entry);
                    
                    delete_tree_item(Vcb, &tp2, rollback);
                } else if (tp2.item->key.obj_type == TYPE_SHARED_DATA_REF && tp2.item->size >= sizeof(SHARED_DATA_REF)) {
                    data_reloc_ref* ref = ExAllocatePoolWithTag(PagedPool, sizeof(data_reloc_ref), ALLOC_TAG);
                    if (!ref) {
                        ERR("out of memory\n");
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }
                    
                    ref->type = TYPE_SHARED_DATA_REF;
                    RtlCopyMemory(&ref->sdr, tp2.item->data, sizeof(SHARED_DATA_REF));
//                     ref->parent = NULL;
                    InsertTailList(&dr->refs, &ref->list_entry);
                    
                    delete_tree_item(Vcb, &tp2, rollback);
                }
            } else
                break;
        }
    }
    
    InsertTailList(items, &dr->list_entry);
    
    return STATUS_SUCCESS;
}

static NTSTATUS add_data_reloc_extent_item(device_extension* Vcb, data_reloc* dr, LIST_ENTRY* rollback) {
    LIST_ENTRY* le;
    UINT64 rc = 0;
    UINT16 inline_len;
    BOOL all_inline = TRUE;
    data_reloc_ref* first_noninline = NULL;
    EXTENT_ITEM* ei;
    UINT8* ptr;
    
    inline_len = sizeof(EXTENT_ITEM);
    
    le = dr->refs.Flink;
    while (le != &dr->refs) {
        data_reloc_ref* ref = CONTAINING_RECORD(le, data_reloc_ref, list_entry);
        ULONG extlen = 0;
        
        rc++;
        
        if (ref->type == TYPE_EXTENT_DATA_REF)
            extlen += sizeof(EXTENT_DATA_REF);
        else if (ref->type == TYPE_SHARED_DATA_REF)
            extlen += sizeof(SHARED_DATA_REF);

        if (all_inline) {
            if (inline_len + 1 + extlen > Vcb->superblock.node_size / 4) {
                all_inline = FALSE;
                first_noninline = ref;
            } else
                inline_len += extlen + 1;
        }
        
        le = le->Flink;
    }
    
    ei = ExAllocatePoolWithTag(PagedPool, inline_len, ALLOC_TAG);
    if (!ei) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    ei->refcount = rc;
    ei->generation = dr->ei->generation;
    ei->flags = dr->ei->flags;
    ptr = (UINT8*)&ei[1];
    
    le = dr->refs.Flink;
    while (le != &dr->refs) {
        data_reloc_ref* ref = CONTAINING_RECORD(le, data_reloc_ref, list_entry);
        
        if (ref == first_noninline)
            break;
        
        *ptr = ref->type;
        ptr++;
        
        if (ref->type == TYPE_EXTENT_DATA_REF) {
            EXTENT_DATA_REF* edr = (EXTENT_DATA_REF*)ptr;
            
            RtlCopyMemory(edr, &ref->edr, sizeof(EXTENT_DATA_REF));
            
            ptr += sizeof(EXTENT_DATA_REF);
        } else if (ref->type == TYPE_SHARED_DATA_REF) {
            SHARED_DATA_REF* sdr = (SHARED_DATA_REF*)ptr;
            
//             sdr->offset = ref->parent->new_address;
            RtlCopyMemory(sdr, &ref->sdr, sizeof(SHARED_DATA_REF));
            
            ptr += sizeof(SHARED_DATA_REF);
        }
        
        le = le->Flink;
    }
    
    if (!insert_tree_item(Vcb, Vcb->extent_root, dr->new_address, TYPE_EXTENT_ITEM, dr->size, ei, inline_len, NULL, NULL, rollback)) {
        ERR("insert_tree_item failed\n");
        return STATUS_INTERNAL_ERROR;
    }
    
    if (!all_inline) {
        le = &first_noninline->list_entry;
        
        while (le != &dr->refs) {
            data_reloc_ref* ref = CONTAINING_RECORD(le, data_reloc_ref, list_entry);
            
            if (ref->type == TYPE_EXTENT_DATA_REF) {
                EXTENT_DATA_REF* edr;
                UINT64 off;
                
                edr = ExAllocatePoolWithTag(PagedPool, sizeof(EXTENT_DATA_REF), ALLOC_TAG);
                if (!edr) {
                    ERR("out of memory\n");
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                
//                 edr->offset = ref->tbr.offset;
                RtlCopyMemory(edr, &ref->edr, sizeof(EXTENT_DATA_REF));
                
                off = get_extent_data_ref_hash2(ref->edr.root, ref->edr.objid, ref->edr.offset);
                
                if (!insert_tree_item(Vcb, Vcb->extent_root, dr->new_address, TYPE_EXTENT_DATA_REF, off, edr, sizeof(EXTENT_DATA_REF), NULL, NULL, rollback)) {
                    ERR("insert_tree_item failed\n");
                    return STATUS_INTERNAL_ERROR;
                }
            } else if (ref->type == TYPE_SHARED_DATA_REF) {
                SHARED_DATA_REF* sdr;
                
                sdr = ExAllocatePoolWithTag(PagedPool, sizeof(SHARED_DATA_REF), ALLOC_TAG);
                if (!sdr) {
                    ERR("out of memory\n");
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                
//                 sdr->offset = ref->parent->new_address;
                
                if (!insert_tree_item(Vcb, Vcb->extent_root, dr->new_address, TYPE_SHARED_DATA_REF, sdr->offset, sdr, sizeof(SHARED_DATA_REF), NULL, NULL, rollback)) {
                    ERR("insert_tree_item failed\n");
                    return STATUS_INTERNAL_ERROR;
                }
            }
            
            le = le->Flink;
        }
    }

    return STATUS_SUCCESS;
}

static NTSTATUS balance_data_chunk(device_extension* Vcb, chunk* c, BOOL* changed) {
    KEY searchkey;
    traverse_ptr tp;
    NTSTATUS Status;
    BOOL b;
    LIST_ENTRY items, rollback, *le;
    UINT64 loaded = 0;
    chunk* newchunk = NULL;
    
    TRACE("chunk %llx\n", c->offset);
    
    InitializeListHead(&rollback);
    InitializeListHead(&items);
    
    ExAcquireResourceExclusiveLite(&Vcb->tree_lock, TRUE);
    
    searchkey.obj_id = c->offset;
    searchkey.obj_type = TYPE_EXTENT_ITEM;
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
        
        if (tp.item->key.obj_id >= c->offset && tp.item->key.obj_type == TYPE_EXTENT_ITEM) {
            BOOL tree = FALSE;
            
            if (tp.item->key.obj_type == TYPE_EXTENT_ITEM && tp.item->size >= sizeof(EXTENT_ITEM)) {
                EXTENT_ITEM* ei = (EXTENT_ITEM*)tp.item->data;
                
                if (ei->flags & EXTENT_ITEM_TREE_BLOCK)
                    tree = TRUE;
            }
            
            if (!tree) {
                Status = add_data_reloc(Vcb, &items, &tp, c, &rollback);
                
                if (!NT_SUCCESS(Status)) {
                    ERR("add_data_reloc returned %08x\n", Status);
                    goto end;
                }
                
                loaded += tp.item->key.offset;
                
                if (loaded >= 0x1000000) // only do so much at a time, so we don't block too obnoxiously
                    break;
            }
        }
    
        b = find_next_item(Vcb, &tp, &next_tp, FALSE, NULL);
        
        if (b)
            tp = next_tp;
    } while (b);
    
    if (IsListEmpty(&items)) {
        *changed = FALSE;
        Status = STATUS_SUCCESS;
        goto end;
    } else
        *changed = TRUE;

    le = items.Flink;
    while (le != &items) {
        data_reloc* dr = CONTAINING_RECORD(le, data_reloc, list_entry);
        BOOL done = FALSE;
        LIST_ENTRY* le2;
        
        if (newchunk) {
            ExAcquireResourceExclusiveLite(&newchunk->lock, TRUE);
            
            if (find_address_in_chunk(Vcb, newchunk, dr->size, &dr->new_address)) {
                increase_chunk_usage(newchunk, dr->size);
                space_list_subtract(Vcb, newchunk, FALSE, dr->new_address, dr->size, &rollback);
                done = TRUE;
            }
            
            ExReleaseResourceLite(&newchunk->lock);
        }
        
        if (!done) {
            ExAcquireResourceExclusiveLite(&Vcb->chunk_lock, TRUE);

            le2 = Vcb->chunks.Flink;
            while (le2 != &Vcb->chunks) {
                chunk* c2 = CONTAINING_RECORD(le2, chunk, list_entry);
                
                if (!c2->readonly && !c2->reloc && c2 != newchunk && c2->chunk_item->type == Vcb->data_flags) {
                    ExAcquireResourceExclusiveLite(&c2->lock, TRUE);
                    
                    if ((c2->chunk_item->size - c2->used) >= dr->size) {
                        if (find_address_in_chunk(Vcb, c2, dr->size, &dr->new_address)) {
                            increase_chunk_usage(c2, dr->size);
                            space_list_subtract(Vcb, c2, FALSE, dr->new_address, dr->size, &rollback);
                            ExReleaseResourceLite(&c2->lock);
                            newchunk = c2;
                            done = TRUE;
                            break;
                        }
                    }
                    
                    ExReleaseResourceLite(&c2->lock);
                }

                le2 = le2->Flink;
            }
            
            // allocate new chunk if necessary
            if (!done) {
                newchunk = alloc_chunk(Vcb, Vcb->data_flags);
                
                if (!newchunk) {
                    ERR("could not allocate new chunk\n");
                    ExReleaseResourceLite(&Vcb->chunk_lock);
                    Status = STATUS_DISK_FULL;
                    goto end;
                }
                
                ExAcquireResourceExclusiveLite(&newchunk->lock, TRUE);
                
                if (!find_address_in_chunk(Vcb, newchunk, dr->size, &dr->new_address)) {
                    ExReleaseResourceLite(&newchunk->lock);
                    ERR("could not find address in new chunk\n");
                    Status = STATUS_DISK_FULL;
                    goto end;
                } else {
                    increase_chunk_usage(newchunk, dr->size);
                    space_list_subtract(Vcb, newchunk, FALSE, dr->new_address, dr->size, &rollback);
                }
                
                ExReleaseResourceLite(&newchunk->lock);
            }
            
            ExReleaseResourceLite(&Vcb->chunk_lock);
        }

        le = le->Flink;
    }
    
    le = items.Flink;
    while (le != &items) {
        data_reloc* dr = CONTAINING_RECORD(le, data_reloc, list_entry);
        
        Status = add_data_reloc_extent_item(Vcb, dr, &rollback);
        if (!NT_SUCCESS(Status)) {
            ERR("add_data_reloc_extent_item returned %08x\n", Status);
            goto end;
        }
        
        le = le->Flink;
    }
    
    // FIXME - read and rewrite data
    // FIXME - update checksums
    // FIXME - update metadata
    // FIXME - update changed_extent_ref
    // FIXME - update open FCBs
    
    Status = STATUS_SUCCESS;
    
    Vcb->need_write = TRUE;
    
end:
    if (NT_SUCCESS(Status))
        clear_rollback(Vcb, &rollback);
    else
        do_rollback(Vcb, &rollback);
    
    ExReleaseResourceLite(&Vcb->tree_lock);
    
    while (!IsListEmpty(&items)) {
        data_reloc* dr = CONTAINING_RECORD(RemoveHeadList(&items), data_reloc, list_entry);
        
        while (!IsListEmpty(&dr->refs)) {
            data_reloc_ref* ref = CONTAINING_RECORD(RemoveHeadList(&dr->refs), data_reloc_ref, list_entry);
            
            ExFreePool(ref);
        }
        
        ExFreePool(dr);
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
        
        if (c->chunk_item->type & BLOCK_FLAG_DATA) { // FIXME
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
            if (c->chunk_item->type & BLOCK_FLAG_METADATA) {
                Status = balance_metadata_chunk(Vcb, c, &changed);
                if (!NT_SUCCESS(Status)) {
                    ERR("balance_metadata_chunk returned %08x\n", Status);
                    // FIXME - store failure status, so we can show this on propsheet
                    break;
                }
            } else if (c->chunk_item->type & BLOCK_FLAG_DATA) {
                Status = balance_data_chunk(Vcb, c, &changed);
                if (!NT_SUCCESS(Status)) {
                    ERR("balance_data_chunk returned %08x\n", Status);
                    // FIXME - store failure status, so we can show this on propsheet
                    break;
                }
            }
        } while (changed);
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
