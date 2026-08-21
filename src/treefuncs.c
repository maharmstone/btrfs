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

__attribute__((nonnull(1,3,4,5)))
NTSTATUS load_tree(device_extension* Vcb, uint64_t addr, uint8_t* buf, root* r, tree** pt) {
    struct btrfs_header* th;
    tree* t;
    tree_data* td;
    uint8_t h;
    bool inserted;
    LIST_ENTRY* le;

    th = (struct btrfs_header*)buf;

    t = ExAllocatePoolWithTag(PagedPool, sizeof(tree), ALLOC_TAG);
    if (!t) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (th->level > 0) {
        t->nonpaged = ExAllocatePoolWithTag(NonPagedPool, sizeof(tree_nonpaged), ALLOC_TAG);
        if (!t->nonpaged) {
            ERR("out of memory\n");
            ExFreePool(t);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        ExInitializeFastMutex(&t->nonpaged->mutex);
    } else
        t->nonpaged = NULL;

    RtlCopyMemory(&t->header, th, sizeof(struct btrfs_header));
    t->hash = calc_crc32c(0xffffffff, (uint8_t*)&addr, sizeof(uint64_t));
    t->has_address = true;
    t->Vcb = Vcb;
    t->parent = NULL;
    t->root = r;
    t->paritem = NULL;
    t->size = 0;
    t->new_address = 0;
    t->has_new_address = false;
    t->updated_extents = false;
    t->write = false;
    t->uniqueness_determined = false;

    InitializeListHead(&t->itemlist);

    if (t->header.level == 0) { // leaf node
        struct btrfs_item* ln = (struct btrfs_item*)(buf + sizeof(struct btrfs_header));
        unsigned int i;

        if ((t->header.nritems * sizeof(struct btrfs_item)) + sizeof(struct btrfs_header) > Vcb->superblock.nodesize) {
            ERR("tree at %I64x has more items than expected (%x)\n", addr, t->header.nritems);
            ExFreePool(t);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        for (i = 0; i < t->header.nritems; i++) {
            td = ExAllocateFromPagedLookasideList(&Vcb->tree_data_lookaside);
            if (!td) {
                ERR("out of memory\n");
                ExFreePool(t);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            td->key = ln[i].key;

            if (ln[i].size > 0)
                td->data = buf + sizeof(struct btrfs_header) + ln[i].offset;
            else
                td->data = NULL;

            if (ln[i].size + sizeof(struct btrfs_header) + sizeof(struct btrfs_item) > Vcb->superblock.nodesize) {
                ERR("overlarge item in tree %I64x: %u > %Iu\n", addr, ln[i].size, Vcb->superblock.nodesize - sizeof(struct btrfs_header) - sizeof(struct btrfs_item));
                ExFreeToPagedLookasideList(&t->Vcb->tree_data_lookaside, td);
                ExFreePool(t);
                return STATUS_INTERNAL_ERROR;
            }

            td->size = (uint16_t)ln[i].size;
            td->ignore = false;
            td->inserted = false;

            InsertTailList(&t->itemlist, &td->list_entry);

            t->size += ln[i].size;
        }

        t->size += t->header.nritems * sizeof(struct btrfs_item);
        t->buf = buf;
    } else {
        struct btrfs_key_ptr* in = (struct btrfs_key_ptr*)(buf + sizeof(struct btrfs_header));
        unsigned int i;

        if ((t->header.nritems * sizeof(struct btrfs_key_ptr)) + sizeof(struct btrfs_header) > Vcb->superblock.nodesize) {
            ERR("tree at %I64x has more items than expected (%x)\n", addr, t->header.nritems);
            ExFreePool(t);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        for (i = 0; i < t->header.nritems; i++) {
            td = ExAllocateFromPagedLookasideList(&Vcb->tree_data_lookaside);
            if (!td) {
                ERR("out of memory\n");
                ExFreePool(t);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            td->key = in[i].key;

            td->treeholder.address = in[i].blockptr;
            td->treeholder.generation = in[i].generation;
            td->treeholder.tree = NULL;
            td->ignore = false;
            td->inserted = false;

            InsertTailList(&t->itemlist, &td->list_entry);
        }

        t->size = t->header.nritems * sizeof(struct btrfs_key_ptr);
        t->buf = NULL;
    }

    ExAcquireFastMutex(&Vcb->trees_list_mutex);

    InsertTailList(&Vcb->trees, &t->list_entry);

    h = t->hash >> 24;

    if (!Vcb->trees_ptrs[h]) {
        uint8_t h2 = h;

        le = Vcb->trees_hash.Flink;

        if (h2 > 0) {
            h2--;
            do {
                if (Vcb->trees_ptrs[h2]) {
                    le = Vcb->trees_ptrs[h2];
                    break;
                }

                h2--;
            } while (h2 > 0);
        }
    } else
        le = Vcb->trees_ptrs[h];

    inserted = false;
    while (le != &Vcb->trees_hash) {
        tree* t2 = CONTAINING_RECORD(le, tree, list_entry_hash);

        if (t2->hash >= t->hash) {
            InsertHeadList(le->Blink, &t->list_entry_hash);
            inserted = true;
            break;
        }

        le = le->Flink;
    }

    if (!inserted)
        InsertTailList(&Vcb->trees_hash, &t->list_entry_hash);

    if (!Vcb->trees_ptrs[h] || t->list_entry_hash.Flink == Vcb->trees_ptrs[h])
        Vcb->trees_ptrs[h] = &t->list_entry_hash;

    ExReleaseFastMutex(&Vcb->trees_list_mutex);

    TRACE("returning %p\n", t);

    *pt = t;

    return STATUS_SUCCESS;
}

__attribute__((nonnull(1,2,3,4)))
static NTSTATUS do_load_tree2(device_extension* Vcb, tree_holder* th, uint8_t* buf, root* r, tree* t, tree_data* td) {
    if (!th->tree) {
        NTSTATUS Status;
        tree* nt;

        Status = load_tree(Vcb, th->address, buf, r, &nt);
        if (!NT_SUCCESS(Status)) {
            ERR("load_tree returned %08lx\n", Status);
            return Status;
        }

        nt->parent = t;

#ifdef DEBUG_PARANOID
        if (t && t->header.level <= nt->header.level) int3;
#endif

        nt->paritem = td;

        th->tree = nt;
    }

    return STATUS_SUCCESS;
}

__attribute__((nonnull(1,2,3)))
NTSTATUS do_load_tree(device_extension* Vcb, tree_holder* th, root* r, tree* t, tree_data* td, PIRP Irp) {
    NTSTATUS Status;
    uint8_t* buf;
    chunk* c;

    buf = ExAllocatePoolWithTag(PagedPool, Vcb->superblock.nodesize, ALLOC_TAG);
    if (!buf) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = read_data(Vcb, th->address, Vcb->superblock.nodesize, NULL, true, buf, NULL,
                       &c, Irp, th->generation, false, NormalPagePriority);
    if (!NT_SUCCESS(Status)) {
        ERR("read_data returned 0x%08lx\n", Status);
        ExFreePool(buf);
        return Status;
    }

    if (t)
        ExAcquireFastMutex(&t->nonpaged->mutex);
    else
        ExAcquireResourceExclusiveLite(&r->nonpaged->load_tree_lock, true);

    Status = do_load_tree2(Vcb, th, buf, r, t, td);

    if (t)
        ExReleaseFastMutex(&t->nonpaged->mutex);
    else
        ExReleaseResourceLite(&r->nonpaged->load_tree_lock);

    if (!th->tree || th->tree->buf != buf)
        ExFreePool(buf);

    if (!NT_SUCCESS(Status)) {
        ERR("do_load_tree2 returned %08lx\n", Status);
        return Status;
    }

    return Status;
}

__attribute__((nonnull(1)))
void free_tree(tree* t) {
    tree* par;
    root* r = t->root;

    // No need to acquire lock, as this is only ever called while Vcb->tree_lock held exclusively

    par = t->parent;

    if (r && r->treeholder.tree != t)
        r = NULL;

    if (par) {
        if (t->paritem)
            t->paritem->treeholder.tree = NULL;
    }

    while (!IsListEmpty(&t->itemlist)) {
        tree_data* td = CONTAINING_RECORD(RemoveHeadList(&t->itemlist), tree_data, list_entry);

        if (t->header.level == 0 && td->data && td->inserted)
            ExFreePool(td->data);

        ExFreeToPagedLookasideList(&t->Vcb->tree_data_lookaside, td);
    }

    RemoveEntryList(&t->list_entry);

    if (r)
        r->treeholder.tree = NULL;

    if (t->list_entry_hash.Flink) {
        uint8_t h = t->hash >> 24;
        if (t->Vcb->trees_ptrs[h] == &t->list_entry_hash) {
            if (t->list_entry_hash.Flink != &t->Vcb->trees_hash) {
                tree* t2 = CONTAINING_RECORD(t->list_entry_hash.Flink, tree, list_entry_hash);

                if ((t2->hash >> 24) == h)
                    t->Vcb->trees_ptrs[h] = &t2->list_entry_hash;
                else
                    t->Vcb->trees_ptrs[h] = NULL;
            } else
                t->Vcb->trees_ptrs[h] = NULL;
        }

        RemoveEntryList(&t->list_entry_hash);
    }

    if (t->buf)
        ExFreePool(t->buf);

    if (t->nonpaged)
        ExFreePool(t->nonpaged);

    ExFreePool(t);
}

__attribute__((nonnull(1)))
static __inline tree_data* first_item(tree* t) {
    LIST_ENTRY* le = t->itemlist.Flink;

    if (le == &t->itemlist)
        return NULL;

    return CONTAINING_RECORD(le, tree_data, list_entry);
}

__attribute__((nonnull(1,2)))
static __inline tree_data* prev_item(tree* t, tree_data* td) {
    LIST_ENTRY* le = td->list_entry.Blink;

    if (le == &t->itemlist)
        return NULL;

    return CONTAINING_RECORD(le, tree_data, list_entry);
}

__attribute__((nonnull(1,2)))
static __inline tree_data* next_item(tree* t, tree_data* td) {
    LIST_ENTRY* le = td->list_entry.Flink;

    if (le == &t->itemlist)
        return NULL;

    return CONTAINING_RECORD(le, tree_data, list_entry);
}

__attribute__((nonnull(1,2,3,4)))
static NTSTATUS next_item2(device_extension* Vcb, tree* t, tree_data* td, traverse_ptr* tp) {
    tree_data* td2 = next_item(t, td);
    tree* t2;

    if (td2) {
        tp->tree = t;
        tp->item = td2;
        return STATUS_SUCCESS;
    }

    t2 = t;

    do {
        td2 = t2->paritem;
        t2 = t2->parent;
    } while (td2 && !next_item(t2, td2));

    if (!td2)
        return STATUS_NOT_FOUND;

    td2 = next_item(t2, td2);

    return find_item_to_level(Vcb, t2->root, tp, &td2->key, false, t->header.level, NULL);
}

__attribute__((nonnull(1,2,3,4,5)))
NTSTATUS skip_to_difference(device_extension* Vcb, traverse_ptr* tp, traverse_ptr* tp2, bool* ended1, bool* ended2) {
    NTSTATUS Status;
    tree *t1, *t2;
    tree_data *td1, *td2;

    t1 = tp->tree;
    t2 = tp2->tree;

    do {
        td1 = t1->paritem;
        td2 = t2->paritem;
        t1 = t1->parent;
        t2 = t2->parent;
    } while (t1 && t2 && t1->header.bytenr == t2->header.bytenr);

    while (true) {
        traverse_ptr tp3, tp4;

        Status = next_item2(Vcb, t1, td1, &tp3);
        if (Status == STATUS_NOT_FOUND)
            *ended1 = true;
        else if (!NT_SUCCESS(Status)) {
            ERR("next_item2 returned %08lx\n", Status);
            return Status;
        }

        Status = next_item2(Vcb, t2, td2, &tp4);
        if (Status == STATUS_NOT_FOUND)
            *ended2 = true;
        else if (!NT_SUCCESS(Status)) {
            ERR("next_item2 returned %08lx\n", Status);
            return Status;
        }

        if (*ended1 || *ended2) {
            if (!*ended1) {
                Status = find_item(Vcb, t1->root, tp, &tp3.item->key, false, NULL);
                if (!NT_SUCCESS(Status)) {
                    ERR("find_item returned %08lx\n", Status);
                    return Status;
                }
            } else if (!*ended2) {
                Status = find_item(Vcb, t2->root, tp2, &tp4.item->key, false, NULL);
                if (!NT_SUCCESS(Status)) {
                    ERR("find_item returned %08lx\n", Status);
                    return Status;
                }
            }

            return STATUS_SUCCESS;
        }

        if (tp3.tree->header.bytenr != tp4.tree->header.bytenr) {
            Status = find_item(Vcb, t1->root, tp, &tp3.item->key, false, NULL);
            if (!NT_SUCCESS(Status)) {
                ERR("find_item returned %08lx\n", Status);
                return Status;
            }

            Status = find_item(Vcb, t2->root, tp2, &tp4.item->key, false, NULL);
            if (!NT_SUCCESS(Status)) {
                ERR("find_item returned %08lx\n", Status);
                return Status;
            }

            return STATUS_SUCCESS;
        }

        t1 = tp3.tree;
        td1 = tp3.item;
        t2 = tp4.tree;
        td2 = tp4.item;
    }
}

__attribute__((nonnull(1,2,3,4)))
static NTSTATUS find_item_in_tree(device_extension* Vcb, tree* t, traverse_ptr* tp, const struct btrfs_key* searchkey, bool ignore, uint8_t level, PIRP Irp) {
    int cmp;
    tree_data *td, *lasttd;
    struct btrfs_key key2;

    cmp = 1;
    td = first_item(t);
    lasttd = NULL;

    if (!td) return STATUS_NOT_FOUND;

    key2 = *searchkey;

    do {
        cmp = keycmp(key2, td->key);

        if (cmp == 1) {
            lasttd = td;
            td = next_item(t, td);
        }

        if (t->header.level == 0 && cmp == 0 && !ignore && td && td->ignore) {
            tree_data* origtd = td;

            while (td && td->ignore)
                td = next_item(t, td);

            if (td) {
                cmp = keycmp(key2, td->key);

                if (cmp != 0) {
                    td = origtd;
                    cmp = 0;
                }
            } else
                td = origtd;
        }
    } while (td && cmp == 1);

    if ((cmp == -1 || !td) && lasttd)
        td = lasttd;

    if (t->header.level == 0) {
        if (td->ignore && !ignore) {
            traverse_ptr oldtp;

            oldtp.tree = t;
            oldtp.item = td;

            while (find_prev_item(Vcb, &oldtp, tp, Irp)) {
                if (!tp->item->ignore)
                    return STATUS_SUCCESS;

                oldtp = *tp;
            }

            // if no valid entries before where item should be, look afterwards instead

            oldtp.tree = t;
            oldtp.item = td;

            while (find_next_item(Vcb, &oldtp, tp, true, Irp)) {
                if (!tp->item->ignore)
                    return STATUS_SUCCESS;

                oldtp = *tp;
            }

            return STATUS_NOT_FOUND;
        } else {
            tp->tree = t;
            tp->item = td;
        }

        return STATUS_SUCCESS;
    } else {
        NTSTATUS Status;

        while (td && td->treeholder.tree && IsListEmpty(&td->treeholder.tree->itemlist)) {
            td = prev_item(t, td);
        }

        if (!td)
            return STATUS_NOT_FOUND;

        if (t->header.level <= level) {
            tp->tree = t;
            tp->item = td;
            return STATUS_SUCCESS;
        }

        if (!td->treeholder.tree) {
            Status = do_load_tree(Vcb, &td->treeholder, t->root, t, td, Irp);
            if (!NT_SUCCESS(Status)) {
                ERR("do_load_tree returned %08lx\n", Status);
                return Status;
            }
        }

        Status = find_item_in_tree(Vcb, td->treeholder.tree, tp, searchkey, ignore, level, Irp);

        return Status;
    }
}

__attribute__((nonnull(1,2,3,4)))
NTSTATUS find_item(_In_ _Requires_lock_held_(_Curr_->tree_lock) device_extension* Vcb, _In_ root* r, _Out_ traverse_ptr* tp,
                   _In_ const struct btrfs_key* searchkey, _In_ bool ignore, _In_opt_ PIRP Irp) {
    NTSTATUS Status;

    if (!r->treeholder.tree) {
        Status = do_load_tree(Vcb, &r->treeholder, r, NULL, NULL, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("do_load_tree returned %08lx\n", Status);
            return Status;
        }
    }

    Status = find_item_in_tree(Vcb, r->treeholder.tree, tp, searchkey, ignore, 0, Irp);
    if (!NT_SUCCESS(Status) && Status != STATUS_NOT_FOUND) {
        ERR("find_item_in_tree returned %08lx\n", Status);
    }

    return Status;
}

__attribute__((nonnull(1,2,3,4)))
NTSTATUS find_item_to_level(device_extension* Vcb, root* r, traverse_ptr* tp, const struct btrfs_key* searchkey, bool ignore, uint8_t level, PIRP Irp) {
    NTSTATUS Status;

    if (!r->treeholder.tree) {
        Status = do_load_tree(Vcb, &r->treeholder, r, NULL, NULL, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("do_load_tree returned %08lx\n", Status);
            return Status;
        }
    }

    Status = find_item_in_tree(Vcb, r->treeholder.tree, tp, searchkey, ignore, level, Irp);
    if (!NT_SUCCESS(Status) && Status != STATUS_NOT_FOUND) {
        ERR("find_item_in_tree returned %08lx\n", Status);
    }

    if (Status == STATUS_NOT_FOUND) {
        tp->tree = r->treeholder.tree;
        tp->item = NULL;
    }

    return Status;
}

__attribute__((nonnull(1,2,3)))
bool find_next_item(_Requires_lock_held_(_Curr_->tree_lock) device_extension* Vcb, const traverse_ptr* tp, traverse_ptr* next_tp, bool ignore, PIRP Irp) {
    tree* t;
    tree_data *td = NULL, *next;
    NTSTATUS Status;

    next = next_item(tp->tree, tp->item);

    if (!ignore) {
        while (next && next->ignore)
            next = next_item(tp->tree, next);
    }

    if (next) {
        next_tp->tree = tp->tree;
        next_tp->item = next;

#ifdef DEBUG_PARANOID
        if (!ignore && next_tp->item->ignore) {
            ERR("error - returning ignored item\n");
            int3;
        }
#endif

        return true;
    }

    if (!tp->tree->parent)
        return false;

    t = tp->tree;
    do {
        if (t->parent) {
            td = next_item(t->parent, t->paritem);

            if (td) break;
        }

        t = t->parent;
    } while (t);

    if (!t)
        return false;

    if (!td->treeholder.tree) {
        Status = do_load_tree(Vcb, &td->treeholder, t->parent->root, t->parent, td, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("do_load_tree returned %08lx\n", Status);
            return false;
        }
    }

    t = td->treeholder.tree;

    while (t->header.level != 0) {
        tree_data* fi;

        fi = first_item(t);

        if (!fi)
            return false;

        if (!fi->treeholder.tree) {
            Status = do_load_tree(Vcb, &fi->treeholder, t->parent->root, t, fi, Irp);
            if (!NT_SUCCESS(Status)) {
                ERR("do_load_tree returned %08lx\n", Status);
                return false;
            }
        }

        t = fi->treeholder.tree;
    }

    next_tp->tree = t;
    next_tp->item = first_item(t);

    if (!next_tp->item)
        return false;

    if (!ignore && next_tp->item->ignore) {
        traverse_ptr ntp2;
        bool b;

        while ((b = find_next_item(Vcb, next_tp, &ntp2, true, Irp))) {
            *next_tp = ntp2;

            if (!next_tp->item->ignore)
                break;
        }

        if (!b)
            return false;
    }

#ifdef DEBUG_PARANOID
    if (!ignore && next_tp->item->ignore) {
        ERR("error - returning ignored item\n");
        int3;
    }
#endif

    return true;
}

__attribute__((nonnull(1)))
static __inline tree_data* last_item(tree* t) {
    LIST_ENTRY* le = t->itemlist.Blink;

    if (le == &t->itemlist)
        return NULL;

    return CONTAINING_RECORD(le, tree_data, list_entry);
}

__attribute__((nonnull(1,2,3)))
bool find_prev_item(_Requires_lock_held_(_Curr_->tree_lock) device_extension* Vcb, const traverse_ptr* tp, traverse_ptr* prev_tp, PIRP Irp) {
    tree* t;
    tree_data* td;
    NTSTATUS Status;

    // FIXME - support ignore flag
    if (prev_item(tp->tree, tp->item)) {
        prev_tp->tree = tp->tree;
        prev_tp->item = prev_item(tp->tree, tp->item);

        return true;
    }

    if (!tp->tree->parent)
        return false;

    t = tp->tree;
    while (t && (!t->parent || !prev_item(t->parent, t->paritem))) {
        t = t->parent;
    }

    if (!t)
        return false;

    td = prev_item(t->parent, t->paritem);

    if (!td->treeholder.tree) {
        Status = do_load_tree(Vcb, &td->treeholder, t->parent->root, t->parent, td, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("do_load_tree returned %08lx\n", Status);
            return false;
        }
    }

    t = td->treeholder.tree;

    while (t->header.level != 0) {
        tree_data* li;

        li = last_item(t);

        if (!li->treeholder.tree) {
            Status = do_load_tree(Vcb, &li->treeholder, t->parent->root, t, li, Irp);
            if (!NT_SUCCESS(Status)) {
                ERR("do_load_tree returned %08lx\n", Status);
                return false;
            }
        }

        t = li->treeholder.tree;
    }

    prev_tp->tree = t;
    prev_tp->item = last_item(t);

    return true;
}

__attribute__((nonnull(1,2)))
void free_trees_root(device_extension* Vcb, root* r) {
    LIST_ENTRY* le;
    ULONG level;

    for (level = 0; level <= 255; level++) {
        bool empty = true;

        le = Vcb->trees.Flink;

        while (le != &Vcb->trees) {
            LIST_ENTRY* nextle = le->Flink;
            tree* t = CONTAINING_RECORD(le, tree, list_entry);

            if (t->root == r) {
                if (t->header.level == level) {
                    bool top = !t->paritem;

                    empty = false;

                    free_tree(t);
                    if (top && r->treeholder.tree == t)
                        r->treeholder.tree = NULL;

                    if (IsListEmpty(&Vcb->trees))
                        return;
                } else if (t->header.level > level)
                    empty = false;
            }

            le = nextle;
        }

        if (empty)
            break;
    }
}

__attribute__((nonnull(1)))
void free_trees(device_extension* Vcb) {
    LIST_ENTRY* le;
    ULONG level;

    for (level = 0; level <= 255; level++) {
        bool empty = true;

        le = Vcb->trees.Flink;

        while (le != &Vcb->trees) {
            LIST_ENTRY* nextle = le->Flink;
            tree* t = CONTAINING_RECORD(le, tree, list_entry);
            root* r = t->root;

            if (t->header.level == level) {
                bool top = !t->paritem;

                empty = false;

                free_tree(t);
                if (top && r->treeholder.tree == t)
                    r->treeholder.tree = NULL;

                if (IsListEmpty(&Vcb->trees))
                    break;
            } else if (t->header.level > level)
                empty = false;

            le = nextle;
        }

        if (empty)
            break;
    }

    reap_filerefs(Vcb);
    reap_fcbs(Vcb);
}

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(suppress: 28194)
#endif
__attribute__((nonnull(1,2)))
NTSTATUS insert_tree_item(_In_ _Requires_exclusive_lock_held_(_Curr_->tree_lock) device_extension* Vcb, _In_ root* r, _In_ uint64_t objectid,
                          _In_ uint8_t type, _In_ uint64_t offset, _In_reads_bytes_opt_(size) _When_(return >= 0, __drv_aliasesMem) void* data,
                          _In_ uint16_t size, _Out_opt_ traverse_ptr* ptp, _In_opt_ PIRP Irp) {
    traverse_ptr tp;
    struct btrfs_key searchkey;
    int cmp;
    tree_data *td, *paritem;
    tree* t;
#ifdef _DEBUG
    LIST_ENTRY* le;
    struct btrfs_key firstitem = {0xcccccccccccccccc,0xcc,0xcccccccccccccccc};
#endif
    NTSTATUS Status;

    TRACE("(%p, %p, %I64x, %x, %I64x, %p, %x, %p)\n", Vcb, r, objectid, type, offset, data, size, ptp);

    searchkey.objectid = objectid;
    searchkey.type = type;
    searchkey.offset = offset;

    Status = find_item(Vcb, r, &tp, &searchkey, true, Irp);
    if (Status == STATUS_NOT_FOUND) {
        if (!r->treeholder.tree) {
            Status = do_load_tree(Vcb, &r->treeholder, r, NULL, NULL, Irp);
            if (!NT_SUCCESS(Status)) {
                ERR("do_load_tree returned %08lx\n", Status);
                return Status;
            }
        }

        if (r->treeholder.tree && r->treeholder.tree->header.nritems == 0) {
            tp.tree = r->treeholder.tree;
            tp.item = NULL;
        } else {
            ERR("error: unable to load tree for root %I64x\n", r->id);
            return STATUS_INTERNAL_ERROR;
        }
    } else if (!NT_SUCCESS(Status)) {
        ERR("find_item returned %08lx\n", Status);
        return Status;
    }

    TRACE("tp.item = %p\n", tp.item);

    if (tp.item) {
        TRACE("tp.item->key = %p\n", &tp.item->key);
        cmp = keycmp(searchkey, tp.item->key);

        if (cmp == 0 && !tp.item->ignore) {
            ERR("error: key (%I64x,%x,%I64x) already present\n", objectid, type, offset);
#ifdef DEBUG_PARANOID
            int3;
#endif
            return STATUS_INTERNAL_ERROR;
        }
    } else
        cmp = -1;

    td = ExAllocateFromPagedLookasideList(&Vcb->tree_data_lookaside);
    if (!td) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    td->key = searchkey;
    td->size = size;
    td->data = data;
    td->ignore = false;
    td->inserted = true;

#ifdef _DEBUG
    le = tp.tree->itemlist.Flink;
    while (le != &tp.tree->itemlist) {
        tree_data* td2 = CONTAINING_RECORD(le, tree_data, list_entry);
        firstitem = td2->key;
        break;
    }

    TRACE("inserting %I64x,%x,%I64x into tree beginning %I64x,%x,%I64x (num_items %x)\n", objectid, type, offset, firstitem.objectid, firstitem.type, firstitem.offset, tp.tree->header.nritems);
#endif

    if (cmp == -1) { // very first key in root
        InsertHeadList(&tp.tree->itemlist, &td->list_entry);

        paritem = tp.tree->paritem;
        while (paritem) {
            if (!keycmp(paritem->key, tp.item->key)) {
                paritem->key = searchkey;
            } else
                break;

            paritem = paritem->treeholder.tree->paritem;
        }
    } else if (cmp == 0)
        InsertHeadList(tp.item->list_entry.Blink, &td->list_entry); // make sure non-deleted item is before deleted ones
    else
        InsertHeadList(&tp.item->list_entry, &td->list_entry);

    tp.tree->header.nritems++;
    tp.tree->size += size + sizeof(struct btrfs_item);

    if (!tp.tree->write) {
        tp.tree->write = true;
        Vcb->need_write = true;
    }

    if (ptp)
        *ptp = tp;

    t = tp.tree;
    while (t) {
        if (t->paritem && t->paritem->ignore) {
            t->paritem->ignore = false;
            t->parent->header.nritems++;
            t->parent->size += sizeof(struct btrfs_key_ptr);
        }

        t->header.generation = Vcb->superblock.generation;
        t = t->parent;
    }

    return STATUS_SUCCESS;
}
#ifdef _MSC_VER
#pragma warning(pop)
#endif

__attribute__((nonnull(1,2)))
NTSTATUS delete_tree_item(_In_ _Requires_exclusive_lock_held_(_Curr_->tree_lock) device_extension* Vcb, _Inout_ traverse_ptr* tp) {
    tree* t;
    uint64_t gen;

    TRACE("deleting item %I64x,%x,%I64x (ignore = %s)\n", tp->item->key.objectid, tp->item->key.type, tp->item->key.offset, tp->item->ignore ? "true" : "false");

#ifdef DEBUG_PARANOID
    if (tp->item->ignore) {
        ERR("trying to delete already-deleted item %I64x,%x,%I64x\n", tp->item->key.objectid, tp->item->key.type, tp->item->key.offset);
        int3;
        return STATUS_INTERNAL_ERROR;
    }
#endif

    tp->item->ignore = true;

    if (!tp->tree->write) {
        tp->tree->write = true;
        Vcb->need_write = true;
    }

    tp->tree->header.nritems--;

    if (tp->tree->header.level == 0)
        tp->tree->size -= sizeof(struct btrfs_item) + tp->item->size;
    else
        tp->tree->size -= sizeof(struct btrfs_key_ptr);

    gen = tp->tree->Vcb->superblock.generation;

    t = tp->tree;
    while (t) {
        t->header.generation = gen;
        t = t->parent;
    }

    return STATUS_SUCCESS;
}

__attribute__((nonnull(1)))
void clear_rollback(LIST_ENTRY* rollback) {
    while (!IsListEmpty(rollback)) {
        rollback_item* ri = CONTAINING_RECORD(RemoveHeadList(rollback), rollback_item, list_entry);

        ExFreePool(ri);
    }
}

__attribute__((nonnull(1,2)))
void do_rollback(device_extension* Vcb, LIST_ENTRY* rollback) {
    NTSTATUS Status;
    rollback_item* ri;

    while (!IsListEmpty(rollback)) {
        LIST_ENTRY* le = RemoveTailList(rollback);
        ri = CONTAINING_RECORD(le, rollback_item, list_entry);

        switch (ri->type) {
            case ROLLBACK_INSERT_EXTENT:
                ri->extent.ext->ignore = true;

                switch (ri->extent.ext->extent_data.type) {
                    case BTRFS_FILE_EXTENT_REG:
                    case BTRFS_FILE_EXTENT_PREALLOC: {
                        if (ri->extent.ext->extent_data.disk_num_bytes != 0)
                            ri->extent.fcb->inode_item.nbytes -= ri->extent.ext->extent_data.num_bytes;

                        break;
                    }

                    case BTRFS_FILE_EXTENT_INLINE:
                        ri->extent.fcb->inode_item.nbytes -= ri->extent.ext->extent_data.ram_bytes;
                    break;
                }

                break;

            case ROLLBACK_DELETE_EXTENT:
                ri->extent.ext->ignore = false;

                switch (ri->extent.ext->extent_data.type) {
                    case BTRFS_FILE_EXTENT_REG:
                    case BTRFS_FILE_EXTENT_PREALLOC:
                        if (ri->extent.ext->extent_data.disk_num_bytes != 0)
                            ri->extent.fcb->inode_item.nbytes += ri->extent.ext->extent_data.num_bytes;
                        break;

                    case BTRFS_FILE_EXTENT_INLINE:
                        ri->extent.fcb->inode_item.nbytes += ri->extent.ext->extent_data.ram_bytes;
                    break;
                }

                break;

            case ROLLBACK_ADD_SPACE:
            case ROLLBACK_SUBTRACT_SPACE:
                if (ri->space.chunk)
                    acquire_chunk_lock(ri->space.chunk, Vcb);

                if (ri->type == ROLLBACK_ADD_SPACE) {
                    Status = space_list_subtract2(ri->space.list, ri->space.list_size,
                                                  ri->space.address, ri->space.length,
                                                  NULL, NULL);
                    if (!NT_SUCCESS(Status)) {
                        ERR("space_list_subtract2 returned %08lx\n", Status);

                        if (ri->space.chunk)
                            release_chunk_lock(ri->space.chunk, Vcb);

                        ExFreePool(ri);

                        goto fail;
                    }
                } else {
                    Status = space_list_add2(ri->space.list, ri->space.list_size,
                                             ri->space.address, ri->space.length,
                                             NULL, NULL);
                    if (!NT_SUCCESS(Status)) {
                        ERR("space_list_add2 returned %08lx\n", Status);

                        if (ri->space.chunk)
                            release_chunk_lock(ri->space.chunk, Vcb);

                        ExFreePool(ri);

                        goto fail;
                    }
                }

                if (ri->space.chunk) {
                    if (ri->type == ROLLBACK_ADD_SPACE)
                        ri->space.chunk->used += ri->space.length;
                    else
                        ri->space.chunk->used -= ri->space.length;
                }

                if (ri->space.chunk) {
                    LIST_ENTRY* le2 = le->Blink;

                    while (le2 != rollback) {
                        LIST_ENTRY* le3 = le2->Blink;
                        rollback_item* ri2 = CONTAINING_RECORD(le2, rollback_item, list_entry);

                        if (ri2->type == ROLLBACK_ADD_SPACE || ri2->type == ROLLBACK_SUBTRACT_SPACE) {
                            if (ri2->space.chunk == ri->space.chunk) {
                                if (ri2->type == ROLLBACK_ADD_SPACE) {
                                    Status = space_list_subtract2(ri2->space.list,
                                                                  ri2->space.list_size,
                                                                  ri2->space.address,
                                                                  ri2->space.length,
                                                                  NULL, NULL);
                                    if (!NT_SUCCESS(Status)) {
                                        ERR("space_list_subtract2 returned %08lx\n", Status);
                                        release_chunk_lock(ri->space.chunk, Vcb);
                                        ExFreePool(ri);
                                        goto fail;
                                    }

                                    ri->space.chunk->used += ri2->space.length;
                                } else {
                                    Status = space_list_add2(ri2->space.list,
                                                             ri2->space.list_size,
                                                             ri2->space.address,
                                                             ri2->space.length,
                                                             NULL, NULL);
                                    if (!NT_SUCCESS(Status)) {
                                        ERR("space_list_add2 returned %08lx\n", Status);
                                        release_chunk_lock(ri->space.chunk, Vcb);
                                        ExFreePool(ri);
                                        goto fail;
                                    }

                                    ri->space.chunk->used -= ri2->space.length;
                                }

                                RemoveEntryList(&ri2->list_entry);
                                ExFreePool(ri2);
                            }
                        }

                        le2 = le3;
                    }

                    release_chunk_lock(ri->space.chunk, Vcb);
                }

                break;

            case ROLLBACK_UPDATE_CHANGED_EXTENT_REF: {
                chunk* c = get_chunk_from_address(Vcb, ri->changed_extent_ref.address);

                if (c) {
                    changed_extent* ce;

                    Status = update_changed_extent_ref(Vcb, c, ri->changed_extent_ref.address,
                                                       ri->changed_extent_ref.size,
                                                       ri->changed_extent_ref.root,
                                                       ri->changed_extent_ref.objid,
                                                       ri->changed_extent_ref.offset,
                                                       -ri->changed_extent_ref.count,
                                                       false, false, NULL, NULL);
                    if (!NT_SUCCESS(Status)) {
                        ERR("update_changed_extent_ref returned %08lx\n", Status);
                        ExFreePool(ri);
                        goto fail;
                    }

                    ExAcquireResourceExclusiveLite(&c->changed_extents_lock, true);

                    ce = get_changed_extent_item(c, ri->changed_extent_ref.address,
                                                 ri->changed_extent_ref.size, false);
                    if (!ce) { // shouldn't happen
                        ERR("get_changed_extent_item returned NULL\n");
                        ExFreePool(ri);
                        ExReleaseResourceLite(&c->changed_extents_lock);
                        Status = STATUS_INTERNAL_ERROR;
                        goto fail;
                    }

                    if (ce->count == 0 && ce->old_count == 0) {
                        while (!IsListEmpty(&ce->refs)) {
                            changed_extent_ref* cer = CONTAINING_RECORD(RemoveHeadList(&ce->refs), changed_extent_ref, list_entry);
                            ExFreePool(cer);
                        }

                        RemoveEntryList(&ce->list_entry);
                        ExFreePool(ce);
                    }

                    ExReleaseResourceLite(&c->changed_extents_lock);
                }

                break;
            }

            case ROLLBACK_ADD_DIR_CHILD: {
                dir_child* dc = ri->dir_child.dc;

                ExAcquireResourceExclusiveLite(&ri->dir_child.parent->nonpaged->dir_children_lock,
                                               true);
                RemoveEntryList(&dc->list_entry_index);
                remove_dir_child_from_hash_lists(ri->dir_child.parent, dc);
                ExReleaseResourceLite(&ri->dir_child.parent->nonpaged->dir_children_lock);

                ExFreePool(dc->utf8.Buffer);
                ExFreePool(dc->name.Buffer);
                ExFreePool(dc->name_uc.Buffer);
                ExFreePool(dc);

                break;
            }
        }

        ExFreePool(ri);
    }

    return;

fail:
    ERR("do_rollback failed, going readonly\n");

    while (!IsListEmpty(rollback)) {
        LIST_ENTRY* le = RemoveTailList(rollback);
        ri = CONTAINING_RECORD(le, rollback_item, list_entry);

        ExFreePool(ri);
    }

    Vcb->readonly = true;
    FsRtlNotifyVolumeEvent(Vcb->root_file, FSRTL_VOLUME_FORCED_CLOSED);
}

__attribute__((nonnull(1,2,3)))
static NTSTATUS find_tree_end(tree* t, struct btrfs_key* tree_end, bool* no_end) {
    tree* p;

    p = t;
    do {
        tree_data* pi;

        if (!p->parent) {
            tree_end->objectid = 0xffffffffffffffff;
            tree_end->type = 0xff;
            tree_end->offset = 0xffffffffffffffff;
            *no_end = true;
            return STATUS_SUCCESS;
        }

        pi = p->paritem;

        if (pi->list_entry.Flink != &p->parent->itemlist) {
            tree_data* td = CONTAINING_RECORD(pi->list_entry.Flink, tree_data, list_entry);

            *tree_end = td->key;
            *no_end = false;
            return STATUS_SUCCESS;
        }

        p = p->parent;
    } while (p);

    return STATUS_INTERNAL_ERROR;
}

__attribute__((nonnull(1,2)))
void clear_batch_list(device_extension* Vcb, LIST_ENTRY* batchlist) {
    while (!IsListEmpty(batchlist)) {
        LIST_ENTRY* le = RemoveHeadList(batchlist);
        batch_root* br = CONTAINING_RECORD(le, batch_root, list_entry);

        while (!IsListEmpty(&br->items_ind)) {
            batch_item_ind* bii = CONTAINING_RECORD(RemoveHeadList(&br->items_ind), batch_item_ind, list_entry);

            while (!IsListEmpty(&bii->items)) {
                batch_item* bi = CONTAINING_RECORD(RemoveHeadList(&bii->items), batch_item, list_entry);

                ExFreeToPagedLookasideList(&Vcb->batch_item_lookaside, bi);
            }

            ExFreePool(bii);
        }

        ExFreePool(br);
    }
}

__attribute__((nonnull(1,2,3)))
static NTSTATUS add_delete_inode_extref(device_extension* Vcb, batch_item* bi, LIST_ENTRY* listhead) {
    batch_item* bi2;
    LIST_ENTRY* le;
    struct btrfs_inode_ref* delir = (struct btrfs_inode_ref*)bi->data;
    struct btrfs_inode_extref* ier;

    TRACE("entry in INODE_REF not found, adding Batch_DeleteInodeExtRef entry\n");

    bi2 = ExAllocateFromPagedLookasideList(&Vcb->batch_item_lookaside);
    if (!bi2) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ier = ExAllocatePoolWithTag(PagedPool, offsetof(struct btrfs_inode_extref, name) + delir->name_len, ALLOC_TAG);
    if (!ier) {
        ERR("out of memory\n");
        ExFreePool(bi2);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ier->parent_objectid = bi->key.offset;
    ier->index = delir->index;
    ier->name_len = delir->name_len;
    RtlCopyMemory(ier->name, &delir[1], delir->name_len);

    bi2->key.objectid = bi->key.objectid;
    bi2->key.type = BTRFS_INODE_EXTREF_KEY;
    bi2->key.offset = calc_crc32c((uint32_t)bi->key.offset, (uint8_t*)ier->name, ier->name_len);
    bi2->data = ier;
    bi2->datalen = offsetof(struct btrfs_inode_extref, name) + ier->name_len;
    bi2->operation = Batch_DeleteInodeExtRef;

    le = bi->list_entry.Flink;
    while (le != listhead) {
        batch_item* bi3 = CONTAINING_RECORD(le, batch_item, list_entry);

        if (keycmp(bi3->key, bi2->key) != -1) {
            InsertHeadList(le->Blink, &bi2->list_entry);
            return STATUS_SUCCESS;
        }

        le = le->Flink;
    }

    InsertTailList(listhead, &bi2->list_entry);

    return STATUS_SUCCESS;
}

__attribute__((nonnull(1,2,3,4,6,7)))
static NTSTATUS handle_batch_collision(device_extension* Vcb, batch_item* bi, tree* t, tree_data* td, tree_data* newtd, LIST_ENTRY* listhead, bool* ignore) {
    NTSTATUS Status;

    if (bi->operation == Batch_Delete || bi->operation == Batch_SetXattr || bi->operation == Batch_DirItem || bi->operation == Batch_InodeRef ||
        bi->operation == Batch_InodeExtRef || bi->operation == Batch_DeleteDirItem || bi->operation == Batch_DeleteInodeRef ||
        bi->operation == Batch_DeleteInodeExtRef || bi->operation == Batch_DeleteXattr) {
        uint16_t maxlen = (uint16_t)(Vcb->superblock.nodesize - sizeof(struct btrfs_header) - sizeof(struct btrfs_item));

        switch (bi->operation) {
            case Batch_SetXattr: {
                if (td->size < sizeof(struct btrfs_dir_item)) {
                    ERR("(%I64x,%x,%I64x) was %u bytes, expected at least %Iu\n", bi->key.objectid, bi->key.type, bi->key.offset, td->size, sizeof(struct btrfs_dir_item));
                } else {
                    uint8_t* newdata;
                    ULONG size = td->size;
                    struct btrfs_dir_item* newxa = (struct btrfs_dir_item*)bi->data;
                    struct btrfs_dir_item* xa = (struct btrfs_dir_item*)td->data;

                    while (true) {
                        ULONG oldxasize;

                        if (size < sizeof(struct btrfs_dir_item) || size < sizeof(struct btrfs_dir_item) + xa->data_len + xa->name_len) {
                            ERR("(%I64x,%x,%I64x) was truncated\n", bi->key.objectid, bi->key.type, bi->key.offset);
                            break;
                        }

                        oldxasize = sizeof(struct btrfs_dir_item) + xa->data_len + xa->name_len;

                        if (xa->name_len == newxa->name_len && RtlCompareMemory(&newxa[1], &xa[1], xa->name_len) == xa->name_len) {
                            uint64_t pos;

                            // replace

                            if (td->size + bi->datalen - oldxasize > maxlen)
                                ERR("DIR_ITEM would be over maximum size, truncating (%u + %u - %lu > %u)\n", td->size, bi->datalen, oldxasize, maxlen);

                            newdata = ExAllocatePoolWithTag(PagedPool, td->size + bi->datalen - oldxasize, ALLOC_TAG);
                            if (!newdata) {
                                ERR("out of memory\n");
                                return STATUS_INSUFFICIENT_RESOURCES;
                            }

                            pos = (uint8_t*)xa - td->data;
                            if (pos + oldxasize < td->size) // copy after changed xattr
                                RtlCopyMemory(newdata + pos + bi->datalen, td->data + pos + oldxasize, (ULONG)(td->size - pos - oldxasize));

                            if (pos > 0) { // copy before changed xattr
                                RtlCopyMemory(newdata, td->data, (ULONG)pos);
                                xa = (struct btrfs_dir_item*)(newdata + pos);
                            } else
                                xa = (struct btrfs_dir_item*)newdata;

                            RtlCopyMemory(xa, bi->data, bi->datalen);

                            bi->datalen = (uint16_t)min(td->size + bi->datalen - oldxasize, maxlen);

                            ExFreePool(bi->data);
                            bi->data = newdata;

                            break;
                        }

                        if ((uint8_t*)xa - (uint8_t*)td->data + oldxasize >= size) {
                            // not found, add to end of data

                            if (td->size + bi->datalen > maxlen)
                                ERR("DIR_ITEM would be over maximum size, truncating (%u + %u > %u)\n", td->size, bi->datalen, maxlen);

                            newdata = ExAllocatePoolWithTag(PagedPool, td->size + bi->datalen, ALLOC_TAG);
                            if (!newdata) {
                                ERR("out of memory\n");
                                return STATUS_INSUFFICIENT_RESOURCES;
                            }

                            RtlCopyMemory(newdata, td->data, td->size);

                            xa = (struct btrfs_dir_item*)((uint8_t*)newdata + td->size);
                            RtlCopyMemory(xa, bi->data, bi->datalen);

                            bi->datalen = min(bi->datalen + td->size, maxlen);

                            ExFreePool(bi->data);
                            bi->data = newdata;

                            break;
                        } else {
                            xa = (struct btrfs_dir_item*)((uint8_t*)&xa[1] + xa->data_len + xa->name_len);
                            size -= oldxasize;
                        }
                    }
                }
                break;
            }

            case Batch_DirItem: {
                uint8_t* newdata;

                if (td->size + bi->datalen > maxlen) {
                    ERR("DIR_ITEM would be over maximum size (%u + %u > %u)\n", td->size, bi->datalen, maxlen);
                    return STATUS_INTERNAL_ERROR;
                }

                newdata = ExAllocatePoolWithTag(PagedPool, td->size + bi->datalen, ALLOC_TAG);
                if (!newdata) {
                    ERR("out of memory\n");
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                RtlCopyMemory(newdata, td->data, td->size);

                RtlCopyMemory(newdata + td->size, bi->data, bi->datalen);

                bi->datalen += td->size;

                ExFreePool(bi->data);
                bi->data = newdata;

                break;
            }

            case Batch_InodeRef: {
                uint8_t* newdata;

                if (td->size + bi->datalen > maxlen) {
                    if (Vcb->superblock.incompat_flags & BTRFS_FEATURE_INCOMPAT_EXTENDED_IREF) {
                        struct btrfs_inode_ref* ir = (struct btrfs_inode_ref*)bi->data;
                        struct btrfs_inode_extref* ier;
                        uint16_t ierlen;
                        batch_item* bi2;
                        LIST_ENTRY* le;
                        bool inserted = false;

                        TRACE("INODE_REF would be too long, adding INODE_EXTREF instead\n");

                        ierlen = (uint16_t)(offsetof(struct btrfs_inode_extref, name) + ir->name_len);

                        ier = ExAllocatePoolWithTag(PagedPool, ierlen, ALLOC_TAG);
                        if (!ier) {
                            ERR("out of memory\n");
                            return STATUS_INSUFFICIENT_RESOURCES;
                        }

                        ier->parent_objectid = bi->key.offset;
                        ier->index = ir->index;
                        ier->name_len = ir->name_len;
                        RtlCopyMemory(ier->name, &ir[1], ier->name_len);

                        bi2 = ExAllocateFromPagedLookasideList(&Vcb->batch_item_lookaside);
                        if (!bi2) {
                            ERR("out of memory\n");
                            ExFreePool(ier);
                            return STATUS_INSUFFICIENT_RESOURCES;
                        }

                        bi2->key.objectid = bi->key.objectid;
                        bi2->key.type = BTRFS_INODE_EXTREF_KEY;
                        bi2->key.offset = calc_crc32c((uint32_t)ier->parent_objectid, (uint8_t*)ier->name, ier->name_len);
                        bi2->data = ier;
                        bi2->datalen = ierlen;
                        bi2->operation = Batch_InodeExtRef;

                        le = bi->list_entry.Flink;
                        while (le != listhead) {
                            batch_item* bi3 = CONTAINING_RECORD(le, batch_item, list_entry);

                            if (keycmp(bi3->key, bi2->key) != -1) {
                                InsertHeadList(le->Blink, &bi2->list_entry);
                                inserted = true;
                            }

                            le = le->Flink;
                        }

                        if (!inserted)
                            InsertTailList(listhead, &bi2->list_entry);

                        *ignore = true;
                        return STATUS_SUCCESS;
                    } else {
                        ERR("INODE_REF would be over maximum size (%u + %u > %u)\n", td->size, bi->datalen, maxlen);
                        return STATUS_INTERNAL_ERROR;
                    }
                }

                newdata = ExAllocatePoolWithTag(PagedPool, td->size + bi->datalen, ALLOC_TAG);
                if (!newdata) {
                    ERR("out of memory\n");
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                RtlCopyMemory(newdata, td->data, td->size);

                RtlCopyMemory(newdata + td->size, bi->data, bi->datalen);

                bi->datalen += td->size;

                ExFreePool(bi->data);
                bi->data = newdata;

                break;
            }

            case Batch_InodeExtRef: {
                uint8_t* newdata;

                if (td->size + bi->datalen > maxlen) {
                    ERR("INODE_EXTREF would be over maximum size (%u + %u > %u)\n", td->size, bi->datalen, maxlen);
                    return STATUS_INTERNAL_ERROR;
                }

                newdata = ExAllocatePoolWithTag(PagedPool, td->size + bi->datalen, ALLOC_TAG);
                if (!newdata) {
                    ERR("out of memory\n");
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                RtlCopyMemory(newdata, td->data, td->size);

                RtlCopyMemory(newdata + td->size, bi->data, bi->datalen);

                bi->datalen += td->size;

                ExFreePool(bi->data);
                bi->data = newdata;

                break;
            }

            case Batch_DeleteDirItem: {
                if (td->size < sizeof(struct btrfs_dir_item)) {
                    ERR("DIR_ITEM was %u bytes, expected at least %Iu\n", td->size, sizeof(struct btrfs_dir_item));
                    return STATUS_INTERNAL_ERROR;
                } else {
                    struct btrfs_dir_item *di, *deldi;
                    LONG len;

                    deldi = (struct btrfs_dir_item*)bi->data;
                    di = (struct btrfs_dir_item*)td->data;
                    len = td->size;

                    do {
                        if (di->data_len == deldi->data_len && di->name_len == deldi->name_len && RtlCompareMemory(&di[1], &deldi[1], di->name_len + di->data_len) == di->name_len + di->data_len) {
                            uint16_t newlen = td->size - (sizeof(struct btrfs_dir_item) + di->name_len + di->data_len);

                            if (newlen == 0) {
                                TRACE("deleting DIR_ITEM\n");
                            } else {
                                uint8_t *newdi = ExAllocatePoolWithTag(PagedPool, newlen, ALLOC_TAG), *dioff;
                                tree_data* td2;

                                if (!newdi) {
                                    ERR("out of memory\n");
                                    return STATUS_INSUFFICIENT_RESOURCES;
                                }

                                TRACE("modifying DIR_ITEM\n");

                                if ((uint8_t*)di > td->data) {
                                    RtlCopyMemory(newdi, td->data, (uint8_t*)di - td->data);
                                    dioff = newdi + ((uint8_t*)di - td->data);
                                } else {
                                    dioff = newdi;
                                }

                                if ((uint8_t*)&di[1] + di->name_len + di->data_len < td->data + td->size)
                                    RtlCopyMemory(dioff, (uint8_t*)&di[1] + di->name_len + di->data_len, td->size - (((uint8_t*)&di[1] + di->name_len + di->data_len) - td->data));

                                td2 = ExAllocateFromPagedLookasideList(&Vcb->tree_data_lookaside);
                                if (!td2) {
                                    ERR("out of memory\n");
                                    ExFreePool(newdi);
                                    return STATUS_INSUFFICIENT_RESOURCES;
                                }

                                td2->key = bi->key;
                                td2->size = newlen;
                                td2->data = newdi;
                                td2->ignore = false;
                                td2->inserted = true;

                                InsertHeadList(td->list_entry.Blink, &td2->list_entry);

                                t->header.nritems++;
                                t->size += newlen + sizeof(struct btrfs_item);
                                t->write = true;
                            }

                            break;
                        }

                        len -= sizeof(struct btrfs_dir_item) + di->name_len + di->data_len;
                        di = (struct btrfs_dir_item*)((uint8_t*)&di[1] + di->data_len + di->name_len);

                        if (len == 0) {
                            TRACE("could not find DIR_ITEM to delete\n");
                            *ignore = true;
                            return STATUS_SUCCESS;
                        }
                    } while (len > 0);
                }
                break;
            }

            case Batch_DeleteInodeRef: {
                if (td->size < sizeof(struct btrfs_inode_ref)) {
                    ERR("INODE_REF was %u bytes, expected at least %Iu\n", td->size, sizeof(struct btrfs_inode_ref));
                    return STATUS_INTERNAL_ERROR;
                } else {
                    struct btrfs_inode_ref *ir, *delir;
                    ULONG len;
                    bool changed = false;

                    delir = (struct btrfs_inode_ref*)bi->data;
                    ir = (struct btrfs_inode_ref*)td->data;
                    len = td->size;

                    do {
                        uint16_t itemlen;

                        if (len < sizeof(struct btrfs_inode_ref) || len < sizeof(struct btrfs_inode_ref) + ir->name_len) {
                            ERR("INODE_REF was truncated\n");
                            break;
                        }

                        itemlen = (uint16_t)sizeof(struct btrfs_inode_ref) + ir->name_len;

                        if (ir->name_len == delir->name_len && RtlCompareMemory(&ir[1], &delir[1], ir->name_len) == ir->name_len) {
                            uint16_t newlen = td->size - itemlen;

                            changed = true;

                            if (newlen == 0)
                                TRACE("deleting INODE_REF\n");
                            else {
                                uint8_t *newir = ExAllocatePoolWithTag(PagedPool, newlen, ALLOC_TAG), *iroff;
                                tree_data* td2;

                                if (!newir) {
                                    ERR("out of memory\n");
                                    return STATUS_INSUFFICIENT_RESOURCES;
                                }

                                TRACE("modifying INODE_REF\n");

                                if ((uint8_t*)ir > td->data) {
                                    RtlCopyMemory(newir, td->data, (uint8_t*)ir - td->data);
                                    iroff = newir + ((uint8_t*)ir - td->data);
                                } else {
                                    iroff = newir;
                                }

                                if ((uint8_t*)&ir[1] + ir->name_len < td->data + td->size)
                                    RtlCopyMemory(iroff, (uint8_t*)&ir[1] + ir->name_len, td->size - (((uint8_t*)&ir[1] + ir->name_len) - td->data));

                                td2 = ExAllocateFromPagedLookasideList(&Vcb->tree_data_lookaside);
                                if (!td2) {
                                    ERR("out of memory\n");
                                    ExFreePool(newir);
                                    return STATUS_INSUFFICIENT_RESOURCES;
                                }

                                td2->key = bi->key;
                                td2->size = newlen;
                                td2->data = newir;
                                td2->ignore = false;
                                td2->inserted = true;

                                InsertHeadList(td->list_entry.Blink, &td2->list_entry);

                                t->header.nritems++;
                                t->size += newlen + sizeof(struct btrfs_item);
                                t->write = true;
                            }

                            break;
                        }

                        if (len > itemlen) {
                            len -= itemlen;
                            ir = (struct btrfs_inode_ref*)((uint8_t*)&ir[1] + ir->name_len);
                        } else
                            break;
                    } while (len > 0);

                    if (!changed) {
                        if (Vcb->superblock.incompat_flags & BTRFS_FEATURE_INCOMPAT_EXTENDED_IREF) {
                            TRACE("entry in INODE_REF not found, adding Batch_DeleteInodeExtRef entry\n");

                            Status = add_delete_inode_extref(Vcb, bi, listhead);
                            if (!NT_SUCCESS(Status)) {
                                ERR("add_delete_inode_extref returned %08lx\n", Status);
                                return Status;
                            }

                            *ignore = true;
                            return STATUS_SUCCESS;
                        } else
                            WARN("entry not found in INODE_REF\n");
                    }
                }

                break;
            }

            case Batch_DeleteInodeExtRef: {
                if (td->size < offsetof(struct btrfs_inode_extref, name)) {
                    ERR("INODE_EXTREF was %u bytes, expected at least %Iu\n", td->size, offsetof(struct btrfs_inode_extref, name));
                    return STATUS_INTERNAL_ERROR;
                } else {
                    struct btrfs_inode_extref *ier, *delier;
                    ULONG len;

                    delier = (struct btrfs_inode_extref*)bi->data;
                    ier = (struct btrfs_inode_extref*)td->data;
                    len = td->size;

                    do {
                        uint16_t itemlen;

                        if (len < offsetof(struct btrfs_inode_extref, name) || len < offsetof(struct btrfs_inode_extref, name) + ier->name_len) {
                            ERR("INODE_REF was truncated\n");
                            break;
                        }

                        itemlen = (uint16_t)offsetof(struct btrfs_inode_extref, name) + ier->name_len;

                        if (ier->parent_objectid == delier->parent_objectid && ier->name_len == delier->name_len && RtlCompareMemory(ier->name, delier->name, ier->name_len) == ier->name_len) {
                            uint16_t newlen = td->size - itemlen;

                            if (newlen == 0)
                                TRACE("deleting INODE_EXTREF\n");
                            else {
                                uint8_t *newier = ExAllocatePoolWithTag(PagedPool, newlen, ALLOC_TAG), *ieroff;
                                tree_data* td2;

                                if (!newier) {
                                    ERR("out of memory\n");
                                    return STATUS_INSUFFICIENT_RESOURCES;
                                }

                                TRACE("modifying INODE_EXTREF\n");

                                if ((uint8_t*)ier > td->data) {
                                    RtlCopyMemory(newier, td->data, (uint8_t*)ier - td->data);
                                    ieroff = newier + ((uint8_t*)ier - td->data);
                                } else {
                                    ieroff = newier;
                                }

                                if ((uint8_t*)&ier->name[ier->name_len] < td->data + td->size)
                                    RtlCopyMemory(ieroff, &ier->name[ier->name_len], td->size - ((uint8_t*)&ier->name[ier->name_len] - td->data));

                                td2 = ExAllocateFromPagedLookasideList(&Vcb->tree_data_lookaside);
                                if (!td2) {
                                    ERR("out of memory\n");
                                    ExFreePool(newier);
                                    return STATUS_INSUFFICIENT_RESOURCES;
                                }

                                td2->key = bi->key;
                                td2->size = newlen;
                                td2->data = newier;
                                td2->ignore = false;
                                td2->inserted = true;

                                InsertHeadList(td->list_entry.Blink, &td2->list_entry);

                                t->header.nritems++;
                                t->size += newlen + sizeof(struct btrfs_item);
                                t->write = true;
                            }

                            break;
                        }

                        if (len > itemlen) {
                            len -= itemlen;
                            ier = (struct btrfs_inode_extref*)&ier->name[ier->name_len];
                        } else
                            break;
                    } while (len > 0);
                }
                break;
            }

            case Batch_DeleteXattr: {
                if (td->size < sizeof(struct btrfs_dir_item)) {
                    ERR("XATTR_ITEM was %u bytes, expected at least %Iu\n", td->size, sizeof(struct btrfs_dir_item));
                    return STATUS_INTERNAL_ERROR;
                } else {
                    struct btrfs_dir_item *di, *deldi;
                    LONG len;

                    deldi = (struct btrfs_dir_item*)bi->data;
                    di = (struct btrfs_dir_item*)td->data;
                    len = td->size;

                    do {
                        if (di->name_len == deldi->name_len && RtlCompareMemory(&di[1], &deldi[1], di->name_len) == di->name_len) {
                            uint16_t newlen = td->size - ((uint16_t)sizeof(struct btrfs_dir_item) + di->name_len + di->data_len);

                            if (newlen == 0)
                                TRACE("deleting XATTR_ITEM\n");
                            else {
                                uint8_t *newdi = ExAllocatePoolWithTag(PagedPool, newlen, ALLOC_TAG), *dioff;
                                tree_data* td2;

                                if (!newdi) {
                                    ERR("out of memory\n");
                                    return STATUS_INSUFFICIENT_RESOURCES;
                                }

                                TRACE("modifying XATTR_ITEM\n");

                                if ((uint8_t*)di > td->data) {
                                    RtlCopyMemory(newdi, td->data, (uint8_t*)di - td->data);
                                    dioff = newdi + ((uint8_t*)di - td->data);
                                } else
                                    dioff = newdi;

                                if ((uint8_t*)&di[1] + di->name_len + di->data_len < td->data + td->size)
                                    RtlCopyMemory(dioff, (uint8_t*)&di[1] + di->name_len + di->data_len, td->size - (((uint8_t*)&di[1] + di->name_len + di->data_len) - td->data));

                                td2 = ExAllocateFromPagedLookasideList(&Vcb->tree_data_lookaside);
                                if (!td2) {
                                    ERR("out of memory\n");
                                    ExFreePool(newdi);
                                    return STATUS_INSUFFICIENT_RESOURCES;
                                }

                                td2->key = bi->key;
                                td2->size = newlen;
                                td2->data = newdi;
                                td2->ignore = false;
                                td2->inserted = true;

                                InsertHeadList(td->list_entry.Blink, &td2->list_entry);

                                t->header.nritems++;
                                t->size += newlen + sizeof(struct btrfs_item);
                                t->write = true;
                            }

                            break;
                        }

                        len -= sizeof(struct btrfs_dir_item) + di->name_len + di->data_len;
                        di = (struct btrfs_dir_item*)((uint8_t*)&di[1] + di->data_len + di->name_len);

                        if (len == 0) {
                            TRACE("could not find DIR_ITEM to delete\n");
                            *ignore = true;
                            return STATUS_SUCCESS;
                        }
                    } while (len > 0);
                }
                break;
            }

            case Batch_Delete:
                break;

            default:
                ERR("unexpected batch operation type\n");
                return STATUS_INTERNAL_ERROR;
        }

        // delete old item
        if (!td->ignore) {
            td->ignore = true;

            t->header.nritems--;
            t->size -= sizeof(struct btrfs_item) + td->size;
            t->write = true;
        }

        if (newtd) {
            newtd->data = bi->data;
            newtd->size = bi->datalen;
            InsertHeadList(td->list_entry.Blink, &newtd->list_entry);
        }
    } else {
        ERR("(%I64x,%x,%I64x) already exists\n", bi->key.objectid, bi->key.type, bi->key.offset);
        return STATUS_INTERNAL_ERROR;
    }

    *ignore = false;
    return STATUS_SUCCESS;
}

__attribute__((nonnull(1,2)))
static NTSTATUS commit_batch_list_root(_Requires_exclusive_lock_held_(_Curr_->tree_lock) device_extension* Vcb, batch_root* br, PIRP Irp) {
    LIST_ENTRY items;
    LIST_ENTRY* le;
    NTSTATUS Status;

    TRACE("root: %I64x\n", br->r->id);

    InitializeListHead(&items);

    // move sub-lists into one big list

    while (!IsListEmpty(&br->items_ind)) {
        batch_item_ind* bii = CONTAINING_RECORD(RemoveHeadList(&br->items_ind), batch_item_ind, list_entry);

        items.Blink->Flink = bii->items.Flink;
        bii->items.Flink->Blink = items.Blink;
        items.Blink = bii->items.Blink;
        bii->items.Blink->Flink = &items;

        ExFreePool(bii);
    }

    le = items.Flink;
    while (le != &items) {
        batch_item* bi = CONTAINING_RECORD(le, batch_item, list_entry);
        LIST_ENTRY* le2;
        traverse_ptr tp;
        struct btrfs_key tree_end;
        bool no_end;
        tree_data *td, *listhead;
        int cmp;
        tree* t;
        bool ignore = false;

        TRACE("(%I64x,%x,%I64x)\n", bi->key.objectid, bi->key.type, bi->key.offset);

        Status = find_item(Vcb, br->r, &tp, &bi->key, true, Irp);
        if (!NT_SUCCESS(Status)) { // FIXME - handle STATUS_NOT_FOUND
            ERR("find_item returned %08lx\n", Status);
            return Status;
        }

        Status = find_tree_end(tp.tree, &tree_end, &no_end);
        if (!NT_SUCCESS(Status)) {
            ERR("find_tree_end returned %08lx\n", Status);
            return Status;
        }

        if (bi->operation == Batch_DeleteInode) {
            if (tp.item->key.objectid == bi->key.objectid) {
                bool ended = false;

                td = tp.item;

                if (!tp.item->ignore) {
                    tp.item->ignore = true;
                    tp.tree->header.nritems--;
                    tp.tree->size -= tp.item->size + sizeof(struct btrfs_item);
                    tp.tree->write = true;
                }

                le2 = tp.item->list_entry.Flink;
                while (le2 != &tp.tree->itemlist) {
                    td = CONTAINING_RECORD(le2, tree_data, list_entry);

                    if (td->key.objectid == bi->key.objectid) {
                        if (!td->ignore) {
                            td->ignore = true;
                            tp.tree->header.nritems--;
                            tp.tree->size -= td->size + sizeof(struct btrfs_item);
                            tp.tree->write = true;
                        }
                    } else {
                        ended = true;
                        break;
                    }

                    le2 = le2->Flink;
                }

                while (!ended) {
                    traverse_ptr next_tp;

                    tp.item = td;

                    if (!find_next_item(Vcb, &tp, &next_tp, false, Irp))
                        break;

                    tp = next_tp;

                    le2 = &tp.item->list_entry;
                    while (le2 != &tp.tree->itemlist) {
                        td = CONTAINING_RECORD(le2, tree_data, list_entry);

                        if (td->key.objectid == bi->key.objectid) {
                            if (!td->ignore) {
                                td->ignore = true;
                                tp.tree->header.nritems--;
                                tp.tree->size -= td->size + sizeof(struct btrfs_item);
                                tp.tree->write = true;
                            }
                        } else {
                            ended = true;
                            break;
                        }

                        le2 = le2->Flink;
                    }
                }
            }
        } else if (bi->operation == Batch_DeleteExtentData) {
            if (tp.item->key.objectid < bi->key.objectid || (tp.item->key.objectid == bi->key.objectid && tp.item->key.type < bi->key.type)) {
                traverse_ptr tp2;

                if (find_next_item(Vcb, &tp, &tp2, false, Irp)) {
                    if (tp2.item->key.objectid == bi->key.objectid && tp2.item->key.type == bi->key.type) {
                        tp = tp2;
                        Status = find_tree_end(tp.tree, &tree_end, &no_end);
                        if (!NT_SUCCESS(Status)) {
                            ERR("find_tree_end returned %08lx\n", Status);
                            return Status;
                        }
                    }
                }
            }

            if (tp.item->key.objectid == bi->key.objectid && tp.item->key.type == bi->key.type) {
                bool ended = false;

                td = tp.item;

                if (!tp.item->ignore) {
                    tp.item->ignore = true;
                    tp.tree->header.nritems--;
                    tp.tree->size -= tp.item->size + sizeof(struct btrfs_item);
                    tp.tree->write = true;
                }

                le2 = tp.item->list_entry.Flink;
                while (le2 != &tp.tree->itemlist) {
                    td = CONTAINING_RECORD(le2, tree_data, list_entry);

                    if (td->key.objectid == bi->key.objectid && td->key.type == bi->key.type) {
                        if (!td->ignore) {
                            td->ignore = true;
                            tp.tree->header.nritems--;
                            tp.tree->size -= td->size + sizeof(struct btrfs_item);
                            tp.tree->write = true;
                        }
                    } else {
                        ended = true;
                        break;
                    }

                    le2 = le2->Flink;
                }

                while (!ended) {
                    traverse_ptr next_tp;

                    tp.item = td;

                    if (!find_next_item(Vcb, &tp, &next_tp, false, Irp))
                        break;

                    tp = next_tp;

                    le2 = &tp.item->list_entry;
                    while (le2 != &tp.tree->itemlist) {
                        td = CONTAINING_RECORD(le2, tree_data, list_entry);

                        if (td->key.objectid == bi->key.objectid && td->key.type == bi->key.type) {
                            if (!td->ignore) {
                                td->ignore = true;
                                tp.tree->header.nritems--;
                                tp.tree->size -= td->size + sizeof(struct btrfs_item);
                                tp.tree->write = true;
                            }
                        } else {
                            ended = true;
                            break;
                        }

                        le2 = le2->Flink;
                    }
                }
            }
        } else if (bi->operation == Batch_DeleteFreeSpace) {
            if (tp.item->key.objectid >= bi->key.objectid && tp.item->key.objectid < bi->key.objectid + bi->key.offset) {
                bool ended = false;

                td = tp.item;

                if (!tp.item->ignore) {
                    tp.item->ignore = true;
                    tp.tree->header.nritems--;
                    tp.tree->size -= tp.item->size + sizeof(struct btrfs_item);
                    tp.tree->write = true;
                }

                le2 = tp.item->list_entry.Flink;
                while (le2 != &tp.tree->itemlist) {
                    td = CONTAINING_RECORD(le2, tree_data, list_entry);

                    if (td->key.objectid >= bi->key.objectid && td->key.objectid < bi->key.objectid + bi->key.offset) {
                        if (!td->ignore) {
                            td->ignore = true;
                            tp.tree->header.nritems--;
                            tp.tree->size -= td->size + sizeof(struct btrfs_item);
                            tp.tree->write = true;
                        }
                    } else {
                        ended = true;
                        break;
                    }

                    le2 = le2->Flink;
                }

                while (!ended) {
                    traverse_ptr next_tp;

                    tp.item = td;

                    if (!find_next_item(Vcb, &tp, &next_tp, false, Irp))
                        break;

                    tp = next_tp;

                    le2 = &tp.item->list_entry;
                    while (le2 != &tp.tree->itemlist) {
                        td = CONTAINING_RECORD(le2, tree_data, list_entry);

                        if (td->key.objectid >= bi->key.objectid && td->key.objectid < bi->key.objectid + bi->key.offset) {
                            if (!td->ignore) {
                                td->ignore = true;
                                tp.tree->header.nritems--;
                                tp.tree->size -= td->size + sizeof(struct btrfs_item);
                                tp.tree->write = true;
                            }
                        } else {
                            ended = true;
                            break;
                        }

                        le2 = le2->Flink;
                    }
                }
            }
        } else {
            if (bi->operation == Batch_Delete || bi->operation == Batch_DeleteDirItem || bi->operation == Batch_DeleteInodeRef ||
                bi->operation == Batch_DeleteInodeExtRef || bi->operation == Batch_DeleteXattr)
                td = NULL;
            else {
                td = ExAllocateFromPagedLookasideList(&Vcb->tree_data_lookaside);
                if (!td) {
                    ERR("out of memory\n");
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                td->key = bi->key;
                td->size = bi->datalen;
                td->data = bi->data;
                td->ignore = false;
                td->inserted = true;
            }

            cmp = keycmp(bi->key, tp.item->key);

            if (cmp == -1) { // very first key in root
                if (td) {
                    tree_data* paritem;

                    InsertHeadList(&tp.tree->itemlist, &td->list_entry);

                    paritem = tp.tree->paritem;
                    while (paritem) {
                        if (!keycmp(paritem->key, tp.item->key)) {
                            paritem->key = bi->key;
                        } else
                            break;

                        paritem = paritem->treeholder.tree->paritem;
                    }
                }
            } else if (cmp == 0) { // item already exists
                if (tp.item->ignore) {
                    if (td)
                        InsertHeadList(tp.item->list_entry.Blink, &td->list_entry);
                } else {
                    Status = handle_batch_collision(Vcb, bi, tp.tree, tp.item, td, &items, &ignore);
                    if (!NT_SUCCESS(Status)) {
                        ERR("handle_batch_collision returned %08lx\n", Status);
#ifdef _DEBUG
                        int3;
#endif

                        if (td)
                            ExFreeToPagedLookasideList(&Vcb->tree_data_lookaside, td);

                        return Status;
                    }
                }
            } else if (td) {
                InsertHeadList(&tp.item->list_entry, &td->list_entry);
            }

            if (bi->operation == Batch_DeleteInodeRef && cmp != 0 && Vcb->superblock.incompat_flags & BTRFS_FEATURE_INCOMPAT_EXTENDED_IREF) {
                Status = add_delete_inode_extref(Vcb, bi, &items);
                if (!NT_SUCCESS(Status)) {
                    ERR("add_delete_inode_extref returned %08lx\n", Status);
                    return Status;
                }
            }

            if (!ignore && td) {
                tp.tree->header.nritems++;
                tp.tree->size += bi->datalen + sizeof(struct btrfs_item);
                tp.tree->write = true;

                listhead = td;
            } else
                listhead = tp.item;

            while (listhead->list_entry.Blink != &tp.tree->itemlist) {
                tree_data* prevtd = CONTAINING_RECORD(listhead->list_entry.Blink, tree_data, list_entry);

                if (!keycmp(prevtd->key, listhead->key))
                    listhead = prevtd;
                else
                    break;
            }

            le2 = le->Flink;
            while (le2 != &items) {
                batch_item* bi2 = CONTAINING_RECORD(le2, batch_item, list_entry);

                if (bi2->operation == Batch_DeleteInode || bi2->operation == Batch_DeleteExtentData || bi2->operation == Batch_DeleteFreeSpace)
                    break;

                if (no_end || keycmp(bi2->key, tree_end) == -1) {
                    LIST_ENTRY* le3;
                    bool inserted = false;

                    ignore = false;

                    if (bi2->operation == Batch_Delete || bi2->operation == Batch_DeleteDirItem || bi2->operation == Batch_DeleteInodeRef ||
                        bi2->operation == Batch_DeleteInodeExtRef || bi2->operation == Batch_DeleteXattr)
                        td = NULL;
                    else {
                        td = ExAllocateFromPagedLookasideList(&Vcb->tree_data_lookaside);
                        if (!td) {
                            ERR("out of memory\n");
                            return STATUS_INSUFFICIENT_RESOURCES;
                        }

                        td->key = bi2->key;
                        td->size = bi2->datalen;
                        td->data = bi2->data;
                        td->ignore = false;
                        td->inserted = true;
                    }

                    le3 = &listhead->list_entry;
                    while (le3 != &tp.tree->itemlist) {
                        tree_data* td2 = CONTAINING_RECORD(le3, tree_data, list_entry);

                        cmp = keycmp(bi2->key, td2->key);

                        if (cmp == 0) {
                            if (td2->ignore) {
                                if (td) {
                                    InsertHeadList(le3->Blink, &td->list_entry);
                                    inserted = true;
                                } else if (bi2->operation == Batch_DeleteInodeRef && Vcb->superblock.incompat_flags & BTRFS_FEATURE_INCOMPAT_EXTENDED_IREF) {
                                    Status = add_delete_inode_extref(Vcb, bi2, &items);
                                    if (!NT_SUCCESS(Status)) {
                                        ERR("add_delete_inode_extref returned %08lx\n", Status);
                                        return Status;
                                    }
                                }
                            } else {
                                Status = handle_batch_collision(Vcb, bi2, tp.tree, td2, td, &items, &ignore);
                                if (!NT_SUCCESS(Status)) {
                                    ERR("handle_batch_collision returned %08lx\n", Status);
#ifdef _DEBUG
                                    int3;
#endif
                                    return Status;
                                }
                            }

                            inserted = true;
                            break;
                        } else if (cmp == -1) {
                            if (td) {
                                InsertHeadList(le3->Blink, &td->list_entry);
                                inserted = true;
                            } else if (bi2->operation == Batch_DeleteInodeRef && Vcb->superblock.incompat_flags & BTRFS_FEATURE_INCOMPAT_EXTENDED_IREF) {
                                Status = add_delete_inode_extref(Vcb, bi2, &items);
                                if (!NT_SUCCESS(Status)) {
                                    ERR("add_delete_inode_extref returned %08lx\n", Status);
                                    return Status;
                                }
                            }
                            break;
                        }

                        le3 = le3->Flink;
                    }

                    if (td) {
                        if (!inserted)
                            InsertTailList(&tp.tree->itemlist, &td->list_entry);

                        if (!ignore) {
                            tp.tree->header.nritems++;
                            tp.tree->size += bi2->datalen + sizeof(struct btrfs_item);

                            listhead = td;
                        }
                    } else if (!inserted && bi2->operation == Batch_DeleteInodeRef && Vcb->superblock.incompat_flags & BTRFS_FEATURE_INCOMPAT_EXTENDED_IREF) {
                        Status = add_delete_inode_extref(Vcb, bi2, &items);
                        if (!NT_SUCCESS(Status)) {
                            ERR("add_delete_inode_extref returned %08lx\n", Status);
                            return Status;
                        }
                    }

                    while (listhead->list_entry.Blink != &tp.tree->itemlist) {
                        tree_data* prevtd = CONTAINING_RECORD(listhead->list_entry.Blink, tree_data, list_entry);

                        if (!keycmp(prevtd->key, listhead->key))
                            listhead = prevtd;
                        else
                            break;
                    }

                    le = le2;
                } else
                    break;

                le2 = le2->Flink;
            }

            t = tp.tree;
            while (t) {
                if (t->paritem && t->paritem->ignore) {
                    t->paritem->ignore = false;
                    t->parent->header.nritems++;
                    t->parent->size += sizeof(struct btrfs_key_ptr);
                }

                t->header.generation = Vcb->superblock.generation;
                t = t->parent;
            }
        }

        le = le->Flink;
    }

    // FIXME - remove as we are going along
    while (!IsListEmpty(&items)) {
        batch_item* bi = CONTAINING_RECORD(RemoveHeadList(&items), batch_item, list_entry);

        if ((bi->operation == Batch_DeleteDirItem || bi->operation == Batch_DeleteInodeRef ||
            bi->operation == Batch_DeleteInodeExtRef || bi->operation == Batch_DeleteXattr) && bi->data)
            ExFreePool(bi->data);

        ExFreeToPagedLookasideList(&Vcb->batch_item_lookaside, bi);
    }

    return STATUS_SUCCESS;
}

__attribute__((nonnull(1,2)))
NTSTATUS commit_batch_list(_Requires_exclusive_lock_held_(_Curr_->tree_lock) device_extension* Vcb, LIST_ENTRY* batchlist, PIRP Irp) {
    NTSTATUS Status;

    while (!IsListEmpty(batchlist)) {
        LIST_ENTRY* le = RemoveHeadList(batchlist);
        batch_root* br2 = CONTAINING_RECORD(le, batch_root, list_entry);

        Status = commit_batch_list_root(Vcb, br2, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("commit_batch_list_root returned %08lx\n", Status);
            return Status;
        }

        ExFreePool(br2);
    }

    return STATUS_SUCCESS;
}
