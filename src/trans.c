#include "btrfs_drv.h"

tIoGetTransactionParameterBlock fIoGetTransactionParameterBlock;
tNtCreateTransactionManager fNtCreateTransactionManager;
tNtCreateResourceManager fNtCreateResourceManager;
tTmCreateEnlistment fTmCreateEnlistment;
tTmEnableCallbacks fTmEnableCallbacks;

typedef struct _trans_ref {
    LIST_ENTRY list_entry;
    void* trans_object;
    LONG refcount;
    HANDLE enlistment;
    PKENLISTMENT enlistment_object;
    bool finished;
    ERESOURCE lock;
    LIST_ENTRY old_dir_children;
    LIST_ENTRY filerefs;
} trans_ref;

static NTSTATUS trans_commit(device_extension* Vcb, trans_ref* trans) {
    bool skip_lock;
    LIST_ENTRY rollback;

    TRACE("(%p, %p)\n", Vcb, trans);

    InitializeListHead(&rollback);

    skip_lock = ExIsResourceAcquiredExclusiveLite(&Vcb->tree_lock);

    if (!skip_lock)
        ExAcquireResourceSharedLite(&Vcb->tree_lock, true);

    ExAcquireResourceExclusiveLite(&Vcb->fileref_lock, true);

    ExAcquireResourceExclusiveLite(&trans->lock, true);

    // remove old dir_children and mark fcbs as orphaned

    while (!IsListEmpty(&trans->old_dir_children)) {
        dir_child* dc = CONTAINING_RECORD(RemoveHeadList(&trans->old_dir_children), dir_child, list_entry_trans);
        NTSTATUS Status;

        RemoveEntryList(&dc->list_entry_index);
        remove_dir_child_from_hash_lists(get_dcb(dc->fileref->parent->fcb), dc);

        ExAcquireResourceExclusiveLite(dc->fileref->fcb->Header.Resource, true);

        dc->fileref->fcb->inode_item.st_nlink = 0;
        dc->fileref->fcb->inode_item_changed = true;
        dc->fileref->fcb->deleted = true;

        // FIXME - should be doing POSIX-style deletion?

        if (dc->fileref->fcb->type != BTRFS_TYPE_DIRECTORY && dc->fileref->fcb->inode_item.st_size > 0) {
            Status = excise_extents(Vcb, dc->fileref->fcb, 0, sector_align(dc->fileref->fcb->inode_item.st_size, dc->fileref->fcb->Vcb->superblock.sector_size),
                                    NULL, &rollback);
            if (!NT_SUCCESS(Status))
                ERR("excise_extents returned %08lx\n", Status);
        }

        dc->fileref->fcb->Header.AllocationSize.QuadPart = 0;
        dc->fileref->fcb->Header.FileSize.QuadPart = 0;
        dc->fileref->fcb->Header.ValidDataLength.QuadPart = 0;

        ExReleaseResourceLite(dc->fileref->fcb->Header.Resource);

        mark_fcb_dirty(dc->fileref->fcb);

        dc->fileref->deleted = true;
        mark_fileref_dirty(dc->fileref);

        dc->fileref->oldindex = dc->index;

        if (!dc->fileref->oldutf8.Buffer)
            dc->fileref->oldutf8 = dc->utf8;
        else
            ExFreePool(dc->utf8.Buffer);

        ExFreePool(dc->name.Buffer);
        ExFreePool(dc->name_uc.Buffer);

        dc->fileref->dc = NULL;
        ExFreePool(dc);
    }

    // loop through fileref list

    while (!IsListEmpty(&trans->filerefs)) {
        file_ref* fr = CONTAINING_RECORD(RemoveHeadList(&trans->filerefs), file_ref, list_entry_trans);

        if (fr->dc) {
            fr->dc->trans = NULL;

            if (fr->dc->key.obj_type == TYPE_INODE_ITEM)
                fr->dc->key.obj_id = fr->fcb->inode;

            fr->dc->non_trans_dc = NULL;

            if (fr->created) {
                fcb* parfcb = &(get_dcb(fr->parent->fcb)->fcb);

                ExAcquireResourceExclusiveLite(parfcb->Header.Resource, true);
                parfcb->inode_item.st_size += (uint64_t)fr->dc->utf8.Length * 2;
                parfcb->inode_item.sequence++;
                parfcb->inode_item_changed = true;
                ExReleaseResourceLite(parfcb->Header.Resource);

                // FIXME - update parent st_ctime? To now, or when operation performed?

                mark_fcb_dirty(parfcb);
            } else if (fr->oldutf8.Buffer) { // renamed
                fcb* parfcb = &(get_dcb(fr->parent->fcb)->fcb);

                ExAcquireResourceExclusiveLite(parfcb->Header.Resource, true);
                get_dcb(parfcb)->fcb.inode_item.st_size = parfcb->inode_item.st_size + (2 * (uint64_t)fr->dc->utf8.Length) - (2 * (uint64_t)fr->oldutf8.Length);
                parfcb->inode_item.sequence++;
                parfcb->inode_item_changed = true;
                ExReleaseResourceLite(parfcb->Header.Resource);

                mark_fcb_dirty(parfcb);
            }
        } else if (fr->deleted && fr->oldutf8.Buffer) {
            fcb* parfcb = &(get_dcb(fr->parent->fcb)->fcb);

            ExAcquireResourceExclusiveLite(parfcb->Header.Resource, true);
            parfcb->inode_item.st_size -= (uint64_t)fr->oldutf8.Length * 2;
            parfcb->inode_item.sequence++;
            parfcb->inode_item_changed = true;
            ExReleaseResourceLite(parfcb->Header.Resource);

            // FIXME - update parent st_ctime? To now, or when operation performed?

            mark_fcb_dirty(parfcb);
        }

        if (!fr->fcb->ads && fr->fcb->type == BTRFS_TYPE_DIRECTORY) {
            struct _dcb* dcb = (struct _dcb*)fr->fcb;

            if (dcb->real_dcb) { // swap inode numbers if committing forked directory
                uint32_t hash;
                uint64_t inode;
                bool fcb_created;
                LIST_ENTRY* le;

                inode = dcb->real_dcb->fcb.inode;
                hash = dcb->real_dcb->fcb.hash;
                fcb_created = dcb->real_dcb->fcb.created;

                ExAcquireResourceExclusiveLite(&Vcb->fcb_lock, true);

                remove_fcb_from_subvol(&dcb->real_dcb->fcb);
                remove_fcb_from_subvol(fr->fcb);

                dcb->real_dcb->fcb.hash = fr->fcb->hash;
                dcb->real_dcb->fcb.inode = fr->fcb->inode;
                fr->fcb->inode = inode;
                fr->fcb->hash = hash;

                add_fcb_to_subvol(&dcb->real_dcb->fcb);
                add_fcb_to_subvol(fr->fcb);

                fr->fcb->subvol->fcbs_version++;

                ExReleaseResourceLite(&Vcb->fcb_lock);

                dcb->real_dcb->fcb.created = fr->fcb->created;
                fr->fcb->created = fr->created = fcb_created;

                fr->fcb->inode_item.st_size = dcb->real_dcb->fcb.inode_item.st_size;
                fr->fcb->inode_item_changed = true;
                dcb->real_dcb->fcb.inode_item.st_size = 0;

                if (dcb->real_dcb->fcb.fileref) {
                    dcb->real_dcb->fcb.fileref->created = true;
                    dcb->real_dcb->fcb.fileref->deleted = true;
                }

                if (fr->dc && fr->dc->key.obj_type == TYPE_INODE_ITEM)
                    fr->dc->key.obj_id = inode;

                dcb->dir_children_index.Flink = dcb->real_dcb->dir_children_index.Flink;
                dcb->dir_children_index.Flink->Blink = &dcb->dir_children_index;
                dcb->dir_children_index.Blink = dcb->real_dcb->dir_children_index.Blink;
                dcb->dir_children_index.Blink->Flink = &dcb->dir_children_index;

                dcb->dir_children_hash.Flink = dcb->real_dcb->dir_children_hash.Flink;
                dcb->dir_children_hash.Flink->Blink = &dcb->dir_children_hash;
                dcb->dir_children_hash.Blink = dcb->real_dcb->dir_children_hash.Blink;
                dcb->dir_children_hash.Blink->Flink = &dcb->dir_children_hash;

                dcb->dir_children_hash_uc.Flink = dcb->real_dcb->dir_children_hash_uc.Flink;
                dcb->dir_children_hash_uc.Flink->Blink = &dcb->dir_children_hash_uc;
                dcb->dir_children_hash_uc.Blink = dcb->real_dcb->dir_children_hash_uc.Blink;
                dcb->dir_children_hash_uc.Blink->Flink = &dcb->dir_children_hash_uc;

                RtlCopyMemory(dcb->hash_ptrs, dcb->real_dcb->hash_ptrs, sizeof(dcb->hash_ptrs));
                RtlCopyMemory(dcb->hash_ptrs_uc, dcb->real_dcb->hash_ptrs_uc, sizeof(dcb->hash_ptrs_uc));
                RtlZeroMemory(dcb->real_dcb->hash_ptrs, sizeof(dcb->real_dcb->hash_ptrs));
                RtlZeroMemory(dcb->real_dcb->hash_ptrs_uc, sizeof(dcb->real_dcb->hash_ptrs_uc));

                InitializeListHead(&dcb->real_dcb->dir_children_index);
                InitializeListHead(&dcb->real_dcb->dir_children_hash);
                InitializeListHead(&dcb->real_dcb->dir_children_hash_uc);

                le = dcb->dir_children_index.Flink;
                while (le != &dcb->dir_children_index) {
                    dir_child* dc = CONTAINING_RECORD(le, dir_child, list_entry_index);

                    if (dc->fileref) {
                        free_fileref(dc->fileref->parent);
                        dc->fileref->parent = fr;
                        increase_fileref_refcount(fr);
                    }

                    le = le->Flink;
                }

                free_fcb((fcb*)dcb->real_dcb);
                dcb->real_dcb = NULL;
            } else
                fr->created = true;
        } else {
            fr->created = true;
            fr->fcb->marked_as_orphan = true;
        }

        fr->trans = NULL;

        fr->fcb->transacted = false;
        fr->fcb->inode_item_changed = true;

        mark_fcb_dirty(fr->fcb);

        mark_fileref_dirty(fr);
    }

    ExReleaseResourceLite(&trans->lock);

    ExReleaseResourceLite(&Vcb->fileref_lock);

    Vcb->need_write = true;

    if (!skip_lock)
        ExReleaseResourceLite(&Vcb->tree_lock);

    clear_rollback(&rollback);

    return STATUS_SUCCESS;
}

static NTSTATUS trans_rollback(device_extension* Vcb, trans_ref* trans) {
    bool skip_lock;

    TRACE("(%p, %p)\n", Vcb, trans);

    skip_lock = ExIsResourceAcquiredExclusiveLite(&Vcb->tree_lock);

    if (!skip_lock)
        ExAcquireResourceSharedLite(&Vcb->tree_lock, true);

    ExAcquireResourceExclusiveLite(&Vcb->fileref_lock, true);

    ExAcquireResourceExclusiveLite(&trans->lock, true);

    // mark old dir_children as not forked, and remove from list

    while (!IsListEmpty(&trans->old_dir_children)) {
        dir_child* dc = CONTAINING_RECORD(RemoveHeadList(&trans->old_dir_children), dir_child, list_entry_trans);

        if (dc->fileref && !dc->fileref->fcb->ads && dc->fileref->fcb->type == BTRFS_TYPE_DIRECTORY) {
            struct _dcb* dcb = (struct _dcb*)dc->fileref->fcb;
            LIST_ENTRY* le;

            le = dcb->dir_children_index.Flink;
            while (le != &dcb->dir_children_index) {
                dir_child* dc2 = CONTAINING_RECORD(le, dir_child, list_entry_index);

                if (dc2->fileref && dc2->fileref->parent != dc->fileref) {
                    increase_fileref_refcount(dc->fileref);
                    free_fileref(dc2->fileref->parent);
                    dc2->fileref->parent = dc->fileref;
                }

                le = le->Flink;
            }
        }

        dc->forked = false;
    }

    // loop through fileref list

    while (!IsListEmpty(&trans->filerefs)) {
        file_ref* fr = CONTAINING_RECORD(RemoveHeadList(&trans->filerefs), file_ref, list_entry_trans);

        if (fr->dc) { // delete dir_child
            RemoveEntryList(&fr->dc->list_entry_index);
            remove_dir_child_from_hash_lists(get_dcb(fr->parent->fcb), fr->dc);

            ExFreePool(fr->dc->utf8.Buffer);
            ExFreePool(fr->dc->name.Buffer);
            ExFreePool(fr->dc->name_uc.Buffer);
            ExFreePool(fr->dc);

            fr->dc = NULL;
        }

        fr->fcb->deleted = true;

        if (fr->fcb->type != BTRFS_TYPE_DIRECTORY && fr->fcb->inode_item.st_size > 0) {
            NTSTATUS Status;
            LIST_ENTRY rollback;

            InitializeListHead(&rollback);

            Status = excise_extents(Vcb, fr->fcb, 0, sector_align(fr->fcb->inode_item.st_size, fr->fcb->Vcb->superblock.sector_size),
                                    NULL, &rollback);
            if (!NT_SUCCESS(Status))
                ERR("excise_extents returned %08lx\n", Status);

            clear_rollback(&rollback);
        }

        if (!fr->fcb->ads && fr->fcb->type == BTRFS_TYPE_DIRECTORY) {
            struct _dcb* dcb = (struct _dcb*)fr->fcb;

            if (dcb->real_dcb) {
                free_fcb(&dcb->real_dcb->fcb);
                dcb->real_dcb = NULL;
            }
        }

        mark_fcb_dirty(fr->fcb);

        fr->created = true;
        fr->deleted = true;
        fr->trans = NULL;
        fr->fcb->transacted = false;
    }

    ExReleaseResourceLite(&trans->lock);

    // FIXME - make sure trans->refcount decreased correctly

    ExReleaseResourceLite(&Vcb->fileref_lock);

    if (!skip_lock)
        ExReleaseResourceLite(&Vcb->tree_lock);

    return STATUS_SUCCESS;
}

static NTSTATUS rm_notification(PKENLISTMENT EnlistmentObject, PVOID RMContext, PVOID TransactionContext,
                                ULONG TransactionNotification, PLARGE_INTEGER TmVirtualClock, ULONG ArgumentLength,
                                PVOID Argument) {
    NTSTATUS Status;
    device_extension* Vcb = RMContext;
    KIRQL irql;
    LIST_ENTRY* le;
    trans_ref* tr = NULL;
    bool already_finished = false;

    UNUSED(TransactionContext);
    UNUSED(TmVirtualClock);
    UNUSED(ArgumentLength);
    UNUSED(Argument);

    KeAcquireSpinLock(&Vcb->trans_list_lock, &irql);

    le = Vcb->trans_list.Flink;
    while (le != &Vcb->trans_list) {
        trans_ref* tr2 = CONTAINING_RECORD(le, trans_ref, list_entry);

        if (tr2->enlistment_object == EnlistmentObject) {
            InterlockedIncrement(&tr2->refcount);
            tr = tr2;
            break;
        }

        le = le->Flink;
    }

    if (tr && (TransactionNotification == TRANSACTION_NOTIFY_COMMIT || TransactionNotification == TRANSACTION_NOTIFY_ROLLBACK)) {
        if (tr->finished)
            already_finished = true;

        tr->finished = true;
    }

    KeReleaseSpinLock(&Vcb->trans_list_lock, irql);

    if (!tr) {
        TRACE("rm_notification message for unrecognized transaction\n");
        return STATUS_SUCCESS;
    }

    if (already_finished) {
        TRACE("ignoring rm_notification message for finished transaction\n");
        free_trans(Vcb, tr);
        return STATUS_SUCCESS;
    }

    switch (TransactionNotification) {
        case TRANSACTION_NOTIFY_COMMIT:
            Status = trans_commit(Vcb, tr);
        break;

        case TRANSACTION_NOTIFY_ROLLBACK:
            Status = trans_rollback(Vcb, tr);
        break;

        default:
            WARN("unhandle rm_notification message %lx\n", TransactionNotification);
            Status = STATUS_SUCCESS;
    }

    free_trans(Vcb, tr);

    return Status;
}

NTSTATUS init_trans_man(device_extension* Vcb) {
    NTSTATUS Status;
    OBJECT_ATTRIBUTES oa;
    UUID rm_uuid;

    if (!fNtCreateTransactionManager)
        return STATUS_SUCCESS;

    memset(&oa, 0, sizeof(OBJECT_ATTRIBUTES));
    oa.Length = sizeof(OBJECT_ATTRIBUTES);
    oa.Attributes = OBJ_KERNEL_HANDLE;

    Status = fNtCreateTransactionManager(&Vcb->tm_handle, TRANSACTIONMANAGER_CREATE_RM, &oa,
                                         NULL, TRANSACTION_MANAGER_VOLATILE, 0);
    if (!NT_SUCCESS(Status)) {
        ERR("NtCreateTransactionManager returned %08lx\n", Status);
        return Status;
    }

    Status = ExUuidCreate(&rm_uuid);
    if (!NT_SUCCESS(Status)) {
        ERR("ExUuidCreate returned %08lx\n", Status);
        NtClose(Vcb->tm_handle);
        return Status;
    }

    // MSDN says that RmGuid is an optional parameter, but we get a BSOD if it's NULL!

    Status = fNtCreateResourceManager(&Vcb->rm_handle, RESOURCEMANAGER_ENLIST | RESOURCEMANAGER_GET_NOTIFICATION,
                                      Vcb->tm_handle, &rm_uuid, &oa, RESOURCE_MANAGER_VOLATILE, NULL);
    if (!NT_SUCCESS(Status)) {
        ERR("NtCreateResourceManager returned %08lx\n", Status);
        NtClose(Vcb->tm_handle);
        return Status;
    }

    Status = ObReferenceObjectByHandle(Vcb->rm_handle, RESOURCEMANAGER_ENLIST, NULL, KernelMode,
                                       (void**)&Vcb->rm, NULL);
    if (!NT_SUCCESS(Status)) {
        ERR("ObReferenceObjectByHandle returned %08lx\n", Status);
        NtClose(Vcb->rm_handle);
        NtClose(Vcb->tm_handle);
        return Status;
    }

    Status = fTmEnableCallbacks(Vcb->rm, rm_notification, Vcb);
    if (!NT_SUCCESS(Status)) {
        ERR("TmEnableCallbacks returned %08lx\n", Status);
        ObDereferenceObject(Vcb->rm);
        NtClose(Vcb->rm_handle);
        NtClose(Vcb->tm_handle);
        return Status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS get_trans(device_extension* Vcb, PTXN_PARAMETER_BLOCK block, trans_ref** t) {
    NTSTATUS Status;
    KIRQL irql;
    LIST_ENTRY* le;
    trans_ref* new_tr;
    OBJECT_ATTRIBUTES oa;

    if (block->Length < sizeof(TXN_PARAMETER_BLOCK))
        return STATUS_INVALID_PARAMETER;

    if (block->TxFsContext != TXF_MINIVERSION_DEFAULT_VIEW)
        return STATUS_INVALID_PARAMETER;

    KeAcquireSpinLock(&Vcb->trans_list_lock, &irql);

    le = Vcb->trans_list.Flink;
    while (le != &Vcb->trans_list) {
        trans_ref* tr = CONTAINING_RECORD(le, trans_ref, list_entry);

        if (tr->trans_object == block->TransactionObject) {
            if (tr->finished) {
                KeReleaseSpinLock(&Vcb->trans_list_lock, irql);
                return STATUS_TRANSACTION_NOT_ACTIVE;
            }

            InterlockedIncrement(&tr->refcount);
            KeReleaseSpinLock(&Vcb->trans_list_lock, irql);

            *t = tr;

            return STATUS_SUCCESS;
        }

        le = le->Flink;
    }

    KeReleaseSpinLock(&Vcb->trans_list_lock, irql);

    new_tr = ExAllocatePoolWithTag(NonPagedPool, sizeof(trans_ref), ALLOC_TAG);
    if (!new_tr) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ObReferenceObject(block->TransactionObject);
    new_tr->trans_object = block->TransactionObject;
    new_tr->refcount = 1;
    new_tr->enlistment = NULL;
    new_tr->enlistment_object = NULL;
    new_tr->finished = false;

    InitializeListHead(&new_tr->old_dir_children);
    InitializeListHead(&new_tr->filerefs);
    ExInitializeResourceLite(&new_tr->lock);

    TRACE("created new transaction\n");

    memset(&oa, 0, sizeof(OBJECT_ATTRIBUTES));
    oa.Length = sizeof(OBJECT_ATTRIBUTES);
    oa.Attributes = OBJ_KERNEL_HANDLE;

    Status = fTmCreateEnlistment(&new_tr->enlistment, KernelMode, 0, &oa, Vcb->rm, new_tr->trans_object,
                                 0, TRANSACTION_NOTIFY_COMMIT | TRANSACTION_NOTIFY_ROLLBACK, new_tr);

    if (!NT_SUCCESS(Status)) {
        ERR("TmCreateEnlistment returned %08lx\n", Status);
        ObDereferenceObject(block->TransactionObject);
        ExDeleteResourceLite(&new_tr->lock);
        ExFreePool(new_tr);
        return Status;
    }

    Status = ObReferenceObjectByHandle(new_tr->enlistment, 0, NULL, KernelMode,
                                       (void**)&new_tr->enlistment_object, NULL);
    if (!NT_SUCCESS(Status)) {
        ERR("ObReferenceObjectByHandle returned %08lx\n", Status);
        NtClose(new_tr->enlistment);
        ObDereferenceObject(block->TransactionObject);
        ExDeleteResourceLite(&new_tr->lock);
        ExFreePool(new_tr);
        return Status;
    }

    // open handle guarantees refcount > 0
    ObDereferenceObject(new_tr->enlistment_object);

    KeAcquireSpinLock(&Vcb->trans_list_lock, &irql);

    le = Vcb->trans_list.Flink;
    while (le != &Vcb->trans_list) {
        trans_ref* tr = CONTAINING_RECORD(le, trans_ref, list_entry);

        if (tr->trans_object == block->TransactionObject) { // already created
            if (tr->finished) {
                KeReleaseSpinLock(&Vcb->trans_list_lock, irql);

                NtClose(new_tr->enlistment);
                ObDereferenceObject(block->TransactionObject);
                ExDeleteResourceLite(&new_tr->lock);
                ExFreePool(new_tr);

                return STATUS_TRANSACTION_NOT_ACTIVE;
            }

            InterlockedIncrement(&tr->refcount);
            KeReleaseSpinLock(&Vcb->trans_list_lock, irql);

            NtClose(new_tr->enlistment);
            ObDereferenceObject(block->TransactionObject);
            ExFreePool(new_tr);
            ExDeleteResourceLite(&new_tr->lock);

            *t = tr;

            return STATUS_SUCCESS;
        }

        le = le->Flink;
    }

    InsertTailList(&Vcb->trans_list, &new_tr->list_entry);

    KeReleaseSpinLock(&Vcb->trans_list_lock, irql);

    *t = new_tr;

    return STATUS_SUCCESS;
}

void free_trans(_In_ device_extension* Vcb, _In_ trans_ref* t) {
    KIRQL irql;

    KeAcquireSpinLock(&Vcb->trans_list_lock, &irql);

    if (InterlockedDecrement(&t->refcount) > 0) {
        KeReleaseSpinLock(&Vcb->trans_list_lock, irql);
        return;
    }

    RemoveEntryList(&t->list_entry);

    KeReleaseSpinLock(&Vcb->trans_list_lock, irql);

    if (t->enlistment)
        NtClose(t->enlistment);

    ObDereferenceObject(t->trans_object);
    ExDeleteResourceLite(&t->lock);
    ExFreePool(t);
}

void mark_dc_forked(dir_child* dc, trans_ref* trans) {
    dc->forked = true;

    ExAcquireResourceExclusiveLite(&trans->lock, true);
    InsertTailList(&trans->old_dir_children, &dc->list_entry_trans);
    ExReleaseResourceLite(&trans->lock);
}

void add_fileref_to_trans(file_ref* fr, trans_ref* trans) {
    ExAcquireResourceExclusiveLite(&trans->lock, true);
    InsertTailList(&trans->filerefs, &fr->list_entry_trans);
    ExReleaseResourceLite(&trans->lock);
}

NTSTATUS get_transacted_version(PFILE_OBJECT FileObject, TXFS_GET_TRANSACTED_VERSION* buf, ULONG buflen, ULONG_PTR* retlen) {
    ccb* ccb;
    file_ref* fileref;

    TRACE("(%p, %p, %lu, %p)\n", FileObject, buf, buflen, retlen);

    if (buflen < sizeof(TXFS_GET_TRANSACTED_VERSION))
        return STATUS_INVALID_PARAMETER;

    ccb = FileObject->FsContext2;

    if (!ccb)
        return STATUS_INVALID_PARAMETER;

    fileref = ccb->fileref;

    buf->ThisBaseVersion = fileref->trans ? TXFS_TRANSACTED_VERSION_UNCOMMITTED : TXFS_TRANSACTED_VERSION_NONTRANSACTED;
    buf->LatestVersion = 0; // FIXME?
    buf->ThisMiniVersion = 0;
    buf->FirstMiniVersion = 0;
    buf->LatestMiniVersion = 0;

    *retlen = sizeof(TXFS_GET_TRANSACTED_VERSION);

    return STATUS_SUCCESS;
}
