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
} trans_ref;

static NTSTATUS trans_commit(device_extension* Vcb, trans_ref* trans) {
    FIXME("(%p, %p)\n", Vcb, trans);

    // FIXME

    return STATUS_SUCCESS;
}

static NTSTATUS trans_rollback(device_extension* Vcb, trans_ref* trans) {
    FIXME("(%p, %p)\n", Vcb, trans);

    ExAcquireResourceExclusiveLite(&trans->lock, true);

    // mark old dir_children as not forked, and remove from list

    while (!IsListEmpty(&trans->old_dir_children)) {
        dir_child* dc = CONTAINING_RECORD(RemoveHeadList(&trans->old_dir_children), dir_child, list_entry_trans);

        dc->forked = false;
    }

    ExReleaseResourceLite(&trans->lock);

    // FIXME - loop through fileref list
    // FIXME - for new filerefs, delete dir_children and clear trans
    // FIXME - for new filerefs, clear fcb->trans

    // FIXME - make sure trans->refcount decreased correctly

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

void free_trans(device_extension* Vcb, trans_ref* t) {
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
