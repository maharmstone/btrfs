#include "btrfs_drv.h"

tIoGetTransactionParameterBlock fIoGetTransactionParameterBlock;
tNtCreateTransactionManager fNtCreateTransactionManager;
tNtCreateResourceManager fNtCreateResourceManager;
tTmCreateEnlistment fTmCreateEnlistment;

typedef struct _trans_ref {
    LIST_ENTRY list_entry;
    void* trans_object;
    LONG refcount;
    ERESOURCE lock;
    HANDLE enlistment;
} trans_ref;

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
        return Status;
    }

    // MSDN says that RmGuid is an optional parameter, but we get a BSOD if it's NULL!

    Status = fNtCreateResourceManager(&Vcb->rm_handle, RESOURCEMANAGER_ENLIST | RESOURCEMANAGER_GET_NOTIFICATION,
                                      Vcb->tm_handle, &rm_uuid, &oa, RESOURCE_MANAGER_VOLATILE, NULL);
    if (!NT_SUCCESS(Status)) {
        ERR("NtCreateResourceManager returned %08lx\n", Status);
        return Status;
    }

    // FIXME - TmEnableCallbacks

    return STATUS_SUCCESS;
}

NTSTATUS get_trans(device_extension* Vcb, PTXN_PARAMETER_BLOCK block, trans_ref** t) {
    NTSTATUS Status;
    KIRQL irql;
    LIST_ENTRY* le;
    trans_ref* new_tr;
    OBJECT_ATTRIBUTES oa;
    PRKRESOURCEMANAGER rm;

    if (block->Length < sizeof(TXN_PARAMETER_BLOCK))
        return STATUS_INVALID_PARAMETER;

    if (block->TxFsContext != TXF_MINIVERSION_DEFAULT_VIEW)
        return STATUS_INVALID_PARAMETER;

    new_tr = ExAllocatePoolWithTag(NonPagedPool, sizeof(trans_ref), ALLOC_TAG);
    if (!new_tr) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ObReferenceObject(block->TransactionObject);
    new_tr->trans_object = block->TransactionObject;
    new_tr->refcount = 1;
    new_tr->enlistment = NULL;
    ExInitializeResourceLite(&new_tr->lock);

    KeAcquireSpinLock(&Vcb->trans_list_lock, &irql);

    le = Vcb->trans_list.Flink;
    while (le != &Vcb->trans_list) {
        trans_ref* tr = CONTAINING_RECORD(le, trans_ref, list_entry);

        if (tr->trans_object == block->TransactionObject) {
            InterlockedIncrement(&tr->refcount);
            KeReleaseSpinLock(&Vcb->trans_list_lock, irql);

            ObDereferenceObject(block->TransactionObject);
            ExDeleteResourceLite(&new_tr->lock);
            ExFreePool(new_tr);

            *t = tr;

            return STATUS_SUCCESS;
        }

        le = le->Flink;
    }

    InsertTailList(&Vcb->trans_list, &new_tr->list_entry);

    KeReleaseSpinLock(&Vcb->trans_list_lock, irql);

    TRACE("created new transaction\n");

    Status = ObReferenceObjectByHandle(Vcb->rm_handle, RESOURCEMANAGER_ENLIST, NULL, KernelMode,
                                       (void**)&rm, NULL);
    if (!NT_SUCCESS(Status)) {
        ERR("ObReferenceObjectByHandle returned %08lx\n", Status);
        *t = new_tr;
        return Status;
    }

    memset(&oa, 0, sizeof(OBJECT_ATTRIBUTES));
    oa.Length = sizeof(OBJECT_ATTRIBUTES);
    oa.Attributes = OBJ_KERNEL_HANDLE;

    ExAcquireResourceExclusiveLite(&new_tr->lock, true);

    Status = fTmCreateEnlistment(&new_tr->enlistment, KernelMode, 0, &oa, rm, new_tr->trans_object,
                                 0, TRANSACTION_NOTIFY_COMMIT | TRANSACTION_NOTIFY_ROLLBACK, new_tr);

    if (!NT_SUCCESS(Status)) {
        ERR("TmCreateEnlistment returned %08lx\n", Status);
        ExReleaseResourceLite(&new_tr->lock);
        ObDereferenceObject(rm);
        *t = new_tr;
        return Status;
    }

    ExReleaseResourceLite(&new_tr->lock);

    ObDereferenceObject(rm);

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

    ObDereferenceObject(&t->trans_object);
    ExDeleteResourceLite(&t->lock);
    ExFreePool(t);
}
