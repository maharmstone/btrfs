#include "btrfs_drv.h"

tIoGetTransactionParameterBlock fIoGetTransactionParameterBlock;
tNtCreateTransactionManager fNtCreateTransactionManager;
tNtCreateResourceManager fNtCreateResourceManager;

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
