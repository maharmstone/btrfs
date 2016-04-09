#include "btrfs_drv.h"

static NTSTATUS pnp_cancel_remove_device(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    FIXME("STUB\n");

    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS pnp_query_remove_device(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    FIXME("STUB\n");

    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS pnp_remove_device(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    FIXME("STUB\n");

    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS pnp_start_device(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    FIXME("STUB\n");

    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS pnp_surprise_removal(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    FIXME("STUB\n");

    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS pnp_query_device_relations(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    FIXME("STUB\n");

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS STDCALL drv_pnp(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
//     device_extension* Vcb = DeviceObject->DeviceExtension;
    NTSTATUS Status;
    BOOL top_level;

    FsRtlEnterFileSystem();

    top_level = is_top_level(Irp);
    
    Status = STATUS_NOT_IMPLEMENTED;
    
    switch (IrpSp->MinorFunction) {
        case IRP_MN_CANCEL_REMOVE_DEVICE:
            Status = pnp_cancel_remove_device(DeviceObject, Irp);
            break;

        case IRP_MN_QUERY_REMOVE_DEVICE:
            Status = pnp_query_remove_device(DeviceObject, Irp);
            break;

        case IRP_MN_REMOVE_DEVICE:
            Status = pnp_remove_device(DeviceObject, Irp);
            break;

        case IRP_MN_START_DEVICE:
            Status = pnp_start_device(DeviceObject, Irp);
            break;

        case IRP_MN_SURPRISE_REMOVAL:
            Status = pnp_surprise_removal(DeviceObject, Irp);
            break;
            
        case IRP_MN_QUERY_DEVICE_RELATIONS:
            Status = pnp_query_device_relations(DeviceObject, Irp);
            break;
        
        default:
            WARN("Unrecognized minor function 0x%x\n", IrpSp->MinorFunction);
            break;
    }

// //     Irp->IoStatus.Status = Status;
// //     Irp->IoStatus.Information = 0;
// 
//     IoSkipCurrentIrpStackLocation(Irp);
//     
//     Status = IoCallDriver(Vcb->devices[0].devobj, Irp);
// 
// //     IoCompleteRequest(Irp, IO_NO_INCREMENT);

    Irp->IoStatus.Status = Status;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
    if (top_level) 
        IoSetTopLevelIrp(NULL);
    
    FsRtlExitFileSystem();

    return Status;
}
