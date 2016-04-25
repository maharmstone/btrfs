#include "btrfs_drv.h"

NTSTATUS STDCALL drv_pnp(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    device_extension* Vcb = DeviceObject->DeviceExtension;
    NTSTATUS Status;
    BOOL top_level;

    FIXME("STUB: pnp\n");
    
    FsRtlEnterFileSystem();

    top_level = is_top_level(Irp);
    
    Status = STATUS_NOT_IMPLEMENTED;
    
    switch (IrpSp->MinorFunction) {
        case IRP_MN_CANCEL_REMOVE_DEVICE:
            TRACE("    IRP_MN_CANCEL_REMOVE_DEVICE\n");
            break;

        case IRP_MN_QUERY_REMOVE_DEVICE:
            TRACE("    IRP_MN_QUERY_REMOVE_DEVICE\n");
            break;

        case IRP_MN_REMOVE_DEVICE:
            TRACE("    IRP_MN_REMOVE_DEVICE\n");
            break;

        case IRP_MN_START_DEVICE:
            TRACE("    IRP_MN_START_DEVICE\n");
            break;

        case IRP_MN_SURPRISE_REMOVAL:
            TRACE("    IRP_MN_SURPRISE_REMOVAL\n");
            break;
            
        case IRP_MN_QUERY_DEVICE_RELATIONS:
            TRACE("    IRP_MN_QUERY_DEVICE_RELATIONS\n");
            break;
        
        default:
            WARN("Unrecognized minor function 0x%x\n", IrpSp->MinorFunction);
            break;
    }

//     Irp->IoStatus.Status = Status;
//     Irp->IoStatus.Information = 0;

    IoSkipCurrentIrpStackLocation(Irp);
    
    Status = IoCallDriver(Vcb->devices[0].devobj, Irp);

//     IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
    if (top_level) 
        IoSetTopLevelIrp(NULL);
    
    FsRtlExitFileSystem();

    return Status;
}
