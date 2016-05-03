#include "btrfs_drv.h"

static void do_read_job(PIRP Irp) {
    NTSTATUS Status;
    ULONG bytes_read;
    BOOL top_level = is_top_level(Irp);
    
    Irp->IoStatus.Information = 0;
    
    Status = do_read(Irp, TRUE, &bytes_read);

    Irp->IoStatus.Status = Status;
    
    // fastfat doesn't do this, but the Wine ntdll file test seems to think we ought to
    if (Irp->UserIosb)
        *Irp->UserIosb = Irp->IoStatus;
    
    TRACE("Irp->IoStatus.Status = %08x\n", Irp->IoStatus.Status);
    TRACE("Irp->IoStatus.Information = %lu\n", Irp->IoStatus.Information);
    TRACE("returning %08x\n", Status);
    
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
    if (top_level) 
        IoSetTopLevelIrp(NULL);
}

static void do_job(LIST_ENTRY* le) {
    thread_job* tj = CONTAINING_RECORD(le, thread_job, list_entry);
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(tj->Irp);
    
    if (IrpSp->MajorFunction == IRP_MJ_READ) {
        do_read_job(tj->Irp);
    } else {
        ERR("unsupported major function %x\n", IrpSp->MajorFunction);
        tj->Irp->IoStatus.Status = STATUS_INTERNAL_ERROR;
        tj->Irp->IoStatus.Information = 0;
        IoCompleteRequest(tj->Irp, IO_NO_INCREMENT);
    }
    
    ExFreePool(tj);
}

void STDCALL worker_thread(void* context) {
    drv_thread* thread = context;
    KIRQL irql;
    
    ObReferenceObject(thread->DeviceObject);
    
    while (TRUE) {
        KeWaitForSingleObject(&thread->event, Executive, KernelMode, FALSE, NULL);
        
        if (thread->quit)
            break;
        
        FsRtlEnterFileSystem();
        
        while (TRUE) {
            LIST_ENTRY* le;
            
            KeAcquireSpinLock(&thread->spin_lock, &irql);
            
            if (IsListEmpty(&thread->jobs)) {
                KeReleaseSpinLock(&thread->spin_lock, irql);
                break;
            }
            
            le = thread->jobs.Flink;
            RemoveEntryList(le);
            
            KeReleaseSpinLock(&thread->spin_lock, irql);
            
            do_job(le);
        }

        FsRtlExitFileSystem();
    }
    
    ObDereferenceObject(thread->DeviceObject);
    PsTerminateSystemThread(STATUS_SUCCESS);
}
