#include "btrfs_drv.h"

static void do_job(LIST_ENTRY* le) {
    thread_job* tj = CONTAINING_RECORD(le, thread_job, list_entry);
    
    // FIXME
    
    tj->Irp->IoStatus.Status = STATUS_INTERNAL_ERROR; // TESTING
    tj->Irp->IoStatus.Information = 0;
    IoCompleteRequest(tj->Irp, IO_NO_INCREMENT);
    
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
