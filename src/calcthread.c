/* Copyright (c) Mark Harmstone 2016
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

NTSTATUS add_calc_job(device_extension* Vcb, UINT8* data, UINT32 sectors, calc_job** pcj) {
    calc_job* cj;
    KIRQL irql;
    
    cj = ExAllocatePoolWithTag(NonPagedPool, sizeof(calc_job), ALLOC_TAG);
    if (!cj) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    cj->csum = ExAllocatePoolWithTag(PagedPool, sizeof(UINT32) * sectors, ALLOC_TAG);
    if (!cj->csum) {
        ERR("out of memory\n");
        ExFreePool(cj);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    cj->data = data;
    cj->sectors = sectors;
    cj->pos = 0;
    cj->done = 0;
    KeInitializeEvent(&cj->event, NotificationEvent, FALSE);
        
    KeAcquireSpinLock(&Vcb->calcthreads.spin_lock, &irql);
    InsertTailList(&Vcb->calcthreads.job_list, &cj->list_entry);
    KeReleaseSpinLock(&Vcb->calcthreads.spin_lock, irql);
    
    KeSetEvent(&Vcb->calcthreads.event, 0, FALSE);
    KeClearEvent(&Vcb->calcthreads.event);
    
    *pcj = cj;
    
    return STATUS_SUCCESS;
}

void free_calc_job(calc_job* cj) {
    ExFreePool(cj->csum);
    ExFreePool(cj);
}

static BOOL do_calc(device_extension* Vcb, calc_job* cj, drv_calc_thread* thread) {
    LONG pos, done;
    
    pos = InterlockedIncrement(&cj->pos) - 1;
    
    if (pos >= cj->sectors)
        return FALSE;

    cj->csum[pos] = ~calc_crc32c(0xffffffff, cj->data + (pos * Vcb->superblock.sector_size), Vcb->superblock.sector_size);
    
    done = InterlockedIncrement(&cj->done);
    
    if (done == cj->sectors) {
        KIRQL irql;
        
        KeAcquireSpinLock(&Vcb->calcthreads.spin_lock, &irql);
        RemoveEntryList(&cj->list_entry);
        KeReleaseSpinLock(&Vcb->calcthreads.spin_lock, irql);
        
        KeSetEvent(&cj->event, 0, FALSE);
    }
    
    return TRUE;
}

void calc_thread(void* context) {
    drv_calc_thread* thread = context;
    device_extension* Vcb = thread->DeviceObject->DeviceExtension;
    
    ObReferenceObject(thread->DeviceObject);
    
    while (TRUE) {
        KeWaitForSingleObject(&Vcb->calcthreads.event, Executive, KernelMode, FALSE, NULL);
        
        FsRtlEnterFileSystem();
        
        while (TRUE) {
            KIRQL irql;
            calc_job* cj;
            
            KeAcquireSpinLock(&Vcb->calcthreads.spin_lock, &irql);
            
            if (IsListEmpty(&Vcb->calcthreads.job_list)) {
                KeReleaseSpinLock(&Vcb->calcthreads.spin_lock, irql);
                break;
            }
            
            cj = CONTAINING_RECORD(Vcb->calcthreads.job_list.Flink, calc_job, list_entry);
            
            KeReleaseSpinLock(&Vcb->calcthreads.spin_lock, irql);
            
            if (!do_calc(Vcb, cj, thread))
                break;
        }
        
        FsRtlExitFileSystem();
        
        if (thread->quit)
            break;
    }

    ObDereferenceObject(thread->DeviceObject);
     
    KeSetEvent(&thread->finished, 0, FALSE);
     
    PsTerminateSystemThread(STATUS_SUCCESS);
}
