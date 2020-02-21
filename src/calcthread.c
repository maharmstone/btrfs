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
#include "xxhash.h"
#include "blake2.h"

static void do_calc_crc32(device_extension* Vcb, calc_job* cj, uint8_t* src, uint32_t* dest) {
    // FIXME - do at DISPATCH irql?

    *dest = ~calc_crc32c(0xffffffff, src, Vcb->superblock.sector_size);

    if (InterlockedDecrement(&cj->left) == 0)
        KeSetEvent(&cj->event, 0, false);
}

static void do_calc_xxhash(device_extension* Vcb, calc_job* cj, uint8_t* src, uint64_t* dest) {
    // FIXME - do at DISPATCH irql?

    *dest = XXH64(src, Vcb->superblock.sector_size, 0);

    if (InterlockedDecrement(&cj->left) == 0)
        KeSetEvent(&cj->event, 0, false);
}

static void do_calc_sha256(device_extension* Vcb, calc_job* cj, uint8_t* src, uint8_t* dest) {
    // FIXME - do at DISPATCH irql?

    calc_sha256(dest, src, Vcb->superblock.sector_size);

    if (InterlockedDecrement(&cj->left) == 0)
        KeSetEvent(&cj->event, 0, false);
}

static void do_calc_blake2(device_extension* Vcb, calc_job* cj, uint8_t* src, uint8_t* dest) {
    // FIXME - do at DISPATCH irql?

    blake2b(dest, BLAKE2_HASH_SIZE, src, Vcb->superblock.sector_size, NULL, 0);

    if (InterlockedDecrement(&cj->left) == 0)
        KeSetEvent(&cj->event, 0, false);
}

static void calc_thread_main(device_extension* Vcb, calc_job* cj) {
    while (true) {
        KIRQL irql;
        calc_job* cj2;
        uint8_t* src;
        void* dest;
        bool last_one = false;

        KeAcquireSpinLock(&Vcb->calcthreads.spinlock, &irql);

        if (cj && cj->not_started == 0) {
            KeReleaseSpinLock(&Vcb->calcthreads.spinlock, irql);
            break;
        }

        if (cj)
            cj2 = cj;
        else {
            if (IsListEmpty(&Vcb->calcthreads.job_list)) {
                KeReleaseSpinLock(&Vcb->calcthreads.spinlock, irql);
                break;
            }

            cj2 = CONTAINING_RECORD(Vcb->calcthreads.job_list.Flink, calc_job, list_entry);
        }

        src = cj2->data;
        cj2->data += Vcb->superblock.sector_size;

        dest = cj2->csum;
        cj2->csum = (uint8_t*)cj2->csum + Vcb->csum_size;

        cj2->not_started--;

        if (cj2->not_started == 0) {
            RemoveEntryList(&cj2->list_entry);
            last_one = true;
        }

        KeReleaseSpinLock(&Vcb->calcthreads.spinlock, irql);

        switch (Vcb->superblock.csum_type) {
            case CSUM_TYPE_CRC32C:
                do_calc_crc32(Vcb, cj2, src, dest);
            break;

            case CSUM_TYPE_XXHASH:
                do_calc_xxhash(Vcb, cj2, src, dest);
            break;

            case CSUM_TYPE_SHA256:
                do_calc_sha256(Vcb, cj2, src, dest);
            break;

            case CSUM_TYPE_BLAKE2:
                do_calc_blake2(Vcb, cj2, src, dest);
            break;
        }

        if (last_one)
            break;
    }
}

void do_calc_job(device_extension* Vcb, uint8_t* data, uint32_t sectors, void* csum) {
    KIRQL irql;
    calc_job cj;

    cj.data = data;
    cj.csum = csum;
    cj.left = cj.not_started = sectors;
    KeInitializeEvent(&cj.event, NotificationEvent, false);

    KeAcquireSpinLock(&Vcb->calcthreads.spinlock, &irql);

    InsertTailList(&Vcb->calcthreads.job_list, &cj.list_entry);

    KeSetEvent(&Vcb->calcthreads.event, 0, false);
    KeClearEvent(&Vcb->calcthreads.event);

    KeReleaseSpinLock(&Vcb->calcthreads.spinlock, irql);

    calc_thread_main(Vcb, &cj);

    KeWaitForSingleObject(&cj.event, Executive, KernelMode, false, NULL);
}

_Function_class_(KSTART_ROUTINE)
void __stdcall calc_thread(void* context) {
    drv_calc_thread* thread = context;
    device_extension* Vcb = thread->DeviceObject->DeviceExtension;

    ObReferenceObject(thread->DeviceObject);

    KeSetSystemAffinityThread(1 << thread->number);

    while (true) {
        KeWaitForSingleObject(&Vcb->calcthreads.event, Executive, KernelMode, false, NULL);

        calc_thread_main(Vcb, NULL);

        if (thread->quit)
            break;
    }

    ObDereferenceObject(thread->DeviceObject);

    KeSetEvent(&thread->finished, 0, false);

    PsTerminateSystemThread(STATUS_SUCCESS);
}
