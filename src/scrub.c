/* Copyright (c) Mark Harmstone 2017
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

static void scrub_thread(void* context) {
    device_extension* Vcb = context;
    
    FIXME("STUB\n"); // FIXME
    
    ZwClose(Vcb->scrub.thread);
    Vcb->scrub.thread = NULL;
}

NTSTATUS start_scrub(device_extension* Vcb) {
    NTSTATUS Status;
    
    if (Vcb->balance.thread) {
        WARN("cannot start scrub while balance running\n");
        return STATUS_DEVICE_NOT_READY;
    }
    
    if (Vcb->scrub.thread) {
        WARN("scrub already running\n");
        return STATUS_DEVICE_NOT_READY;
    }
    
    if (Vcb->readonly)
        return STATUS_MEDIA_WRITE_PROTECTED;
    
    Status = PsCreateSystemThread(&Vcb->scrub.thread, 0, NULL, NULL, NULL, scrub_thread, Vcb);
    if (!NT_SUCCESS(Status)) {
        ERR("PsCreateSystemThread returned %08x\n", Status);
        return Status;
    }
    
    return STATUS_SUCCESS;
}
