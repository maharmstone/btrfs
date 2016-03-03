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
#include <wdm.h>

CACHE_MANAGER_CALLBACKS* cache_callbacks;

static BOOLEAN STDCALL acquire_for_lazy_write(PVOID Context, BOOLEAN Wait) {
    fcb* fcb = (_fcb*)Context;
    
    TRACE("(%p, %u)\n", Context, Wait);
    
    fcb->lazy_writer_thread = KeGetCurrentThread();
    
    return TRUE;
}

static void STDCALL release_from_lazy_write(PVOID Context) {
    fcb* fcb = (_fcb*)Context;
    
    TRACE("(%p)\n", Context);
    
    fcb->lazy_writer_thread = NULL;
}

static BOOLEAN STDCALL acquire_for_read_ahead(PVOID Context, BOOLEAN Wait) {
    TRACE("(%p, %u)\n", Context, Wait);
    
    return TRUE;
}

static void STDCALL release_from_read_ahead(PVOID Context) {
    TRACE("(%p)\n", Context);
}

NTSTATUS STDCALL init_cache() {
    cache_callbacks = (CACHE_MANAGER_CALLBACKS*)ExAllocatePoolWithTag(NonPagedPool, sizeof(CACHE_MANAGER_CALLBACKS), ALLOC_TAG);
    if (!cache_callbacks) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    cache_callbacks->AcquireForLazyWrite = (PACQUIRE_FOR_LAZY_WRITE)acquire_for_lazy_write;
    cache_callbacks->ReleaseFromLazyWrite = (PRELEASE_FROM_LAZY_WRITE)release_from_lazy_write;
    cache_callbacks->AcquireForReadAhead = (PACQUIRE_FOR_READ_AHEAD)acquire_for_read_ahead;
    cache_callbacks->ReleaseFromReadAhead = (PRELEASE_FROM_READ_AHEAD)release_from_read_ahead;
    
    return STATUS_SUCCESS;
}

void STDCALL free_cache() {
    ExFreePool(cache_callbacks);
}
