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

#include <ntifs.h>
#include "btrfs_drv.h"

FAST_IO_DISPATCH FastIoDispatch;

static void STDCALL acquire_file_for_create_section(PFILE_OBJECT FileObject) {
    TRACE("STUB: acquire_file_for_create_section\n");
}

static void STDCALL release_file_for_create_section(PFILE_OBJECT FileObject) {
    TRACE("STUB: release_file_for_create_section\n");
}

static BOOLEAN STDCALL fast_query_basic_info(PFILE_OBJECT FileObject, BOOLEAN wait, PFILE_BASIC_INFORMATION buf,
                                     PIO_STATUS_BLOCK IoStatus, PDEVICE_OBJECT DeviceObject) {
    
    TRACE("STUB: fast_query_basic_info\n");
    
    return FALSE;
}

static BOOLEAN STDCALL fast_query_standard_info(PFILE_OBJECT FileObject, BOOLEAN wait, PFILE_STANDARD_INFORMATION buf,
                                     PIO_STATUS_BLOCK IoStatus, PDEVICE_OBJECT DeviceObject) {
    
    TRACE("STUB: fast_query_standard_info\n");
    
    return FALSE;
}

static BOOLEAN STDCALL fast_io_query_open(PIRP Irp, PFILE_NETWORK_OPEN_INFORMATION  NetworkInformation, PDEVICE_OBJECT DeviceObject) {
    TRACE("STUB: fast_io_query_open\n");
    
    return FALSE;
}

static BOOLEAN STDCALL fast_io_check_if_possible(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, ULONG Length, BOOLEAN Wait,
                                         ULONG LockKey, BOOLEAN CheckForReadOperation, PIO_STATUS_BLOCK IoStatus,
                                         PDEVICE_OBJECT DeviceObject) {
    fcb* fcb = (_fcb*)FileObject->FsContext;
    LARGE_INTEGER len2;
    
    TRACE("(%p, %llx, %x, %x, %x, %x, %p, %p)\n", FileObject, FileOffset->QuadPart, Length, Wait, LockKey, CheckForReadOperation, IoStatus, DeviceObject);
    
    len2.QuadPart = Length;
    
    if (CheckForReadOperation) {
        if (FsRtlFastCheckLockForRead(&fcb->lock, FileOffset, &len2, LockKey, FileObject, PsGetCurrentProcess()))
            return TRUE;
    } else {
        if (!fcb->Vcb->readonly && !(fcb->subvol->root_item.flags & BTRFS_SUBVOL_READONLY) && FsRtlFastCheckLockForWrite(&fcb->lock, FileOffset, &len2, LockKey, FileObject, PsGetCurrentProcess()))
            return TRUE;
    }
    
    return FALSE;
}

static BOOLEAN STDCALL fast_io_lock(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, PLARGE_INTEGER Length, PEPROCESS ProcessId, ULONG Key, BOOLEAN FailImmediately, BOOLEAN ExclusiveLock, PIO_STATUS_BLOCK IoStatus, PDEVICE_OBJECT DeviceObject){
    TRACE("STUB: fast_io_lock\n");
    return FALSE;
}

static BOOLEAN STDCALL fast_io_unlock_single(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, PLARGE_INTEGER Length, PEPROCESS ProcessId, ULONG Key, PIO_STATUS_BLOCK IoStatus, PDEVICE_OBJECT DeviceObject){
    TRACE("STUB: fast_io_unlock_single\n");
    return FALSE;
}

static BOOLEAN STDCALL fast_io_unlock_all(PFILE_OBJECT FileObject, PEPROCESS ProcessId, PIO_STATUS_BLOCK IoStatus, PDEVICE_OBJECT DeviceObject){
    TRACE("STUB: fast_io_unlock_all\n");
    return FALSE;
}

static BOOLEAN STDCALL fast_io_unlock_all_by_key(PFILE_OBJECT FileObject, PVOID ProcessId, ULONG Key, PIO_STATUS_BLOCK IoStatus, PDEVICE_OBJECT DeviceObject){
    TRACE("STUB: fast_io_unlock_all_by_key\n");
    return FALSE;
}

static BOOLEAN STDCALL fast_io_device_control(PFILE_OBJECT FileObject, BOOLEAN Wait, PVOID InputBuffer OPTIONAL, ULONG InputBufferLength, PVOID OutputBuffer OPTIONAL, ULONG OutputBufferLength, ULONG IoControlCode, PIO_STATUS_BLOCK IoStatus, PDEVICE_OBJECT DeviceObject){
    TRACE("STUB: fast_io_device_control\n");
    return FALSE;
}

static VOID STDCALL fast_io_detach_device(PDEVICE_OBJECT SourceDevice, PDEVICE_OBJECT TargetDevice){
    TRACE("STUB: fast_io_detach_device\n");
}

static BOOLEAN STDCALL fast_io_query_network_open_info(PFILE_OBJECT FileObject, BOOLEAN Wait, struct _FILE_NETWORK_OPEN_INFORMATION *Buffer, struct _IO_STATUS_BLOCK *IoStatus, PDEVICE_OBJECT DeviceObject){
    TRACE("STUB: fast_io_query_network_open_info\n");
    return FALSE;
}

static NTSTATUS STDCALL fast_io_acquire_for_mod_write(PFILE_OBJECT FileObject, PLARGE_INTEGER EndingOffset, struct _ERESOURCE **ResourceToRelease, PDEVICE_OBJECT DeviceObject){
    TRACE("STUB: fast_io_acquire_for_mod_write\n");
    return STATUS_NOT_IMPLEMENTED;
}

static BOOLEAN STDCALL fast_io_read_compressed(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, ULONG Length, ULONG LockKey, PVOID Buffer, PMDL *MdlChain, PIO_STATUS_BLOCK IoStatus, struct _COMPRESSED_DATA_INFO *CompressedDataInfo, ULONG CompressedDataInfoLength, PDEVICE_OBJECT DeviceObject){
    TRACE("STUB: fast_io_read_compressed\n");
    return FALSE;
}

static BOOLEAN STDCALL fast_io_write_compressed(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, ULONG Length, ULONG LockKey, PVOID Buffer, PMDL *MdlChain, PIO_STATUS_BLOCK IoStatus, struct _COMPRESSED_DATA_INFO *CompressedDataInfo, ULONG CompressedDataInfoLength, PDEVICE_OBJECT DeviceObject){
    TRACE("STUB: fast_io_write_compressed\n");
    return FALSE;
}

static BOOLEAN STDCALL fast_io_mdl_read_complete_compressed(PFILE_OBJECT FileObject, PMDL MdlChain, PDEVICE_OBJECT DeviceObject){
    TRACE("STUB: fast_io_mdl_read_complete_compressed\n");
    return FALSE;
}

static BOOLEAN STDCALL fast_io_mdl_write_complete_compressed(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, PMDL MdlChain, PDEVICE_OBJECT DeviceObject){
    TRACE("STUB: fast_io_mdl_write_complete_compressed\n");
    return FALSE;
}

static NTSTATUS STDCALL fast_io_release_for_mod_write(PFILE_OBJECT FileObject, struct _ERESOURCE *ResourceToRelease, PDEVICE_OBJECT DeviceObject){
    TRACE("STUB: fast_io_release_for_mod_write\n");
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS STDCALL fast_io_acquire_for_ccflush(PFILE_OBJECT FileObject, PDEVICE_OBJECT DeviceObject){
    TRACE("STUB: fast_io_acquire_for_ccflush\n");
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS STDCALL fast_io_release_for_ccflush(PFILE_OBJECT FileObject, PDEVICE_OBJECT DeviceObject){
    TRACE("STUB: fast_io_release_for_ccflush\n");
    return STATUS_NOT_IMPLEMENTED;
}

void __stdcall init_fast_io_dispatch(FAST_IO_DISPATCH** fiod) {
    RtlZeroMemory(&FastIoDispatch, sizeof(FastIoDispatch));

    FastIoDispatch.SizeOfFastIoDispatch = sizeof(FAST_IO_DISPATCH);

    FastIoDispatch.FastIoCheckIfPossible = (PFAST_IO_CHECK_IF_POSSIBLE)fast_io_check_if_possible;
    FastIoDispatch.FastIoRead = FsRtlCopyRead;
    FastIoDispatch.FastIoWrite = FsRtlCopyWrite;
    FastIoDispatch.FastIoQueryBasicInfo = (PFAST_IO_QUERY_BASIC_INFO)fast_query_basic_info;
    FastIoDispatch.FastIoQueryStandardInfo = (PFAST_IO_QUERY_STANDARD_INFO)fast_query_standard_info;
    FastIoDispatch.FastIoLock = (PFAST_IO_LOCK)fast_io_lock;
    FastIoDispatch.FastIoUnlockSingle = (PFAST_IO_UNLOCK_SINGLE)fast_io_unlock_single;
    FastIoDispatch.FastIoUnlockAll = (PFAST_IO_UNLOCK_ALL)fast_io_unlock_all;
    FastIoDispatch.FastIoUnlockAllByKey = (PFAST_IO_UNLOCK_ALL_BY_KEY)fast_io_unlock_all_by_key;
    FastIoDispatch.FastIoDeviceControl = (PFAST_IO_DEVICE_CONTROL)fast_io_device_control;
    FastIoDispatch.AcquireFileForNtCreateSection = (PFAST_IO_ACQUIRE_FILE)acquire_file_for_create_section;
    FastIoDispatch.ReleaseFileForNtCreateSection = (PFAST_IO_RELEASE_FILE)release_file_for_create_section;
    FastIoDispatch.FastIoDetachDevice = (PFAST_IO_DETACH_DEVICE)fast_io_detach_device;
    FastIoDispatch.FastIoQueryNetworkOpenInfo = (PFAST_IO_QUERY_NETWORK_OPEN_INFO)fast_io_query_network_open_info;
    FastIoDispatch.AcquireForModWrite = (PFAST_IO_ACQUIRE_FOR_MOD_WRITE)fast_io_acquire_for_mod_write;
    FastIoDispatch.MdlRead = (PFAST_IO_MDL_READ)FsRtlMdlReadDev;
    FastIoDispatch.MdlReadComplete = (PFAST_IO_MDL_READ_COMPLETE)FsRtlMdlReadCompleteDev;
    FastIoDispatch.PrepareMdlWrite = FsRtlPrepareMdlWriteDev;
    FastIoDispatch.MdlWriteComplete = FsRtlMdlWriteCompleteDev;
    FastIoDispatch.FastIoReadCompressed = (PFAST_IO_READ_COMPRESSED)fast_io_read_compressed;
    FastIoDispatch.FastIoWriteCompressed = (PFAST_IO_WRITE_COMPRESSED)fast_io_write_compressed;
    FastIoDispatch.MdlReadCompleteCompressed = (PFAST_IO_MDL_READ_COMPLETE_COMPRESSED)fast_io_mdl_read_complete_compressed;
    FastIoDispatch.MdlWriteCompleteCompressed = (PFAST_IO_MDL_WRITE_COMPLETE_COMPRESSED)fast_io_mdl_write_complete_compressed;
    FastIoDispatch.FastIoQueryOpen = (PFAST_IO_QUERY_OPEN)fast_io_query_open;
    FastIoDispatch.ReleaseForModWrite = (PFAST_IO_RELEASE_FOR_MOD_WRITE)fast_io_release_for_mod_write;
    FastIoDispatch.AcquireForCcFlush = (PFAST_IO_ACQUIRE_FOR_CCFLUSH)fast_io_acquire_for_ccflush;
    FastIoDispatch.ReleaseForCcFlush = (PFAST_IO_RELEASE_FOR_CCFLUSH)fast_io_release_for_ccflush;
    
    *fiod = &FastIoDispatch;
}