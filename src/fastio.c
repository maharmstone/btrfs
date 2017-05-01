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

FAST_IO_DISPATCH FastIoDispatch;

static BOOLEAN STDCALL fast_query_basic_info(PFILE_OBJECT FileObject, BOOLEAN wait, PFILE_BASIC_INFORMATION fbi,
                                             PIO_STATUS_BLOCK IoStatus, PDEVICE_OBJECT DeviceObject) {
    fcb* fcb;
    ccb* ccb;
    
    TRACE("(%p, %u, %p, %p, %p)\n", FileObject, wait, fbi, IoStatus, DeviceObject);
    
    if (!FileObject)
        return FALSE;
    
    fcb = FileObject->FsContext;
    
    if (!fcb)
        return FALSE;
    
    ccb = FileObject->FsContext2;
    
    if (!ccb)
        return FALSE;
    
    if (!(ccb->access & (FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES)))
        return FALSE;
    
    if (fcb->ads) {
        if (!ccb || !ccb->fileref || !ccb->fileref->parent || !ccb->fileref->parent->fcb)
            return FALSE;
        
        fcb = ccb->fileref->parent->fcb;
    }
    
    FsRtlEnterFileSystem();
    
    if (!ExAcquireResourceSharedLite(fcb->Header.Resource, wait)) {
        FsRtlExitFileSystem();
        return FALSE;
    }

    if (fcb == fcb->Vcb->dummy_fcb) {
        LARGE_INTEGER time;

        KeQuerySystemTime(&time);
        fbi->CreationTime = fbi->LastAccessTime = fbi->LastWriteTime = fbi->ChangeTime = time;
    } else {
        fbi->CreationTime.QuadPart = unix_time_to_win(&fcb->inode_item.otime);
        fbi->LastAccessTime.QuadPart = unix_time_to_win(&fcb->inode_item.st_atime);
        fbi->LastWriteTime.QuadPart = unix_time_to_win(&fcb->inode_item.st_mtime);
        fbi->ChangeTime.QuadPart = unix_time_to_win(&fcb->inode_item.st_ctime);
    }

    fbi->FileAttributes = fcb->atts == 0 ? FILE_ATTRIBUTE_NORMAL : fcb->atts;

    IoStatus->Status = STATUS_SUCCESS;
    IoStatus->Information = sizeof(FILE_BASIC_INFORMATION);
    
    ExReleaseResourceLite(fcb->Header.Resource);

    FsRtlExitFileSystem();
    
    return TRUE;
}

static BOOLEAN STDCALL fast_query_standard_info(PFILE_OBJECT FileObject, BOOLEAN wait, PFILE_STANDARD_INFORMATION fsi,
                                                PIO_STATUS_BLOCK IoStatus, PDEVICE_OBJECT DeviceObject) {
    fcb* fcb;
    ccb* ccb;
    BOOL ads;
    ULONG adssize;
    
    TRACE("(%p, %u, %p, %p, %p)\n", FileObject, wait, fsi, IoStatus, DeviceObject);
    
    if (!FileObject)
        return FALSE;
    
    fcb = FileObject->FsContext;
    ccb = FileObject->FsContext2;
    
    if (!fcb)
        return FALSE;
    
    FsRtlEnterFileSystem();
    
    if (!ExAcquireResourceSharedLite(fcb->Header.Resource, wait)) {
        FsRtlExitFileSystem();
        return FALSE;
    }
    
    ads = fcb->ads;
    
    if (ads) {
        struct _fcb* fcb2;
        
        if (!ccb || !ccb->fileref || !ccb->fileref->parent || !ccb->fileref->parent->fcb) {
            ExReleaseResourceLite(fcb->Header.Resource);
            FsRtlExitFileSystem();
            return FALSE;
        }
        
        adssize = fcb->adsdata.Length;
        
        fcb2 = ccb->fileref->parent->fcb;
        
        ExReleaseResourceLite(fcb->Header.Resource);
        
        fcb = fcb2;
        
        if (!ExAcquireResourceSharedLite(fcb->Header.Resource, wait)) {
            FsRtlExitFileSystem();
            return FALSE;
        }

        fsi->AllocationSize.QuadPart = fsi->EndOfFile.QuadPart = adssize;
        fsi->NumberOfLinks = fcb->inode_item.st_nlink;
        fsi->Directory = FALSE;
    } else {
        fsi->AllocationSize.QuadPart = fcb_alloc_size(fcb);
        fsi->EndOfFile.QuadPart = S_ISDIR(fcb->inode_item.st_mode) ? 0 : fcb->inode_item.st_size;
        fsi->NumberOfLinks = fcb->inode_item.st_nlink;
        fsi->Directory = S_ISDIR(fcb->inode_item.st_mode);
    }
    
    fsi->DeletePending = ccb->fileref ? ccb->fileref->delete_on_close : FALSE;

    IoStatus->Status = STATUS_SUCCESS;
    IoStatus->Information = sizeof(FILE_STANDARD_INFORMATION);
    
    ExReleaseResourceLite(fcb->Header.Resource);

    FsRtlExitFileSystem();
    
    return TRUE;
}

static BOOLEAN STDCALL fast_io_check_if_possible(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, ULONG Length, BOOLEAN Wait,
                                         ULONG LockKey, BOOLEAN CheckForReadOperation, PIO_STATUS_BLOCK IoStatus,
                                         PDEVICE_OBJECT DeviceObject) {
    fcb* fcb = FileObject->FsContext;
    LARGE_INTEGER len2;
    
    TRACE("(%p, %llx, %x, %x, %x, %x, %p, %p)\n", FileObject, FileOffset->QuadPart, Length, Wait, LockKey, CheckForReadOperation, IoStatus, DeviceObject);
    
    len2.QuadPart = Length;
    
    if (CheckForReadOperation) {
        if (FsRtlFastCheckLockForRead(&fcb->lock, FileOffset, &len2, LockKey, FileObject, PsGetCurrentProcess()))
            return TRUE;
    } else {
        if (!fcb->Vcb->readonly && !is_subvol_readonly(fcb->subvol, NULL) && FsRtlFastCheckLockForWrite(&fcb->lock, FileOffset, &len2, LockKey, FileObject, PsGetCurrentProcess()))
            return TRUE;
    }
    
    return FALSE;
}

static BOOLEAN STDCALL fast_io_query_network_open_info(PFILE_OBJECT FileObject, BOOLEAN Wait, FILE_NETWORK_OPEN_INFORMATION* fnoi,
                                                       PIO_STATUS_BLOCK IoStatus, PDEVICE_OBJECT DeviceObject) {
    fcb* fcb;
    ccb* ccb;
    file_ref* fileref;
    
    TRACE("(%p, %u, %p, %p, %p)\n", FileObject, Wait, fnoi, IoStatus, DeviceObject);
    
    RtlZeroMemory(fnoi, sizeof(FILE_NETWORK_OPEN_INFORMATION));
    
    fcb = FileObject->FsContext;
    
    if (!fcb || fcb == fcb->Vcb->volume_fcb)
        return FALSE;
    
    ccb = FileObject->FsContext2;
    
    if (!ccb)
        return FALSE;
    
    fileref = ccb->fileref;
    
    if (fcb == fcb->Vcb->dummy_fcb) {
        LARGE_INTEGER time;
        
        KeQuerySystemTime(&time);
        fnoi->CreationTime = fnoi->LastAccessTime = fnoi->LastWriteTime = fnoi->ChangeTime = time;
    } else {
        INODE_ITEM* ii;

        if (fcb->ads) {
            if (!fileref || !fileref->parent) {
                ERR("no fileref for stream\n");
                return FALSE;
            }

            ii = &fileref->parent->fcb->inode_item;
        } else
            ii = &fcb->inode_item;

        fnoi->CreationTime.QuadPart = unix_time_to_win(&ii->otime);
        fnoi->LastAccessTime.QuadPart = unix_time_to_win(&ii->st_atime);
        fnoi->LastWriteTime.QuadPart = unix_time_to_win(&ii->st_mtime);
        fnoi->ChangeTime.QuadPart = unix_time_to_win(&ii->st_ctime);
    }

    if (fcb->ads) {
        fnoi->AllocationSize.QuadPart = fnoi->EndOfFile.QuadPart = fcb->adsdata.Length;
        fnoi->FileAttributes = fileref->parent->fcb->atts == 0 ? FILE_ATTRIBUTE_NORMAL : fileref->parent->fcb->atts;
    } else {
        fnoi->AllocationSize.QuadPart = fcb_alloc_size(fcb);
        fnoi->EndOfFile.QuadPart = S_ISDIR(fcb->inode_item.st_mode) ? 0 : fcb->inode_item.st_size;
        fnoi->FileAttributes = fcb->atts == 0 ? FILE_ATTRIBUTE_NORMAL : fcb->atts;
    }
    
    return TRUE;
}

static NTSTATUS STDCALL fast_io_acquire_for_mod_write(PFILE_OBJECT FileObject, PLARGE_INTEGER EndingOffset, struct _ERESOURCE **ResourceToRelease, PDEVICE_OBJECT DeviceObject) {
    fcb* fcb;
    
    TRACE("(%p, %llx, %p, %p)\n", FileObject, EndingOffset->QuadPart, ResourceToRelease, DeviceObject);
    
    fcb = FileObject->FsContext;
    
    if (!fcb)
        return STATUS_INVALID_PARAMETER;
    
    *ResourceToRelease = fcb->Header.PagingIoResource;
    
    if (!ExAcquireResourceSharedLite(*ResourceToRelease, FALSE))
        return STATUS_CANT_WAIT;
    
    return STATUS_SUCCESS;
}

static NTSTATUS STDCALL fast_io_release_for_mod_write(PFILE_OBJECT FileObject, struct _ERESOURCE *ResourceToRelease, PDEVICE_OBJECT DeviceObject) {
    TRACE("(%p, %p, %p)\n", FileObject, ResourceToRelease, DeviceObject);
    
    ExReleaseResourceLite(ResourceToRelease);
    
    return STATUS_SUCCESS;
}

static NTSTATUS STDCALL fast_io_acquire_for_ccflush(PFILE_OBJECT FileObject, PDEVICE_OBJECT DeviceObject) {
    TRACE("STUB: fast_io_acquire_for_ccflush\n");
    
    UNUSED(FileObject);
    UNUSED(DeviceObject);
    
    IoSetTopLevelIrp((PIRP)FSRTL_CACHE_TOP_LEVEL_IRP);
    
    return STATUS_SUCCESS;
}

static NTSTATUS STDCALL fast_io_release_for_ccflush(PFILE_OBJECT FileObject, PDEVICE_OBJECT DeviceObject) {
    TRACE("STUB: fast_io_release_for_ccflush\n");
    
    UNUSED(FileObject);
    UNUSED(DeviceObject);
    
    if (IoGetTopLevelIrp() == (PIRP)FSRTL_CACHE_TOP_LEVEL_IRP)
        IoSetTopLevelIrp(NULL);

    return STATUS_SUCCESS;
}

static BOOLEAN STDCALL fast_io_write(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, ULONG Length, BOOLEAN Wait, ULONG LockKey, PVOID Buffer, PIO_STATUS_BLOCK IoStatus, PDEVICE_OBJECT DeviceObject) {
    TRACE("(%p (%.*S), %llx, %x, %x, %x, %p, %p, %p)\n", FileObject, FileObject->FileName.Length / sizeof(WCHAR), FileObject->FileName.Buffer,
                                                        *FileOffset, Length, Wait, LockKey, Buffer, IoStatus, DeviceObject);

    if (FsRtlCopyWrite(FileObject, FileOffset, Length, Wait, LockKey, Buffer, IoStatus, DeviceObject)) {
        fcb* fcb = FileObject->FsContext;
        
        fcb->inode_item.st_size = fcb->Header.FileSize.QuadPart;
        
        return TRUE;
    }
    
    return FALSE;
}

#ifdef _DEBUG
static BOOLEAN STDCALL fast_io_read(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, ULONG Length, BOOLEAN Wait, ULONG LockKey, PVOID Buffer, PIO_STATUS_BLOCK IoStatus, PDEVICE_OBJECT DeviceObject) {
    TRACE("(%p, %p, %x, %x, %x, %p, %p, %p)\n", FileObject, FileOffset, Length, Wait, LockKey, Buffer, IoStatus, DeviceObject);

    return FsRtlCopyRead(FileObject, FileOffset, Length, Wait, LockKey, Buffer, IoStatus, DeviceObject);
}

static BOOLEAN STDCALL fast_io_mdl_read(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, ULONG Length, ULONG LockKey, PMDL* MdlChain, PIO_STATUS_BLOCK IoStatus, PDEVICE_OBJECT DeviceObject) {
    TRACE("(%p, %p, %x, %x, %p, %p, %p)\n", FileObject, FileOffset, Length, LockKey, MdlChain, IoStatus, DeviceObject);

    return FsRtlMdlReadDev(FileObject, FileOffset, Length, LockKey, MdlChain, IoStatus, DeviceObject);
}

static BOOLEAN STDCALL fast_io_mdl_read_complete(PFILE_OBJECT FileObject, PMDL MdlChain, PDEVICE_OBJECT DeviceObject) {
    TRACE("(%p, %p, %p)\n", FileObject, MdlChain, DeviceObject);

    return FsRtlMdlReadCompleteDev(FileObject, MdlChain, DeviceObject);
}

static BOOLEAN STDCALL fast_io_prepare_mdl_write(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, ULONG Length, ULONG LockKey, PMDL* MdlChain, PIO_STATUS_BLOCK IoStatus, PDEVICE_OBJECT DeviceObject) {
    TRACE("(%p, %p, %x, %x, %p, %p, %p)\n", FileObject, FileOffset, Length, LockKey, MdlChain, IoStatus, DeviceObject);

    return FsRtlPrepareMdlWriteDev(FileObject, FileOffset, Length, LockKey, MdlChain, IoStatus, DeviceObject);
}

static BOOLEAN STDCALL fast_io_mdl_write_complete(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, PMDL MdlChain, PDEVICE_OBJECT DeviceObject) {
    TRACE("(%p, %p, %p, %p)\n", FileObject, FileOffset, MdlChain, DeviceObject);

    return FsRtlMdlWriteCompleteDev(FileObject, FileOffset, MdlChain, DeviceObject);
}
#endif

void __stdcall init_fast_io_dispatch(FAST_IO_DISPATCH** fiod) {
    RtlZeroMemory(&FastIoDispatch, sizeof(FastIoDispatch));

    FastIoDispatch.SizeOfFastIoDispatch = sizeof(FAST_IO_DISPATCH);

    FastIoDispatch.FastIoCheckIfPossible = fast_io_check_if_possible;
    FastIoDispatch.FastIoQueryBasicInfo = fast_query_basic_info;
    FastIoDispatch.FastIoQueryStandardInfo = fast_query_standard_info;
//     FastIoDispatch.FastIoLock = fast_io_lock;
//     FastIoDispatch.FastIoUnlockSingle = fast_io_unlock_single;
//     FastIoDispatch.FastIoUnlockAll = fast_io_unlock_all;
//     FastIoDispatch.FastIoUnlockAllByKey = fast_io_unlock_all_by_key;
//     FastIoDispatch.FastIoDeviceControl = fast_io_device_control;
//     FastIoDispatch.AcquireFileForNtCreateSection = acquire_file_for_create_section;
//     FastIoDispatch.ReleaseFileForNtCreateSection = release_file_for_create_section;
    FastIoDispatch.FastIoQueryNetworkOpenInfo = fast_io_query_network_open_info;
    FastIoDispatch.AcquireForModWrite = fast_io_acquire_for_mod_write;
    FastIoDispatch.ReleaseForModWrite = fast_io_release_for_mod_write;
    FastIoDispatch.AcquireForCcFlush = fast_io_acquire_for_ccflush;
    FastIoDispatch.ReleaseForCcFlush = fast_io_release_for_ccflush;
    FastIoDispatch.FastIoWrite = fast_io_write;
    
#ifdef _DEBUG
    FastIoDispatch.FastIoRead = fast_io_read;
    FastIoDispatch.MdlRead = fast_io_mdl_read;
    FastIoDispatch.MdlReadComplete = fast_io_mdl_read_complete;
    FastIoDispatch.PrepareMdlWrite = fast_io_prepare_mdl_write;
    FastIoDispatch.MdlWriteComplete = fast_io_mdl_write_complete;
#else
    FastIoDispatch.FastIoRead = FsRtlCopyRead;
    FastIoDispatch.MdlRead = FsRtlMdlReadDev;
    FastIoDispatch.MdlReadComplete = FsRtlMdlReadCompleteDev;
    FastIoDispatch.PrepareMdlWrite = FsRtlPrepareMdlWriteDev;
    FastIoDispatch.MdlWriteComplete = FsRtlMdlWriteCompleteDev;
#endif
    
    *fiod = &FastIoDispatch;
}
