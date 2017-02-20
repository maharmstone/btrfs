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

#ifdef _DEBUG
#define DEBUG
#endif

#include "btrfs_drv.h"
#ifndef _MSC_VER
#include <cpuid.h>
#else
#include <intrin.h>
#endif
#include <ntddscsi.h>
#include "btrfs.h"
#include <ata.h>

#ifndef _MSC_VER
#include <initguid.h>
#include <ntddstor.h>
#undef INITGUID
#endif

#include <ntdddisk.h>
#include <ntddvol.h>

#ifdef _MSC_VER
#include <initguid.h>
#include <ntddstor.h>
#undef INITGUID
#endif

#define INCOMPAT_SUPPORTED (BTRFS_INCOMPAT_FLAGS_MIXED_BACKREF | BTRFS_INCOMPAT_FLAGS_DEFAULT_SUBVOL | BTRFS_INCOMPAT_FLAGS_MIXED_GROUPS | \
                            BTRFS_INCOMPAT_FLAGS_COMPRESS_LZO | BTRFS_INCOMPAT_FLAGS_BIG_METADATA | BTRFS_INCOMPAT_FLAGS_RAID56 | \
                            BTRFS_INCOMPAT_FLAGS_EXTENDED_IREF | BTRFS_INCOMPAT_FLAGS_SKINNY_METADATA | BTRFS_INCOMPAT_FLAGS_NO_HOLES)
#define COMPAT_RO_SUPPORTED 0

static WCHAR device_name[] = {'\\','B','t','r','f','s',0};
static WCHAR dosdevice_name[] = {'\\','D','o','s','D','e','v','i','c','e','s','\\','B','t','r','f','s',0};

PDRIVER_OBJECT drvobj;
PDEVICE_OBJECT devobj;
BOOL have_sse42 = FALSE, have_sse2 = FALSE;
UINT64 num_reads = 0;
LIST_ENTRY uid_map_list;
LIST_ENTRY VcbList;
ERESOURCE global_loading_lock;
UINT32 debug_log_level = 0;
UINT32 mount_compress = 0;
UINT32 mount_compress_force = 0;
UINT32 mount_compress_type = 0;
UINT32 mount_zlib_level = 3;
UINT32 mount_flush_interval = 30;
UINT32 mount_max_inline = 2048;
UINT32 mount_skip_balance = 0;
UINT32 mount_no_barrier = 0;
UINT32 mount_no_trim = 0;
UINT32 mount_clear_cache = 0;
BOOL log_started = FALSE;
UNICODE_STRING log_device, log_file, registry_path;
tPsUpdateDiskCounters PsUpdateDiskCounters;
tCcCopyReadEx CcCopyReadEx;
tCcCopyWriteEx CcCopyWriteEx;
tCcSetAdditionalCacheAttributesEx CcSetAdditionalCacheAttributesEx;
BOOL diskacc = FALSE;
void *notification_entry = NULL, *notification_entry2 = NULL, *notification_entry3 = NULL;
ERESOURCE volume_list_lock;
LIST_ENTRY volume_list;

#ifdef _DEBUG
PFILE_OBJECT comfo = NULL;
PDEVICE_OBJECT comdo = NULL;
HANDLE log_handle = NULL;
#endif

static NTSTATUS STDCALL close_file(device_extension* Vcb, PFILE_OBJECT FileObject);

typedef struct {
    KEVENT Event;
    IO_STATUS_BLOCK iosb;
} read_context;

#ifdef _DEBUG
static NTSTATUS STDCALL dbg_completion(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID conptr) {
    read_context* context = conptr;
    
//     DbgPrint("dbg_completion\n");
    
    context->iosb = Irp->IoStatus;
    KeSetEvent(&context->Event, 0, FALSE);
    
//     return STATUS_SUCCESS;
    return STATUS_MORE_PROCESSING_REQUIRED;
}

#ifdef DEBUG_LONG_MESSAGES
void STDCALL _debug_message(const char* func, const char* file, unsigned int line, char* s, ...) {
#else
void STDCALL _debug_message(const char* func, char* s, ...) {
#endif
    LARGE_INTEGER offset;
    PIO_STACK_LOCATION IrpSp;
    NTSTATUS Status;
    PIRP Irp;
    va_list ap;
    char *buf2 = NULL, *buf;
    read_context* context = NULL;
    UINT32 length;
    
    buf2 = ExAllocatePoolWithTag(NonPagedPool, 1024, ALLOC_TAG);
    
    if (!buf2) {
        DbgPrint("Couldn't allocate buffer in debug_message\n");
        return;
    }
    
#ifdef DEBUG_LONG_MESSAGES
    sprintf(buf2, "%p:%s:%s:%u:", PsGetCurrentThreadId(), func, file, line);
#else
    sprintf(buf2, "%p:%s:", PsGetCurrentThreadId(), func);
#endif
    buf = &buf2[strlen(buf2)];
    
    va_start(ap, s);
    vsprintf(buf, s, ap);
    
    if (!log_started || (log_device.Length == 0 && log_file.Length == 0)) {
        DbgPrint(buf2);
    } else if (log_device.Length > 0) {
        if (!comdo) {
            DbgPrint("comdo is NULL :-(\n");
            DbgPrint(buf2);
            goto exit2;
        }
        
        length = (UINT32)strlen(buf2);
        
        offset.u.LowPart = 0;
        offset.u.HighPart = 0;
        
        context = ExAllocatePoolWithTag(NonPagedPool, sizeof(read_context), ALLOC_TAG);
        if (!context) {
            DbgPrint("Couldn't allocate context in debug_message\n");
            return;
        }
        
        RtlZeroMemory(context, sizeof(read_context));
        
        KeInitializeEvent(&context->Event, NotificationEvent, FALSE);

    //     status = ZwWriteFile(comh, NULL, NULL, NULL, &io, buf2, strlen(buf2), &offset, NULL);
        
        Irp = IoAllocateIrp(comdo->StackSize, FALSE);
        
        if (!Irp) {
            DbgPrint("IoAllocateIrp failed\n");
            goto exit2;
        }
        
        IrpSp = IoGetNextIrpStackLocation(Irp);
        IrpSp->MajorFunction = IRP_MJ_WRITE;
        
        if (comdo->Flags & DO_BUFFERED_IO) {
            Irp->AssociatedIrp.SystemBuffer = buf2;

            Irp->Flags = IRP_BUFFERED_IO;
        } else if (comdo->Flags & DO_DIRECT_IO) {
            Irp->MdlAddress = IoAllocateMdl(buf2, length, FALSE, FALSE, NULL);
            if (!Irp->MdlAddress) {
                DbgPrint("IoAllocateMdl failed\n");
                goto exit;
            }
            
            MmProbeAndLockPages(Irp->MdlAddress, KernelMode, IoWriteAccess);
        } else {
            Irp->UserBuffer = buf2;
        }

        IrpSp->Parameters.Write.Length = length;
        IrpSp->Parameters.Write.ByteOffset = offset;
        
        Irp->UserIosb = &context->iosb;

        Irp->UserEvent = &context->Event;

        IoSetCompletionRoutine(Irp, dbg_completion, context, TRUE, TRUE, TRUE);

        Status = IoCallDriver(comdo, Irp);

        if (Status == STATUS_PENDING) {
            KeWaitForSingleObject(&context->Event, Executive, KernelMode, FALSE, NULL);
            Status = context->iosb.Status;
        }
        
        if (comdo->Flags & DO_DIRECT_IO) {
            MmUnlockPages(Irp->MdlAddress);
            IoFreeMdl(Irp->MdlAddress);
        }
        
        if (!NT_SUCCESS(Status)) {
            DbgPrint("failed to write to COM1 - error %08x\n", Status);
            goto exit;
        }
        
exit:
        IoFreeIrp(Irp);
    } else if (log_handle != NULL) {
        IO_STATUS_BLOCK iosb;
        
        length = (UINT32)strlen(buf2);
        
        Status = ZwWriteFile(log_handle, NULL, NULL, NULL, &iosb, buf2, length, NULL, NULL);
        
        if (!NT_SUCCESS(Status)) {
            DbgPrint("failed to write to file - error %08x\n", Status);
        }
    }
    
exit2:
    va_end(ap);
    
    if (context)
        ExFreePool(context);
    
    if (buf2)
        ExFreePool(buf2);
}
#endif

UINT64 sector_align( UINT64 NumberToBeAligned, UINT64 Alignment )
{
    if( Alignment & ( Alignment - 1 ) )
    {
        //
        //  Alignment not a power of 2
        //  Just returning
        //
        return NumberToBeAligned;
    }
    if( ( NumberToBeAligned & ( Alignment - 1 ) ) != 0 )
    {
        NumberToBeAligned = NumberToBeAligned + Alignment;
        NumberToBeAligned = NumberToBeAligned & ( ~ (Alignment-1) );
    }
    return NumberToBeAligned;
}

BOOL is_top_level(PIRP Irp) {
    if (!IoGetTopLevelIrp()) {
        IoSetTopLevelIrp(Irp);
        return TRUE;
    }

    return FALSE;
}

static void STDCALL DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING dosdevice_nameW;

    ERR("DriverUnload\n");
    
    free_cache();
    
    IoUnregisterFileSystem(DriverObject->DeviceObject);
    
    if (notification_entry2)
        IoUnregisterPlugPlayNotificationEx(notification_entry2);
    
    if (notification_entry3)
        IoUnregisterPlugPlayNotificationEx(notification_entry3);
    
    if (notification_entry)
        IoUnregisterPlugPlayNotificationEx(notification_entry);
   
    dosdevice_nameW.Buffer = dosdevice_name;
    dosdevice_nameW.Length = dosdevice_nameW.MaximumLength = (USHORT)wcslen(dosdevice_name) * sizeof(WCHAR);

    IoDeleteSymbolicLink(&dosdevice_nameW);
    IoDeleteDevice(DriverObject->DeviceObject);
    
    while (!IsListEmpty(&uid_map_list)) {
        LIST_ENTRY* le = RemoveHeadList(&uid_map_list);
        uid_map* um = CONTAINING_RECORD(le, uid_map, listentry);
        
        ExFreePool(um->sid);

        ExFreePool(um);
    }
    
    // FIXME - free volumes and their devpaths
    
#ifdef _DEBUG
    if (comfo)
        ObDereferenceObject(comfo);
    
    if (log_handle)
        ZwClose(log_handle);
#endif
    
    ExDeleteResourceLite(&global_loading_lock);
    ExDeleteResourceLite(&volume_list_lock);
    
    if (log_device.Buffer)
        ExFreePool(log_device.Buffer);
    
    if (log_file.Buffer)
        ExFreePool(log_file.Buffer);
    
    if (registry_path.Buffer)
        ExFreePool(registry_path.Buffer);
}

static BOOL STDCALL get_last_inode(device_extension* Vcb, root* r, PIRP Irp) {
    KEY searchkey;
    traverse_ptr tp, prev_tp;
    NTSTATUS Status;
    
    // get last entry
    searchkey.obj_id = 0xffffffffffffffff;
    searchkey.obj_type = 0xff;
    searchkey.offset = 0xffffffffffffffff;
    
    Status = find_item(Vcb, r, &tp, &searchkey, FALSE, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08x\n", Status);
        return FALSE;
    }
    
    if (tp.item->key.obj_type == TYPE_INODE_ITEM || (tp.item->key.obj_type == TYPE_ROOT_ITEM && !(tp.item->key.obj_id & 0x8000000000000000))) {
        r->lastinode = tp.item->key.obj_id;
        TRACE("last inode for tree %llx is %llx\n", r->id, r->lastinode);
        return TRUE;
    }
    
    while (find_prev_item(Vcb, &tp, &prev_tp, Irp)) {
        tp = prev_tp;
        
        TRACE("moving on to %llx,%x,%llx\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset);
        
        if (tp.item->key.obj_type == TYPE_INODE_ITEM || (tp.item->key.obj_type == TYPE_ROOT_ITEM && !(tp.item->key.obj_id & 0x8000000000000000))) {
            r->lastinode = tp.item->key.obj_id;
            TRACE("last inode for tree %llx is %llx\n", r->id, r->lastinode);
            return TRUE;
        }
    }
    
    r->lastinode = SUBVOL_ROOT_INODE;
    
    WARN("no INODE_ITEMs in tree %llx\n", r->id);
    
    return TRUE;
}

BOOL extract_xattr(void* item, USHORT size, char* name, UINT8** data, UINT16* datalen) {
    DIR_ITEM* xa = (DIR_ITEM*)item;
    USHORT xasize;
    
    while (TRUE) {
        if (size < sizeof(DIR_ITEM) || size < (sizeof(DIR_ITEM) - 1 + xa->m + xa->n)) {
            WARN("DIR_ITEM is truncated\n");
            return FALSE;
        }
        
        if (xa->n == strlen(name) && RtlCompareMemory(name, xa->name, xa->n) == xa->n) {
            TRACE("found xattr %s\n", name);
            
            *datalen = xa->m;
            
            if (xa->m > 0) {
                *data = ExAllocatePoolWithTag(PagedPool, xa->m, ALLOC_TAG);
                if (!*data) {
                    ERR("out of memory\n");
                    return FALSE;
                }
                
                RtlCopyMemory(*data, &xa->name[xa->n], xa->m);
            } else
                *data = NULL;
            
            return TRUE;
        }
        
        xasize = sizeof(DIR_ITEM) - 1 + xa->m + xa->n;

        if (size > xasize) {
            size -= xasize;
            xa = (DIR_ITEM*)&xa->name[xa->m + xa->n];
        } else
            break;
    }
    
    TRACE("xattr %s not found\n", name);
    
    return FALSE;
}

BOOL STDCALL get_xattr(device_extension* Vcb, root* subvol, UINT64 inode, char* name, UINT32 crc32, UINT8** data, UINT16* datalen, PIRP Irp) {
    KEY searchkey;
    traverse_ptr tp;
    NTSTATUS Status;
    
    TRACE("(%p, %llx, %llx, %s, %08x, %p, %p)\n", Vcb, subvol->id, inode, name, crc32, data, datalen);
    
    searchkey.obj_id = inode;
    searchkey.obj_type = TYPE_XATTR_ITEM;
    searchkey.offset = crc32;
    
    Status = find_item(Vcb, subvol, &tp, &searchkey, FALSE, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08x\n", Status);
        return FALSE;
    }
    
    if (keycmp(tp.item->key, searchkey)) {
        TRACE("could not find item (%llx,%x,%llx)\n", searchkey.obj_id, searchkey.obj_type, searchkey.offset);
        return FALSE;
    }
    
    if (tp.item->size < sizeof(DIR_ITEM)) {
        ERR("(%llx,%x,%llx) was %u bytes, expected at least %u\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, tp.item->size, sizeof(DIR_ITEM));
        return FALSE;
    }
    
    return extract_xattr(tp.item->data, tp.item->size, name, data, datalen);
}

static NTSTATUS STDCALL drv_close(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    NTSTATUS Status;
    PIO_STACK_LOCATION IrpSp;
    device_extension* Vcb = DeviceObject->DeviceExtension;
    BOOL top_level;

    TRACE("close\n");
    
    FsRtlEnterFileSystem();

    top_level = is_top_level(Irp);
    
    if (DeviceObject == devobj) {
        TRACE("Closing file system\n");
        Status = STATUS_SUCCESS;
        goto end;
    } else if (Vcb && Vcb->type == VCB_TYPE_VOLUME) {
        Status = vol_close(DeviceObject, Irp);
        goto end;
    } else if (!Vcb || Vcb->type != VCB_TYPE_FS) {
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }
    
    IrpSp = IoGetCurrentIrpStackLocation(Irp);
    
    // FIXME - unmount if called for volume
    // FIXME - call FsRtlNotifyUninitializeSync(&Vcb->NotifySync) if unmounting
    
    Status = close_file(DeviceObject->DeviceExtension, IrpSp->FileObject);

end:
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;
    
    IoCompleteRequest( Irp, IO_DISK_INCREMENT );
    
    if (top_level) 
        IoSetTopLevelIrp(NULL);
    
    FsRtlExitFileSystem();
    
    TRACE("returning %08x\n", Status);

    return Status;
}

static NTSTATUS STDCALL drv_flush_buffers(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    NTSTATUS Status;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation( Irp );
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    fcb* fcb = FileObject->FsContext;
    device_extension* Vcb = DeviceObject->DeviceExtension;
    BOOL top_level;

    TRACE("flush buffers\n");
    
    FsRtlEnterFileSystem();

    top_level = is_top_level(Irp);
    
    if (Vcb && Vcb->type == VCB_TYPE_VOLUME) {
        Status = vol_flush_buffers(DeviceObject, Irp);
        goto end;
    } else if (!Vcb || Vcb->type != VCB_TYPE_FS) {
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }
    
    Status = STATUS_SUCCESS;
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;
    
    if (fcb->type != BTRFS_TYPE_DIRECTORY) {
        CcFlushCache(&fcb->nonpaged->segment_object, NULL, 0, &Irp->IoStatus);
        
        if (fcb->Header.PagingIoResource) {
            ExAcquireResourceExclusiveLite(fcb->Header.PagingIoResource, TRUE);
            ExReleaseResourceLite(fcb->Header.PagingIoResource);
        }
        
        Status = Irp->IoStatus.Status;
    }
    
end:
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
    if (top_level) 
        IoSetTopLevelIrp(NULL);
    
    FsRtlExitFileSystem();

    return Status;
}

static void calculate_total_space(device_extension* Vcb, LONGLONG* totalsize, LONGLONG* freespace) {
    UINT16 nfactor, dfactor;
    UINT64 sectors_used;
    
    if (Vcb->data_flags & BLOCK_FLAG_DUPLICATE || Vcb->data_flags & BLOCK_FLAG_RAID1 || Vcb->data_flags & BLOCK_FLAG_RAID10) {
        nfactor = 1;
        dfactor = 2;
    } else if (Vcb->data_flags & BLOCK_FLAG_RAID5) {
        nfactor = Vcb->superblock.num_devices - 1;
        dfactor = Vcb->superblock.num_devices;
    } else if (Vcb->data_flags & BLOCK_FLAG_RAID6) {
        nfactor = Vcb->superblock.num_devices - 2;
        dfactor = Vcb->superblock.num_devices;
    } else {
        nfactor = 1;
        dfactor = 1;
    }
    
    sectors_used = Vcb->superblock.bytes_used / Vcb->superblock.sector_size;
    
    *totalsize = (Vcb->superblock.total_bytes / Vcb->superblock.sector_size) * nfactor / dfactor;
    *freespace = sectors_used > *totalsize ? 0 : (*totalsize - sectors_used);
}

// This function exists because we have to lie about our FS type in certain situations. 
// MPR!MprGetConnection queries the FS type, and compares it to a whitelist. If it doesn't match,
// it will return ERROR_NO_NET_OR_BAD_PATH, which prevents UAC from working.
// The command mklink refuses to create hard links on anything other than NTFS, so we have to
// blacklist cmd.exe too.

static BOOL lie_about_fs_type() {
    NTSTATUS Status;
    PROCESS_BASIC_INFORMATION pbi;
    PPEB peb;
    LIST_ENTRY* le;
    ULONG retlen;
    
    static WCHAR mpr[] = L"MPR.DLL";
    static WCHAR cmd[] = L"CMD.EXE";
    UNICODE_STRING mprus, cmdus;
    
    mprus.Buffer = mpr;
    mprus.Length = mprus.MaximumLength = wcslen(mpr) * sizeof(WCHAR);
    cmdus.Buffer = cmd;
    cmdus.Length = cmdus.MaximumLength = wcslen(cmd) * sizeof(WCHAR);
    
    if (!PsGetCurrentProcess())
        return FALSE;
    
    Status = ZwQueryInformationProcess(NtCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), &retlen);
    
    if (!NT_SUCCESS(Status)) {
        ERR("ZwQueryInformationProcess returned %08x\n", Status);
        return FALSE;
    }

    if (!pbi.PebBaseAddress)
        return FALSE;
    
    peb = pbi.PebBaseAddress;
    
    if (!peb->Ldr)
        return FALSE;
    
    le = peb->Ldr->InMemoryOrderModuleList.Flink;
    while (le != &peb->Ldr->InMemoryOrderModuleList) {
        LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(le, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        BOOL blacklist = FALSE;
        
        if (entry->FullDllName.Length >= mprus.Length) {
            UNICODE_STRING name;
            
            name.Buffer = &entry->FullDllName.Buffer[(entry->FullDllName.Length - mprus.Length) / sizeof(WCHAR)];
            name.Length = name.MaximumLength = mprus.Length;
            
            blacklist = FsRtlAreNamesEqual(&name, &mprus, TRUE, NULL);
        }
        
        if (!blacklist && entry->FullDllName.Length >= cmdus.Length) {
            UNICODE_STRING name;
            
            name.Buffer = &entry->FullDllName.Buffer[(entry->FullDllName.Length - cmdus.Length) / sizeof(WCHAR)];
            name.Length = name.MaximumLength = cmdus.Length;
            
            blacklist = FsRtlAreNamesEqual(&name, &cmdus, TRUE, NULL);
        }
        
        if (blacklist) {
            void** frames;
            USHORT i, num_frames;
            
            frames = ExAllocatePoolWithTag(PagedPool, 256 * sizeof(void*), ALLOC_TAG);

            num_frames = RtlWalkFrameChain(frames, 256, 1);
            
            for (i = 0; i < num_frames; i++) {
                // entry->Reserved3[1] appears to be the image size
                if (frames[i] >= entry->DllBase && (ULONG_PTR)frames[i] <= (ULONG_PTR)entry->DllBase + (ULONG_PTR)entry->Reserved3[1]) {
                    ExFreePool(frames);
                    return TRUE;
                }
            }
            
            ExFreePool(frames);
        }
        
        le = le->Flink;
    }

    return FALSE;
}

static NTSTATUS STDCALL drv_query_volume_information(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    PIO_STACK_LOCATION IrpSp;
    NTSTATUS Status;
    ULONG BytesCopied = 0;
    device_extension* Vcb = DeviceObject->DeviceExtension;
    BOOL top_level;
    
    TRACE("query volume information\n");
    
    FsRtlEnterFileSystem();
    top_level = is_top_level(Irp);
    
    if (Vcb && Vcb->type == VCB_TYPE_VOLUME) {
        Status = vol_query_volume_information(DeviceObject, Irp);
        goto end;
    } else if (!Vcb || Vcb->type != VCB_TYPE_FS) {
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }
    
    IrpSp = IoGetCurrentIrpStackLocation(Irp);
    
    Status = STATUS_NOT_IMPLEMENTED;
    
    switch (IrpSp->Parameters.QueryVolume.FsInformationClass) {
        case FileFsAttributeInformation:
        {
            FILE_FS_ATTRIBUTE_INFORMATION* data = Irp->AssociatedIrp.SystemBuffer;
            BOOL overflow = FALSE;
            WCHAR* fs_name = (Irp->RequestorMode == UserMode && lie_about_fs_type()) ? L"NTFS" : L"Btrfs";
            ULONG fs_name_len = wcslen(fs_name) * sizeof(WCHAR);
            ULONG orig_fs_name_len = fs_name_len;
            
            TRACE("FileFsAttributeInformation\n");
            
            if (IrpSp->Parameters.QueryVolume.Length < sizeof(FILE_FS_ATTRIBUTE_INFORMATION) - sizeof(WCHAR) + fs_name_len) {
                if (IrpSp->Parameters.QueryVolume.Length > sizeof(FILE_FS_ATTRIBUTE_INFORMATION) - sizeof(WCHAR))
                    fs_name_len = IrpSp->Parameters.QueryVolume.Length - sizeof(FILE_FS_ATTRIBUTE_INFORMATION) + sizeof(WCHAR);
                else
                    fs_name_len = 0;
                
                overflow = TRUE;
            }
            
            data->FileSystemAttributes = FILE_CASE_PRESERVED_NAMES | FILE_CASE_SENSITIVE_SEARCH |
                                         FILE_UNICODE_ON_DISK | FILE_NAMED_STREAMS | FILE_SUPPORTS_HARD_LINKS | FILE_PERSISTENT_ACLS |
                                         FILE_SUPPORTS_REPARSE_POINTS | FILE_SUPPORTS_SPARSE_FILES | FILE_SUPPORTS_OBJECT_IDS |
                                         FILE_SUPPORTS_OPEN_BY_FILE_ID | FILE_SUPPORTS_EXTENDED_ATTRIBUTES;
            if (Vcb->readonly)
                data->FileSystemAttributes |= FILE_READ_ONLY_VOLUME;
                                         
            // should also be FILE_FILE_COMPRESSION when supported
            data->MaximumComponentNameLength = 255; // FIXME - check
            data->FileSystemNameLength = orig_fs_name_len;
            RtlCopyMemory(data->FileSystemName, fs_name, fs_name_len);
            
            BytesCopied = sizeof(FILE_FS_ATTRIBUTE_INFORMATION) - sizeof(WCHAR) + fs_name_len;
            Status = overflow ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
            break;
        }

        case FileFsDeviceInformation:
        {
            FILE_FS_DEVICE_INFORMATION* ffdi = Irp->AssociatedIrp.SystemBuffer;
            
            TRACE("FileFsDeviceInformation\n");
            
            ffdi->DeviceType = FILE_DEVICE_DISK;
            
            ExAcquireResourceSharedLite(&Vcb->tree_lock, TRUE);
            ffdi->Characteristics = Vcb->Vpb->RealDevice->Characteristics;
            ExReleaseResourceLite(&Vcb->tree_lock);
            
            if (Vcb->readonly)
                ffdi->Characteristics |= FILE_READ_ONLY_DEVICE;
            else
                ffdi->Characteristics &= ~FILE_READ_ONLY_DEVICE;

            BytesCopied = sizeof(FILE_FS_DEVICE_INFORMATION);
            Status = STATUS_SUCCESS;
            
            break;
        }

        case FileFsFullSizeInformation:
        {
            FILE_FS_FULL_SIZE_INFORMATION* ffsi = Irp->AssociatedIrp.SystemBuffer;
            
            TRACE("FileFsFullSizeInformation\n");
            
            calculate_total_space(Vcb, &ffsi->TotalAllocationUnits.QuadPart, &ffsi->ActualAvailableAllocationUnits.QuadPart);
            ffsi->CallerAvailableAllocationUnits.QuadPart = ffsi->ActualAvailableAllocationUnits.QuadPart;
            ffsi->SectorsPerAllocationUnit = 1;
            ffsi->BytesPerSector = Vcb->superblock.sector_size;
            
            BytesCopied = sizeof(FILE_FS_FULL_SIZE_INFORMATION);
            Status = STATUS_SUCCESS;
            
            break;
        }

        case FileFsObjectIdInformation:
        {
            FILE_FS_OBJECTID_INFORMATION* ffoi = Irp->AssociatedIrp.SystemBuffer;
            
            TRACE("FileFsObjectIdInformation\n");
            
            RtlCopyMemory(ffoi->ObjectId, &Vcb->superblock.uuid.uuid[0], sizeof(UCHAR) * 16);
            RtlZeroMemory(ffoi->ExtendedInfo, sizeof(ffoi->ExtendedInfo));
            
            BytesCopied = sizeof(FILE_FS_OBJECTID_INFORMATION);
            Status = STATUS_SUCCESS;
            
            break;
        }

        case FileFsSizeInformation:
        {
            FILE_FS_SIZE_INFORMATION* ffsi = Irp->AssociatedIrp.SystemBuffer;
            
            TRACE("FileFsSizeInformation\n");
            
            calculate_total_space(Vcb, &ffsi->TotalAllocationUnits.QuadPart, &ffsi->AvailableAllocationUnits.QuadPart);
            ffsi->SectorsPerAllocationUnit = 1;
            ffsi->BytesPerSector = Vcb->superblock.sector_size;
            
            BytesCopied = sizeof(FILE_FS_SIZE_INFORMATION);
            Status = STATUS_SUCCESS;
            
            break;
        }

        case FileFsVolumeInformation:
        {
            FILE_FS_VOLUME_INFORMATION* data = Irp->AssociatedIrp.SystemBuffer;
            FILE_FS_VOLUME_INFORMATION ffvi;
            BOOL overflow = FALSE;
            ULONG label_len, orig_label_len;
            
            TRACE("FileFsVolumeInformation\n");
            TRACE("max length = %u\n", IrpSp->Parameters.QueryVolume.Length);
            
            ExAcquireResourceSharedLite(&Vcb->tree_lock, TRUE);
            
//             orig_label_len = label_len = (ULONG)(wcslen(Vcb->label) * sizeof(WCHAR));
            RtlUTF8ToUnicodeN(NULL, 0, &label_len, Vcb->superblock.label, (ULONG)strlen(Vcb->superblock.label));
            orig_label_len = label_len;
            
            if (IrpSp->Parameters.QueryVolume.Length < sizeof(FILE_FS_VOLUME_INFORMATION) - sizeof(WCHAR) + label_len) {
                if (IrpSp->Parameters.QueryVolume.Length > sizeof(FILE_FS_VOLUME_INFORMATION) - sizeof(WCHAR))
                    label_len = IrpSp->Parameters.QueryVolume.Length - sizeof(FILE_FS_VOLUME_INFORMATION) + sizeof(WCHAR);
                else
                    label_len = 0;
                
                overflow = TRUE;
            }
            
            TRACE("label_len = %u\n", label_len);
            
            ffvi.VolumeCreationTime.QuadPart = 0; // FIXME
            ffvi.VolumeSerialNumber = Vcb->superblock.uuid.uuid[12] << 24 | Vcb->superblock.uuid.uuid[13] << 16 | Vcb->superblock.uuid.uuid[14] << 8 | Vcb->superblock.uuid.uuid[15];
            ffvi.VolumeLabelLength = orig_label_len;
            ffvi.SupportsObjects = FALSE;
            
            RtlCopyMemory(data, &ffvi, min(sizeof(FILE_FS_VOLUME_INFORMATION) - sizeof(WCHAR), IrpSp->Parameters.QueryVolume.Length));
            
            if (label_len > 0) {
                ULONG bytecount;
                
//                 RtlCopyMemory(&data->VolumeLabel[0], Vcb->label, label_len);
                RtlUTF8ToUnicodeN(&data->VolumeLabel[0], label_len, &bytecount, Vcb->superblock.label, (ULONG)strlen(Vcb->superblock.label));
                TRACE("label = %.*S\n", label_len / sizeof(WCHAR), data->VolumeLabel);
            }
            
            ExReleaseResourceLite(&Vcb->tree_lock);

            BytesCopied = sizeof(FILE_FS_VOLUME_INFORMATION) - sizeof(WCHAR) + label_len;
            Status = overflow ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
            break;
        }
        
#ifdef _MSC_VER // not in mingw yet
        case FileFsSectorSizeInformation:
        {
            FILE_FS_SECTOR_SIZE_INFORMATION* data = Irp->AssociatedIrp.SystemBuffer;
            
            data->LogicalBytesPerSector = Vcb->superblock.sector_size;
            data->PhysicalBytesPerSectorForAtomicity = Vcb->superblock.sector_size;
            data->PhysicalBytesPerSectorForPerformance = Vcb->superblock.sector_size;
            data->FileSystemEffectivePhysicalBytesPerSectorForAtomicity = Vcb->superblock.sector_size;
            data->ByteOffsetForSectorAlignment = 0;
            data->ByteOffsetForPartitionAlignment = 0;
            
            data->Flags = SSINFO_FLAGS_ALIGNED_DEVICE | SSINFO_FLAGS_PARTITION_ALIGNED_ON_DEVICE;
            
            if (Vcb->trim && !Vcb->options.no_trim)
                data->Flags |= SSINFO_FLAGS_TRIM_ENABLED;
            
            BytesCopied = sizeof(FILE_FS_SECTOR_SIZE_INFORMATION);
  
            break;
        }
#endif

        default:
            Status = STATUS_INVALID_PARAMETER;
            WARN("unknown FsInformationClass %u\n", IrpSp->Parameters.QueryVolume.FsInformationClass);
            break;
    }
    
//     if (NT_SUCCESS(Status) && IrpSp->Parameters.QueryVolume.Length < BytesCopied) { // FIXME - should not copy anything if overflow
//         WARN("overflow: %u < %u\n", IrpSp->Parameters.QueryVolume.Length, BytesCopied);
//         BytesCopied = IrpSp->Parameters.QueryVolume.Length;
//         Status = STATUS_BUFFER_OVERFLOW;
//     }

    if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_OVERFLOW)
        Irp->IoStatus.Information = 0;
    else
        Irp->IoStatus.Information = BytesCopied;
    
end:
    Irp->IoStatus.Status = Status;
    
    IoCompleteRequest( Irp, IO_DISK_INCREMENT );
    
    if (top_level) 
        IoSetTopLevelIrp(NULL);
    
    FsRtlExitFileSystem();
    
    TRACE("query volume information returning %08x\n", Status);

    return Status;
}

static NTSTATUS STDCALL read_completion(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID conptr) {
    read_context* context = conptr;
    
//     DbgPrint("read_completion\n");
    
    context->iosb = Irp->IoStatus;
    KeSetEvent(&context->Event, 0, FALSE);
    
//     return STATUS_SUCCESS;
    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS create_root(device_extension* Vcb, UINT64 id, root** rootptr, BOOL no_tree, UINT64 offset, PIRP Irp) {
    NTSTATUS Status;
    root* r;
    tree* t;
    ROOT_ITEM* ri;
    traverse_ptr tp;
    
    r = ExAllocatePoolWithTag(PagedPool, sizeof(root), ALLOC_TAG);
    if (!r) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    r->nonpaged = ExAllocatePoolWithTag(NonPagedPool, sizeof(root_nonpaged), ALLOC_TAG);
    if (!r->nonpaged) {
        ERR("out of memory\n");
        ExFreePool(r);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    if (!no_tree) {
        t = ExAllocatePoolWithTag(PagedPool, sizeof(tree), ALLOC_TAG);
        if (!t) {
            ERR("out of memory\n");
            ExFreePool(r->nonpaged);
            ExFreePool(r);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        
        t->is_unique = TRUE;
        t->uniqueness_determined = TRUE;
        t->buf = NULL;
    }
    
    ri = ExAllocatePoolWithTag(PagedPool, sizeof(ROOT_ITEM), ALLOC_TAG);
    if (!ri) {
        ERR("out of memory\n");
        
        if (!no_tree)
            ExFreePool(t);
        
        ExFreePool(r->nonpaged);
        ExFreePool(r);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    r->id = id;
    r->treeholder.address = 0;
    r->treeholder.generation = Vcb->superblock.generation;
    r->treeholder.tree = no_tree ? NULL : t;
    r->lastinode = 0;
    r->path.Buffer = NULL;
    RtlZeroMemory(&r->root_item, sizeof(ROOT_ITEM));
    r->root_item.num_references = 1;
    InitializeListHead(&r->fcbs);
    
    RtlCopyMemory(ri, &r->root_item, sizeof(ROOT_ITEM));
    
    // We ask here for a traverse_ptr to the item we're inserting, so we can
    // copy some of the tree's variables
    
    Status = insert_tree_item(Vcb, Vcb->root_root, id, TYPE_ROOT_ITEM, offset, ri, sizeof(ROOT_ITEM), &tp, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("insert_tree_item returned %08x\n", Status);
        ExFreePool(ri);
        
        if (!no_tree)
            ExFreePool(t);
        
        ExFreePool(r->nonpaged);
        ExFreePool(r);
        return Status;
    }
        
    ExInitializeResourceLite(&r->nonpaged->load_tree_lock);
    
    InsertTailList(&Vcb->roots, &r->list_entry);
    
    if (!no_tree) {
        t->header.fs_uuid = tp.tree->header.fs_uuid;
        t->header.address = 0;
        t->header.flags = HEADER_FLAG_MIXED_BACKREF | 1; // 1 == "written"? Why does the Linux driver record this?
        t->header.chunk_tree_uuid = tp.tree->header.chunk_tree_uuid;
        t->header.generation = Vcb->superblock.generation;
        t->header.tree_id = id;
        t->header.num_items = 0;
        t->header.level = 0;

        t->has_address = FALSE;
        t->size = 0;
        t->Vcb = Vcb;
        t->parent = NULL;
        t->paritem = NULL;
        t->root = r;
        
        InitializeListHead(&t->itemlist);
    
        t->new_address = 0;
        t->has_new_address = FALSE;
        t->updated_extents = FALSE;
        
        InsertTailList(&Vcb->trees, &t->list_entry);
        t->list_entry_hash.Flink = NULL;
        
        t->write = TRUE;
        Vcb->need_write = TRUE;
    }
    
    *rootptr = r;

    return STATUS_SUCCESS;
}

static NTSTATUS STDCALL set_label(device_extension* Vcb, FILE_FS_LABEL_INFORMATION* ffli) {
    ULONG utf8len;
    NTSTATUS Status;
    USHORT vollen, i;
//     HANDLE h;
    
    TRACE("label = %.*S\n", ffli->VolumeLabelLength / sizeof(WCHAR), ffli->VolumeLabel);
    
    vollen = ffli->VolumeLabelLength;
    
    for (i = 0; i < ffli->VolumeLabelLength / sizeof(WCHAR); i++) {
        if (ffli->VolumeLabel[i] == 0) {
            vollen = i * sizeof(WCHAR);
            break;
        } else if (ffli->VolumeLabel[i] == '/' || ffli->VolumeLabel[i] == '\\') {
            Status = STATUS_INVALID_VOLUME_LABEL;
            goto end;
        }
    }
    
    if (vollen == 0) {
        utf8len = 0;
    } else {
        Status = RtlUnicodeToUTF8N(NULL, 0, &utf8len, ffli->VolumeLabel, vollen);
        if (!NT_SUCCESS(Status))
            goto end;
        
        if (utf8len > MAX_LABEL_SIZE) {
            Status = STATUS_INVALID_VOLUME_LABEL;
            goto end;
        }
    }
    
    ExAcquireResourceExclusiveLite(&Vcb->tree_lock, TRUE);
    
    if (utf8len > 0) {
        Status = RtlUnicodeToUTF8N((PCHAR)&Vcb->superblock.label, MAX_LABEL_SIZE, &utf8len, ffli->VolumeLabel, vollen);
        if (!NT_SUCCESS(Status))
            goto release;
    } else
        Status = STATUS_SUCCESS;
    
    if (utf8len < MAX_LABEL_SIZE)
        RtlZeroMemory(Vcb->superblock.label + utf8len, MAX_LABEL_SIZE - utf8len);
    
//     test_tree_deletion(Vcb); // TESTING
//     test_tree_splitting(Vcb);
//     test_dropping_tree(Vcb);
//     test_creating_root(Vcb);
//     test_alloc_chunk(Vcb);
//     test_space_list(Vcb);
//     test_calc_thread(Vcb);
    
    Vcb->need_write = TRUE;
    
//     PsCreateSystemThread(&h, 0, NULL, NULL, NULL, tree_test, Vcb);
    
release:  
    ExReleaseResourceLite(&Vcb->tree_lock);

end:
    TRACE("returning %08x\n", Status);

    return Status;
}

static NTSTATUS STDCALL drv_set_volume_information(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    device_extension* Vcb = DeviceObject->DeviceExtension;
    NTSTATUS Status;
    BOOL top_level;

    TRACE("set volume information\n");
    
    FsRtlEnterFileSystem();

    top_level = is_top_level(Irp);
    
    if (Vcb && Vcb->type == VCB_TYPE_VOLUME) {
        Status = vol_set_volume_information(DeviceObject, Irp);
        goto end;
    } else if (!Vcb || Vcb->type != VCB_TYPE_FS) {
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }
    
    Status = STATUS_NOT_IMPLEMENTED;
    
    if (Vcb->readonly) {
        Status = STATUS_MEDIA_WRITE_PROTECTED;
        goto end;
    }
    
    if (Vcb->removing || Vcb->locked) {
        Status = STATUS_ACCESS_DENIED;
        goto end;
    }
    
    switch (IrpSp->Parameters.SetVolume.FsInformationClass) {
        case FileFsControlInformation:
            FIXME("STUB: FileFsControlInformation\n");
            break;

        case FileFsLabelInformation:
            TRACE("FileFsLabelInformation\n");
    
            Status = set_label(Vcb, Irp->AssociatedIrp.SystemBuffer);
            break;

        case FileFsObjectIdInformation:
            FIXME("STUB: FileFsObjectIdInformation\n");
            break;

        default:
            WARN("Unrecognized FsInformationClass 0x%x\n", IrpSp->Parameters.SetVolume.FsInformationClass);
            break;
    }
    
end:
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest( Irp, IO_NO_INCREMENT );
    
    if (top_level) 
        IoSetTopLevelIrp(NULL);
    
    FsRtlExitFileSystem();

    return Status;
}

static WCHAR* file_desc_fcb(fcb* fcb) {
    char s[60];
    UNICODE_STRING us;
    ANSI_STRING as;
    
    if (fcb->debug_desc)
        return fcb->debug_desc;
    
    if (fcb == fcb->Vcb->volume_fcb)
        return L"volume FCB";
    
    fcb->debug_desc = ExAllocatePoolWithTag(PagedPool, 60 * sizeof(WCHAR), ALLOC_TAG);
    if (!fcb->debug_desc)
        return L"(memory error)";
    
    // I know this is pretty hackish...
    // GCC doesn't like %llx in sprintf, and MSVC won't let us use swprintf
    // without the CRT, which breaks drivers.
    
    sprintf(s, "subvol %x, inode %x", (UINT32)fcb->subvol->id, (UINT32)fcb->inode);
    
    as.Buffer = s;
    as.Length = as.MaximumLength = strlen(s);
    
    us.Buffer = fcb->debug_desc;
    us.MaximumLength = 60 * sizeof(WCHAR);
    us.Length = 0;
    
    RtlAnsiStringToUnicodeString(&us, &as, FALSE);
    
    us.Buffer[us.Length / sizeof(WCHAR)] = 0;
    
    return fcb->debug_desc;
}

WCHAR* file_desc_fileref(file_ref* fileref) {
    NTSTATUS Status;
    UNICODE_STRING fn;
    ULONG reqlen;
    
    if (fileref->debug_desc)
        return fileref->debug_desc;
    
    fn.Length = fn.MaximumLength = 0;
    Status = fileref_get_filename(fileref, &fn, NULL, &reqlen);
    if (Status != STATUS_BUFFER_OVERFLOW)
        return L"ERROR";
    
    fileref->debug_desc = ExAllocatePoolWithTag(PagedPool, reqlen + sizeof(WCHAR), ALLOC_TAG);
    if (!fileref->debug_desc)
        return L"(memory error)";
    
    fn.Buffer = fileref->debug_desc;
    fn.Length = 0;
    fn.MaximumLength = reqlen + sizeof(WCHAR);
    
    Status = fileref_get_filename(fileref, &fn, NULL, &reqlen);
    if (!NT_SUCCESS(Status)) {
        ExFreePool(fileref->debug_desc);
        fileref->debug_desc = NULL;
        return L"ERROR";
    }
    
    fileref->debug_desc[fn.Length / sizeof(WCHAR)] = 0;

    return fileref->debug_desc;
}

WCHAR* file_desc(PFILE_OBJECT FileObject) {
    fcb* fcb = FileObject->FsContext;
    ccb* ccb = FileObject->FsContext2;
    file_ref* fileref = ccb ? ccb->fileref : NULL;
    
    if (fileref)
        return file_desc_fileref(fileref);
    else
        return file_desc_fcb(fcb);
}

void send_notification_fileref(file_ref* fileref, ULONG filter_match, ULONG action) {
    UNICODE_STRING fn;
    NTSTATUS Status;
    ULONG reqlen;
    USHORT name_offset;
    fcb* fcb = fileref->fcb;
    
    fn.Length = fn.MaximumLength = 0;
    Status = fileref_get_filename(fileref, &fn, NULL, &reqlen);
    if (Status != STATUS_BUFFER_OVERFLOW) {
        ERR("fileref_get_filename returned %08x\n", Status);
        return;
    }
    
    fn.Buffer = ExAllocatePoolWithTag(PagedPool, reqlen, ALLOC_TAG);
    if (!fn.Buffer) {
        ERR("out of memory\n");
        return;
    }
    
    fn.MaximumLength = reqlen;
    fn.Length = 0;
    
    Status = fileref_get_filename(fileref, &fn, &name_offset, &reqlen);
    if (!NT_SUCCESS(Status)) {
        ERR("fileref_get_filename returned %08x\n", Status);
        ExFreePool(fn.Buffer);
        return;
    }
    
    FsRtlNotifyFilterReportChange(fcb->Vcb->NotifySync, &fcb->Vcb->DirNotifyList, (PSTRING)&fn, name_offset,
                                  NULL, NULL, filter_match, action, NULL, NULL);
    ExFreePool(fn.Buffer);
}

void send_notification_fcb(file_ref* fileref, ULONG filter_match, ULONG action) {
    fcb* fcb = fileref->fcb;
    LIST_ENTRY* le;
    NTSTATUS Status;
    
    // no point looking for hardlinks if st_nlink == 1
    if (fileref->fcb->inode_item.st_nlink == 1) {
        send_notification_fileref(fileref, filter_match, action);
        return;
    }
    
    ExAcquireResourceExclusiveLite(&fcb->Vcb->fcb_lock, TRUE);
    
    le = fcb->hardlinks.Flink;
    while (le != &fcb->hardlinks) {
        hardlink* hl = CONTAINING_RECORD(le, hardlink, list_entry);
        file_ref* parfr;
        
        Status = open_fileref_by_inode(fcb->Vcb, fcb->subvol, hl->parent, &parfr, NULL);
        
        if (!NT_SUCCESS(Status)) {
            ERR("open_fileref_by_inode returned %08x\n", Status);
        } else if (!parfr->deleted) {
            LIST_ENTRY* le2;
            BOOL found = FALSE, deleted = FALSE;
            UNICODE_STRING* fn;
            
            le2 = parfr->children.Flink;
            while (le2 != &parfr->children) {
                file_ref* fr2 = CONTAINING_RECORD(le2, file_ref, list_entry);
                
                if (fr2->index == hl->index) {
                    found = TRUE;
                    deleted = fr2->deleted;
                    
                    if (!deleted)
                        fn = &fr2->filepart;
                    
                    break;
                }
                
                le2 = le2->Flink;
            }
            
            if (!found)
                fn = &hl->name;
            
            if (!deleted) {
                ULONG reqlen;
                UNICODE_STRING path;
                
                path.Length = path.MaximumLength = 0;
                
                Status = fileref_get_filename(parfr, &path, NULL, &reqlen);
                if (Status != STATUS_BUFFER_OVERFLOW)
                    ERR("fileref_get_filename returned %08x\n", Status);
                else {
                    UNICODE_STRING fn2;
                    ULONG name_offset;
                    
                    path.MaximumLength = reqlen;
                    path.Buffer = ExAllocatePoolWithTag(PagedPool, reqlen, ALLOC_TAG);
                    if (!path.Buffer)
                        ERR("out of memory\n");
                    else {
                        Status = fileref_get_filename(parfr, &path, NULL, &reqlen);
                        
                        if (!NT_SUCCESS(Status))
                            ERR("fileref_get_filename returned %08x\n", Status);
                        else {
                            name_offset = path.Length;
                            if (parfr != fileref->fcb->Vcb->root_fileref) name_offset += sizeof(WCHAR);
                            
                            fn2.Length = fn2.MaximumLength = fn->Length + name_offset;
                            fn2.Buffer = ExAllocatePoolWithTag(PagedPool, fn2.MaximumLength, ALLOC_TAG);
                            
                            RtlCopyMemory(fn2.Buffer, path.Buffer, path.Length);
                            if (parfr != fileref->fcb->Vcb->root_fileref) fn2.Buffer[path.Length / sizeof(WCHAR)] = '\\';
                            RtlCopyMemory(&fn2.Buffer[name_offset / sizeof(WCHAR)], fn->Buffer, fn->Length);
                            
                            TRACE("%.*S\n", fn2.Length / sizeof(WCHAR), fn2.Buffer);
                            
                            FsRtlNotifyFilterReportChange(fcb->Vcb->NotifySync, &fcb->Vcb->DirNotifyList, (PSTRING)&fn2, name_offset,
                                                        NULL, NULL, filter_match, action, NULL, NULL);
                        }
                        
                        ExFreePool(fn2.Buffer);
                        ExFreePool(path.Buffer);
                    }
                }
            }
            
            free_fileref(fcb->Vcb, parfr);
        }
        
        le = le->Flink;
    }
    
    ExReleaseResourceLite(&fcb->Vcb->fcb_lock);
}

void mark_fcb_dirty(fcb* fcb) {
    if (!fcb->dirty) {
#ifdef DEBUG_FCB_REFCOUNTS
        LONG rc;
#endif
        dirty_fcb* dirt = ExAllocatePoolWithTag(NonPagedPool, sizeof(dirty_fcb), ALLOC_TAG);
        
        if (!dirt) {
            ExFreePool("out of memory\n");
            return;
        }
        
        fcb->dirty = TRUE;
        
#ifdef DEBUG_FCB_REFCOUNTS
        rc = InterlockedIncrement(&fcb->refcount);
        WARN("fcb %p: refcount now %i\n", fcb, rc);
#else
        InterlockedIncrement(&fcb->refcount);
#endif
        
        dirt->fcb = fcb;
        
        ExAcquireResourceExclusiveLite(&fcb->Vcb->dirty_fcbs_lock, TRUE);
        InsertTailList(&fcb->Vcb->dirty_fcbs, &dirt->list_entry);
        ExReleaseResourceLite(&fcb->Vcb->dirty_fcbs_lock);
    }
    
    fcb->Vcb->need_write = TRUE;
}

void mark_fileref_dirty(file_ref* fileref) {
    if (!fileref->dirty) {
        dirty_fileref* dirt = ExAllocatePoolWithTag(NonPagedPool, sizeof(dirty_fileref), ALLOC_TAG);
        
        if (!dirt) {
            ExFreePool("out of memory\n");
            return;
        }
        
        fileref->dirty = TRUE;
        increase_fileref_refcount(fileref);
        
        dirt->fileref = fileref;
        
        ExAcquireResourceExclusiveLite(&fileref->fcb->Vcb->dirty_filerefs_lock, TRUE);
        InsertTailList(&fileref->fcb->Vcb->dirty_filerefs, &dirt->list_entry);
        ExReleaseResourceLite(&fileref->fcb->Vcb->dirty_filerefs_lock);
    }
    
    fileref->fcb->Vcb->need_write = TRUE;
}

void free_fcb(fcb* fcb) {
    LONG rc;

// #ifdef DEBUG    
//     if (!ExIsResourceAcquiredExclusiveLite(&fcb->Vcb->fcb_lock) && !ExIsResourceAcquiredExclusiveLite(&fcb->Vcb->tree_lock)) {
//         ERR("fcb_lock not acquired exclusively\n");
//         int3;
//     }
// #endif

    rc = InterlockedDecrement(&fcb->refcount);
    
#ifdef DEBUG_FCB_REFCOUNTS
#ifdef DEBUG_LONG_MESSAGES
    ERR("fcb %p: refcount now %i (subvol %llx, inode %llx)\n", fcb, rc, fcb->subvol ? fcb->subvol->id : 0, fcb->inode);
#else
    ERR("fcb %p: refcount now %i (subvol %llx, inode %llx)\n", fcb, rc, fcb->subvol ? fcb->subvol->id : 0, fcb->inode);
#endif
#endif
    
    if (rc > 0)
        return;
    
//     ExAcquireResourceExclusiveLite(&fcb->Vcb->fcb_lock, TRUE);
    
    if (fcb->list_entry.Flink)
        RemoveEntryList(&fcb->list_entry);
    
    if (fcb->list_entry_all.Flink)
        RemoveEntryList(&fcb->list_entry_all);
    
//     ExReleaseResourceLite(&fcb->Vcb->fcb_lock);
   
    ExDeleteResourceLite(&fcb->nonpaged->resource);
    ExDeleteResourceLite(&fcb->nonpaged->paging_resource);
    ExDeleteResourceLite(&fcb->nonpaged->dir_children_lock);
    ExFreePool(fcb->nonpaged);
    
    if (fcb->sd)
        ExFreePool(fcb->sd);
    
    if (fcb->adsxattr.Buffer)
        ExFreePool(fcb->adsxattr.Buffer);
    
    if (fcb->reparse_xattr.Buffer)
        ExFreePool(fcb->reparse_xattr.Buffer);
    
    if (fcb->ea_xattr.Buffer)
        ExFreePool(fcb->ea_xattr.Buffer);
    
    if (fcb->adsdata.Buffer)
        ExFreePool(fcb->adsdata.Buffer);
    
    if (fcb->debug_desc)
        ExFreePool(fcb->debug_desc);
    
    while (!IsListEmpty(&fcb->extents)) {
        LIST_ENTRY* le = RemoveHeadList(&fcb->extents);
        extent* ext = CONTAINING_RECORD(le, extent, list_entry);
        
        if (ext->csum)
            ExFreePool(ext->csum);
        
        ExFreePool(ext);
    }
    
    while (!IsListEmpty(&fcb->hardlinks)) {
        LIST_ENTRY* le = RemoveHeadList(&fcb->hardlinks);
        hardlink* hl = CONTAINING_RECORD(le, hardlink, list_entry);
        
        if (hl->name.Buffer)
            ExFreePool(hl->name.Buffer);
        
        if (hl->utf8.Buffer)
            ExFreePool(hl->utf8.Buffer);

        ExFreePool(hl);
    }
    
    while (!IsListEmpty(&fcb->dir_children_index)) {
        LIST_ENTRY* le = RemoveHeadList(&fcb->dir_children_index);
        dir_child* dc = CONTAINING_RECORD(le, dir_child, list_entry_index);
        
        ExFreePool(dc->utf8.Buffer);
        ExFreePool(dc->name.Buffer);
        ExFreePool(dc->name_uc.Buffer);
        ExFreePool(dc);
    }
    
    if (fcb->hash_ptrs)
        ExFreePool(fcb->hash_ptrs);
    
    if (fcb->hash_ptrs_uc)
        ExFreePool(fcb->hash_ptrs_uc);
    
    FsRtlUninitializeFileLock(&fcb->lock);
    
    ExFreePool(fcb);
#ifdef DEBUG_FCB_REFCOUNTS
#ifdef DEBUG_LONG_MESSAGES
    _debug_message(func, file, line, "freeing fcb %p\n", fcb);
#else
    _debug_message(func, "freeing fcb %p\n", fcb);
#endif
#endif
}

void free_fileref(device_extension* Vcb, file_ref* fr) {
    LONG rc;

// #ifdef DEBUG    
//     if (!ExIsResourceAcquiredExclusiveLite(&fr->fcb->Vcb->fcb_lock) && !ExIsResourceAcquiredExclusiveLite(&fr->fcb->Vcb->tree_lock) && !fr->dirty) {
//         ERR("fcb_lock not acquired exclusively\n");
//         int3;
//     }
// #endif

    rc = InterlockedDecrement(&fr->refcount);
    
#ifdef DEBUG_FCB_REFCOUNTS
    ERR("fileref %p: refcount now %i\n", fr, rc);
#endif
    
#ifdef _DEBUG
    if (rc < 0) {
        ERR("fileref %p: refcount now %i\n", fr, rc);
        int3;
    }
#endif
    
    if (rc > 0)
        return;
        
    if (fr->parent)
        ExAcquireResourceExclusiveLite(&fr->parent->nonpaged->children_lock, TRUE);
    
    // FIXME - do we need a file_ref lock?
    
    // FIXME - do delete if needed
    
    if (fr->filepart.Buffer)
        ExFreePool(fr->filepart.Buffer);
    
    if (fr->filepart_uc.Buffer)
        ExFreePool(fr->filepart_uc.Buffer);
    
    if (fr->debug_desc)
        ExFreePool(fr->debug_desc);
    
    ExDeleteResourceLite(&fr->nonpaged->children_lock);
    ExDeleteResourceLite(&fr->nonpaged->fileref_lock);
    
    ExFreePool(fr->nonpaged);
    
    // FIXME - throw error if children not empty
    
    if (fr->fcb->fileref == fr)
        fr->fcb->fileref = NULL;
    
    if (fr->dc)
        fr->dc->fileref = NULL;

    if (fr->list_entry.Flink)
        RemoveEntryList(&fr->list_entry);
    
    if (fr->parent) {
        ExReleaseResourceLite(&fr->parent->nonpaged->children_lock);
        free_fileref(Vcb, fr->parent);
    }
    
    free_fcb(fr->fcb);
    
    ExFreeToPagedLookasideList(&Vcb->fileref_lookaside, fr);
}

static NTSTATUS STDCALL close_file(device_extension* Vcb, PFILE_OBJECT FileObject) {
    fcb* fcb;
    ccb* ccb;
    file_ref* fileref = NULL;
    LONG open_files;
    
    TRACE("FileObject = %p\n", FileObject);
    
    open_files = InterlockedDecrement(&Vcb->open_files);
    
    fcb = FileObject->FsContext;
    if (!fcb) {
        TRACE("FCB was NULL, returning success\n");
        
        if (open_files == 0 && Vcb->removing)
            uninit(Vcb, FALSE);
        
        return STATUS_SUCCESS;
    }
    
    ccb = FileObject->FsContext2;
    
    TRACE("close called for %S (fcb == %p)\n", file_desc(FileObject), fcb);
    
    // FIXME - make sure notification gets sent if file is being deleted
    
    if (ccb) {    
        if (ccb->query_string.Buffer)
            RtlFreeUnicodeString(&ccb->query_string);
        
        if (ccb->filename.Buffer)
            ExFreePool(ccb->filename.Buffer);
        
        // FIXME - use refcounts for fileref
        fileref = ccb->fileref;
        
        ExFreePool(ccb);
    }
    
    CcUninitializeCacheMap(FileObject, NULL, NULL);
    
    if (open_files == 0 && Vcb->removing) {
        uninit(Vcb, FALSE);
        return STATUS_SUCCESS;
    }
    
    if (!(Vcb->Vpb->Flags & VPB_MOUNTED))
        return STATUS_SUCCESS;
    
    ExAcquireResourceExclusiveLite(&Vcb->fcb_lock, TRUE);
    
    if (fileref)
        free_fileref(Vcb, fileref);
    else
        free_fcb(fcb);
    
    ExReleaseResourceLite(&Vcb->fcb_lock);
    
    return STATUS_SUCCESS;
}

void STDCALL uninit(device_extension* Vcb, BOOL flush) {
    space* s;
    UINT64 i;
    NTSTATUS Status;
    LIST_ENTRY* le;
    LARGE_INTEGER time;
    
    Vcb->removing = TRUE;
    
    RemoveEntryList(&Vcb->list_entry);
    
    if (Vcb->balance.thread) {
        Vcb->balance.paused = FALSE;
        Vcb->balance.stopping = TRUE;
        KeSetEvent(&Vcb->balance.event, 0, FALSE);
        KeWaitForSingleObject(&Vcb->balance.finished, Executive, KernelMode, FALSE, NULL);
    }
    
    if (Vcb->scrub.thread) {
        Vcb->scrub.paused = FALSE;
        Vcb->scrub.stopping = TRUE;
        KeSetEvent(&Vcb->scrub.event, 0, FALSE);
        KeWaitForSingleObject(&Vcb->scrub.finished, Executive, KernelMode, FALSE, NULL);
    }
    
    Status = registry_mark_volume_unmounted(&Vcb->superblock.uuid);
    if (!NT_SUCCESS(Status) && Status != STATUS_TOO_LATE)
        WARN("registry_mark_volume_unmounted returned %08x\n", Status);
    
    if (flush) {
        ExAcquireResourceExclusiveLite(&Vcb->tree_lock, TRUE);

        if (Vcb->need_write && !Vcb->readonly) {
            Status = do_write(Vcb, NULL);
            if (!NT_SUCCESS(Status))
                ERR("do_write returned %08x\n", Status);
        }
        
        free_trees(Vcb);
        
        ExReleaseResourceLite(&Vcb->tree_lock);
    }
    
    for (i = 0; i < Vcb->calcthreads.num_threads; i++) {
        Vcb->calcthreads.threads[i].quit = TRUE;
    }
    
    KeSetEvent(&Vcb->calcthreads.event, 0, FALSE);
        
    for (i = 0; i < Vcb->calcthreads.num_threads; i++) {
        KeWaitForSingleObject(&Vcb->calcthreads.threads[i].finished, Executive, KernelMode, FALSE, NULL);
        
        ZwClose(Vcb->calcthreads.threads[i].handle);
    }
    
    ExDeleteResourceLite(&Vcb->calcthreads.lock);
    ExFreePool(Vcb->calcthreads.threads);
    
    time.QuadPart = 0;
    KeSetTimer(&Vcb->flush_thread_timer, time, NULL); // trigger the timer early
    KeWaitForSingleObject(&Vcb->flush_thread_finished, Executive, KernelMode, FALSE, NULL);
    
    free_fcb(Vcb->volume_fcb);
    
    if (Vcb->root_file)
        ObDereferenceObject(Vcb->root_file);
    
    le = Vcb->chunks.Flink;
    while (le != &Vcb->chunks) {
        chunk* c = CONTAINING_RECORD(le, chunk, list_entry);
        
        if (c->cache) {
            free_fcb(c->cache);
            c->cache = NULL;
        }
        
        le = le->Flink;
    }

    while (!IsListEmpty(&Vcb->roots)) {
        LIST_ENTRY* le = RemoveHeadList(&Vcb->roots);
        root* r = CONTAINING_RECORD(le, root, list_entry);

        ExDeleteResourceLite(&r->nonpaged->load_tree_lock);
        ExFreePool(r->nonpaged);
        ExFreePool(r);
    }
    
    while (!IsListEmpty(&Vcb->chunks)) {
        chunk* c;
        
        le = RemoveHeadList(&Vcb->chunks);
        c = CONTAINING_RECORD(le, chunk, list_entry);
        
        while (!IsListEmpty(&c->space)) {
            LIST_ENTRY* le2 = RemoveHeadList(&c->space);
            s = CONTAINING_RECORD(le2, space, list_entry);
            
            ExFreePool(s);
        }
        
        while (!IsListEmpty(&c->deleting)) {
            LIST_ENTRY* le2 = RemoveHeadList(&c->deleting);
            s = CONTAINING_RECORD(le2, space, list_entry);
            
            ExFreePool(s);
        }
        
        if (c->devices)
            ExFreePool(c->devices);
        
        if (c->cache)
            free_fcb(c->cache);
        
        ExDeleteResourceLite(&c->range_locks_lock);
        ExDeleteResourceLite(&c->lock);
        ExDeleteResourceLite(&c->changed_extents_lock);
        
        ExFreePool(c->chunk_item);
        ExFreePool(c);
    }
    
    // FIXME - free any open fcbs?
    
    while (!IsListEmpty(&Vcb->devices)) {
        LIST_ENTRY* le = RemoveHeadList(&Vcb->devices);
        device* dev = CONTAINING_RECORD(le, device, list_entry);
        
        while (!IsListEmpty(&dev->space)) {
            LIST_ENTRY* le2 = RemoveHeadList(&dev->space);
            space* s = CONTAINING_RECORD(le2, space, list_entry);
            
            ExFreePool(s);
        }
        
        ExFreePool(dev);
    }
    
    ExAcquireResourceExclusiveLite(&Vcb->scrub.stats_lock, TRUE);
    while (!IsListEmpty(&Vcb->scrub.errors)) {
        scrub_error* err = CONTAINING_RECORD(RemoveHeadList(&Vcb->scrub.errors), scrub_error, list_entry);
        
        ExFreePool(err);
    }
    ExReleaseResourceLite(&Vcb->scrub.stats_lock);
    
    ExDeleteResourceLite(&Vcb->fcb_lock);
    ExDeleteResourceLite(&Vcb->load_lock);
    ExDeleteResourceLite(&Vcb->tree_lock);
    ExDeleteResourceLite(&Vcb->chunk_lock);
    ExDeleteResourceLite(&Vcb->dirty_fcbs_lock);
    ExDeleteResourceLite(&Vcb->dirty_filerefs_lock);
    ExDeleteResourceLite(&Vcb->scrub.stats_lock);
    
    ExDeletePagedLookasideList(&Vcb->tree_data_lookaside);
    ExDeletePagedLookasideList(&Vcb->traverse_ptr_lookaside);
    ExDeletePagedLookasideList(&Vcb->rollback_item_lookaside);
    ExDeletePagedLookasideList(&Vcb->batch_item_lookaside);
    ExDeletePagedLookasideList(&Vcb->fileref_lookaside);
    ExDeleteNPagedLookasideList(&Vcb->range_lock_lookaside);
    
    ZwClose(Vcb->flush_thread_handle);
}

NTSTATUS delete_fileref(file_ref* fileref, PFILE_OBJECT FileObject, PIRP Irp, LIST_ENTRY* rollback) {
    LARGE_INTEGER newlength, time;
    BTRFS_TIME now;
    NTSTATUS Status;
    ULONG utf8len = 0;

    KeQuerySystemTime(&time);
    win_time_to_unix(time, &now);

    ExAcquireResourceExclusiveLite(fileref->fcb->Header.Resource, TRUE);
    
    if (fileref->deleted) {
        ExReleaseResourceLite(fileref->fcb->Header.Resource);
        return STATUS_SUCCESS;
    }
    
    fileref->deleted = TRUE;
    mark_fileref_dirty(fileref);
    
    // delete INODE_ITEM (0x1)

    TRACE("nlink = %u\n", fileref->fcb->inode_item.st_nlink);
    
    if (!fileref->fcb->ads) {
        if (fileref->parent->fcb->subvol == fileref->fcb->subvol) {
            LIST_ENTRY* le;
            
            mark_fcb_dirty(fileref->fcb);
            
            fileref->fcb->inode_item_changed = TRUE;
            
            if (fileref->fcb->inode_item.st_nlink > 1) {
                fileref->fcb->inode_item.st_nlink--;
                fileref->fcb->inode_item.transid = fileref->fcb->Vcb->superblock.generation;
                fileref->fcb->inode_item.sequence++;
                fileref->fcb->inode_item.st_ctime = now;
            } else {
                fileref->fcb->deleted = TRUE;
            
                // excise extents
                
                if (fileref->fcb->type != BTRFS_TYPE_DIRECTORY && fileref->fcb->inode_item.st_size > 0) {
                    Status = excise_extents(fileref->fcb->Vcb, fileref->fcb, 0, sector_align(fileref->fcb->inode_item.st_size, fileref->fcb->Vcb->superblock.sector_size), Irp, rollback);
                    if (!NT_SUCCESS(Status)) {
                        ERR("excise_extents returned %08x\n", Status);
                        ExReleaseResourceLite(fileref->fcb->Header.Resource);
                        return Status;
                    }
                }
                
                fileref->fcb->Header.AllocationSize.QuadPart = 0;
                fileref->fcb->Header.FileSize.QuadPart = 0;
                fileref->fcb->Header.ValidDataLength.QuadPart = 0;
                
                if (FileObject) {
                    CC_FILE_SIZES ccfs;
                    
                    ccfs.AllocationSize = fileref->fcb->Header.AllocationSize;
                    ccfs.FileSize = fileref->fcb->Header.FileSize;
                    ccfs.ValidDataLength = fileref->fcb->Header.ValidDataLength;
                    
                    CcSetFileSizes(FileObject, &ccfs);
                }
            }
                
            le = fileref->fcb->hardlinks.Flink;
            while (le != &fileref->fcb->hardlinks) {
                hardlink* hl = CONTAINING_RECORD(le, hardlink, list_entry);
                
                if (hl->parent == fileref->parent->fcb->inode && hl->index == fileref->index) {
                    RemoveEntryList(&hl->list_entry);
                    
                    if (hl->name.Buffer)
                        ExFreePool(hl->name.Buffer);
                    
                    if (hl->utf8.Buffer)
                        ExFreePool(hl->utf8.Buffer);
                    
                    ExFreePool(hl);
                    break;
                }
                
                le = le->Flink;
            }
        } else { // subvolume
            if (fileref->fcb->subvol->root_item.num_references > 1) {
                fileref->fcb->subvol->root_item.num_references--;
                
                mark_fcb_dirty(fileref->fcb); // so ROOT_ITEM gets updated
            } else {
                // FIXME - we need a lock here
                
                RemoveEntryList(&fileref->fcb->subvol->list_entry);
                
                InsertTailList(&fileref->fcb->Vcb->drop_roots, &fileref->fcb->subvol->list_entry);
            }
        }
    } else {
        fileref->fcb->deleted = TRUE;
        mark_fcb_dirty(fileref->fcb);
    }
    
    // remove dir_child from parent
    
    if (fileref->dc) {
        ExAcquireResourceExclusiveLite(&fileref->parent->fcb->nonpaged->dir_children_lock, TRUE);
        RemoveEntryList(&fileref->dc->list_entry_index);
        remove_dir_child_from_hash_lists(fileref->parent->fcb, fileref->dc);
        ExReleaseResourceLite(&fileref->parent->fcb->nonpaged->dir_children_lock);
        
        if (!fileref->oldutf8.Buffer)
            fileref->oldutf8 = fileref->dc->utf8;
        else
            ExFreePool(fileref->dc->utf8.Buffer);
        
        utf8len = fileref->dc->utf8.Length;
        
        ExFreePool(fileref->dc->name.Buffer);
        ExFreePool(fileref->dc->name_uc.Buffer);
        ExFreePool(fileref->dc);
        
        fileref->dc = NULL;
    }
    
    // update INODE_ITEM of parent
    
    TRACE("delete file %.*S\n", fileref->filepart.Length / sizeof(WCHAR), fileref->filepart.Buffer);
    ExAcquireResourceExclusiveLite(fileref->parent->fcb->Header.Resource, TRUE);
    TRACE("fileref->parent->fcb->inode_item.st_size (inode %llx) was %llx\n", fileref->parent->fcb->inode, fileref->parent->fcb->inode_item.st_size);
    fileref->parent->fcb->inode_item.st_size -= utf8len * 2;
    TRACE("fileref->parent->fcb->inode_item.st_size (inode %llx) now %llx\n", fileref->parent->fcb->inode, fileref->parent->fcb->inode_item.st_size);
    fileref->parent->fcb->inode_item.transid = fileref->fcb->Vcb->superblock.generation;
    fileref->parent->fcb->inode_item.sequence++;
    fileref->parent->fcb->inode_item.st_ctime = now;
    fileref->parent->fcb->inode_item.st_mtime = now;
    ExReleaseResourceLite(fileref->parent->fcb->Header.Resource);

    fileref->parent->fcb->inode_item_changed = TRUE;
    mark_fcb_dirty(fileref->parent->fcb);
    
    send_notification_fcb(fileref->parent, FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_ACTION_MODIFIED);
    
    fileref->fcb->subvol->root_item.ctransid = fileref->fcb->Vcb->superblock.generation;
    fileref->fcb->subvol->root_item.ctime = now;
    
    newlength.QuadPart = 0;
    
    if (FileObject && !CcUninitializeCacheMap(FileObject, &newlength, NULL))
        TRACE("CcUninitializeCacheMap failed\n");

    ExReleaseResourceLite(fileref->fcb->Header.Resource);
    
    return STATUS_SUCCESS;
}

static NTSTATUS STDCALL drv_cleanup(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    NTSTATUS Status;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    device_extension* Vcb = DeviceObject->DeviceExtension;
    fcb* fcb;
    BOOL top_level;

    TRACE("cleanup\n");
    
    FsRtlEnterFileSystem();

    top_level = is_top_level(Irp);
    
    if (Vcb && Vcb->type == VCB_TYPE_VOLUME) {
        Status = vol_cleanup(DeviceObject, Irp);
        goto exit;
    } else if (DeviceObject == devobj) {
        TRACE("closing file system\n");
        Status = STATUS_SUCCESS;
        goto exit;
    } else if (!Vcb || Vcb->type != VCB_TYPE_FS) {
        Status = STATUS_INVALID_PARAMETER;
        goto exit;
    }
    
    if (FileObject && FileObject->FsContext) {
        LONG oc;
        ccb* ccb;
        file_ref* fileref;
        
        fcb = FileObject->FsContext;
        ccb = FileObject->FsContext2;
        fileref = ccb ? ccb->fileref : NULL;
        
        TRACE("cleanup called for FileObject %p\n", FileObject);
        TRACE("fileref %p (%S), refcount = %u, open_count = %u\n", fileref, file_desc(FileObject), fileref ? fileref->refcount : 0, fileref ? fileref->open_count : 0);
        
        ExAcquireResourceSharedLite(&fcb->Vcb->tree_lock, TRUE);
        
        ExAcquireResourceExclusiveLite(fcb->Header.Resource, TRUE);
        
        IoRemoveShareAccess(FileObject, &fcb->share_access);
        
        FsRtlNotifyCleanup(Vcb->NotifySync, &Vcb->DirNotifyList, ccb);    
        
        if (fileref) {
            oc = InterlockedDecrement(&fileref->open_count);
#ifdef DEBUG_FCB_REFCOUNTS
            ERR("fileref %p: open_count now %i\n", fileref, oc);
#endif
        }
        
        if (ccb && ccb->options & FILE_DELETE_ON_CLOSE && fileref)
            fileref->delete_on_close = TRUE;
        
        if (fileref && fileref->delete_on_close && fcb->type == BTRFS_TYPE_DIRECTORY && fcb->inode_item.st_size > 0)
            fileref->delete_on_close = FALSE;
        
        if (Vcb->locked && Vcb->locked_fileobj == FileObject) {
            TRACE("unlocking volume\n");
            do_unlock_volume(Vcb);
            FsRtlNotifyVolumeEvent(FileObject, FSRTL_VOLUME_UNLOCK);
        }
        
        if (fileref && oc == 0) {
            if (!Vcb->removing) {
                LIST_ENTRY rollback;
        
                InitializeListHead(&rollback);
            
                if (fileref && fileref->delete_on_close && fileref != fcb->Vcb->root_fileref && fcb != fcb->Vcb->volume_fcb) {
                    send_notification_fileref(fileref, fcb->type == BTRFS_TYPE_DIRECTORY ? FILE_NOTIFY_CHANGE_DIR_NAME : FILE_NOTIFY_CHANGE_FILE_NAME, FILE_ACTION_REMOVED);
                    
                    ExAcquireResourceExclusiveLite(&fcb->Vcb->fcb_lock, TRUE);
                    
                    Status = delete_fileref(fileref, FileObject, Irp, &rollback);
                    if (!NT_SUCCESS(Status)) {
                        ERR("delete_fileref returned %08x\n", Status);
                        do_rollback(Vcb, &rollback);
                        ExReleaseResourceLite(&fcb->Vcb->fcb_lock);
                        ExReleaseResourceLite(fcb->Header.Resource);
                        ExReleaseResourceLite(&fcb->Vcb->tree_lock);
                        goto exit;
                    }
                    
                    ExReleaseResourceLite(&fcb->Vcb->fcb_lock);
                    
                    clear_rollback(Vcb, &rollback);
                } else if (FileObject->Flags & FO_CACHE_SUPPORTED && fcb->nonpaged->segment_object.DataSectionObject) {
                    IO_STATUS_BLOCK iosb;
                    CcFlushCache(FileObject->SectionObjectPointer, NULL, 0, &iosb);
                    
                    if (!NT_SUCCESS(iosb.Status)) {
                        ERR("CcFlushCache returned %08x\n", iosb.Status);
                    }

                    if (!ExIsResourceAcquiredSharedLite(fcb->Header.PagingIoResource)) {
                        ExAcquireResourceExclusiveLite(fcb->Header.PagingIoResource, TRUE);
                        ExReleaseResourceLite(fcb->Header.PagingIoResource);
                    }

                    CcPurgeCacheSection(&fcb->nonpaged->segment_object, NULL, 0, FALSE);
                    
                    TRACE("flushed cache on close (FileObject = %p, fcb = %p, AllocationSize = %llx, FileSize = %llx, ValidDataLength = %llx)\n",
                        FileObject, fcb, fcb->Header.AllocationSize.QuadPart, fcb->Header.FileSize.QuadPart, fcb->Header.ValidDataLength.QuadPart);
                }
            }
            
            if (fcb->Vcb && fcb != fcb->Vcb->volume_fcb)
                CcUninitializeCacheMap(FileObject, NULL, NULL);
        }
        
        ExReleaseResourceLite(fcb->Header.Resource);
        ExReleaseResourceLite(&fcb->Vcb->tree_lock);
        
        FileObject->Flags |= FO_CLEANUP_COMPLETE;
    }
    
    Status = STATUS_SUCCESS;

exit:
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;
    
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
    if (top_level) 
        IoSetTopLevelIrp(NULL);
    
    FsRtlExitFileSystem();

    return Status;
}

BOOL get_file_attributes_from_xattr(char* val, UINT16 len, ULONG* atts) {
    if (len > 2 && val[0] == '0' && val[1] == 'x') {
        int i;
        ULONG dosnum = 0;

        for (i = 2; i < len; i++) {
            dosnum *= 0x10;
            
            if (val[i] >= '0' && val[i] <= '9')
                dosnum |= val[i] - '0';
            else if (val[i] >= 'a' && val[i] <= 'f')
                dosnum |= val[i] + 10 - 'a';
            else if (val[i] >= 'A' && val[i] <= 'F')
                dosnum |= val[i] + 10 - 'a';
        }
        
        TRACE("DOSATTRIB: %08x\n", dosnum);
        
        *atts = dosnum;
        
        return TRUE;
    }
    
    return FALSE;
}

ULONG STDCALL get_file_attributes(device_extension* Vcb, root* r, UINT64 inode, UINT8 type, BOOL dotfile, BOOL ignore_xa, PIRP Irp) {
    ULONG att;
    char* eaval;
    UINT16 ealen;
    
    if (!ignore_xa && get_xattr(Vcb, r, inode, EA_DOSATTRIB, EA_DOSATTRIB_HASH, (UINT8**)&eaval, &ealen, Irp)) {
        ULONG dosnum = 0;
        
        if (get_file_attributes_from_xattr(eaval, ealen, &dosnum)) {
            ExFreePool(eaval);
            
            if (type == BTRFS_TYPE_DIRECTORY)
                dosnum |= FILE_ATTRIBUTE_DIRECTORY;
            else if (type == BTRFS_TYPE_SYMLINK)
                dosnum |= FILE_ATTRIBUTE_REPARSE_POINT;
            
            if (inode == SUBVOL_ROOT_INODE) {
                if (r->root_item.flags & BTRFS_SUBVOL_READONLY)
                    dosnum |= FILE_ATTRIBUTE_READONLY;
                else
                    dosnum &= ~FILE_ATTRIBUTE_READONLY;
            }
            
            return dosnum;
        }
        
        ExFreePool(eaval);
    }
    
    switch (type) {
        case BTRFS_TYPE_DIRECTORY:
            att = FILE_ATTRIBUTE_DIRECTORY;
            break;
            
        case BTRFS_TYPE_SYMLINK:
            att = FILE_ATTRIBUTE_REPARSE_POINT;
            break;
           
        default:
            att = 0;
            break;
    }
    
    if (dotfile) {
        att |= FILE_ATTRIBUTE_HIDDEN;
    }
    
    att |= FILE_ATTRIBUTE_ARCHIVE;
    
    if (inode == SUBVOL_ROOT_INODE) {
        if (r->root_item.flags & BTRFS_SUBVOL_READONLY)
            att |= FILE_ATTRIBUTE_READONLY;
        else
            att &= ~FILE_ATTRIBUTE_READONLY;
    }
    
    // FIXME - get READONLY from ii->st_mode
    // FIXME - return SYSTEM for block/char devices?
    
    if (att == 0)
        att = FILE_ATTRIBUTE_NORMAL;
    
    return att;
}

NTSTATUS sync_read_phys(PDEVICE_OBJECT DeviceObject, LONGLONG StartingOffset, ULONG Length, PUCHAR Buffer, BOOL override) {
    IO_STATUS_BLOCK IoStatus;
    LARGE_INTEGER Offset;
    PIRP Irp;
    PIO_STACK_LOCATION IrpSp;
    NTSTATUS Status;
    read_context context;
    
    num_reads++;
    
    RtlZeroMemory(&context, sizeof(read_context));
    KeInitializeEvent(&context.Event, NotificationEvent, FALSE);

    Offset.QuadPart = StartingOffset;

    Irp = IoAllocateIrp(DeviceObject->StackSize, FALSE);
    
    if (!Irp) {
        ERR("IoAllocateIrp failed\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto exit;
    }
    
    Irp->Flags |= IRP_NOCACHE;
    IrpSp = IoGetNextIrpStackLocation(Irp);
    IrpSp->MajorFunction = IRP_MJ_READ;
    
    if (override)
        IrpSp->Flags |= SL_OVERRIDE_VERIFY_VOLUME;
    
    if (DeviceObject->Flags & DO_BUFFERED_IO) {
        Irp->AssociatedIrp.SystemBuffer = ExAllocatePoolWithTag(NonPagedPool, Length, ALLOC_TAG);
        if (!Irp->AssociatedIrp.SystemBuffer) {
            ERR("out of memory\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto exit;
        }

        Irp->Flags |= IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER | IRP_INPUT_OPERATION;

        Irp->UserBuffer = Buffer;
    } else if (DeviceObject->Flags & DO_DIRECT_IO) {
        Irp->MdlAddress = IoAllocateMdl(Buffer, Length, FALSE, FALSE, NULL);
        if (!Irp->MdlAddress) {
            ERR("IoAllocateMdl failed\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto exit;
        }
        
        MmProbeAndLockPages(Irp->MdlAddress, KernelMode, IoWriteAccess);
    } else
        Irp->UserBuffer = Buffer;

    IrpSp->Parameters.Read.Length = Length;
    IrpSp->Parameters.Read.ByteOffset = Offset;
    
    Irp->UserIosb = &IoStatus;
    
    Irp->UserEvent = &context.Event;
    
    IoSetCompletionRoutine(Irp, read_completion, &context, TRUE, TRUE, TRUE);

    Status = IoCallDriver(DeviceObject, Irp);

    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject(&context.Event, Executive, KernelMode, FALSE, NULL);
        Status = context.iosb.Status;
    }
    
    if (DeviceObject->Flags & DO_DIRECT_IO) {
        MmUnlockPages(Irp->MdlAddress);
        IoFreeMdl(Irp->MdlAddress);
    }
    
exit:
    IoFreeIrp(Irp);
    
    return Status;
}

static NTSTATUS STDCALL read_superblock(device_extension* Vcb, PDEVICE_OBJECT device, UINT64 length) {
    NTSTATUS Status;
    superblock* sb;
    unsigned int i, to_read;
    UINT8 valid_superblocks;
    
    to_read = device->SectorSize == 0 ? sizeof(superblock) : sector_align(sizeof(superblock), device->SectorSize);
    
    sb = ExAllocatePoolWithTag(NonPagedPool, to_read, ALLOC_TAG);
    if (!sb) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    if (superblock_addrs[0] + to_read > length) {
        WARN("device was too short to have any superblock\n");
        ExFreePool(sb);
        return STATUS_UNRECOGNIZED_VOLUME;
    }
    
    i = 0;
    valid_superblocks = 0;
    
    while (superblock_addrs[i] > 0) {
        UINT32 crc32;
        
        if (i > 0 && superblock_addrs[i] + to_read > length)
            break;
        
        Status = sync_read_phys(device, superblock_addrs[i], to_read, (PUCHAR)sb, FALSE);
        if (!NT_SUCCESS(Status)) {
            ERR("Failed to read superblock %u: %08x\n", i, Status);
            ExFreePool(sb);
            return Status;
        }
        
        if (sb->magic != BTRFS_MAGIC) {
            if (i == 0) {
                TRACE("not a BTRFS volume\n");
                ExFreePool(sb);
                return STATUS_UNRECOGNIZED_VOLUME;
            }
        } else {
            TRACE("got superblock %u!\n", i);
            
            crc32 = ~calc_crc32c(0xffffffff, (UINT8*)&sb->uuid, (ULONG)sizeof(superblock) - sizeof(sb->checksum));
            
            if (crc32 != *((UINT32*)sb->checksum))
                WARN("crc32 was %08x, expected %08x\n", crc32, *((UINT32*)sb->checksum));
            else if (valid_superblocks == 0 || sb->generation > Vcb->superblock.generation) {
                RtlCopyMemory(&Vcb->superblock, sb, sizeof(superblock));
                valid_superblocks++;
            }
        }
        
        i++;
    }
    
    ExFreePool(sb);
    
    if (valid_superblocks == 0) {
        ERR("could not find any valid superblocks\n");
        return STATUS_INTERNAL_ERROR;
    }
    
    TRACE("label is %s\n", Vcb->superblock.label);
    
    return STATUS_SUCCESS;
}

NTSTATUS STDCALL dev_ioctl(PDEVICE_OBJECT DeviceObject, ULONG ControlCode, PVOID InputBuffer, ULONG InputBufferSize,
                           PVOID OutputBuffer, ULONG OutputBufferSize, BOOLEAN Override, IO_STATUS_BLOCK* iosb)
{
    PIRP Irp;
    KEVENT Event;
    NTSTATUS Status;
    PIO_STACK_LOCATION Stack;
    IO_STATUS_BLOCK IoStatus;

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    Irp = IoBuildDeviceIoControlRequest(ControlCode,
                                        DeviceObject,
                                        InputBuffer,
                                        InputBufferSize,
                                        OutputBuffer,
                                        OutputBufferSize,
                                        FALSE,
                                        &Event,
                                        &IoStatus);

    if (!Irp) return STATUS_INSUFFICIENT_RESOURCES;

    if (Override) {
        Stack = IoGetNextIrpStackLocation(Irp);
        Stack->Flags |= SL_OVERRIDE_VERIFY_VOLUME;
    }

    Status = IoCallDriver(DeviceObject, Irp);

    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatus.Status;
    }
    
    if (iosb)
        *iosb = IoStatus;

    return Status;
}

static NTSTATUS STDCALL add_root(device_extension* Vcb, UINT64 id, UINT64 addr, UINT64 generation, traverse_ptr* tp) {
    root* r = ExAllocatePoolWithTag(PagedPool, sizeof(root), ALLOC_TAG);
    if (!r) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    r->id = id;
    r->path.Buffer = NULL;
    r->treeholder.address = addr;
    r->treeholder.tree = NULL;
    r->treeholder.generation = generation;
    InitializeListHead(&r->fcbs);

    r->nonpaged = ExAllocatePoolWithTag(NonPagedPool, sizeof(root_nonpaged), ALLOC_TAG);
    if (!r->nonpaged) {
        ERR("out of memory\n");
        ExFreePool(r);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    ExInitializeResourceLite(&r->nonpaged->load_tree_lock);
    
    r->lastinode = 0;
    
    if (tp) {
        RtlCopyMemory(&r->root_item, tp->item->data, min(sizeof(ROOT_ITEM), tp->item->size));
        if (tp->item->size < sizeof(ROOT_ITEM))
            RtlZeroMemory(((UINT8*)&r->root_item) + tp->item->size, sizeof(ROOT_ITEM) - tp->item->size);
    }
    
    if (!Vcb->readonly && (r->id == BTRFS_ROOT_ROOT || r->id == BTRFS_ROOT_FSTREE || (r->id >= 0x100 && !(r->id & 0xf000000000000000)))) { // FS tree root
        // FIXME - don't call this if subvol is readonly (though we will have to if we ever toggle this flag)
        get_last_inode(Vcb, r, NULL);
        
        if (r->id == BTRFS_ROOT_ROOT && r->lastinode < 0x100)
            r->lastinode = 0x100;
    }
    
    InsertTailList(&Vcb->roots, &r->list_entry);
    
    switch (r->id) {
        case BTRFS_ROOT_ROOT:
            Vcb->root_root = r;
            break;
            
        case BTRFS_ROOT_EXTENT:
            Vcb->extent_root = r;
            break;
            
        case BTRFS_ROOT_CHUNK:
            Vcb->chunk_root = r;
            break;
            
        case BTRFS_ROOT_DEVTREE:
            Vcb->dev_root = r;
            break;
            
        case BTRFS_ROOT_CHECKSUM:
            Vcb->checksum_root = r;
            break;
            
        case BTRFS_ROOT_UUID:
            Vcb->uuid_root = r;
            break;
            
        case BTRFS_ROOT_DATA_RELOC:
            Vcb->data_reloc_root = r;
    }
    
    return STATUS_SUCCESS;
}

static NTSTATUS STDCALL look_for_roots(device_extension* Vcb, PIRP Irp) {
    traverse_ptr tp, next_tp;
    KEY searchkey;
    BOOL b;
    NTSTATUS Status;
    
    searchkey.obj_id = 0;
    searchkey.obj_type = 0;
    searchkey.offset = 0;
    
    Status = find_item(Vcb, Vcb->root_root, &tp, &searchkey, FALSE, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08x\n", Status);
        return Status;
    }
    
    do {
        TRACE("(%llx,%x,%llx)\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset);
        
        if (tp.item->key.obj_type == TYPE_ROOT_ITEM) {
            ROOT_ITEM* ri = (ROOT_ITEM*)tp.item->data;
            
            if (tp.item->size < offsetof(ROOT_ITEM, byte_limit)) {
                ERR("(%llx,%x,%llx) was %u bytes, expected at least %u\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, tp.item->size, offsetof(ROOT_ITEM, byte_limit));
            } else {
                TRACE("root %llx - address %llx\n", tp.item->key.obj_id, ri->block_number);
                
                Status = add_root(Vcb, tp.item->key.obj_id, ri->block_number, ri->generation, &tp);
                if (!NT_SUCCESS(Status)) {
                    ERR("add_root returned %08x\n", Status);
                    return Status;
                }
            }
        }
    
        b = find_next_item(Vcb, &tp, &next_tp, FALSE, Irp);
        
        if (b)
            tp = next_tp;
    } while (b);
    
    if (!Vcb->readonly && !Vcb->data_reloc_root) {
        root* reloc_root;
        INODE_ITEM* ii;
        ULONG irlen;
        INODE_REF* ir;
        LARGE_INTEGER time;
        BTRFS_TIME now;
        
        WARN("data reloc root doesn't exist, creating it\n");
        
        Status = create_root(Vcb, BTRFS_ROOT_DATA_RELOC, &reloc_root, FALSE, 0, Irp);
        
        if (!NT_SUCCESS(Status)) {
            ERR("create_root returned %08x\n", Status);
            goto end;
        }
        
        reloc_root->root_item.inode.generation = 1;
        reloc_root->root_item.inode.st_size = 3;
        reloc_root->root_item.inode.st_blocks = Vcb->superblock.node_size;
        reloc_root->root_item.inode.st_nlink = 1;
        reloc_root->root_item.inode.st_mode = 040755;
        reloc_root->root_item.inode.flags = 0xffffffff80000000;
        reloc_root->root_item.objid = SUBVOL_ROOT_INODE;
        reloc_root->root_item.bytes_used = Vcb->superblock.node_size;
        
        ii = ExAllocatePoolWithTag(PagedPool, sizeof(INODE_ITEM), ALLOC_TAG);
        if (!ii) {
            ERR("out of memory\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }
        
        KeQuerySystemTime(&time);
        win_time_to_unix(time, &now);
        
        RtlZeroMemory(ii, sizeof(INODE_ITEM));
        ii->generation = Vcb->superblock.generation;
        ii->st_blocks = Vcb->superblock.node_size;
        ii->st_nlink = 1;
        ii->st_mode = 040755;
        ii->st_atime = now;
        ii->st_ctime = now;
        ii->st_mtime = now;
        
        Status = insert_tree_item(Vcb, reloc_root, SUBVOL_ROOT_INODE, TYPE_INODE_ITEM, 0, ii, sizeof(INODE_ITEM), NULL, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("insert_tree_item returned %08x\n", Status);
            goto end;
        }

        irlen = offsetof(INODE_REF, name[0]) + 2;
        ir = ExAllocatePoolWithTag(PagedPool, irlen, ALLOC_TAG);
        if (!ir) {
            ERR("out of memory\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }
        
        ir->index = 0;
        ir->n = 2;
        ir->name[0] = '.';
        ir->name[1] = '.';
        
        Status = insert_tree_item(Vcb, reloc_root, SUBVOL_ROOT_INODE, TYPE_INODE_REF, SUBVOL_ROOT_INODE, ir, irlen, NULL, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("insert_tree_item returned %08x\n", Status);
            goto end;
        }
        
        Vcb->data_reloc_root = reloc_root;
        Vcb->need_write = TRUE;
    }
    
    Status = STATUS_SUCCESS;
    
end:
    return Status;
}

static NTSTATUS find_disk_holes(device_extension* Vcb, device* dev, PIRP Irp) {
    KEY searchkey;
    traverse_ptr tp, next_tp;
    BOOL b;
    UINT64 lastaddr;
    NTSTATUS Status;
    
    InitializeListHead(&dev->space);
    
    searchkey.obj_id = dev->devitem.dev_id;
    searchkey.obj_type = TYPE_DEV_EXTENT;
    searchkey.offset = 0;
    
    Status = find_item(Vcb, Vcb->dev_root, &tp, &searchkey, FALSE, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08x\n", Status);
        return Status;
    }
    
    lastaddr = 0;
    
    do {
        if (tp.item->key.obj_id == dev->devitem.dev_id && tp.item->key.obj_type == TYPE_DEV_EXTENT) {
            if (tp.item->size >= sizeof(DEV_EXTENT)) {
                DEV_EXTENT* de = (DEV_EXTENT*)tp.item->data;
                
                if (tp.item->key.offset > lastaddr) {
                    Status = add_space_entry(&dev->space, NULL, lastaddr, tp.item->key.offset - lastaddr);
                    if (!NT_SUCCESS(Status)) {
                        ERR("add_space_entry returned %08x\n", Status);
                        return Status;
                    }
                }

                lastaddr = tp.item->key.offset + de->length;
            } else {
                ERR("(%llx,%x,%llx) was %u bytes, expected %u\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, tp.item->size, sizeof(DEV_EXTENT));
            }
        }
    
        b = find_next_item(Vcb, &tp, &next_tp, FALSE, Irp);
        
        if (b) {
            tp = next_tp;
            if (tp.item->key.obj_id > searchkey.obj_id || tp.item->key.obj_type > searchkey.obj_type)
                break;
        }
    } while (b);
    
    if (lastaddr < dev->devitem.num_bytes) {
        Status = add_space_entry(&dev->space, NULL, lastaddr, dev->devitem.num_bytes - lastaddr);
        if (!NT_SUCCESS(Status)) {
            ERR("add_space_entry returned %08x\n", Status);
            return Status;
        }
    }
    
    // The Linux driver doesn't like to allocate chunks within the first megabyte of a device.
    
    space_list_subtract2(Vcb, &dev->space, NULL, 0, 0x100000, NULL);
    
    return STATUS_SUCCESS;
}

static void add_device_to_list(device_extension* Vcb, device* dev) {
    LIST_ENTRY* le;
    
    le = Vcb->devices.Flink;
    
    while (le != &Vcb->devices) {
        device* dev2 = CONTAINING_RECORD(le, device, list_entry);
        
        if (dev2->devitem.dev_id > dev->devitem.dev_id) {
            InsertHeadList(le->Blink, &dev->list_entry);
            return;
        }
        
        le = le->Flink;
    }
    
    InsertTailList(&Vcb->devices, &dev->list_entry);
}

device* find_device_from_uuid(device_extension* Vcb, BTRFS_UUID* uuid) {
    volume_device_extension* vde;
    LIST_ENTRY* le;
    
    le = Vcb->devices.Flink;
    while (le != &Vcb->devices) {
        device* dev = CONTAINING_RECORD(le, device, list_entry);
        
        TRACE("device %llx, uuid %02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n", dev->devitem.dev_id,
            dev->devitem.device_uuid.uuid[0], dev->devitem.device_uuid.uuid[1], dev->devitem.device_uuid.uuid[2], dev->devitem.device_uuid.uuid[3], dev->devitem.device_uuid.uuid[4], dev->devitem.device_uuid.uuid[5], dev->devitem.device_uuid.uuid[6], dev->devitem.device_uuid.uuid[7],
            dev->devitem.device_uuid.uuid[8], dev->devitem.device_uuid.uuid[9], dev->devitem.device_uuid.uuid[10], dev->devitem.device_uuid.uuid[11], dev->devitem.device_uuid.uuid[12], dev->devitem.device_uuid.uuid[13], dev->devitem.device_uuid.uuid[14], dev->devitem.device_uuid.uuid[15]);
        
        if (dev->devobj && RtlCompareMemory(&dev->devitem.device_uuid, uuid, sizeof(BTRFS_UUID)) == sizeof(BTRFS_UUID)) {
            TRACE("returning device %llx\n", dev->devitem.dev_id);
            return dev;
        }
        
        le = le->Flink;
    }
    
    vde = Vcb->vde;
    
    ExAcquireResourceSharedLite(&vde->child_lock, TRUE);
    
    if (Vcb->devices_loaded < Vcb->superblock.num_devices) {
        LIST_ENTRY* le = vde->children.Flink;
        
        while (le != &vde->children) {
            volume_child* vc = CONTAINING_RECORD(le, volume_child, list_entry);
            
            if (RtlCompareMemory(uuid, &vc->uuid, sizeof(BTRFS_UUID)) == sizeof(BTRFS_UUID)) {
                device* dev;
                
                dev = ExAllocatePoolWithTag(NonPagedPool, sizeof(device), ALLOC_TAG);
                if (!dev) {
                    ExReleaseResourceLite(&vde->child_lock);
                    ERR("out of memory\n");
                    return NULL;
                }
                
                RtlZeroMemory(dev, sizeof(device));
                dev->devobj = vc->devobj;
                dev->devitem.device_uuid = *uuid;
                dev->devitem.dev_id = vc->devid;
                dev->seeding = vc->seeding;
                dev->readonly = dev->seeding;
                dev->reloc = FALSE;
                dev->removable = FALSE;
                dev->disk_num = vc->disk_num;
                dev->part_num = vc->part_num;
                dev->length = vc->size;
                dev->num_trim_entries = 0;
                InitializeListHead(&dev->trim_list);
                
                add_device_to_list(Vcb, dev);
                Vcb->devices_loaded++;
                
                ExReleaseResourceLite(&vde->child_lock);
                
                return dev;
            }
            
            le = le->Flink;
        }
    }
    
    ExReleaseResourceLite(&vde->child_lock);
    
    WARN("could not find device with uuid %02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n",
         uuid->uuid[0], uuid->uuid[1], uuid->uuid[2], uuid->uuid[3], uuid->uuid[4], uuid->uuid[5], uuid->uuid[6], uuid->uuid[7],
         uuid->uuid[8], uuid->uuid[9], uuid->uuid[10], uuid->uuid[11], uuid->uuid[12], uuid->uuid[13], uuid->uuid[14], uuid->uuid[15]);
    
    return NULL;
}

static BOOL is_device_removable(PDEVICE_OBJECT devobj) {
    NTSTATUS Status;
    STORAGE_HOTPLUG_INFO shi;
    
    Status = dev_ioctl(devobj, IOCTL_STORAGE_GET_HOTPLUG_INFO, NULL, 0, &shi, sizeof(STORAGE_HOTPLUG_INFO), TRUE, NULL);
    
    if (!NT_SUCCESS(Status)) {
        ERR("dev_ioctl returned %08x\n", Status);
        return FALSE;
    }
    
    return shi.MediaRemovable != 0 ? TRUE : FALSE;
}

static ULONG get_device_change_count(PDEVICE_OBJECT devobj) {
    NTSTATUS Status;
    ULONG cc;
    IO_STATUS_BLOCK iosb;
    
    Status = dev_ioctl(devobj, IOCTL_STORAGE_CHECK_VERIFY, NULL, 0, &cc, sizeof(ULONG), TRUE, &iosb);
    
    if (!NT_SUCCESS(Status)) {
        ERR("dev_ioctl returned %08x\n", Status);
        return 0;
    }
    
    if (iosb.Information < sizeof(ULONG)) {
        ERR("iosb.Information was too short\n");
        return 0;
    }
    
    return cc;
}

void init_device(device_extension* Vcb, device* dev, BOOL get_nums) {
    NTSTATUS Status;
    ULONG aptelen;
    ATA_PASS_THROUGH_EX* apte;
    IDENTIFY_DEVICE_DATA* idd;
    STORAGE_PROPERTY_QUERY spq;
    DEVICE_TRIM_DESCRIPTOR dtd;
    
    dev->removable = is_device_removable(dev->devobj);
    dev->change_count = dev->removable ? get_device_change_count(dev->devobj) : 0;
    
    if (get_nums) {
        STORAGE_DEVICE_NUMBER sdn;
        
        Status = dev_ioctl(dev->devobj, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0,
                           &sdn, sizeof(STORAGE_DEVICE_NUMBER), TRUE, NULL);
        
        if (!NT_SUCCESS(Status)) {
            WARN("IOCTL_STORAGE_GET_DEVICE_NUMBER returned %08x\n", Status);
            dev->disk_num = 0xffffffff;
            dev->part_num = 0xffffffff;
        } else {
            dev->disk_num = sdn.DeviceNumber;
            dev->part_num = sdn.PartitionNumber;
        }
    }
    
    dev->trim = FALSE;
    dev->readonly = dev->seeding;
    dev->reloc = FALSE;
    dev->num_trim_entries = 0;
    InitializeListHead(&dev->trim_list);
    
    if (!dev->readonly) {
        Status = dev_ioctl(dev->devobj, IOCTL_DISK_IS_WRITABLE, NULL, 0,
                        NULL, 0, TRUE, NULL);
        if (Status == STATUS_MEDIA_WRITE_PROTECTED)
            dev->readonly = TRUE;
    }

    aptelen = sizeof(ATA_PASS_THROUGH_EX) + 512;
    apte = ExAllocatePoolWithTag(NonPagedPool, aptelen, ALLOC_TAG);
    if (!apte) {
        ERR("out of memory\n");
        return;
    }
    
    RtlZeroMemory(apte, aptelen);
    
    apte->Length = sizeof(ATA_PASS_THROUGH_EX);
    apte->AtaFlags = ATA_FLAGS_DATA_IN;
    apte->DataTransferLength = aptelen - sizeof(ATA_PASS_THROUGH_EX);
    apte->TimeOutValue = 3;
    apte->DataBufferOffset = apte->Length;
    apte->CurrentTaskFile[6] = IDE_COMMAND_IDENTIFY;
    
    Status = dev_ioctl(dev->devobj, IOCTL_ATA_PASS_THROUGH, apte, aptelen,
                       apte, aptelen, TRUE, NULL);
    
    if (!NT_SUCCESS(Status))
        TRACE("IOCTL_ATA_PASS_THROUGH returned %08x for IDENTIFY DEVICE\n", Status);
    else {
        idd = (IDENTIFY_DEVICE_DATA*)((UINT8*)apte + sizeof(ATA_PASS_THROUGH_EX));
        
        if (idd->CommandSetSupport.FlushCache) {
            dev->can_flush = TRUE;
            TRACE("FLUSH CACHE supported\n");
        } else
            TRACE("FLUSH CACHE not supported\n");
    }
    
    ExFreePool(apte);
    
    spq.PropertyId = StorageDeviceTrimProperty;
    spq.QueryType = PropertyStandardQuery;
    spq.AdditionalParameters[0] = 0;
    
    Status = dev_ioctl(dev->devobj, IOCTL_STORAGE_QUERY_PROPERTY, &spq, sizeof(STORAGE_PROPERTY_QUERY),
                       &dtd, sizeof(DEVICE_TRIM_DESCRIPTOR), TRUE, NULL);
    
    if (NT_SUCCESS(Status)) {
        if (dtd.TrimEnabled) {
            dev->trim = TRUE;
            Vcb->trim = TRUE;
            TRACE("TRIM supported\n");
        } else
            TRACE("TRIM not supported\n");
    }
}

static NTSTATUS STDCALL load_chunk_root(device_extension* Vcb, PIRP Irp) {
    traverse_ptr tp, next_tp;
    KEY searchkey;
    BOOL b;
    chunk* c;
    NTSTATUS Status;

    searchkey.obj_id = 0;
    searchkey.obj_type = 0;
    searchkey.offset = 0;
    
    Vcb->data_flags = 0;
    Vcb->metadata_flags = 0;
    Vcb->system_flags = 0;
    
    Status = find_item(Vcb, Vcb->chunk_root, &tp, &searchkey, FALSE, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08x\n", Status);
        return Status;
    }
    
    do {
        TRACE("(%llx,%x,%llx)\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset);
        
        if (tp.item->key.obj_id == 1 && tp.item->key.obj_type == TYPE_DEV_ITEM) {
            if (tp.item->size < sizeof(DEV_ITEM)) {
                ERR("(%llx,%x,%llx) was %u bytes, expected %u\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, tp.item->size, sizeof(DEV_ITEM));
            } else {
                DEV_ITEM* di = (DEV_ITEM*)tp.item->data;
                LIST_ENTRY* le;
                BOOL done = FALSE;
                
                le = Vcb->devices.Flink;
                while (le != &Vcb->devices) {
                    device* dev = CONTAINING_RECORD(le, device, list_entry);
                    
                    if (dev->devobj && RtlCompareMemory(&dev->devitem.device_uuid, &di->device_uuid, sizeof(BTRFS_UUID)) == sizeof(BTRFS_UUID)) {
                        RtlCopyMemory(&dev->devitem, tp.item->data, min(tp.item->size, sizeof(DEV_ITEM)));
                        
                        if (le != Vcb->devices.Flink)
                            init_device(Vcb, dev, TRUE);
                        
                        done = TRUE;
                        break;
                    }

                    le = le->Flink;
                }
                
                if (!done) {
                    volume_device_extension* vde = Vcb->vde;
                    
                    ExAcquireResourceSharedLite(&vde->child_lock, TRUE);
                    
                    if (Vcb->devices_loaded < Vcb->superblock.num_devices) {
                        LIST_ENTRY* le = vde->children.Flink;
                        
                        while (le != &vde->children) {
                            volume_child* vc = CONTAINING_RECORD(le, volume_child, list_entry);
            
                            if (RtlCompareMemory(&di->device_uuid, &vc->uuid, sizeof(BTRFS_UUID)) == sizeof(BTRFS_UUID)) {
                                device* dev;

                                dev = ExAllocatePoolWithTag(NonPagedPool, sizeof(device), ALLOC_TAG);
                                if (!dev) {
                                    ExReleaseResourceLite(&vde->child_lock);
                                    ERR("out of memory\n");
                                    return STATUS_INSUFFICIENT_RESOURCES;
                                }
                                
                                RtlZeroMemory(dev, sizeof(device));
                               
                                dev->devobj = vc->devobj;
                                RtlCopyMemory(&dev->devitem, di, min(tp.item->size, sizeof(DEV_ITEM)));
                                dev->seeding = vc->seeding;
                                init_device(Vcb, dev, FALSE);

                                dev->length = vc->size;
                                dev->disk_num = vc->disk_num;
                                dev->part_num = vc->part_num;
                                add_device_to_list(Vcb, dev);
                                Vcb->devices_loaded++;

                                done = TRUE;
                                break;
                            }
                            
                            le = le->Flink;
                        }
                        
                        if (!done) {
                            ERR("volume not found: device %llx, uuid %02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n", tp.item->key.offset,
                            di->device_uuid.uuid[0], di->device_uuid.uuid[1], di->device_uuid.uuid[2], di->device_uuid.uuid[3], di->device_uuid.uuid[4], di->device_uuid.uuid[5], di->device_uuid.uuid[6], di->device_uuid.uuid[7],
                            di->device_uuid.uuid[8], di->device_uuid.uuid[9], di->device_uuid.uuid[10], di->device_uuid.uuid[11], di->device_uuid.uuid[12], di->device_uuid.uuid[13], di->device_uuid.uuid[14], di->device_uuid.uuid[15]);
                        }
                    } else
                        ERR("unexpected device %llx found\n", tp.item->key.offset);
                    
                    ExReleaseResourceLite(&vde->child_lock);
                }
            }
        } else if (tp.item->key.obj_type == TYPE_CHUNK_ITEM) {
            if (tp.item->size < sizeof(CHUNK_ITEM)) {
                ERR("(%llx,%x,%llx) was %u bytes, expected at least %u\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, tp.item->size, sizeof(CHUNK_ITEM));
            } else {            
                c = ExAllocatePoolWithTag(NonPagedPool, sizeof(chunk), ALLOC_TAG);
                
                if (!c) {
                    ERR("out of memory\n");
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                
                c->size = tp.item->size;
                c->offset = tp.item->key.offset;
                c->used = c->oldused = 0;
                c->cache = c->old_cache = NULL;
                c->created = FALSE;
                c->readonly = FALSE;
                c->reloc = FALSE;
                c->cache_loaded = FALSE;
                
                c->chunk_item = ExAllocatePoolWithTag(NonPagedPool, tp.item->size, ALLOC_TAG);
                
                if (!c->chunk_item) {
                    ERR("out of memory\n");
                    ExFreePool(c);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
            
                RtlCopyMemory(c->chunk_item, tp.item->data, tp.item->size);
                
                if (c->chunk_item->type & BLOCK_FLAG_DATA && c->chunk_item->type > Vcb->data_flags)
                    Vcb->data_flags = c->chunk_item->type;
                
                if (c->chunk_item->type & BLOCK_FLAG_METADATA && c->chunk_item->type > Vcb->metadata_flags)
                    Vcb->metadata_flags = c->chunk_item->type;
                
                if (c->chunk_item->type & BLOCK_FLAG_SYSTEM && c->chunk_item->type > Vcb->system_flags)
                    Vcb->system_flags = c->chunk_item->type;
                
                if (c->chunk_item->num_stripes > 0) {
                    CHUNK_ITEM_STRIPE* cis = (CHUNK_ITEM_STRIPE*)&c->chunk_item[1];
                    UINT16 i;
                    
                    c->devices = ExAllocatePoolWithTag(NonPagedPool, sizeof(device*) * c->chunk_item->num_stripes, ALLOC_TAG);
                    
                    if (!c->devices) {
                        ERR("out of memory\n");
                        ExFreePool(c->chunk_item);
                        ExFreePool(c);
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }
                    
                    for (i = 0; i < c->chunk_item->num_stripes; i++) {
                        c->devices[i] = find_device_from_uuid(Vcb, &cis[i].dev_uuid);
                        TRACE("device %llu = %p\n", i, c->devices[i]);
                        
                        if (!c->devices[i]) {
                            ERR("missing device\n");
                            ExFreePool(c->chunk_item);
                            ExFreePool(c);
                            return STATUS_INTERNAL_ERROR;
                        }
                            
                        if (c->devices[i]->readonly)
                            c->readonly = TRUE;
                    }
                } else
                    c->devices = NULL;
                
                ExInitializeResourceLite(&c->lock);
                ExInitializeResourceLite(&c->changed_extents_lock);
                
                InitializeListHead(&c->space);
                InitializeListHead(&c->space_size);
                InitializeListHead(&c->deleting);
                InitializeListHead(&c->changed_extents);
                
                InitializeListHead(&c->range_locks);
                ExInitializeResourceLite(&c->range_locks_lock);
                KeInitializeEvent(&c->range_locks_event, NotificationEvent, FALSE);
                
                c->last_alloc_set = FALSE;
                
                c->last_stripe = 0;

                InsertTailList(&Vcb->chunks, &c->list_entry);
                
                c->list_entry_changed.Flink = NULL;
                c->list_entry_balance.Flink = NULL;
            }
        }
    
        b = find_next_item(Vcb, &tp, &next_tp, FALSE, Irp);
        
        if (b)
            tp = next_tp;
    } while (b);
    
    Vcb->log_to_phys_loaded = TRUE;
    
    if (Vcb->data_flags == 0)
        Vcb->data_flags = BLOCK_FLAG_DATA | (Vcb->superblock.num_devices > 1 ? BLOCK_FLAG_RAID0 : 0);
    
    if (Vcb->metadata_flags == 0)
        Vcb->metadata_flags = BLOCK_FLAG_METADATA | (Vcb->superblock.num_devices > 1 ? BLOCK_FLAG_RAID1 : BLOCK_FLAG_DUPLICATE);
    
    if (Vcb->system_flags == 0)
        Vcb->system_flags = BLOCK_FLAG_SYSTEM | (Vcb->superblock.num_devices > 1 ? BLOCK_FLAG_RAID1 : BLOCK_FLAG_DUPLICATE);
    
    if (Vcb->superblock.incompat_flags & BTRFS_INCOMPAT_FLAGS_MIXED_GROUPS) {
        Vcb->metadata_flags |= BLOCK_FLAG_DATA;
        Vcb->data_flags = Vcb->metadata_flags;
    }
    
    return STATUS_SUCCESS;
}

void protect_superblocks(device_extension* Vcb, chunk* c) {
    UINT16 i = 0, j;
    UINT64 off_start, off_end;
    
    // The Linux driver also protects all the space before the first superblock.
    // I realize this confuses physical and logical addresses, but this is what btrfs-progs does - 
    // evidently Linux assumes the chunk at 0 is always SINGLE.
    if (c->offset < superblock_addrs[0])
        space_list_subtract(Vcb, c, FALSE, c->offset, superblock_addrs[0] - c->offset, NULL);
    
    while (superblock_addrs[i] != 0) {
        CHUNK_ITEM* ci = c->chunk_item;
        CHUNK_ITEM_STRIPE* cis = (CHUNK_ITEM_STRIPE*)&ci[1];
        
        if (ci->type & BLOCK_FLAG_RAID0 || ci->type & BLOCK_FLAG_RAID10) {
            for (j = 0; j < ci->num_stripes; j++) {
                ULONG sub_stripes = max(ci->sub_stripes, 1);
                
                if (cis[j].offset + (ci->size * ci->num_stripes / sub_stripes) > superblock_addrs[i] && cis[j].offset <= superblock_addrs[i] + sizeof(superblock)) {
#ifdef _DEBUG
                    UINT64 startoff;
                    UINT16 startoffstripe;
#endif
                    
                    TRACE("cut out superblock in chunk %llx\n", c->offset);
                    
                    off_start = superblock_addrs[i] - cis[j].offset;
                    off_start -= off_start % ci->stripe_length;
                    off_start *= ci->num_stripes / sub_stripes;
                    off_start += (j / sub_stripes) * ci->stripe_length;

                    off_end = off_start + ci->stripe_length;
                    
#ifdef _DEBUG
                    get_raid0_offset(off_start, ci->stripe_length, ci->num_stripes / sub_stripes, &startoff, &startoffstripe);
                    TRACE("j = %u, startoffstripe = %u\n", j, startoffstripe);
                    TRACE("startoff = %llx, superblock = %llx\n", startoff + cis[j].offset, superblock_addrs[i]);
#endif
                    
                    space_list_subtract(Vcb, c, FALSE, c->offset + off_start, off_end - off_start, NULL);
                }
            }
        } else if (ci->type & BLOCK_FLAG_RAID5) {
            UINT64 stripe_size = ci->size / (ci->num_stripes - 1);
            
            for (j = 0; j < ci->num_stripes; j++) {
                if (cis[j].offset + stripe_size > superblock_addrs[i] && cis[j].offset <= superblock_addrs[i] + sizeof(superblock)) {
                    TRACE("cut out superblock in chunk %llx\n", c->offset);
                    
                    off_start = superblock_addrs[i] - cis[j].offset;
                    off_start -= off_start % ci->stripe_length;
                    off_start *= ci->num_stripes - 1;

                    off_end = sector_align(superblock_addrs[i] - cis[j].offset + sizeof(superblock), ci->stripe_length);
                    off_end *= ci->num_stripes - 1;
                    
                    TRACE("cutting out %llx, size %llx\n", c->offset + off_start, off_end - off_start);

                    space_list_subtract(Vcb, c, FALSE, c->offset + off_start, off_end - off_start, NULL);
                }
            }
        } else if (ci->type & BLOCK_FLAG_RAID6) {
            UINT64 stripe_size = ci->size / (ci->num_stripes - 2);
            
            for (j = 0; j < ci->num_stripes; j++) {
                if (cis[j].offset + stripe_size > superblock_addrs[i] && cis[j].offset <= superblock_addrs[i] + sizeof(superblock)) {
                    TRACE("cut out superblock in chunk %llx\n", c->offset);
                    
                    off_start = superblock_addrs[i] - cis[j].offset;
                    off_start -= off_start % ci->stripe_length;
                    off_start *= ci->num_stripes - 2;

                    off_end = sector_align(superblock_addrs[i] - cis[j].offset + sizeof(superblock), ci->stripe_length);
                    off_end *= ci->num_stripes - 2;
                    
                    TRACE("cutting out %llx, size %llx\n", c->offset + off_start, off_end - off_start);

                    space_list_subtract(Vcb, c, FALSE, c->offset + off_start, off_end - off_start, NULL);
                }
            }
        } else { // SINGLE, DUPLICATE, RAID1
            for (j = 0; j < ci->num_stripes; j++) {
                if (cis[j].offset + ci->size > superblock_addrs[i] && cis[j].offset <= superblock_addrs[i] + sizeof(superblock)) {
                    TRACE("cut out superblock in chunk %llx\n", c->offset);
                    
                    // The Linux driver protects the whole stripe in which the superblock lives

                    off_start = ((superblock_addrs[i] - cis[j].offset) / c->chunk_item->stripe_length) * c->chunk_item->stripe_length;
                    off_end = sector_align(superblock_addrs[i] - cis[j].offset + sizeof(superblock), c->chunk_item->stripe_length);
                    
                    space_list_subtract(Vcb, c, FALSE, c->offset + off_start, off_end - off_start, NULL);
                }
            }
        }
        
        i++;
    }
}

static NTSTATUS STDCALL find_chunk_usage(device_extension* Vcb, PIRP Irp) {
    LIST_ENTRY* le = Vcb->chunks.Flink;
    chunk* c;
    KEY searchkey;
    traverse_ptr tp;
    BLOCK_GROUP_ITEM* bgi;
    NTSTATUS Status;
    
    searchkey.obj_type = TYPE_BLOCK_GROUP_ITEM;
    
    while (le != &Vcb->chunks) {
        c = CONTAINING_RECORD(le, chunk, list_entry);
        
        searchkey.obj_id = c->offset;
        searchkey.offset = c->chunk_item->size;
        
        Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, FALSE, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("error - find_item returned %08x\n", Status);
            return Status;
        }
        
        if (!keycmp(searchkey, tp.item->key)) {
            if (tp.item->size >= sizeof(BLOCK_GROUP_ITEM)) {
                bgi = (BLOCK_GROUP_ITEM*)tp.item->data;
                
                c->used = c->oldused = bgi->used;
                
                TRACE("chunk %llx has %llx bytes used\n", c->offset, c->used);
            } else {
                ERR("(%llx;%llx,%x,%llx) is %u bytes, expected %u\n",
                    Vcb->extent_root->id, tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, tp.item->size, sizeof(BLOCK_GROUP_ITEM));
            }
        }

        le = le->Flink;
    }
    
    return STATUS_SUCCESS;
}

// static void STDCALL root_test(device_extension* Vcb) {
//     root* r;
//     KEY searchkey;
//     traverse_ptr tp, next_tp;
//     BOOL b;
//     
//     r = Vcb->roots;
//     while (r) {
//         if (r->id == 0x102)
//             break;
//         r = r->next;
//     }
//     
//     if (!r) {
//         ERR("Could not find root tree.\n");
//         return;
//     }
//     
//     searchkey.obj_id = 0x1b6;
//     searchkey.obj_type = 0xb;
//     searchkey.offset = 0;
//     
//     if (!find_item(Vcb, r, &tp, &searchkey, NULL, FALSE)) {
//         ERR("Could not find first item.\n");
//         return;
//     }
//     
//     b = TRUE;
//     do {
//         TRACE("%x,%x,%x\n", (UINT32)tp.item->key.obj_id, tp.item->key.obj_type, (UINT32)tp.item->key.offset);
//         
//         b = find_prev_item(Vcb, &tp, &next_tp, NULL, FALSE);
//         
//         if (b) {
//             free_traverse_ptr(&tp);
//             tp = next_tp;
//         }
//     } while (b);
//     
//     free_traverse_ptr(&tp);
// }

static NTSTATUS load_sys_chunks(device_extension* Vcb) {
    KEY key;
    ULONG n = Vcb->superblock.n;
    
    while (n > 0) {
        if (n > sizeof(KEY)) {
            RtlCopyMemory(&key, &Vcb->superblock.sys_chunk_array[Vcb->superblock.n - n], sizeof(KEY));
            n -= sizeof(KEY);
        } else
            return STATUS_SUCCESS;
        
        TRACE("bootstrap: %llx,%x,%llx\n", key.obj_id, key.obj_type, key.offset);
        
        if (key.obj_type == TYPE_CHUNK_ITEM) {
            CHUNK_ITEM* ci;
            ULONG cisize;
            sys_chunk* sc;
            
            if (n < sizeof(CHUNK_ITEM))
                return STATUS_SUCCESS;
            
            ci = (CHUNK_ITEM*)&Vcb->superblock.sys_chunk_array[Vcb->superblock.n - n];
            cisize = sizeof(CHUNK_ITEM) + (ci->num_stripes * sizeof(CHUNK_ITEM_STRIPE));
            
            if (n < cisize)
                return STATUS_SUCCESS;
            
            sc = ExAllocatePoolWithTag(PagedPool, sizeof(sys_chunk), ALLOC_TAG);
            
            if (!sc) {
                ERR("out of memory\n");
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            
            sc->key = key;
            sc->size = cisize;
            sc->data = ExAllocatePoolWithTag(PagedPool, sc->size, ALLOC_TAG);
            
            if (!sc->data) {
                ERR("out of memory\n");
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            
            RtlCopyMemory(sc->data, ci, sc->size);
            InsertTailList(&Vcb->sys_chunks, &sc->list_entry);
            
            n -= cisize;
        } else {
            ERR("unexpected item %llx,%x,%llx in bootstrap\n", key.obj_id, key.obj_type, key.offset);
            return STATUS_INTERNAL_ERROR;
        }
    }
    
    return STATUS_SUCCESS;
}

static root* find_default_subvol(device_extension* Vcb, PIRP Irp) {
    LIST_ENTRY* le;
    
    static char fn[] = "default";
    static UINT32 crc32 = 0x8dbfc2d2;
    
    if (Vcb->options.subvol_id != 0) {
        le = Vcb->roots.Flink;
        while (le != &Vcb->roots) {
            root* r = CONTAINING_RECORD(le, root, list_entry);
            
            if (r->id == Vcb->options.subvol_id)
                return r;
            
            le = le->Flink;
        }
    }
    
    if (Vcb->superblock.incompat_flags & BTRFS_INCOMPAT_FLAGS_DEFAULT_SUBVOL) {
        NTSTATUS Status;
        KEY searchkey;
        traverse_ptr tp;
        DIR_ITEM* di;
        
        searchkey.obj_id = Vcb->superblock.root_dir_objectid;
        searchkey.obj_type = TYPE_DIR_ITEM;
        searchkey.offset = crc32;
        
        Status = find_item(Vcb, Vcb->root_root, &tp, &searchkey, FALSE, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("error - find_item returned %08x\n", Status);
            goto end;
        }
        
        if (keycmp(tp.item->key, searchkey)) {
            ERR("could not find (%llx,%x,%llx) in root tree\n", searchkey.obj_id, searchkey.obj_type, searchkey.offset);
            goto end;
        }
        
        if (tp.item->size < sizeof(DIR_ITEM)) {
            ERR("(%llx,%x,%llx) was %u bytes, expected at least %u\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, tp.item->size, sizeof(DIR_ITEM));
            goto end;
        }
        
        di = (DIR_ITEM*)tp.item->data;
        
        if (tp.item->size < sizeof(DIR_ITEM) - 1 + di->n) {
            ERR("(%llx,%x,%llx) was %u bytes, expected %u\n", tp.item->key.obj_id, tp.item->key.obj_type, tp.item->key.offset, tp.item->size, sizeof(DIR_ITEM) - 1 + di->n);
            goto end;
        }
        
        if (di->n != strlen(fn) || RtlCompareMemory(di->name, fn, di->n) != di->n) {
            ERR("root DIR_ITEM had same CRC32, but was not \"default\"\n");
            goto end;
        }
        
        if (di->key.obj_type != TYPE_ROOT_ITEM) {
            ERR("default root has key (%llx,%x,%llx), expected subvolume\n", di->key.obj_id, di->key.obj_type, di->key.offset);
            goto end;
        }
        
        le = Vcb->roots.Flink;
        while (le != &Vcb->roots) {
            root* r = CONTAINING_RECORD(le, root, list_entry);
            
            if (r->id == di->key.obj_id)
                return r;
            
            le = le->Flink;
        }
        
        ERR("could not find root %llx, using default instead\n", di->key.obj_id);
    }
    
end:
    le = Vcb->roots.Flink;
    while (le != &Vcb->roots) {
        root* r = CONTAINING_RECORD(le, root, list_entry);
        
        if (r->id == BTRFS_ROOT_FSTREE)
            return r;
        
        le = le->Flink;
    }
    
    return NULL;
}

void init_file_cache(PFILE_OBJECT FileObject, CC_FILE_SIZES* ccfs) {
    TRACE("(%p, %p)\n", FileObject, ccfs);
    
    CcInitializeCacheMap(FileObject, ccfs, FALSE, cache_callbacks, FileObject);
    
    if (diskacc)
        CcSetAdditionalCacheAttributesEx(FileObject, CC_ENABLE_DISK_IO_ACCOUNTING);

    CcSetReadAheadGranularity(FileObject, READ_AHEAD_GRANULARITY);
}

static NTSTATUS create_calc_threads(PDEVICE_OBJECT DeviceObject) {
    device_extension* Vcb = DeviceObject->DeviceExtension;
    ULONG i;
    
    Vcb->calcthreads.num_threads = KeQueryActiveProcessorCount(NULL);
    
    Vcb->calcthreads.threads = ExAllocatePoolWithTag(NonPagedPool, sizeof(drv_calc_thread) * Vcb->calcthreads.num_threads, ALLOC_TAG);
    if (!Vcb->calcthreads.threads) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    InitializeListHead(&Vcb->calcthreads.job_list);
    ExInitializeResourceLite(&Vcb->calcthreads.lock);
    KeInitializeEvent(&Vcb->calcthreads.event, NotificationEvent, FALSE);
    
    RtlZeroMemory(Vcb->calcthreads.threads, sizeof(drv_calc_thread) * Vcb->calcthreads.num_threads);
    
    for (i = 0; i < Vcb->calcthreads.num_threads; i++) {
        NTSTATUS Status;
        
        Vcb->calcthreads.threads[i].DeviceObject = DeviceObject;
        KeInitializeEvent(&Vcb->calcthreads.threads[i].finished, NotificationEvent, FALSE);
        
        Status = PsCreateSystemThread(&Vcb->calcthreads.threads[i].handle, 0, NULL, NULL, NULL, calc_thread, &Vcb->calcthreads.threads[i]);
        if (!NT_SUCCESS(Status)) {
            ULONG j;
            
            ERR("PsCreateSystemThread returned %08x\n", Status);
            
            for (j = 0; j < i; j++) {
                Vcb->calcthreads.threads[i].quit = TRUE;
            }
            
            KeSetEvent(&Vcb->calcthreads.event, 0, FALSE);
            
            return Status;
        }
    }
    
    return STATUS_SUCCESS;
}

static BOOL is_btrfs_volume(PDEVICE_OBJECT DeviceObject) {
    NTSTATUS Status;
    MOUNTDEV_NAME mdn, *mdn2;
    ULONG mdnsize;
    
    Status = dev_ioctl(DeviceObject, IOCTL_MOUNTDEV_QUERY_DEVICE_NAME, NULL, 0, &mdn, sizeof(MOUNTDEV_NAME), TRUE, NULL);
    if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_OVERFLOW) {
        ERR("IOCTL_MOUNTDEV_QUERY_DEVICE_NAME returned %08x\n", Status);
        return FALSE;
    }
    
    mdnsize = offsetof(MOUNTDEV_NAME, Name[0]) + mdn.NameLength;
    
    mdn2 = ExAllocatePoolWithTag(PagedPool, mdnsize, ALLOC_TAG);
    if (!mdn2) {
        ERR("out of memory\n");
        return FALSE;
    }
    
    Status = dev_ioctl(DeviceObject, IOCTL_MOUNTDEV_QUERY_DEVICE_NAME, NULL, 0, mdn2, mdnsize, TRUE, NULL);
    if (!NT_SUCCESS(Status)) {
        ERR("IOCTL_MOUNTDEV_QUERY_DEVICE_NAME returned %08x\n", Status);
        ExFreePool(mdn2);
        return FALSE;
    }
    
    if (mdn2->NameLength > wcslen(BTRFS_VOLUME_PREFIX) * sizeof(WCHAR) &&
        RtlCompareMemory(mdn2->Name, BTRFS_VOLUME_PREFIX, wcslen(BTRFS_VOLUME_PREFIX) * sizeof(WCHAR)) == wcslen(BTRFS_VOLUME_PREFIX) * sizeof(WCHAR)) {
        ExFreePool(mdn2);
        return TRUE;
    }
    
    ExFreePool(mdn2);
    
    return FALSE;
}

static NTSTATUS get_device_pnp_name_guid(PDEVICE_OBJECT DeviceObject, PUNICODE_STRING pnp_name, const GUID* guid) {
    NTSTATUS Status;
    WCHAR *list = NULL, *s;
    
    Status = IoGetDeviceInterfaces((PVOID)guid, NULL, 0, &list);
    if (!NT_SUCCESS(Status)) {
        ERR("IoGetDeviceInterfaces returned %08x\n", Status);
        return Status;
    }
    
    s = list;
    while (s[0] != 0) {
        PFILE_OBJECT FileObject;
        PDEVICE_OBJECT devobj;
        UNICODE_STRING name;
        
        name.Length = name.MaximumLength = wcslen(s) * sizeof(WCHAR);
        name.Buffer = s;
        
        if (NT_SUCCESS(IoGetDeviceObjectPointer(&name, FILE_READ_ATTRIBUTES, &FileObject, &devobj))) {
            if (DeviceObject == devobj || DeviceObject == FileObject->DeviceObject) {
                ObDereferenceObject(FileObject);
                
                pnp_name->Buffer = ExAllocatePoolWithTag(PagedPool, name.Length, ALLOC_TAG);
                if (!pnp_name->Buffer) {
                    ERR("out of memory\n");
                    Status = STATUS_INSUFFICIENT_RESOURCES;
                    goto end;
                }
                
                RtlCopyMemory(pnp_name->Buffer, name.Buffer, name.Length);
                pnp_name->Length = pnp_name->MaximumLength = name.Length;
                
                Status = STATUS_SUCCESS;
                goto end;
            }
            
            ObDereferenceObject(FileObject);
        }
        
        s = &s[wcslen(s) + 1];
    }
    
    pnp_name->Length = pnp_name->MaximumLength = 0;
    pnp_name->Buffer = 0;
    
    Status = STATUS_NOT_FOUND;
    
end:
    if (list)
        ExFreePool(list);
    
    return Status;
}

NTSTATUS get_device_pnp_name(PDEVICE_OBJECT DeviceObject, PUNICODE_STRING pnp_name, const GUID** guid) {
    NTSTATUS Status;
    
    Status = get_device_pnp_name_guid(DeviceObject, pnp_name, &GUID_DEVINTERFACE_VOLUME);
    if (NT_SUCCESS(Status)) {
        *guid = &GUID_DEVINTERFACE_VOLUME;
        return Status;
    }
    
    Status = get_device_pnp_name_guid(DeviceObject, pnp_name, &GUID_DEVINTERFACE_HIDDEN_VOLUME);
    if (NT_SUCCESS(Status)) {
        *guid = &GUID_DEVINTERFACE_HIDDEN_VOLUME;
        return Status;
    }
    
    Status = get_device_pnp_name_guid(DeviceObject, pnp_name, &GUID_DEVINTERFACE_DISK);
    if (NT_SUCCESS(Status)) {
        *guid = &GUID_DEVINTERFACE_DISK;
        return Status;
    }
    
    return STATUS_NOT_FOUND;
}

static NTSTATUS check_mount_device(PDEVICE_OBJECT DeviceObject) {
    NTSTATUS Status;
    ULONG to_read;
    superblock* sb;
    UINT32 crc32;
    UNICODE_STRING pnp_name;
    const GUID* guid;
    
    to_read = DeviceObject->SectorSize == 0 ? sizeof(superblock) : sector_align(sizeof(superblock), DeviceObject->SectorSize);
    
    sb = ExAllocatePoolWithTag(NonPagedPool, to_read, ALLOC_TAG);
    if (!sb) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    Status = sync_read_phys(DeviceObject, superblock_addrs[0], to_read, (PUCHAR)sb, FALSE);
    if (!NT_SUCCESS(Status)) {
        ERR("sync_read_phys returned %08x\n", Status);
        goto end;
    }

    if (sb->magic != BTRFS_MAGIC) {
        Status = STATUS_SUCCESS;
        goto end;
    }
    
    crc32 = ~calc_crc32c(0xffffffff, (UINT8*)&sb->uuid, (ULONG)sizeof(superblock) - sizeof(sb->checksum));
        
    if (crc32 != *((UINT32*)sb->checksum)) {
        WARN("crc32 was %08x, expected %08x\n", crc32, *((UINT32*)sb->checksum));
        Status = STATUS_SUCCESS;
        goto end;
    }
    
    Status = get_device_pnp_name(DeviceObject, &pnp_name, &guid);
    if (!NT_SUCCESS(Status)) {
        ERR("get_device_pnp_name returned %08x\n", Status);
        goto end;
    }
    
    if (pnp_name.Length == 0)
        goto end;
    
    volume_arrival(drvobj, &pnp_name);
    
    ExFreePool(pnp_name.Buffer);

end:
    ExFreePool(sb);
    
    return Status;
}

static BOOL still_has_superblock(PDEVICE_OBJECT device) {
    NTSTATUS Status;
    ULONG to_read;
    superblock* sb;
    
    to_read = device->SectorSize == 0 ? sizeof(superblock) : sector_align(sizeof(superblock), device->SectorSize);
    
    sb = ExAllocatePoolWithTag(NonPagedPool, to_read, ALLOC_TAG);
    if (!sb) {
        ERR("out of memory\n");
        return FALSE;
    }
    
    Status = sync_read_phys(device, superblock_addrs[0], to_read, (PUCHAR)sb, TRUE);
    if (!NT_SUCCESS(Status)) {
        ERR("Failed to read superblock: %08x\n", Status);
        ExFreePool(sb);
        return FALSE;
    }
    
    if (sb->magic != BTRFS_MAGIC) {
        TRACE("not a BTRFS volume\n");
        ExFreePool(sb);
        return FALSE;
    } else {
        UINT32 crc32 = ~calc_crc32c(0xffffffff, (UINT8*)&sb->uuid, (ULONG)sizeof(superblock) - sizeof(sb->checksum));
        
        if (crc32 != *((UINT32*)sb->checksum)) {
            WARN("crc32 was %08x, expected %08x\n", crc32, *((UINT32*)sb->checksum));
            ExFreePool(sb);
            return FALSE;
        }
    }
    
    device->Flags &= ~DO_VERIFY_VOLUME;
    
    ExFreePool(sb);
    return TRUE;
}

static NTSTATUS STDCALL mount_vol(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION IrpSp;
    PDEVICE_OBJECT NewDeviceObject = NULL;
    PDEVICE_OBJECT DeviceToMount;
    NTSTATUS Status;
    device_extension* Vcb = NULL;
    LIST_ENTRY *le, batchlist;
    KEY searchkey;
    traverse_ptr tp;
    fcb* root_fcb = NULL;
    ccb* root_ccb = NULL;
    BOOL init_lookaside = FALSE;
    device* dev;
    volume_device_extension* vde;
    volume_child* vc;
    
    TRACE("(%p, %p)\n", DeviceObject, Irp);
    
    if (DeviceObject != devobj) {
        Status = STATUS_INVALID_DEVICE_REQUEST;
        goto exit;
    }

    IrpSp = IoGetCurrentIrpStackLocation(Irp);
    DeviceToMount = IrpSp->Parameters.MountVolume.DeviceObject;
    
    if (!is_btrfs_volume(DeviceToMount)) {
        Status = check_mount_device(DeviceToMount);
        if (!NT_SUCCESS(Status))
            WARN("check_mount_device returned %08x\n", Status);

        Status = STATUS_UNRECOGNIZED_VOLUME;
        goto exit2;
    }
    
    vde = DeviceToMount->DeviceExtension;
    
    if (!vde || vde->type != VCB_TYPE_VOLUME) {
        Status = STATUS_UNRECOGNIZED_VOLUME;
        goto exit2;
    }
    
    ExAcquireResourceExclusiveLite(&vde->child_lock, TRUE);
    
    le = vde->children.Flink;
    while (le != &vde->children) {
        LIST_ENTRY* le2 = le->Flink;
        
        vc = CONTAINING_RECORD(vde->children.Flink, volume_child, list_entry);
        
        if (!still_has_superblock(vc->devobj)) {
            remove_volume_child(vde, vc, TRUE);
            
            if (vde->num_children == 0) {
                ERR("error - number of devices is zero\n");
                Status = STATUS_INTERNAL_ERROR;
                goto exit2;
            }
            
            if (vde->children_loaded == 0) { // just removed last device
                Status = STATUS_DEVICE_NOT_READY;
                goto exit2;
            }
        }
        
        le = le2;
    }
    
    if (vde->children_loaded < vde->num_children) { // devices missing
        Status = STATUS_DEVICE_NOT_READY;
        goto exit;
    }
    
    if (vde->num_children == 0) {
        ERR("error - number of devices is zero\n");
        Status = STATUS_INTERNAL_ERROR;
        goto exit;
    }
    
    ExConvertExclusiveToSharedLite(&vde->child_lock);
    
    vc = CONTAINING_RECORD(vde->children.Flink, volume_child, list_entry);

    Status = IoCreateDevice(drvobj, sizeof(device_extension), NULL, FILE_DEVICE_DISK_FILE_SYSTEM, 0, FALSE, &NewDeviceObject);
    if (!NT_SUCCESS(Status)) {
        ERR("IoCreateDevice returned %08x\n", Status);
        Status = STATUS_UNRECOGNIZED_VOLUME;
        goto exit;
    }
    
    NewDeviceObject->Flags |= DO_DIRECT_IO;
    NewDeviceObject->SectorSize = DeviceToMount->SectorSize;
    Vcb = (PVOID)NewDeviceObject->DeviceExtension;
    RtlZeroMemory(Vcb, sizeof(device_extension));
    Vcb->type = VCB_TYPE_FS;
    Vcb->vde = vde;
    
    ExInitializeResourceLite(&Vcb->tree_lock);
    Vcb->open_trees = 0;
    Vcb->need_write = FALSE;

    ExInitializeResourceLite(&Vcb->fcb_lock);
    ExInitializeResourceLite(&Vcb->chunk_lock);
    ExInitializeResourceLite(&Vcb->dirty_fcbs_lock);
    ExInitializeResourceLite(&Vcb->dirty_filerefs_lock);
    ExInitializeResourceLite(&Vcb->scrub.stats_lock);

    ExInitializeResourceLite(&Vcb->load_lock);
    ExAcquireResourceExclusiveLite(&Vcb->load_lock, TRUE);

    DeviceToMount->Flags |= DO_DIRECT_IO;

    Status = read_superblock(Vcb, vc->devobj, vc->size);
    if (!NT_SUCCESS(Status)) {
        Status = STATUS_UNRECOGNIZED_VOLUME;
        goto exit;
    }

    Status = registry_load_volume_options(Vcb);
    if (!NT_SUCCESS(Status)) {
        ERR("registry_load_volume_options returned %08x\n", Status);
        goto exit;
    }
    
    if (Vcb->options.ignore) {
        TRACE("ignoring volume\n");
        Status = STATUS_UNRECOGNIZED_VOLUME;
        goto exit;
    }

    if (Vcb->superblock.incompat_flags & ~INCOMPAT_SUPPORTED) {
        WARN("cannot mount because of unsupported incompat flags (%llx)\n", Vcb->superblock.incompat_flags & ~INCOMPAT_SUPPORTED);
        Status = STATUS_UNRECOGNIZED_VOLUME;
        goto exit;
    }
    
    Vcb->readonly = FALSE;
    if (Vcb->superblock.compat_ro_flags & ~COMPAT_RO_SUPPORTED) {
        WARN("mounting read-only because of unsupported flags (%llx)\n", Vcb->superblock.compat_ro_flags & ~COMPAT_RO_SUPPORTED);
        Vcb->readonly = TRUE;
    }
    
    if (Vcb->options.readonly)
        Vcb->readonly = TRUE;
    
    Vcb->superblock.generation++;
    Vcb->superblock.incompat_flags |= BTRFS_INCOMPAT_FLAGS_MIXED_BACKREF;
    
    InitializeListHead(&Vcb->devices);
    dev = ExAllocatePoolWithTag(NonPagedPool, sizeof(device), ALLOC_TAG);
    if (!dev) {
        ERR("out of memory\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto exit;
    }
    
    dev->devobj = vc->devobj;
    RtlCopyMemory(&dev->devitem, &Vcb->superblock.dev_item, sizeof(DEV_ITEM));
    dev->length = vc->size;
    
    dev->seeding = Vcb->superblock.flags & BTRFS_SUPERBLOCK_FLAGS_SEEDING ? TRUE : FALSE;
    
    init_device(Vcb, dev, TRUE);
    
    InsertTailList(&Vcb->devices, &dev->list_entry);
    Vcb->devices_loaded = 1;
    
    if (DeviceToMount->Flags & DO_SYSTEM_BOOT_PARTITION)
        Vcb->disallow_dismount = TRUE;
    
    TRACE("DeviceToMount = %p\n", DeviceToMount);
    TRACE("IrpSp->Parameters.MountVolume.Vpb = %p\n", IrpSp->Parameters.MountVolume.Vpb);

    NewDeviceObject->StackSize = DeviceToMount->StackSize + 1;
    NewDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    
    InitializeListHead(&Vcb->roots);
    InitializeListHead(&Vcb->drop_roots);
    
    Vcb->log_to_phys_loaded = FALSE;
    
    add_root(Vcb, BTRFS_ROOT_CHUNK, Vcb->superblock.chunk_tree_addr, Vcb->superblock.chunk_root_generation, NULL);
    
    if (!Vcb->chunk_root) {
        ERR("Could not load chunk root.\n");
        Status = STATUS_INTERNAL_ERROR;
        goto exit;
    }
       
    InitializeListHead(&Vcb->sys_chunks);
    Status = load_sys_chunks(Vcb);
    if (!NT_SUCCESS(Status)) {
        ERR("load_sys_chunks returned %08x\n", Status);
        goto exit;
    }
    
    InitializeListHead(&Vcb->chunks);
    InitializeListHead(&Vcb->chunks_changed);
    InitializeListHead(&Vcb->trees);
    InitializeListHead(&Vcb->trees_hash);
    InitializeListHead(&Vcb->all_fcbs);
    InitializeListHead(&Vcb->dirty_fcbs);
    InitializeListHead(&Vcb->dirty_filerefs);
    
    InitializeListHead(&Vcb->DirNotifyList);
    InitializeListHead(&Vcb->scrub.errors);

    FsRtlNotifyInitializeSync(&Vcb->NotifySync);
    
    ExInitializePagedLookasideList(&Vcb->tree_data_lookaside, NULL, NULL, 0, sizeof(tree_data), ALLOC_TAG, 0);
    ExInitializePagedLookasideList(&Vcb->traverse_ptr_lookaside, NULL, NULL, 0, sizeof(traverse_ptr), ALLOC_TAG, 0);
    ExInitializePagedLookasideList(&Vcb->rollback_item_lookaside, NULL, NULL, 0, sizeof(rollback_item), ALLOC_TAG, 0);
    ExInitializePagedLookasideList(&Vcb->batch_item_lookaside, NULL, NULL, 0, sizeof(batch_item), ALLOC_TAG, 0);
    ExInitializePagedLookasideList(&Vcb->fileref_lookaside, NULL, NULL, 0, sizeof(file_ref), ALLOC_TAG, 0);
    ExInitializeNPagedLookasideList(&Vcb->range_lock_lookaside, NULL, NULL, 0, sizeof(range_lock), ALLOC_TAG, 0);
    init_lookaside = TRUE;
    
    Vcb->Vpb = IrpSp->Parameters.MountVolume.Vpb;
    
    Status = load_chunk_root(Vcb, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("load_chunk_root returned %08x\n", Status);
        goto exit;
    }
    
    if (Vcb->superblock.num_devices > 1) {
        if (Vcb->devices_loaded < Vcb->superblock.num_devices) {
            ERR("could not mount as %u device(s) missing\n", Vcb->superblock.num_devices - Vcb->devices_loaded);
            
            IoRaiseInformationalHardError(IO_ERR_INTERNAL_ERROR, NULL, NULL);

            Status = STATUS_INTERNAL_ERROR;
            goto exit;
        }
        
        if (dev->readonly && !Vcb->readonly) {
            Vcb->readonly = TRUE;
            
            le = Vcb->devices.Flink;
            while (le != &Vcb->devices) {
                device* dev2 = CONTAINING_RECORD(le, device, list_entry);
                
                if (dev2->readonly && !dev2->seeding)
                    break;
                
                if (!dev2->readonly) {
                    Vcb->readonly = FALSE;
                    break;
                }
                
                le = le->Flink;
            }
            
            if (Vcb->readonly)
                WARN("setting volume to readonly\n");
        }
    } else {
        if (dev->readonly) {
            WARN("setting volume to readonly as device is readonly\n");
            Vcb->readonly = TRUE;
        }
    }
    
    add_root(Vcb, BTRFS_ROOT_ROOT, Vcb->superblock.root_tree_addr, Vcb->superblock.generation - 1, NULL);
    
    if (!Vcb->root_root) {
        ERR("Could not load root of roots.\n");
        Status = STATUS_INTERNAL_ERROR;
        goto exit;
    }
    
    Status = look_for_roots(Vcb, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("look_for_roots returned %08x\n", Status);
        goto exit;
    }
    
    Status = find_chunk_usage(Vcb, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("find_chunk_usage returned %08x\n", Status);
        goto exit;
    }
    
    InitializeListHead(&batchlist);
    
    // We've already increased the generation by one
    if (!Vcb->readonly && (Vcb->superblock.generation - 1 != Vcb->superblock.cache_generation || Vcb->options.clear_cache)) {
        if (Vcb->options.clear_cache)
            WARN("ClearCache option was set, clearing cache...\n");
        else
            WARN("generation was %llx, free-space cache generation was %llx; clearing cache...\n", Vcb->superblock.generation - 1, Vcb->superblock.cache_generation);
        
        Status = clear_free_space_cache(Vcb, &batchlist, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("clear_free_space_cache returned %08x\n", Status);
            clear_batch_list(Vcb, &batchlist);
            goto exit;
        }
    }
    
    commit_batch_list(Vcb, &batchlist, Irp);
    
    Vcb->volume_fcb = create_fcb(NonPagedPool);
    if (!Vcb->volume_fcb) {
        ERR("out of memory\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto exit;
    }
    
    Vcb->volume_fcb->Vcb = Vcb;
    Vcb->volume_fcb->sd = NULL;
    
    root_fcb = create_fcb(NonPagedPool);
    if (!root_fcb) {
        ERR("out of memory\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto exit;
    }
    
    root_fcb->Vcb = Vcb;
    root_fcb->inode = SUBVOL_ROOT_INODE;
    root_fcb->type = BTRFS_TYPE_DIRECTORY;
    
#ifdef DEBUG_FCB_REFCOUNTS
    WARN("volume FCB = %p\n", Vcb->volume_fcb);
    WARN("root FCB = %p\n", root_fcb);
#endif
    
    root_fcb->subvol = find_default_subvol(Vcb, Irp);

    if (!root_fcb->subvol) {
        ERR("could not find top subvol\n");
        Status = STATUS_INTERNAL_ERROR;
        goto exit;
    }
    
    Status = load_dir_children(root_fcb, TRUE, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("load_dir_children returned %08x\n", Status);
        goto exit;
    }
    
    searchkey.obj_id = root_fcb->inode;
    searchkey.obj_type = TYPE_INODE_ITEM;
    searchkey.offset = 0xffffffffffffffff;
    
    Status = find_item(Vcb, root_fcb->subvol, &tp, &searchkey, FALSE, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08x\n", Status);
        goto exit;
    }
    
    if (tp.item->key.obj_id != searchkey.obj_id || tp.item->key.obj_type != searchkey.obj_type) {
        ERR("couldn't find INODE_ITEM for root directory\n");
        Status = STATUS_INTERNAL_ERROR;
        goto exit;
    }
    
    if (tp.item->size > 0)
        RtlCopyMemory(&root_fcb->inode_item, tp.item->data, min(sizeof(INODE_ITEM), tp.item->size));
    
    fcb_get_sd(root_fcb, NULL, TRUE, Irp);
    
    root_fcb->atts = get_file_attributes(Vcb, root_fcb->subvol, root_fcb->inode, root_fcb->type, FALSE, FALSE, Irp);
    
    Vcb->root_fileref = create_fileref(Vcb);
    if (!Vcb->root_fileref) {
        ERR("out of memory\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto exit;
    }
    
    Vcb->root_fileref->fcb = root_fcb;
    InsertTailList(&root_fcb->subvol->fcbs, &root_fcb->list_entry);
    InsertTailList(&Vcb->all_fcbs, &root_fcb->list_entry_all);
    
    root_fcb->fileref = Vcb->root_fileref;
    
    root_ccb = ExAllocatePoolWithTag(PagedPool, sizeof(ccb), ALLOC_TAG);
    if (!root_ccb) {
        ERR("out of memory\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto exit;
    }
    
    Vcb->root_file = IoCreateStreamFileObject(NULL, DeviceToMount);
    Vcb->root_file->FsContext = root_fcb;
    Vcb->root_file->SectionObjectPointer = &root_fcb->nonpaged->segment_object;
    Vcb->root_file->Vpb = DeviceObject->Vpb;
    
    RtlZeroMemory(root_ccb, sizeof(ccb));
    root_ccb->NodeType = BTRFS_NODE_TYPE_CCB;
    root_ccb->NodeSize = sizeof(ccb);
    
    Vcb->root_file->FsContext2 = root_ccb;
    
    try {
        CcInitializeCacheMap(Vcb->root_file, (PCC_FILE_SIZES)(&root_fcb->Header.AllocationSize), FALSE, cache_callbacks, Vcb->root_file);
    } except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
        goto exit;
    }
    
    le = Vcb->devices.Flink;
    while (le != &Vcb->devices) {
        device* dev2 = CONTAINING_RECORD(le, device, list_entry);
        
        Status = find_disk_holes(Vcb, dev2, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("find_disk_holes returned %08x\n", Status);
            goto exit;
        }
        
        le = le->Flink;
    }
    
    NewDeviceObject->Vpb = IrpSp->Parameters.MountVolume.Vpb;
    IrpSp->Parameters.MountVolume.Vpb->DeviceObject = NewDeviceObject;
    IrpSp->Parameters.MountVolume.Vpb->Flags |= VPB_MOUNTED;
    NewDeviceObject->Vpb->VolumeLabelLength = 4; // FIXME
    NewDeviceObject->Vpb->VolumeLabel[0] = '?';
    NewDeviceObject->Vpb->VolumeLabel[1] = 0;
    NewDeviceObject->Vpb->ReferenceCount++; // FIXME - should we deref this at any point?
    
    KeInitializeEvent(&Vcb->flush_thread_finished, NotificationEvent, FALSE);
    
    Status = PsCreateSystemThread(&Vcb->flush_thread_handle, 0, NULL, NULL, NULL, flush_thread, NewDeviceObject);
    if (!NT_SUCCESS(Status)) {
        ERR("PsCreateSystemThread returned %08x\n", Status);
        goto exit;
    }
    
    Status = create_calc_threads(NewDeviceObject);
    if (!NT_SUCCESS(Status)) {
        ERR("create_calc_threads returned %08x\n", Status);
        goto exit;
    }
    
    Status = registry_mark_volume_mounted(&Vcb->superblock.uuid);
    if (!NT_SUCCESS(Status))
        WARN("registry_mark_volume_mounted returned %08x\n", Status);
    
    Status = look_for_balance_item(Vcb);
    if (!NT_SUCCESS(Status) && Status != STATUS_NOT_FOUND)
        WARN("look_for_balance_item returned %08x\n", Status);
    
    Status = STATUS_SUCCESS;
    
    vde->mounted_device = NewDeviceObject;
    
exit:
    ExReleaseResourceLite(&vde->child_lock);

exit2:
    if (Vcb) {
        ExReleaseResourceLite(&Vcb->load_lock);
    }

    if (!NT_SUCCESS(Status)) {
        if (Vcb) {
            if (init_lookaside) {
                ExDeletePagedLookasideList(&Vcb->tree_data_lookaside);
                ExDeletePagedLookasideList(&Vcb->traverse_ptr_lookaside);
                ExDeletePagedLookasideList(&Vcb->rollback_item_lookaside);
                ExDeletePagedLookasideList(&Vcb->batch_item_lookaside);
                ExDeletePagedLookasideList(&Vcb->fileref_lookaside);
                ExDeleteNPagedLookasideList(&Vcb->range_lock_lookaside);
            }
                
            if (Vcb->root_file)
                ObDereferenceObject(Vcb->root_file);
            else if (Vcb->root_fileref)
                free_fileref(Vcb, Vcb->root_fileref);
            else if (root_fcb)
                free_fcb(root_fcb);

            if (Vcb->volume_fcb)
                free_fcb(Vcb->volume_fcb);

            ExDeleteResourceLite(&Vcb->tree_lock);
            ExDeleteResourceLite(&Vcb->load_lock);
            ExDeleteResourceLite(&Vcb->fcb_lock);
            ExDeleteResourceLite(&Vcb->chunk_lock);
            ExDeleteResourceLite(&Vcb->dirty_fcbs_lock);
            ExDeleteResourceLite(&Vcb->dirty_filerefs_lock);
            ExDeleteResourceLite(&Vcb->scrub.stats_lock);

            if (Vcb->devices.Flink) {
                while (!IsListEmpty(&Vcb->devices)) {
                    LIST_ENTRY* le = RemoveHeadList(&Vcb->devices);
                    device* dev = CONTAINING_RECORD(le, device, list_entry);
                    
                    ExFreePool(dev);
                }
            }
        }

        if (NewDeviceObject)
            IoDeleteDevice(NewDeviceObject);
    } else {
        ExAcquireResourceExclusiveLite(&global_loading_lock, TRUE);
        InsertTailList(&VcbList, &Vcb->list_entry);
        ExReleaseResourceLite(&global_loading_lock);
        
        FsRtlNotifyVolumeEvent(Vcb->root_file, FSRTL_VOLUME_MOUNT);
    }

    TRACE("mount_vol done (status: %lx)\n", Status);

    return Status;
}

static NTSTATUS verify_volume(PDEVICE_OBJECT devobj) {
    device_extension* Vcb = devobj->DeviceExtension;
    ULONG cc;
    NTSTATUS Status;
    LIST_ENTRY* le;
    
    if (Vcb->removing)
        return STATUS_WRONG_VOLUME;
    
    Status = dev_ioctl(Vcb->Vpb->RealDevice, IOCTL_STORAGE_CHECK_VERIFY, NULL, 0, &cc, sizeof(ULONG), TRUE, NULL);
    
    if (!NT_SUCCESS(Status)) {
        ERR("dev_ioctl returned %08x\n", Status);
        return Status;
    }
    
    ExAcquireResourceSharedLite(&Vcb->tree_lock, TRUE);
    
    le = Vcb->devices.Flink;
    while (le != &Vcb->devices) {
        device* dev = CONTAINING_RECORD(le, device, list_entry);
        superblock* sb;
        UINT32 crc32;
        ULONG to_read;
        
        if (dev->removable) {
            IO_STATUS_BLOCK iosb;
            
            Status = dev_ioctl(dev->devobj, IOCTL_STORAGE_CHECK_VERIFY, NULL, 0, &cc, sizeof(ULONG), TRUE, &iosb);
            
            if (!NT_SUCCESS(Status)) {
                ExReleaseResourceLite(&Vcb->tree_lock);
                ERR("dev_ioctl returned %08x\n", Status);
                return Status;
            }
            
            if (iosb.Information < sizeof(ULONG)) {
                ExReleaseResourceLite(&Vcb->tree_lock);
                ERR("iosb.Information was too short\n");
                return STATUS_INTERNAL_ERROR;
            }
            
            dev->change_count = cc;
        }
        
        to_read = dev->devobj->SectorSize == 0 ? sizeof(superblock) : sector_align(sizeof(superblock), dev->devobj->SectorSize);
        
        sb = ExAllocatePoolWithTag(NonPagedPool, to_read, ALLOC_TAG);
        if (!sb) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        
        Status = sync_read_phys(dev->devobj, superblock_addrs[0], to_read, (PUCHAR)sb, TRUE);
        if (!NT_SUCCESS(Status)) {
            ERR("Failed to read superblock: %08x\n", Status);
            ExFreePool(sb);
            return Status;
        }
        
        if (sb->magic != BTRFS_MAGIC) {
            ERR("not a BTRFS volume\n");
            ExFreePool(sb);
            return STATUS_WRONG_VOLUME;
        }
        
        crc32 = ~calc_crc32c(0xffffffff, (UINT8*)&sb->uuid, (ULONG)sizeof(superblock) - sizeof(sb->checksum));
        TRACE("crc32 was %08x, expected %08x\n", crc32, *((UINT32*)sb->checksum));
        
        if (crc32 != *((UINT32*)sb->checksum)) {
            ERR("checksum error\n");
            ExFreePool(sb);
            return STATUS_WRONG_VOLUME;
        }
        
        if (RtlCompareMemory(&sb->uuid, &Vcb->superblock.uuid, sizeof(BTRFS_UUID)) != sizeof(BTRFS_UUID)) {
            ERR("different UUIDs\n");
            ExFreePool(sb);
            return STATUS_WRONG_VOLUME;
        }
        
        ExFreePool(sb);
        
        dev->devobj->Flags &= ~DO_VERIFY_VOLUME;
        
        le = le->Flink;
    }
    
    ExReleaseResourceLite(&Vcb->tree_lock);
    
    Vcb->Vpb->RealDevice->Flags &= ~DO_VERIFY_VOLUME;
    
    return STATUS_SUCCESS;
}

static NTSTATUS STDCALL drv_file_system_control(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    PIO_STACK_LOCATION IrpSp;
    NTSTATUS Status;
    device_extension* Vcb = DeviceObject->DeviceExtension;
    BOOL top_level;

    TRACE("file system control\n");
    
    FsRtlEnterFileSystem();

    top_level = is_top_level(Irp);
    
    if (Vcb && Vcb->type == VCB_TYPE_VOLUME) {
        Status = vol_file_system_control(DeviceObject, Irp);
        goto end;
    } else if (!Vcb || (Vcb->type != VCB_TYPE_FS && Vcb->type != VCB_TYPE_CONTROL)) {
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }
    
    Status = STATUS_NOT_IMPLEMENTED;

    IrpSp = IoGetCurrentIrpStackLocation( Irp );
    
    Irp->IoStatus.Information = 0;
    
    switch (IrpSp->MinorFunction) {
        case IRP_MN_MOUNT_VOLUME:
            TRACE("IRP_MN_MOUNT_VOLUME\n");
            
            Status = mount_vol(DeviceObject, Irp);
            break;
            
        case IRP_MN_KERNEL_CALL:
            TRACE("IRP_MN_KERNEL_CALL\n");
            
            Status = fsctl_request(DeviceObject, Irp, IrpSp->Parameters.FileSystemControl.FsControlCode, FALSE);
            break;
            
        case IRP_MN_USER_FS_REQUEST:
            TRACE("IRP_MN_USER_FS_REQUEST\n");
            
            Status = fsctl_request(DeviceObject, Irp, IrpSp->Parameters.FileSystemControl.FsControlCode, TRUE);
            break;
            
        case IRP_MN_VERIFY_VOLUME:
            TRACE("IRP_MN_VERIFY_VOLUME\n");
            
            Status = verify_volume(DeviceObject);
            
            if (!NT_SUCCESS(Status) && Vcb->Vpb->Flags & VPB_MOUNTED) {
                if (Vcb->open_files > 0) {
                    Vcb->removing = TRUE;
//                     Vcb->Vpb->Flags &= ~VPB_MOUNTED;
                } else
                    uninit(Vcb, FALSE);
            }
            
            break;
           
        default:
            break;
    }

end:
    Irp->IoStatus.Status = Status;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
    if (top_level) 
        IoSetTopLevelIrp(NULL);
    
    FsRtlExitFileSystem();

    return Status;
}

static NTSTATUS STDCALL drv_lock_control(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    NTSTATUS Status;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    fcb* fcb = IrpSp->FileObject->FsContext;
    device_extension* Vcb = DeviceObject->DeviceExtension;
    BOOL top_level;

    FsRtlEnterFileSystem();

    top_level = is_top_level(Irp);
    
    if (Vcb && Vcb->type == VCB_TYPE_VOLUME) {
        Status = vol_lock_control(DeviceObject, Irp);
        
        Irp->IoStatus.Status = Status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        
        goto exit;
    }
    
    TRACE("lock control\n");
    
    Status = FsRtlProcessFileLock(&fcb->lock, Irp, NULL);

    fcb->Header.IsFastIoPossible = fast_io_possible(fcb);
    
exit:
    if (top_level) 
        IoSetTopLevelIrp(NULL);
    
    FsRtlExitFileSystem();
    
    return Status;
}

static NTSTATUS STDCALL drv_shutdown(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    NTSTATUS Status;
    BOOL top_level;
    device_extension* Vcb = DeviceObject->DeviceExtension;

    TRACE("shutdown\n");
    
    FsRtlEnterFileSystem();

    top_level = is_top_level(Irp);
    
    if (Vcb && Vcb->type == VCB_TYPE_VOLUME) {
        Status = vol_shutdown(DeviceObject, Irp);
        goto end;
    }    
    
    Status = STATUS_SUCCESS;

    while (!IsListEmpty(&VcbList)) {
        Vcb = CONTAINING_RECORD(VcbList.Flink, device_extension, list_entry);
        
        TRACE("shutting down Vcb %p\n", Vcb);
        
        uninit(Vcb, TRUE);
    }
    
#ifdef _DEBUG
    if (comfo) {
        ObDereferenceObject(comfo);
        comdo = NULL;
        comfo = NULL;
    }
#endif
    
end:
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest( Irp, IO_NO_INCREMENT );

    if (top_level) 
        IoSetTopLevelIrp(NULL);
    
    FsRtlExitFileSystem();

    return Status;
}

static NTSTATUS STDCALL drv_power(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    NTSTATUS Status;
    device_extension* Vcb = DeviceObject->DeviceExtension;
    BOOL top_level;

    FsRtlEnterFileSystem();

    top_level = is_top_level(Irp);
    
    Irp->IoStatus.Information = 0;
    
    if (Vcb && Vcb->type == VCB_TYPE_VOLUME) {
        Status = vol_power(DeviceObject, Irp);
        
        Irp->IoStatus.Status = Status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        
        goto exit;
    } else if (Vcb && Vcb->type == VCB_TYPE_FS) {
        IoSkipCurrentIrpStackLocation(Irp);
    
        Status = IoCallDriver(Vcb->Vpb->RealDevice, Irp);
    
        goto exit;
    }

    Status = STATUS_INVALID_DEVICE_REQUEST;
    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
exit:
    if (top_level) 
        IoSetTopLevelIrp(NULL);
    
    FsRtlExitFileSystem();
    
    return Status;
}

static NTSTATUS STDCALL drv_system_control(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    NTSTATUS Status;
    device_extension* Vcb = DeviceObject->DeviceExtension;
    BOOL top_level;

    FsRtlEnterFileSystem();

    top_level = is_top_level(Irp);
    
    Irp->IoStatus.Information = 0;
    
    if (Vcb && Vcb->type == VCB_TYPE_VOLUME) {
        volume_device_extension* vde = DeviceObject->DeviceExtension;

        IoSkipCurrentIrpStackLocation(Irp);
    
        Status = IoCallDriver(vde->pdo, Irp);
        
        goto exit;
    } else if (Vcb && Vcb->type == VCB_TYPE_FS) {
        IoSkipCurrentIrpStackLocation(Irp);
    
        Status = IoCallDriver(Vcb->Vpb->RealDevice, Irp);
    
        goto exit;
    }

    Status = Irp->IoStatus.Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
exit:
    if (top_level) 
        IoSetTopLevelIrp(NULL);
    
    FsRtlExitFileSystem();
    
    return Status;
}

BOOL is_file_name_valid(PUNICODE_STRING us) {
    ULONG i;
    
    if (us->Length < sizeof(WCHAR))
        return FALSE;
    
    if (us->Length > 255 * sizeof(WCHAR))
        return FALSE;
    
    for (i = 0; i < us->Length / sizeof(WCHAR); i++) {
        if (us->Buffer[i] == '/' || us->Buffer[i] == '<' || us->Buffer[i] == '>' || us->Buffer[i] == ':' || us->Buffer[i] == '"' ||
            us->Buffer[i] == '|' || us->Buffer[i] == '?' || us->Buffer[i] == '*' || (us->Buffer[i] >= 1 && us->Buffer[i] <= 31))
            return FALSE;
    }
    
    if (us->Buffer[0] == '.' && (us->Length == sizeof(WCHAR) || (us->Length == 2 * sizeof(WCHAR) && us->Buffer[1] == '.')))
        return FALSE;
    
    return TRUE;
}

void chunk_lock_range(device_extension* Vcb, chunk* c, UINT64 start, UINT64 length) {
    LIST_ENTRY* le;
    BOOL locked;
    range_lock* rl;
    
    rl = ExAllocateFromNPagedLookasideList(&Vcb->range_lock_lookaside);
    if (!rl) {
        ERR("out of memory\n");
        return;
    }
    
    rl->start = start;
    rl->length = length;
    rl->thread = PsGetCurrentThread();
    
    while (TRUE) {
        locked = FALSE;
        
        ExAcquireResourceExclusiveLite(&c->range_locks_lock, TRUE);
        
        le = c->range_locks.Flink;
        while (le != &c->range_locks) {
            range_lock* rl2 = CONTAINING_RECORD(le, range_lock, list_entry);
            
            if (rl2->start < start + length && rl2->start + rl2->length > start && rl2->thread != PsGetCurrentThread()) {
                locked = TRUE;
                break;
            }
            
            le = le->Flink;
        }
        
        if (!locked) {
            InsertTailList(&c->range_locks, &rl->list_entry);
            
            ExReleaseResourceLite(&c->range_locks_lock);
            return;
        }
        
        KeClearEvent(&c->range_locks_event);
        
        ExReleaseResourceLite(&c->range_locks_lock);
        
        KeWaitForSingleObject(&c->range_locks_event, UserRequest, KernelMode, FALSE, NULL);
    }
}

void chunk_unlock_range(device_extension* Vcb, chunk* c, UINT64 start, UINT64 length) {
    LIST_ENTRY* le;
    
    ExAcquireResourceExclusiveLite(&c->range_locks_lock, TRUE);
    
    le = c->range_locks.Flink;
    while (le != &c->range_locks) {
        range_lock* rl = CONTAINING_RECORD(le, range_lock, list_entry);
        
        if (rl->start == start && rl->length == length) {
            RemoveEntryList(&rl->list_entry);
            ExFreeToNPagedLookasideList(&Vcb->range_lock_lookaside, rl);
            break;
        }
        
        le = le->Flink;
    }
    
    KeSetEvent(&c->range_locks_event, 0, FALSE);
    
    ExReleaseResourceLite(&c->range_locks_lock);
}

#ifdef _DEBUG
static void STDCALL init_serial() {
    NTSTATUS Status;
    
    Status = IoGetDeviceObjectPointer(&log_device, FILE_WRITE_DATA, &comfo, &comdo);
    if (!NT_SUCCESS(Status)) {
        ERR("IoGetDeviceObjectPointer returned %08x\n", Status);
    }
}
#endif

static void STDCALL check_cpu() {
    unsigned int cpuInfo[4];
#ifndef _MSC_VER
    __get_cpuid(1, &cpuInfo[0], &cpuInfo[1], &cpuInfo[2], &cpuInfo[3]);
    have_sse42 = cpuInfo[2] & bit_SSE4_2;
    have_sse2 = cpuInfo[3] & bit_SSE2;
#else
   __cpuid(cpuInfo, 1);
   have_sse42 = cpuInfo[2] & (1 << 20);
   have_sse2 = cpuInfo[3] & (1 << 26);
#endif

    if (have_sse42)
        TRACE("SSE4.2 is supported\n");
    else
        TRACE("SSE4.2 not supported\n");
    
    if (have_sse2)
        TRACE("SSE2 is supported\n");
    else
        TRACE("SSE2 is not supported\n");
}

#ifdef _DEBUG
static void init_logging() {
    if (log_device.Length > 0)
        init_serial();
    else if (log_file.Length > 0) {
        NTSTATUS Status;
        OBJECT_ATTRIBUTES oa;
        IO_STATUS_BLOCK iosb;
        char* dateline;
        LARGE_INTEGER time;
        TIME_FIELDS tf;
        
        InitializeObjectAttributes(&oa, &log_file, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        
        Status = ZwCreateFile(&log_handle, FILE_WRITE_DATA, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
                              FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE | FILE_WRITE_THROUGH | FILE_SYNCHRONOUS_IO_ALERT, NULL, 0);
        
        if (!NT_SUCCESS(Status)) {
            ERR("ZwCreateFile returned %08x\n", Status);
            return;
        }
        
        if (iosb.Information == FILE_OPENED) { // already exists
            FILE_STANDARD_INFORMATION fsi;
            FILE_POSITION_INFORMATION fpi;
            
            static char delim[] = "\n---\n";
            
            // move to end of file
            
            Status = ZwQueryInformationFile(log_handle, &iosb, &fsi, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
            
            if (!NT_SUCCESS(Status)) {
                ERR("ZwQueryInformationFile returned %08x\n", Status);
                return;
            }
            
            fpi.CurrentByteOffset = fsi.EndOfFile;
            
            Status = ZwSetInformationFile(log_handle, &iosb, &fpi, sizeof(FILE_POSITION_INFORMATION), FilePositionInformation);
            
            if (!NT_SUCCESS(Status)) {
                ERR("ZwSetInformationFile returned %08x\n", Status);
                return;
            }

            Status = ZwWriteFile(log_handle, NULL, NULL, NULL, &iosb, delim, strlen(delim), NULL, NULL);
        
            if (!NT_SUCCESS(Status)) {
                ERR("ZwWriteFile returned %08x\n", Status);
                return;
            }
        }
        
        dateline = ExAllocatePoolWithTag(PagedPool, 256, ALLOC_TAG);
        
        if (!dateline) {
            ERR("out of memory\n");
            return;
        }
        
        KeQuerySystemTime(&time);
        
        RtlTimeToTimeFields(&time, &tf);
        
        sprintf(dateline, "Starting logging at %04u-%02u-%02u %02u:%02u:%02u\n", tf.Year, tf.Month, tf.Day, tf.Hour, tf.Minute, tf.Second);

        Status = ZwWriteFile(log_handle, NULL, NULL, NULL, &iosb, dateline, strlen(dateline), NULL, NULL);
        
        if (!NT_SUCCESS(Status)) {
            ERR("ZwWriteFile returned %08x\n", Status);
            return;
        }
        
        ExFreePool(dateline);
    }
}
#endif

NTSTATUS STDCALL DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    NTSTATUS Status;
    PDEVICE_OBJECT DeviceObject;
    UNICODE_STRING device_nameW;
    UNICODE_STRING dosdevice_nameW;
    control_device_extension* cde;
    
    InitializeListHead(&uid_map_list);
    
    log_device.Buffer = NULL;
    log_device.Length = log_device.MaximumLength = 0;
    log_file.Buffer = NULL;
    log_file.Length = log_file.MaximumLength = 0;
    
    read_registry(RegistryPath);
    
#ifdef _DEBUG
    if (debug_log_level > 0)
        init_logging();
    
    log_started = TRUE;
#endif

    TRACE("DriverEntry\n");
    
    registry_path.Length = registry_path.MaximumLength = RegistryPath->Length;
    registry_path.Buffer = ExAllocatePoolWithTag(PagedPool, registry_path.Length, ALLOC_TAG);
    
    if (!registry_path.Buffer) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    RtlCopyMemory(registry_path.Buffer, RegistryPath->Buffer, registry_path.Length);
   
    check_cpu();
   
//    TRACE("check CRC32C: %08x\n", calc_crc32c((UINT8*)"123456789", 9)); // should be e3069283
    
    if (RtlIsNtDdiVersionAvailable(NTDDI_WIN8)) {
        UNICODE_STRING name;
        tPsIsDiskCountersEnabled PsIsDiskCountersEnabled;
        
        RtlInitUnicodeString(&name, L"PsIsDiskCountersEnabled");
        PsIsDiskCountersEnabled = (tPsIsDiskCountersEnabled)MmGetSystemRoutineAddress(&name);
        
        if (PsIsDiskCountersEnabled) {
            diskacc = PsIsDiskCountersEnabled();
            
            RtlInitUnicodeString(&name, L"PsUpdateDiskCounters");
            PsUpdateDiskCounters = (tPsUpdateDiskCounters)MmGetSystemRoutineAddress(&name);
            
            if (!PsUpdateDiskCounters)
                diskacc = FALSE;
        }
        
        RtlInitUnicodeString(&name, L"CcCopyReadEx");
        CcCopyReadEx = (tCcCopyReadEx)MmGetSystemRoutineAddress(&name);
        
        RtlInitUnicodeString(&name, L"CcCopyWriteEx");
        CcCopyWriteEx = (tCcCopyWriteEx)MmGetSystemRoutineAddress(&name);
        
        RtlInitUnicodeString(&name, L"CcSetAdditionalCacheAttributesEx");
        CcSetAdditionalCacheAttributesEx = (tCcSetAdditionalCacheAttributesEx)MmGetSystemRoutineAddress(&name);
    } else {
        PsUpdateDiskCounters = NULL;
        CcCopyReadEx = NULL;
        CcCopyWriteEx = NULL;
        CcSetAdditionalCacheAttributesEx = NULL;
    }
   
    drvobj = DriverObject;

    DriverObject->DriverUnload = DriverUnload;

    DriverObject->MajorFunction[IRP_MJ_CREATE]                   = (PDRIVER_DISPATCH)drv_create;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]                    = (PDRIVER_DISPATCH)drv_close;
    DriverObject->MajorFunction[IRP_MJ_READ]                     = (PDRIVER_DISPATCH)drv_read;
    DriverObject->MajorFunction[IRP_MJ_WRITE]                    = (PDRIVER_DISPATCH)drv_write;
    DriverObject->MajorFunction[IRP_MJ_QUERY_INFORMATION]        = (PDRIVER_DISPATCH)drv_query_information;
    DriverObject->MajorFunction[IRP_MJ_SET_INFORMATION]          = (PDRIVER_DISPATCH)drv_set_information;
    DriverObject->MajorFunction[IRP_MJ_QUERY_EA]                 = (PDRIVER_DISPATCH)drv_query_ea;
    DriverObject->MajorFunction[IRP_MJ_SET_EA]                   = (PDRIVER_DISPATCH)drv_set_ea;
    DriverObject->MajorFunction[IRP_MJ_FLUSH_BUFFERS]            = (PDRIVER_DISPATCH)drv_flush_buffers;
    DriverObject->MajorFunction[IRP_MJ_QUERY_VOLUME_INFORMATION] = (PDRIVER_DISPATCH)drv_query_volume_information;
    DriverObject->MajorFunction[IRP_MJ_SET_VOLUME_INFORMATION]   = (PDRIVER_DISPATCH)drv_set_volume_information;
    DriverObject->MajorFunction[IRP_MJ_DIRECTORY_CONTROL]        = (PDRIVER_DISPATCH)drv_directory_control;
    DriverObject->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL]      = (PDRIVER_DISPATCH)drv_file_system_control;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]           = (PDRIVER_DISPATCH)drv_device_control;
    DriverObject->MajorFunction[IRP_MJ_SHUTDOWN]                 = (PDRIVER_DISPATCH)drv_shutdown;
    DriverObject->MajorFunction[IRP_MJ_LOCK_CONTROL]             = (PDRIVER_DISPATCH)drv_lock_control;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP]                  = (PDRIVER_DISPATCH)drv_cleanup;
    DriverObject->MajorFunction[IRP_MJ_QUERY_SECURITY]           = (PDRIVER_DISPATCH)drv_query_security;
    DriverObject->MajorFunction[IRP_MJ_SET_SECURITY]             = (PDRIVER_DISPATCH)drv_set_security;
    DriverObject->MajorFunction[IRP_MJ_POWER]                    = (PDRIVER_DISPATCH)drv_power;
    DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL]           = (PDRIVER_DISPATCH)drv_system_control;
    DriverObject->MajorFunction[IRP_MJ_PNP]                      = (PDRIVER_DISPATCH)drv_pnp;

    init_fast_io_dispatch(&DriverObject->FastIoDispatch);

    device_nameW.Buffer = device_name;
    device_nameW.Length = device_nameW.MaximumLength = (USHORT)wcslen(device_name) * sizeof(WCHAR);
    dosdevice_nameW.Buffer = dosdevice_name;
    dosdevice_nameW.Length = dosdevice_nameW.MaximumLength = (USHORT)wcslen(dosdevice_name) * sizeof(WCHAR);

    Status = IoCreateDevice(DriverObject, sizeof(control_device_extension), &device_nameW, FILE_DEVICE_DISK_FILE_SYSTEM,
                            FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);
    if (!NT_SUCCESS(Status)) {
        ERR("IoCreateDevice returned %08x\n", Status);
        return Status;
    }
    
    devobj = DeviceObject;
    cde = (control_device_extension*)devobj->DeviceExtension;
    
    cde->type = VCB_TYPE_CONTROL;
    
    DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    Status = IoCreateSymbolicLink(&dosdevice_nameW, &device_nameW);
    if (!NT_SUCCESS(Status)) {
        ERR("IoCreateSymbolicLink returned %08x\n", Status);
        return Status;
    }
    
    Status = init_cache();
    if (!NT_SUCCESS(Status)) {
        ERR("init_cache returned %08x\n", Status);
        return Status;
    }

    InitializeListHead(&VcbList);
    ExInitializeResourceLite(&global_loading_lock);
    ExInitializeResourceLite(&volume_list_lock);
    
    InitializeListHead(&volume_list);
    
    Status = IoRegisterPlugPlayNotification(EventCategoryDeviceInterfaceChange, PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES,
                                            (PVOID)&GUID_DEVINTERFACE_VOLUME, DriverObject, volume_notification, DriverObject, &notification_entry2);
    if (!NT_SUCCESS(Status))
        ERR("IoRegisterPlugPlayNotification returned %08x\n", Status);
    
    Status = IoRegisterPlugPlayNotification(EventCategoryDeviceInterfaceChange, PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES,
                                            (PVOID)&GUID_DEVINTERFACE_HIDDEN_VOLUME, DriverObject, volume_notification, DriverObject, &notification_entry3);
    if (!NT_SUCCESS(Status))
        ERR("IoRegisterPlugPlayNotification returned %08x\n", Status);
    
    Status = IoRegisterPlugPlayNotification(EventCategoryDeviceInterfaceChange, PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES,
                                            (PVOID)&GUID_DEVINTERFACE_DISK, DriverObject, pnp_notification, DriverObject, &notification_entry);
    if (!NT_SUCCESS(Status))
        ERR("IoRegisterPlugPlayNotification returned %08x\n", Status);
    
    IoRegisterFileSystem(DeviceObject);

    return STATUS_SUCCESS;
}
