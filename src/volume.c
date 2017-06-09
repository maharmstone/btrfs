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
#include <mountdev.h>
#include <ntddvol.h>
#include <ntddstor.h>
#include <ntdddisk.h>
#include <wdmguid.h>

#define IOCTL_VOLUME_IS_DYNAMIC     CTL_CODE(IOCTL_VOLUME_BASE, 18, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VOLUME_POST_ONLINE    CTL_CODE(IOCTL_VOLUME_BASE, 25, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

extern PDRIVER_OBJECT drvobj;
extern ERESOURCE volume_list_lock;
extern LIST_ENTRY volume_list;
extern UNICODE_STRING registry_path;

NTSTATUS STDCALL vol_create(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    volume_device_extension* vde = DeviceObject->DeviceExtension;

    TRACE("(%p, %p)\n", DeviceObject, Irp);

    if (vde->removing)
        return STATUS_DEVICE_NOT_READY;

    Irp->IoStatus.Information = FILE_OPENED;
    InterlockedIncrement(&vde->open_count);
    
    return STATUS_SUCCESS;
}

NTSTATUS STDCALL vol_close(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    volume_device_extension* vde = DeviceObject->DeviceExtension;

    TRACE("(%p, %p)\n", DeviceObject, Irp);
    
    Irp->IoStatus.Information = 0;

    ExAcquireResourceSharedLite(&vde->child_lock, TRUE);

    if (InterlockedDecrement(&vde->open_count) == 0 && vde->removing) {
        NTSTATUS Status;
        UNICODE_STRING mmdevpath;
        PDEVICE_OBJECT mountmgr;
        PFILE_OBJECT mountmgrfo;

        RtlInitUnicodeString(&mmdevpath, MOUNTMGR_DEVICE_NAME);
        Status = IoGetDeviceObjectPointer(&mmdevpath, FILE_READ_ATTRIBUTES, &mountmgrfo, &mountmgr);
        if (!NT_SUCCESS(Status))
            ERR("IoGetDeviceObjectPointer returned %08x\n", Status);
        else {
            remove_drive_letter(mountmgr, &vde->name);

            ObDereferenceObject(mountmgrfo);
        }

        if (vde->mounted_device) {
            device_extension* Vcb = vde->mounted_device->DeviceExtension;

            Vcb->vde = NULL;
        }

        if (vde->name.Buffer)
            ExFreePool(vde->name.Buffer);

        ExReleaseResourceLite(&vde->child_lock);
        ExDeleteResourceLite(&vde->child_lock);
        IoDeleteDevice(vde->device);
    } else
        ExReleaseResourceLite(&vde->child_lock);

    return STATUS_SUCCESS;
}

typedef struct {
    IO_STATUS_BLOCK iosb;
    KEVENT Event;
} vol_read_context;

static NTSTATUS vol_read_completion(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID conptr) {
    vol_read_context* context = conptr;
    
    UNUSED(DeviceObject);
    
    context->iosb = Irp->IoStatus;
    KeSetEvent(&context->Event, 0, FALSE);
    
    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS STDCALL vol_read(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    volume_device_extension* vde = DeviceObject->DeviceExtension;
    volume_child* vc;
    NTSTATUS Status;
    PIRP Irp2;
    vol_read_context context;
    PIO_STACK_LOCATION IrpSp, IrpSp2;
    
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    ExAcquireResourceSharedLite(&vde->child_lock, TRUE);
    
    if (IsListEmpty(&vde->children)) {
        ExReleaseResourceLite(&vde->child_lock);
        Status = STATUS_INVALID_DEVICE_REQUEST;
        goto end;
    }
    
    vc = CONTAINING_RECORD(vde->children.Flink, volume_child, list_entry);
    
    // We can't use IoSkipCurrentIrpStackLocation as the device isn't in our stack
    
    Irp2 = IoAllocateIrp(vc->devobj->StackSize, FALSE);
        
    if (!Irp2) {
        ERR("IoAllocateIrp failed\n");
        ExReleaseResourceLite(&vde->child_lock);
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }
    
    IrpSp = IoGetCurrentIrpStackLocation(Irp);
    IrpSp2 = IoGetNextIrpStackLocation(Irp2);
    
    IrpSp2->MajorFunction = IRP_MJ_READ;
    
    if (vc->devobj->Flags & DO_BUFFERED_IO) {
        Irp2->AssociatedIrp.SystemBuffer = ExAllocatePoolWithTag(NonPagedPool, IrpSp->Parameters.Read.Length, ALLOC_TAG);
        if (!Irp2->AssociatedIrp.SystemBuffer) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        Irp2->Flags |= IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER | IRP_INPUT_OPERATION;

        Irp2->UserBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
    } else if (vc->devobj->Flags & DO_DIRECT_IO)
        Irp2->MdlAddress = Irp->MdlAddress;
    else
        Irp2->UserBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

    IrpSp2->Parameters.Read.Length = IrpSp->Parameters.Read.Length;
    IrpSp2->Parameters.Read.ByteOffset.QuadPart = IrpSp->Parameters.Read.ByteOffset.QuadPart;

    KeInitializeEvent(&context.Event, NotificationEvent, FALSE);
    Irp2->UserIosb = &context.iosb;

    IoSetCompletionRoutine(Irp2, vol_read_completion, &context, TRUE, TRUE, TRUE);

    Status = IoCallDriver(vc->devobj, Irp2);

    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject(&context.Event, Executive, KernelMode, FALSE, NULL);
        Status = context.iosb.Status;
    }
    
    ExReleaseResourceLite(&vde->child_lock);
    
    Irp->IoStatus.Information = context.iosb.Information;
    
end:
    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}

NTSTATUS STDCALL vol_write(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    volume_device_extension* vde = DeviceObject->DeviceExtension;
    volume_child* vc;
    NTSTATUS Status;
    PIRP Irp2;
    vol_read_context context;
    PIO_STACK_LOCATION IrpSp, IrpSp2;
    
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    ExAcquireResourceSharedLite(&vde->child_lock, TRUE);
    
    if (IsListEmpty(&vde->children)) {
        ExReleaseResourceLite(&vde->child_lock);
        Status = STATUS_INVALID_DEVICE_REQUEST;
        goto end;
    }
    
    vc = CONTAINING_RECORD(vde->children.Flink, volume_child, list_entry);
    
    if (vc->list_entry.Flink != &vde->children) { // more than once device
        ExReleaseResourceLite(&vde->child_lock);
        Status = STATUS_ACCESS_DENIED;
        goto end;
    }
    
    // We can't use IoSkipCurrentIrpStackLocation as the device isn't in our stack
    
    Irp2 = IoAllocateIrp(vc->devobj->StackSize, FALSE);
        
    if (!Irp2) {
        ERR("IoAllocateIrp failed\n");
        ExReleaseResourceLite(&vde->child_lock);
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }
    
    IrpSp = IoGetCurrentIrpStackLocation(Irp);
    IrpSp2 = IoGetNextIrpStackLocation(Irp2);
    
    IrpSp2->MajorFunction = IRP_MJ_WRITE;
    
    if (vc->devobj->Flags & DO_BUFFERED_IO) {
        Irp2->AssociatedIrp.SystemBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

        Irp2->Flags |= IRP_BUFFERED_IO;

        Irp2->UserBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
    } else if (vc->devobj->Flags & DO_DIRECT_IO)
        Irp2->MdlAddress = Irp->MdlAddress;
    else
        Irp2->UserBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

    IrpSp2->Parameters.Write.Length = IrpSp->Parameters.Write.Length;
    IrpSp2->Parameters.Write.ByteOffset.QuadPart = IrpSp->Parameters.Write.ByteOffset.QuadPart;

    KeInitializeEvent(&context.Event, NotificationEvent, FALSE);
    Irp2->UserIosb = &context.iosb;

    IoSetCompletionRoutine(Irp2, vol_read_completion, &context, TRUE, TRUE, TRUE);

    Status = IoCallDriver(vc->devobj, Irp2);

    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject(&context.Event, Executive, KernelMode, FALSE, NULL);
        Status = context.iosb.Status;
    }
    
    ExReleaseResourceLite(&vde->child_lock);
    
    Irp->IoStatus.Information = context.iosb.Information;
    
end:
    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}

NTSTATUS STDCALL vol_query_information(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_set_information(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_query_ea(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_set_ea(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_flush_buffers(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_query_volume_information(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_set_volume_information(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_cleanup(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    Irp->IoStatus.Information = 0;

    return STATUS_SUCCESS;
}

NTSTATUS STDCALL vol_directory_control(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_file_system_control(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_lock_control(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    return STATUS_INVALID_DEVICE_REQUEST;
}

static NTSTATUS vol_query_device_name(volume_device_extension* vde, PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    PMOUNTDEV_NAME name;

    if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(MOUNTDEV_NAME)) {
        Irp->IoStatus.Information = sizeof(MOUNTDEV_NAME);
        return STATUS_BUFFER_TOO_SMALL;
    }

    name = Irp->AssociatedIrp.SystemBuffer;
    name->NameLength = vde->name.Length;

    if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < offsetof(MOUNTDEV_NAME, Name[0]) + name->NameLength) {
        Irp->IoStatus.Information = sizeof(MOUNTDEV_NAME);
        return STATUS_BUFFER_OVERFLOW;
    }
    
    RtlCopyMemory(name->Name, vde->name.Buffer, vde->name.Length);

    Irp->IoStatus.Information = offsetof(MOUNTDEV_NAME, Name[0]) + name->NameLength;
    
    return STATUS_SUCCESS;
}

static NTSTATUS vol_query_unique_id(volume_device_extension* vde, PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    MOUNTDEV_UNIQUE_ID* mduid;

    if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(MOUNTDEV_UNIQUE_ID)) {
        Irp->IoStatus.Information = sizeof(MOUNTDEV_UNIQUE_ID);
        return STATUS_BUFFER_TOO_SMALL;
    }

    mduid = Irp->AssociatedIrp.SystemBuffer;
    mduid->UniqueIdLength = sizeof(BTRFS_UUID);

    if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < offsetof(MOUNTDEV_UNIQUE_ID, UniqueId[0]) + mduid->UniqueIdLength) {
        Irp->IoStatus.Information = sizeof(MOUNTDEV_UNIQUE_ID);
        return STATUS_BUFFER_OVERFLOW;
    }

    RtlCopyMemory(mduid->UniqueId, &vde->uuid, sizeof(BTRFS_UUID));

    Irp->IoStatus.Information = offsetof(MOUNTDEV_UNIQUE_ID, UniqueId[0]) + mduid->UniqueIdLength;
    
    return STATUS_SUCCESS;
}

static NTSTATUS vol_is_dynamic(PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    UINT8* buf;
    
    if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength == 0 || !Irp->AssociatedIrp.SystemBuffer)
        return STATUS_INVALID_PARAMETER;
    
    buf = (UINT8*)Irp->AssociatedIrp.SystemBuffer;
    
    *buf = 1;
    
    Irp->IoStatus.Information = 1;
    
    return STATUS_SUCCESS;
}

static NTSTATUS vol_check_verify(volume_device_extension* vde) {
    NTSTATUS Status;
    LIST_ENTRY* le;
    
    ExAcquireResourceSharedLite(&vde->child_lock, TRUE);
    
    le = vde->children.Flink;
    while (le != &vde->children) {
        volume_child* vc = CONTAINING_RECORD(le, volume_child, list_entry);
        
        Status = dev_ioctl(vc->devobj, IOCTL_STORAGE_CHECK_VERIFY, NULL, 0, NULL, 0, FALSE, NULL);
        if (!NT_SUCCESS(Status))
            goto end;
        
        le = le->Flink;
    }
    
    Status = STATUS_SUCCESS;
    
end:
    ExReleaseResourceLite(&vde->child_lock);
    
    return Status;
}

static NTSTATUS vol_get_disk_extents(volume_device_extension* vde, PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    LIST_ENTRY* le;
    ULONG num_extents = 0, i, max_extents = 1;
    NTSTATUS Status;
    VOLUME_DISK_EXTENTS *ext, *ext3;
    
    if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(VOLUME_DISK_EXTENTS))
        return STATUS_BUFFER_TOO_SMALL;
    
    ExAcquireResourceSharedLite(&vde->child_lock, TRUE);
    
    le = vde->children.Flink;
    while (le != &vde->children) {
        volume_child* vc = CONTAINING_RECORD(le, volume_child, list_entry);
        VOLUME_DISK_EXTENTS ext2;
            
        Status = dev_ioctl(vc->devobj, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, NULL, 0, &ext2, sizeof(VOLUME_DISK_EXTENTS), FALSE, NULL);
        if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_OVERFLOW) {
            ERR("IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS returned %08x\n", Status);
            goto end;
        }
        
        num_extents += ext2.NumberOfDiskExtents;
        
        if (ext2.NumberOfDiskExtents > max_extents)
            max_extents = ext2.NumberOfDiskExtents;
        
        le = le->Flink;
    }
    
    ext = Irp->AssociatedIrp.SystemBuffer;
    
    if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < offsetof(VOLUME_DISK_EXTENTS, Extents[0]) + (num_extents * sizeof(DISK_EXTENT))) {
        Irp->IoStatus.Information = offsetof(VOLUME_DISK_EXTENTS, Extents[0]);
        ext->NumberOfDiskExtents = num_extents;
        Status = STATUS_BUFFER_OVERFLOW;
        goto end;
    }
    
    ext3 = ExAllocatePoolWithTag(PagedPool, offsetof(VOLUME_DISK_EXTENTS, Extents[0]) + (max_extents * sizeof(DISK_EXTENT)), ALLOC_TAG);
    if (!ext3) {
        ERR("out of memory\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }
    
    i = 0;
    ext->NumberOfDiskExtents = 0;
    
    le = vde->children.Flink;
    while (le != &vde->children) {
        volume_child* vc = CONTAINING_RECORD(le, volume_child, list_entry);
        
        Status = dev_ioctl(vc->devobj, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, NULL, 0, ext3,
                            offsetof(VOLUME_DISK_EXTENTS, Extents[0]) + (max_extents * sizeof(DISK_EXTENT)), FALSE, NULL);
        if (!NT_SUCCESS(Status)) {
            ERR("IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS returned %08x\n", Status);
            ExFreePool(ext3);
            goto end;
        }
        
        if (i + ext3->NumberOfDiskExtents > num_extents) {
            Irp->IoStatus.Information = offsetof(VOLUME_DISK_EXTENTS, Extents[0]);
            ext->NumberOfDiskExtents = i + ext3->NumberOfDiskExtents;
            Status = STATUS_BUFFER_OVERFLOW;
            goto end;
        }
        
        RtlCopyMemory(&ext->Extents[i], ext3->Extents, sizeof(DISK_EXTENT) * ext3->NumberOfDiskExtents);
        i += ext3->NumberOfDiskExtents;
        
        le = le->Flink;
    }
    
    ExFreePool(ext3);
    
    Status = STATUS_SUCCESS;
    
    ext->NumberOfDiskExtents = i;
    Irp->IoStatus.Information = offsetof(VOLUME_DISK_EXTENTS, Extents[0]) + (i * sizeof(DISK_EXTENT));
    
end:
    ExReleaseResourceLite(&vde->child_lock);
    
    return Status;
}

static NTSTATUS vol_is_writable(volume_device_extension* vde) {
    NTSTATUS Status;
    LIST_ENTRY* le;
    BOOL writable = FALSE;
    
    ExAcquireResourceSharedLite(&vde->child_lock, TRUE);
    
    le = vde->children.Flink;
    while (le != &vde->children) {
        volume_child* vc = CONTAINING_RECORD(le, volume_child, list_entry);
        
        Status = dev_ioctl(vc->devobj, IOCTL_DISK_IS_WRITABLE, NULL, 0, NULL, 0, TRUE, NULL);
        
        if (NT_SUCCESS(Status)) {
            writable = TRUE;
            break;
        } else if (Status != STATUS_MEDIA_WRITE_PROTECTED)
            goto end;
        
        le = le->Flink;
    }
    
    Status = writable ? STATUS_SUCCESS : STATUS_MEDIA_WRITE_PROTECTED;
    
end:
    ExReleaseResourceLite(&vde->child_lock);
    
    return STATUS_SUCCESS;
}

static NTSTATUS vol_get_length(volume_device_extension* vde, PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    GET_LENGTH_INFORMATION* gli;
    LIST_ENTRY* le;
    
    if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(GET_LENGTH_INFORMATION))
        return STATUS_BUFFER_TOO_SMALL;
    
    gli = (GET_LENGTH_INFORMATION*)Irp->AssociatedIrp.SystemBuffer;
    
    gli->Length.QuadPart = 0;
    
    ExAcquireResourceSharedLite(&vde->child_lock, TRUE);
    
    le = vde->children.Flink;
    while (le != &vde->children) {
        volume_child* vc = CONTAINING_RECORD(le, volume_child, list_entry);
        
        gli->Length.QuadPart += vc->size;
        
        le = le->Flink;
    }
    
    ExReleaseResourceLite(&vde->child_lock);
    
    Irp->IoStatus.Information = sizeof(GET_LENGTH_INFORMATION);
    
    return STATUS_SUCCESS;
}

static NTSTATUS vol_get_drive_geometry(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    volume_device_extension* vde = DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    DISK_GEOMETRY* geom;
    UINT64 length;
    LIST_ENTRY* le;
    
    if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(DISK_GEOMETRY))
        return STATUS_BUFFER_TOO_SMALL;

    length = 0;
    
    ExAcquireResourceSharedLite(&vde->child_lock, TRUE);
    
    le = vde->children.Flink;
    while (le != &vde->children) {
        volume_child* vc = CONTAINING_RECORD(le, volume_child, list_entry);
        
        length += vc->size;
        
        le = le->Flink;
    }
    
    ExReleaseResourceLite(&vde->child_lock);
    
    geom = (DISK_GEOMETRY*)Irp->AssociatedIrp.SystemBuffer;
    geom->BytesPerSector = DeviceObject->SectorSize == 0 ? 0x200 : DeviceObject->SectorSize;
    geom->SectorsPerTrack = 0x3f;
    geom->TracksPerCylinder = 0xff;
    geom->Cylinders.QuadPart = length / (UInt32x32To64(geom->TracksPerCylinder, geom->SectorsPerTrack) * geom->BytesPerSector);
    geom->MediaType = DeviceObject->Characteristics & FILE_REMOVABLE_MEDIA ? RemovableMedia : FixedMedia;
    
    Irp->IoStatus.Information = sizeof(DISK_GEOMETRY);
    
    return STATUS_SUCCESS;
}

static NTSTATUS vol_get_gpt_attributes(PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    VOLUME_GET_GPT_ATTRIBUTES_INFORMATION* vggai;
    
    if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(VOLUME_GET_GPT_ATTRIBUTES_INFORMATION))
        return STATUS_BUFFER_TOO_SMALL;
    
    vggai = (VOLUME_GET_GPT_ATTRIBUTES_INFORMATION*)Irp->AssociatedIrp.SystemBuffer;
    
    vggai->GptAttributes = 0;
    
    Irp->IoStatus.Information = sizeof(VOLUME_GET_GPT_ATTRIBUTES_INFORMATION);
    
    return STATUS_SUCCESS;
}

static NTSTATUS vol_get_device_number(volume_device_extension* vde, PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    volume_child* vc;
    STORAGE_DEVICE_NUMBER* sdn;
    
    // If only one device, return its disk number. This is needed for ejection to work.
    
    if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(STORAGE_DEVICE_NUMBER))
        return STATUS_BUFFER_TOO_SMALL;
    
    ExAcquireResourceSharedLite(&vde->child_lock, TRUE);
    
    if (IsListEmpty(&vde->children) || vde->num_children > 1) {
        ExReleaseResourceLite(&vde->child_lock);
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    
    vc = CONTAINING_RECORD(vde->children.Flink, volume_child, list_entry);
    
    if (vc->disk_num == 0xffffffff) {
        ExReleaseResourceLite(&vde->child_lock);
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    
    sdn = (STORAGE_DEVICE_NUMBER*)Irp->AssociatedIrp.SystemBuffer;
    
    sdn->DeviceType = FILE_DEVICE_DISK;
    sdn->DeviceNumber = vc->disk_num;
    sdn->PartitionNumber = vc->part_num;
    
    ExReleaseResourceLite(&vde->child_lock);
    
    Irp->IoStatus.Information = sizeof(STORAGE_DEVICE_NUMBER);
    
    return STATUS_SUCCESS;
}

static NTSTATUS vol_ioctl_completion(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID conptr) {
    KEVENT* event = conptr;
    
    UNUSED(DeviceObject);
    UNUSED(Irp);
    
    KeSetEvent(event, 0, FALSE);
    
    return STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS vol_ioctl_passthrough(volume_device_extension* vde, PIRP Irp) {
    NTSTATUS Status;
    volume_child* vc;
    PIRP Irp2;
    PIO_STACK_LOCATION IrpSp, IrpSp2;
    KEVENT Event;
    
    TRACE("(%p, %p)\n", vde, Irp);
    
    ExAcquireResourceSharedLite(&vde->child_lock, TRUE);
    
    if (IsListEmpty(&vde->children)) {
        ExReleaseResourceLite(&vde->child_lock);
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    
    vc = CONTAINING_RECORD(vde->children.Flink, volume_child, list_entry);
    
    if (vc->list_entry.Flink != &vde->children) { // more than once device
        ExReleaseResourceLite(&vde->child_lock);
        return STATUS_ACCESS_DENIED;
    }
    
    Irp2 = IoAllocateIrp(vc->devobj->StackSize, FALSE);
        
    if (!Irp2) {
        ERR("IoAllocateIrp failed\n");
        ExReleaseResourceLite(&vde->child_lock);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    IrpSp = IoGetCurrentIrpStackLocation(Irp);
    IrpSp2 = IoGetNextIrpStackLocation(Irp2);
    
    IrpSp2->MajorFunction = IrpSp->MajorFunction;
    IrpSp2->MinorFunction = IrpSp->MinorFunction;
    
    IrpSp2->Parameters.DeviceIoControl.OutputBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    IrpSp2->Parameters.DeviceIoControl.InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
    IrpSp2->Parameters.DeviceIoControl.IoControlCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;
    IrpSp2->Parameters.DeviceIoControl.Type3InputBuffer = IrpSp->Parameters.DeviceIoControl.Type3InputBuffer;
    
    Irp2->AssociatedIrp.SystemBuffer = Irp->AssociatedIrp.SystemBuffer;
    Irp2->MdlAddress = Irp->MdlAddress;
    Irp2->UserBuffer = Irp->UserBuffer;
    Irp2->Flags = Irp->Flags;

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    IoSetCompletionRoutine(Irp2, vol_ioctl_completion, &Event, TRUE, TRUE, TRUE);

    Status = IoCallDriver(vc->devobj, Irp2);

    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = Irp2->IoStatus.Status;
    }
    
    Irp->IoStatus.Status = Irp2->IoStatus.Status;
    Irp->IoStatus.Information = Irp2->IoStatus.Information;
    
    ExReleaseResourceLite(&vde->child_lock);

    return Status;
}

NTSTATUS STDCALL vol_device_control(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    volume_device_extension* vde = DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    Irp->IoStatus.Information = 0;
    
    switch (IrpSp->Parameters.DeviceIoControl.IoControlCode) {
        case IOCTL_MOUNTDEV_QUERY_DEVICE_NAME:
            return vol_query_device_name(vde, Irp);
            
        case IOCTL_MOUNTDEV_QUERY_UNIQUE_ID:
            return vol_query_unique_id(vde, Irp);
            
        case IOCTL_STORAGE_GET_DEVICE_NUMBER:
            return vol_get_device_number(vde, Irp);

        case IOCTL_MOUNTDEV_QUERY_SUGGESTED_LINK_NAME:
            TRACE("unhandled control code IOCTL_MOUNTDEV_QUERY_SUGGESTED_LINK_NAME\n");
            break;

        case IOCTL_MOUNTDEV_QUERY_STABLE_GUID:
            TRACE("unhandled control code IOCTL_MOUNTDEV_QUERY_STABLE_GUID\n");
            break;

        case IOCTL_MOUNTDEV_LINK_CREATED:
            TRACE("unhandled control code IOCTL_MOUNTDEV_LINK_CREATED\n");
            break;

        case IOCTL_VOLUME_GET_GPT_ATTRIBUTES:
            return vol_get_gpt_attributes(Irp);

        case IOCTL_VOLUME_IS_DYNAMIC:
            return vol_is_dynamic(Irp);

        case IOCTL_VOLUME_ONLINE:
            TRACE("unhandled control code IOCTL_VOLUME_ONLINE\n");
            break;

        case IOCTL_VOLUME_POST_ONLINE:
            TRACE("unhandled control code IOCTL_VOLUME_POST_ONLINE\n");
            break;

        case IOCTL_DISK_GET_DRIVE_GEOMETRY:
            return vol_get_drive_geometry(DeviceObject, Irp);

        case IOCTL_DISK_IS_WRITABLE:
            return vol_is_writable(vde);

        case IOCTL_DISK_GET_LENGTH_INFO:
            return vol_get_length(vde, Irp);
            
        case IOCTL_STORAGE_CHECK_VERIFY:
            return vol_check_verify(vde);

        case IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS:
            return vol_get_disk_extents(vde, Irp);

        default: // pass ioctl through if only one child device
            return vol_ioctl_passthrough(vde, Irp);
    }

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_shutdown(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_query_security(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_set_security(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_power(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status;
    
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    if (IrpSp->MinorFunction == IRP_MN_SET_POWER || IrpSp->MinorFunction == IRP_MN_QUERY_POWER)
        Irp->IoStatus.Status = STATUS_SUCCESS;
    
    Status = Irp->IoStatus.Status;
    PoStartNextPowerIrp(Irp);

    return Status;
}

NTSTATUS mountmgr_add_drive_letter(PDEVICE_OBJECT mountmgr, PUNICODE_STRING devpath) {
    NTSTATUS Status;
    ULONG mmdltsize;
    MOUNTMGR_DRIVE_LETTER_TARGET* mmdlt;
    MOUNTMGR_DRIVE_LETTER_INFORMATION mmdli;
    
    mmdltsize = offsetof(MOUNTMGR_DRIVE_LETTER_TARGET, DeviceName[0]) + devpath->Length;
    
    mmdlt = ExAllocatePoolWithTag(NonPagedPool, mmdltsize, ALLOC_TAG);
    if (!mmdlt) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    mmdlt->DeviceNameLength = devpath->Length;
    RtlCopyMemory(&mmdlt->DeviceName, devpath->Buffer, devpath->Length);
    TRACE("mmdlt = %.*S\n", mmdlt->DeviceNameLength / sizeof(WCHAR), mmdlt->DeviceName);
    
    Status = dev_ioctl(mountmgr, IOCTL_MOUNTMGR_NEXT_DRIVE_LETTER, mmdlt, mmdltsize, &mmdli, sizeof(MOUNTMGR_DRIVE_LETTER_INFORMATION), FALSE, NULL);
    
    if (!NT_SUCCESS(Status))
        ERR("IOCTL_MOUNTMGR_NEXT_DRIVE_LETTER returned %08x\n", Status);
    else
        TRACE("DriveLetterWasAssigned = %u, CurrentDriveLetter = %c\n", mmdli.DriveLetterWasAssigned, mmdli.CurrentDriveLetter);
    
    return Status;
}

static __inline WCHAR hex_digit(UINT8 n) {
    if (n <= 9)
        return n + '0';
    else
        return n - 0xa + 'a';
}

NTSTATUS pnp_removal(PVOID NotificationStructure, PVOID Context) {
    TARGET_DEVICE_REMOVAL_NOTIFICATION* tdrn = (TARGET_DEVICE_REMOVAL_NOTIFICATION*)NotificationStructure;
    volume_device_extension* vde = (volume_device_extension*)Context;
    
    if (RtlCompareMemory(&tdrn->Event, &GUID_TARGET_DEVICE_QUERY_REMOVE, sizeof(GUID)) == sizeof(GUID)) {
        TRACE("GUID_TARGET_DEVICE_QUERY_REMOVE\n");
        
        if (vde->mounted_device)
            return pnp_query_remove_device(vde->mounted_device, NULL);
    }
    
    return STATUS_SUCCESS;
}

static BOOL allow_degraded_mount(BTRFS_UUID* uuid) {
    HANDLE h;
    NTSTATUS Status;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING path, adus;
    UINT32 degraded = mount_allow_degraded;
    ULONG i, j, kvfilen, retlen;
    KEY_VALUE_FULL_INFORMATION* kvfi;

    path.Length = path.MaximumLength = registry_path.Length + (37 * sizeof(WCHAR));
    path.Buffer = ExAllocatePoolWithTag(PagedPool, path.Length, ALLOC_TAG);

    if (!path.Buffer) {
        ERR("out of memory\n");
        return FALSE;
    }

    RtlCopyMemory(path.Buffer, registry_path.Buffer, registry_path.Length);
    i = registry_path.Length / sizeof(WCHAR);

    path.Buffer[i] = '\\';
    i++;

    for (j = 0; j < 16; j++) {
        path.Buffer[i] = hex_digit((uuid->uuid[j] & 0xF0) >> 4);
        path.Buffer[i+1] = hex_digit(uuid->uuid[j] & 0xF);

        i += 2;

        if (j == 3 || j == 5 || j == 7 || j == 9) {
            path.Buffer[i] = '-';
            i++;
        }
    }

    InitializeObjectAttributes(&oa, &path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    kvfilen = offsetof(KEY_VALUE_FULL_INFORMATION, Name[0]) + (255 * sizeof(WCHAR));
    kvfi = ExAllocatePoolWithTag(PagedPool, kvfilen, ALLOC_TAG);
    if (!kvfi) {
        ERR("out of memory\n");
        ExFreePool(path.Buffer);
        return FALSE;
    }

    Status = ZwOpenKey(&h, KEY_QUERY_VALUE, &oa);
    if (Status == STATUS_OBJECT_NAME_NOT_FOUND)
        goto end;
    else if (!NT_SUCCESS(Status)) {
        ERR("ZwOpenKey returned %08x\n", Status);
        goto end;
    }

    adus.Buffer = L"AllowDegraded";
    adus.Length = adus.MaximumLength = wcslen(adus.Buffer) * sizeof(WCHAR);

    if (NT_SUCCESS(ZwQueryValueKey(h, &adus, KeyValueFullInformation, kvfi, kvfilen, &retlen))) {
        if (kvfi->Type == REG_DWORD && kvfi->DataLength >= sizeof(UINT32)) {
            UINT32* val = (UINT32*)((UINT8*)kvfi + kvfi->DataOffset);

            degraded = *val;
        }
    }

    ZwClose(h);

    ExFreePool(kvfi);

end:
    ExFreePool(path.Buffer);

    return degraded;
}

void add_volume_device(superblock* sb, PDEVICE_OBJECT mountmgr, PUNICODE_STRING devpath, UINT64 length, ULONG disk_num, ULONG part_num) {
    NTSTATUS Status;
    LIST_ENTRY* le;
    UNICODE_STRING volname;
    PDEVICE_OBJECT voldev, DeviceObject;
    volume_device_extension* vde = NULL;
    int i, j;
    BOOL new_vde = FALSE;
    volume_child* vc;
    PFILE_OBJECT FileObject;
    UNICODE_STRING devpath2;
    BOOL inserted = FALSE;
    
    if (devpath->Length == 0)
        return;
    
    ExAcquireResourceExclusiveLite(&volume_list_lock, TRUE);
    
    le = volume_list.Flink;
    while (le != &volume_list) {
        volume_device_extension* vde2 = CONTAINING_RECORD(le, volume_device_extension, list_entry);
        
        if (RtlCompareMemory(&vde2->uuid, &sb->uuid, sizeof(BTRFS_UUID)) == sizeof(BTRFS_UUID)) {
            vde = vde2;
            break;
        }
        
        le = le->Flink;
    }
    
    Status = IoGetDeviceObjectPointer(devpath, FILE_READ_ATTRIBUTES, &FileObject, &DeviceObject);
    if (!NT_SUCCESS(Status)) {
        ERR("IoGetDeviceObjectPointer returned %08x\n", Status);
        ExReleaseResourceLite(&volume_list_lock);
        return;
    }
    
    if (!vde) {
        PDEVICE_OBJECT pdo = NULL;
        
        Status = IoReportDetectedDevice(drvobj, InterfaceTypeUndefined, 0xFFFFFFFF, 0xFFFFFFFF,
                                        NULL, NULL, 0, &pdo);
        if (!NT_SUCCESS(Status)) {
            ERR("IoReportDetectedDevice returned %08x\n", Status);
            ExReleaseResourceLite(&volume_list_lock);
            goto fail;
        }
        
        volname.Length = volname.MaximumLength = (wcslen(BTRFS_VOLUME_PREFIX) + 36 + 1) * sizeof(WCHAR);
        volname.Buffer = ExAllocatePoolWithTag(PagedPool, volname.MaximumLength, ALLOC_TAG); // FIXME - when do we free this?
        
        if (!volname.Buffer) {
            ERR("out of memory\n");
            ExReleaseResourceLite(&volume_list_lock);
            goto fail;
        }
        
        RtlCopyMemory(volname.Buffer, BTRFS_VOLUME_PREFIX, wcslen(BTRFS_VOLUME_PREFIX) * sizeof(WCHAR));
        
        j = wcslen(BTRFS_VOLUME_PREFIX);
        for (i = 0; i < 16; i++) {
            volname.Buffer[j] = hex_digit(sb->uuid.uuid[i] >> 4); j++;
            volname.Buffer[j] = hex_digit(sb->uuid.uuid[i] & 0xf); j++;
            
            if (i == 3 || i == 5 || i == 7 || i == 9) {
                volname.Buffer[j] = '-';
                j++;
            }
        }
        
        volname.Buffer[j] = '}';
        
        Status = IoCreateDevice(drvobj, sizeof(volume_device_extension), &volname, FILE_DEVICE_DISK, FILE_DEVICE_SECURE_OPEN, FALSE, &voldev);
        if (!NT_SUCCESS(Status)) {
            ERR("IoCreateDevice returned %08x\n", Status);
            ExReleaseResourceLite(&volume_list_lock);
            goto fail;
        }
        
        voldev->SectorSize = sb->sector_size;
        voldev->Flags |= DO_DIRECT_IO;
        
        vde = voldev->DeviceExtension;
        vde->type = VCB_TYPE_VOLUME;
        vde->uuid = sb->uuid;
        vde->name = volname;
        vde->device = voldev;
        vde->mounted_device = NULL;
        vde->pdo = pdo;
        vde->removing = FALSE;
        vde->open_count = 0;
        
        ExInitializeResourceLite(&vde->child_lock);
        InitializeListHead(&vde->children);
        vde->num_children = sb->num_devices;
        vde->children_loaded = 0;
        
        new_vde = TRUE;
        
        Status = IoRegisterDeviceInterface(pdo, &GUID_DEVINTERFACE_VOLUME, NULL, &vde->bus_name);
        if (!NT_SUCCESS(Status))
            WARN("IoRegisterDeviceInterface returned %08x\n", Status);
        
        pdo->SectorSize = sb->sector_size;
        vde->attached_device = IoAttachDeviceToDeviceStack(voldev, pdo);
        
        pdo->Flags &= ~DO_DEVICE_INITIALIZING;
    } else {
        ExAcquireResourceExclusiveLite(&vde->child_lock, TRUE);
        ExConvertExclusiveToSharedLite(&volume_list_lock);
        
        le = vde->children.Flink;
        while (le != &vde->children) {
            volume_child* vc2 = CONTAINING_RECORD(le, volume_child, list_entry);
            
            if (RtlCompareMemory(&vc2->uuid, &sb->dev_item.device_uuid, sizeof(BTRFS_UUID)) == sizeof(BTRFS_UUID)) {
                // duplicate, ignore
                ExReleaseResourceLite(&vde->child_lock);
                ExReleaseResourceLite(&volume_list_lock);
                goto fail;
            }
            
            le = le->Flink;
        }

        voldev = vde->device;
    }
    
    vc = ExAllocatePoolWithTag(PagedPool, sizeof(volume_child), ALLOC_TAG);
    if (!vc) {
        ERR("out of memory\n");
        goto fail;
    }

    vc->uuid = sb->dev_item.device_uuid;
    vc->devid = sb->dev_item.dev_id;
    vc->generation = sb->generation;
    vc->notification_entry = NULL;

    Status = IoRegisterPlugPlayNotification(EventCategoryTargetDeviceChange, 0, FileObject,
                                            drvobj, pnp_removal, vde, &vc->notification_entry);
    if (!NT_SUCCESS(Status))
        WARN("IoRegisterPlugPlayNotification returned %08x\n", Status);

    vc->devobj = DeviceObject;
    vc->fileobj = FileObject;

    devpath2 = *devpath;

    // The PNP path sometimes begins \\?\ and sometimes \??\. We need to remove this prefix
    // so we can compare properly if the device is removed.
    if (devpath->Length > 4 * sizeof(WCHAR) && devpath->Buffer[0] == '\\' && (devpath->Buffer[1] == '\\' || devpath->Buffer[1] == '?') &&
        devpath->Buffer[2] == '?' && devpath->Buffer[3] == '\\') {
        devpath2.Buffer = &devpath2.Buffer[3];
        devpath2.Length -= 3 * sizeof(WCHAR);
        devpath2.MaximumLength -= 3 * sizeof(WCHAR);
    }

    vc->pnp_name.Length = vc->pnp_name.MaximumLength = devpath2.Length;
    vc->pnp_name.Buffer = ExAllocatePoolWithTag(PagedPool, devpath2.Length, ALLOC_TAG);

    if (vc->pnp_name.Buffer)
        RtlCopyMemory(vc->pnp_name.Buffer, devpath2.Buffer, devpath2.Length);
    else {
        ERR("out of memory\n");
        vc->pnp_name.Length = vc->pnp_name.MaximumLength = 0;
    }

    vc->size = length;
    vc->seeding = sb->flags & BTRFS_SUPERBLOCK_FLAGS_SEEDING ? TRUE : FALSE;
    vc->disk_num = disk_num;
    vc->part_num = part_num;
    vc->had_drive_letter = FALSE;

    le = vde->children.Flink;
    while (le != &vde->children) {
        volume_child* vc2 = CONTAINING_RECORD(le, volume_child, list_entry);

        if (vc2->generation < vc->generation) {
            if (le == vde->children.Flink)
                vde->num_children = sb->num_devices;

            InsertHeadList(vc2->list_entry.Blink, &vc->list_entry);
            inserted = TRUE;
            break;
        }

        le = le->Flink;
    }

    if (!inserted)
        InsertTailList(&vde->children, &vc->list_entry);

    vde->children_loaded++;
    
    if (vde->mounted_device) {
        device_extension* Vcb = vde->mounted_device->DeviceExtension;

        ExAcquireResourceExclusiveLite(&Vcb->tree_lock, TRUE);

        le = Vcb->devices.Flink;
        while (le != &Vcb->devices) {
            device* dev = CONTAINING_RECORD(le, device, list_entry);

            if (!dev->devobj && RtlCompareMemory(&dev->devitem.device_uuid, &sb->dev_item.device_uuid, sizeof(BTRFS_UUID)) == sizeof(BTRFS_UUID)) {
                dev->devobj = DeviceObject;
                dev->disk_num = disk_num;
                dev->part_num = part_num;
                init_device(Vcb, dev, FALSE);
                break;
            }

            le = le->Flink;
        }

        ExReleaseResourceLite(&Vcb->tree_lock);
    }

    if (DeviceObject->Characteristics & FILE_REMOVABLE_MEDIA)
        voldev->Characteristics |= FILE_REMOVABLE_MEDIA;
    
    if (vde->num_children == vde->children_loaded || (vde->children_loaded == 1 && allow_degraded_mount(&sb->uuid))) {
        if (vde->num_children == 1) {
            Status = remove_drive_letter(mountmgr, devpath);
            if (!NT_SUCCESS(Status) && Status != STATUS_NOT_FOUND)
                WARN("remove_drive_letter returned %08x\n", Status);
            
            vc->had_drive_letter = NT_SUCCESS(Status);
        } else {
            le = vde->children.Flink;
            
            while (le != &vde->children) {
                UNICODE_STRING name;
                
                vc = CONTAINING_RECORD(le, volume_child, list_entry);
                
                name.Length = name.MaximumLength = vc->pnp_name.Length + (3 * sizeof(WCHAR));
                name.Buffer = ExAllocatePoolWithTag(PagedPool, name.Length, ALLOC_TAG);
                
                if (!name.Buffer) {
                    ERR("out of memory\n");
                    goto fail;
                }
                
                RtlCopyMemory(name.Buffer, L"\\??", 3 * sizeof(WCHAR));
                RtlCopyMemory(&name.Buffer[3], vc->pnp_name.Buffer, vc->pnp_name.Length);
                
                Status = remove_drive_letter(mountmgr, &name);
                
                if (!NT_SUCCESS(Status) && Status != STATUS_NOT_FOUND)
                    WARN("remove_drive_letter returned %08x\n", Status);
                
                ExFreePool(name.Buffer);
                
                vc->had_drive_letter = NT_SUCCESS(Status);
                
                le = le->Flink;
            }
        }
        
        Status = IoSetDeviceInterfaceState(&vde->bus_name, TRUE);
        if (!NT_SUCCESS(Status))
            WARN("IoSetDeviceInterfaceState returned %08x\n", Status);
    }
    
    if (!new_vde) {
        ExReleaseResourceLite(&vde->child_lock);
        ExReleaseResourceLite(&volume_list_lock);
    } else {
        InsertTailList(&volume_list, &vde->list_entry);
        
        voldev->Flags &= ~DO_DEVICE_INITIALIZING;
        
        ExReleaseResourceLite(&volume_list_lock);
    }

    return;
    
fail:
    ObDereferenceObject(FileObject);
}
