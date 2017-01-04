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
#include <mountdev.h>
#include <ntddvol.h>
#include <ntddstor.h>
#include <ntdddisk.h>
// #include <winioctl.h>

#define IOCTL_VOLUME_IS_DYNAMIC     CTL_CODE(IOCTL_VOLUME_BASE, 18, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VOLUME_POST_ONLINE    CTL_CODE(IOCTL_VOLUME_BASE, 25, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

extern PDRIVER_OBJECT drvobj;
extern ERESOURCE volume_list_lock;
extern LIST_ENTRY volume_list;

NTSTATUS STDCALL vol_create(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    Irp->IoStatus.Information = FILE_OPENED;
    
    return STATUS_SUCCESS;
}

NTSTATUS STDCALL vol_close(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    TRACE("(%p, %p)\n", DeviceObject, Irp);
    
    Irp->IoStatus.Information = 0;

    return STATUS_SUCCESS;
}

NTSTATUS STDCALL vol_read(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    ERR("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_write(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    ERR("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_query_information(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    ERR("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_set_information(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    ERR("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_query_ea(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    ERR("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_set_ea(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    ERR("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_flush_buffers(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    ERR("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_query_volume_information(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    ERR("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_set_volume_information(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    ERR("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_cleanup(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    Irp->IoStatus.Information = 0;

    return STATUS_SUCCESS;
}

NTSTATUS STDCALL vol_directory_control(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    ERR("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_file_system_control(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    ERR("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_lock_control(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    ERR("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

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

static NTSTATUS vol_is_dynamic(volume_device_extension* vde, PIRP Irp) {
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
            TRACE("unhandled control code IOCTL_STORAGE_GET_DEVICE_NUMBER\n");
            break;

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
            ERR("unhandled control code IOCTL_VOLUME_GET_GPT_ATTRIBUTES\n");
            break;

        case IOCTL_VOLUME_IS_DYNAMIC:
            return vol_is_dynamic(vde, Irp);

        case IOCTL_VOLUME_ONLINE:
            TRACE("unhandled control code IOCTL_VOLUME_ONLINE\n");
            break;

        case IOCTL_VOLUME_POST_ONLINE:
            TRACE("unhandled control code IOCTL_VOLUME_POST_ONLINE\n");
            break;

        case IOCTL_DISK_GET_DRIVE_GEOMETRY:
            ERR("unhandled control code IOCTL_DISK_GET_DRIVE_GEOMETRY\n");
            break;

        case IOCTL_DISK_IS_WRITABLE:
            ERR("unhandled control code IOCTL_DISK_IS_WRITABLE\n");
            break;

        case IOCTL_DISK_GET_LENGTH_INFO:
            ERR("unhandled control code IOCTL_DISK_GET_LENGTH_INFO\n");
            break;
            
        case IOCTL_STORAGE_CHECK_VERIFY:
            return vol_check_verify(vde);

        default:
            ERR("unhandled control code %x\n", IrpSp->Parameters.DeviceIoControl.IoControlCode);
            break;
    }

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_shutdown(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    ERR("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_pnp(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    ERR("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_query_security(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    ERR("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_set_security(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    ERR("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

    return STATUS_INVALID_DEVICE_REQUEST;
}

static NTSTATUS mountmgr_volume_arrival(PDEVICE_OBJECT mountmgr, PUNICODE_STRING devpath) {
    NTSTATUS Status;
    MOUNTMGR_TARGET_NAME* mtn;
    
    mtn = ExAllocatePoolWithTag(PagedPool, offsetof(MOUNTMGR_TARGET_NAME, DeviceName[0]) + devpath->Length, ALLOC_TAG);
    if (!mtn) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    mtn->DeviceNameLength = devpath->Length;
    RtlCopyMemory(mtn->DeviceName, devpath->Buffer, devpath->Length);
    
    Status = dev_ioctl(mountmgr, IOCTL_MOUNTMGR_VOLUME_ARRIVAL_NOTIFICATION, mtn, offsetof(MOUNTMGR_TARGET_NAME, DeviceName[0]) + devpath->Length,
                       NULL, 0, FALSE, NULL);
    
    ExFreePool(mtn);
    
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
    if (n >= 0 && n <= 9)
        return n + '0';
    else
        return n - 0xa + 'a';
}

void add_volume_device(superblock* sb, PDEVICE_OBJECT mountmgr, PUNICODE_STRING devpath, UINT64 offset, UINT64 length, ULONG disk_num,
                       ULONG part_num, PUNICODE_STRING partname) {
    NTSTATUS Status;
    LIST_ENTRY* le;
    UNICODE_STRING volname;
    PDEVICE_OBJECT voldev, DeviceObject;
    volume_device_extension* vde = NULL;
    int i, j;
    BOOL new_vde = FALSE;
    volume_child* vc;
    PFILE_OBJECT FileObject;
    
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
        goto end;
    }
    
    if (!vde) {
        volname.Length = volname.MaximumLength = (wcslen(BTRFS_VOLUME_PREFIX) + 36 + 1) * sizeof(WCHAR);
        volname.Buffer = ExAllocatePoolWithTag(PagedPool, volname.MaximumLength, ALLOC_TAG); // FIXME - when do we free this?
        
        if (!volname.Buffer) {
            ERR("out of memory\n");
            ExReleaseResourceLite(&volume_list_lock);
            goto end;
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
            goto end;
        }
        
        voldev->StackSize = 1;
        // FIXME - set sector size?
        
        vde = voldev->DeviceExtension;
        vde->type = VCB_TYPE_VOLUME;
        vde->uuid = sb->uuid;
        vde->name = volname;
        vde->device = voldev;
        vde->mounted_device = NULL;
        
        ExInitializeResourceLite(&vde->child_lock);
        InitializeListHead(&vde->children);
        vde->num_children = sb->num_devices;
        vde->children_loaded = 0;
        
        new_vde = TRUE;
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
                goto end;
            }
            
            le = le->Flink;
        }
    }
    
    vc = ExAllocatePoolWithTag(PagedPool, sizeof(volume_child), ALLOC_TAG);
    if (!vc)
        ERR("out of memory\n");
    else {
        vc->uuid = sb->dev_item.device_uuid;
        vc->devid = sb->dev_item.dev_id;
        vc->generation = sb->generation;
        
        ObReferenceObject(DeviceObject);
        vc->devobj = DeviceObject;
        
        vc->pnp_name.Length = vc->pnp_name.MaximumLength = devpath->Length;
        vc->pnp_name.Buffer = ExAllocatePoolWithTag(PagedPool, devpath->Length, ALLOC_TAG);
        
        if (vc->pnp_name.Buffer)
            RtlCopyMemory(vc->pnp_name.Buffer, devpath->Buffer, devpath->Length);
        else {
            ERR("out of memory\n");
            vc->pnp_name.Length = vc->pnp_name.MaximumLength = 0;
        }
        
        vc->offset = offset;
        vc->size = length;
        vc->seeding = sb->flags & BTRFS_SUPERBLOCK_FLAGS_SEEDING ? TRUE : FALSE;
        vc->disk_num = disk_num;
        vc->part_num = part_num;
        
        InsertTailList(&vde->children, &vc->list_entry); // FIXME - these should be in order
        
        vde->children_loaded++;
    }
    
    if (!new_vde) {
        ExReleaseResourceLite(&vde->child_lock);
        ExReleaseResourceLite(&volume_list_lock);
    } else {
        InsertTailList(&volume_list, &vde->list_entry);
        
        voldev->Flags &= ~DO_DEVICE_INITIALIZING;
        
        ExReleaseResourceLite(&volume_list_lock);

        Status = mountmgr_volume_arrival(mountmgr, &volname);
        if (!NT_SUCCESS(Status))
            ERR("mountmgr_volume_arrival returned %08x\n", Status);
        
        Status = mountmgr_add_drive_letter(mountmgr, &volname);
        if (!NT_SUCCESS(Status))
            ERR("mountmgr_add_drive_letter returned %08x\n", Status);
    }
    
    remove_drive_letter(mountmgr, partname);
    
end:
    ObDereferenceObject(FileObject);
}
