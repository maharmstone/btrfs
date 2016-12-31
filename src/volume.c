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

extern PDRIVER_OBJECT drvobj;
extern ERESOURCE volume_list_lock;
extern LIST_ENTRY volume_list;

NTSTATUS STDCALL vol_create(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    ERR("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_close(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    ERR("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

    return STATUS_INVALID_DEVICE_REQUEST;
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
    ERR("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

    return STATUS_INVALID_DEVICE_REQUEST;
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

NTSTATUS STDCALL vol_device_control(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    ERR("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

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

static __inline WCHAR hex_digit(UINT8 n) {
    if (n >= 0 && n <= 9)
        return n + '0';
    else
        return n - 0xa + 'a';
}

void add_volume_device(BTRFS_UUID* uuid) {
    NTSTATUS Status;
    LIST_ENTRY* le;
    UNICODE_STRING volname;
    PDEVICE_OBJECT voldev;
    volume_device_extension* vde;
    int i, j;
    
    static const WCHAR devpref[] = L"\\Device\\Btrfs{";
    
    ExAcquireResourceExclusiveLite(&volume_list_lock, TRUE);
    
    le = volume_list.Flink;
    while (le != &volume_list) {
        vde = CONTAINING_RECORD(le, volume_device_extension, list_entry);
        
        if (RtlCompareMemory(&vde->uuid, uuid, sizeof(BTRFS_UUID)) == sizeof(BTRFS_UUID)) {
            ExReleaseResourceLite(&volume_list_lock);
            return;
        }
        
        le = le->Flink;
    }
    
//     volname.Buffer = L"\\Device\\BtrfsVolume"; // FIXME
//     volname.Length = volname.MaximumLength = wcslen(volname.Buffer) * sizeof(WCHAR);
    volname.Length = volname.MaximumLength = (wcslen(devpref) + 36 + 1) * sizeof(WCHAR);
    volname.Buffer = ExAllocatePoolWithTag(PagedPool, volname.MaximumLength, ALLOC_TAG); // FIXME - when do we free this?
    
    if (!volname.Buffer) {
        ERR("out of memory\n");
        ExReleaseResourceLite(&volume_list_lock);
        return;
    }
    
    RtlCopyMemory(volname.Buffer, devpref, wcslen(devpref) * sizeof(WCHAR));
    
    j = wcslen(devpref);
    for (i = 0; i < 16; i++) {
        volname.Buffer[j] = hex_digit(uuid->uuid[i] >> 4); j++;
        volname.Buffer[j] = hex_digit(uuid->uuid[i] & 0xf); j++;
        
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
        return;
    }
    
    voldev->StackSize = 1;
    // FIXME - set sector size?
    
    vde = voldev->DeviceExtension;
    vde->type = VCB_TYPE_VOLUME;
    vde->uuid = *uuid;
    vde->name = volname;
    
    InsertTailList(&volume_list, &vde->list_entry);
    ExReleaseResourceLite(&volume_list_lock);
    
    voldev->Flags &= ~DO_DEVICE_INITIALIZING;
    
    // FIXME - mountmgr
}
