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
#include <ntdddisk.h>
#include <mountdev.h>
#include <diskguid.h>

extern LIST_ENTRY VcbList;
extern ERESOURCE global_loading_lock;

static NTSTATUS mountdev_query_stable_guid(device_extension* Vcb, PIRP Irp) {
    MOUNTDEV_STABLE_GUID* msg = Irp->UserBuffer;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    
    TRACE("IOCTL_MOUNTDEV_QUERY_STABLE_GUID\n");
    
    if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(MOUNTDEV_STABLE_GUID))
        return STATUS_INVALID_PARAMETER;

    RtlCopyMemory(&msg->StableGuid, &Vcb->superblock.uuid, sizeof(GUID));
    
    Irp->IoStatus.Information = sizeof(MOUNTDEV_STABLE_GUID);
    
    return STATUS_SUCCESS;
}

static NTSTATUS is_writable(device_extension* Vcb) {
    TRACE("IOCTL_DISK_IS_WRITABLE\n");
    
    return Vcb->readonly ? STATUS_MEDIA_WRITE_PROTECTED : STATUS_SUCCESS;
}

static NTSTATUS query_filesystems(void* data, ULONG length) {
    NTSTATUS Status;
    LIST_ENTRY *le, *le2;
    btrfs_filesystem* bfs = NULL;
    ULONG itemsize;
    
    ExAcquireResourceSharedLite(&global_loading_lock, TRUE);
    
    if (IsListEmpty(&VcbList)) {
        if (length < sizeof(btrfs_filesystem)) {
            Status = STATUS_BUFFER_OVERFLOW;
            goto end;
        } else {
            RtlZeroMemory(data, sizeof(btrfs_filesystem));
            Status = STATUS_SUCCESS;
            goto end;
        }
    }

    le = VcbList.Flink;
    
    while (le != &VcbList) {
        device_extension* Vcb = CONTAINING_RECORD(le, device_extension, list_entry);
        btrfs_filesystem_device* bfd;
        
        if (bfs) {
            bfs->next_entry = itemsize;
            bfs = (btrfs_filesystem*)((UINT8*)bfs + itemsize);
        } else
            bfs = data;
        
        if (length < offsetof(btrfs_filesystem, device)) {
            Status = STATUS_BUFFER_OVERFLOW;
            goto end;
        }
        
        itemsize = offsetof(btrfs_filesystem, device);
        length -= offsetof(btrfs_filesystem, device);
        
        bfs->next_entry = 0;
        RtlCopyMemory(&bfs->uuid, &Vcb->superblock.uuid, sizeof(BTRFS_UUID));
        
        ExAcquireResourceSharedLite(&Vcb->tree_lock, TRUE);
        
        bfs->num_devices = Vcb->superblock.num_devices;
        
        bfd = NULL;
        
        le2 = Vcb->devices.Flink;
        while (le2 != &Vcb->devices) {
            device* dev = CONTAINING_RECORD(le2, device, list_entry);
            MOUNTDEV_NAME mdn;
            
            if (bfd)
                bfd = (btrfs_filesystem_device*)((UINT8*)bfd + offsetof(btrfs_filesystem_device, name[0]) + bfd->name_length);
            else
                bfd = &bfs->device;
            
            if (length < offsetof(btrfs_filesystem_device, name[0])) {
                ExReleaseResourceLite(&Vcb->tree_lock);
                Status = STATUS_BUFFER_OVERFLOW;
                goto end;
            }
            
            itemsize += offsetof(btrfs_filesystem_device, name[0]);
            length -= offsetof(btrfs_filesystem_device, name[0]);
            
            RtlCopyMemory(&bfd->uuid, &dev->devitem.device_uuid, sizeof(BTRFS_UUID));
            
            Status = dev_ioctl(dev->devobj, IOCTL_MOUNTDEV_QUERY_DEVICE_NAME, NULL, 0, &mdn, sizeof(MOUNTDEV_NAME), TRUE, NULL);
            if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_OVERFLOW) {
                ExReleaseResourceLite(&Vcb->tree_lock);
                ERR("IOCTL_MOUNTDEV_QUERY_DEVICE_NAME returned %08x\n", Status);
                goto end;
            }
            
            if (mdn.NameLength > length) {
                ExReleaseResourceLite(&Vcb->tree_lock);
                Status = STATUS_BUFFER_OVERFLOW;
                goto end;
            }
            
            Status = dev_ioctl(dev->devobj, IOCTL_MOUNTDEV_QUERY_DEVICE_NAME, NULL, 0, &bfd->name_length, offsetof(MOUNTDEV_NAME, Name[0]) + mdn.NameLength, TRUE, NULL);
            if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_OVERFLOW) {
                ExReleaseResourceLite(&Vcb->tree_lock);
                ERR("IOCTL_MOUNTDEV_QUERY_DEVICE_NAME returned %08x\n", Status);
                goto end;
            }
            
            itemsize += bfd->name_length;
            length -= bfd->name_length;
            
            le2 = le2->Flink;
        }
        
        ExReleaseResourceLite(&Vcb->tree_lock);
        
        le = le->Flink;
    }
    
    Status = STATUS_SUCCESS;
    
end:
    ExReleaseResourceLite(&global_loading_lock);
    
    return Status;
}

static NTSTATUS control_ioctl(PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status;
    
    switch (IrpSp->Parameters.DeviceIoControl.IoControlCode) {
        case IOCTL_BTRFS_QUERY_FILESYSTEMS:
            Status = query_filesystems(map_user_buffer(Irp), IrpSp->Parameters.FileSystemControl.OutputBufferLength);
            break;
            
        default:
            TRACE("unhandled ioctl %x\n", IrpSp->Parameters.DeviceIoControl.IoControlCode);
            Status = STATUS_NOT_IMPLEMENTED;
            break;
    }
    
    return Status;
}

NTSTATUS STDCALL drv_device_control(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    NTSTATUS Status;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    device_extension* Vcb = DeviceObject->DeviceExtension;
    BOOL top_level;

    FsRtlEnterFileSystem();

    top_level = is_top_level(Irp);
    
    Irp->IoStatus.Information = 0;
    
    if (Vcb) {
        if (Vcb->type == VCB_TYPE_CONTROL) {
            Status = control_ioctl(Irp);
            goto end;
        } else if (Vcb->type == VCB_TYPE_VOLUME) {
            Status = vol_device_control(DeviceObject, Irp);
            goto end;
        } else if (Vcb->type != VCB_TYPE_FS) {
            Status = STATUS_INVALID_PARAMETER;
            goto end;
        }
    } else {
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }
    
    if (!IrpSp->FileObject || IrpSp->FileObject->FsContext != Vcb->volume_fcb) {
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }
    
    switch (IrpSp->Parameters.DeviceIoControl.IoControlCode) {
        case IOCTL_MOUNTDEV_QUERY_STABLE_GUID:
            Status = mountdev_query_stable_guid(Vcb, Irp);
            goto end;

        case IOCTL_DISK_IS_WRITABLE:
            Status = is_writable(Vcb);
            goto end;
            
        default:
            TRACE("unhandled control code %x\n", IrpSp->Parameters.DeviceIoControl.IoControlCode);
            break;
    }
    
    IoSkipCurrentIrpStackLocation(Irp);
    
    Status = IoCallDriver(Vcb->Vpb->RealDevice, Irp);
    
    goto end2;
    
end:
    Irp->IoStatus.Status = Status;

    if (Status != STATUS_PENDING)
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
end2:
    if (top_level) 
        IoSetTopLevelIrp(NULL);
    
    FsRtlExitFileSystem();

    return Status;
}
