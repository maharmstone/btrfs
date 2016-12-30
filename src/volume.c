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

NTSTATUS STDCALL vol_create(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_close(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_read(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_write(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_query_information(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_set_information(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_query_ea(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_set_ea(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_flush_buffers(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_query_volume_information(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_set_volume_information(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_cleanup(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_directory_control(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_file_system_control(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_lock_control(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_device_control(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_shutdown(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_pnp(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_query_security(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS STDCALL vol_set_security(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    TRACE("(%p, %p)\n", DeviceObject, Irp);

    // FIXME

    return STATUS_INVALID_DEVICE_REQUEST;
}
