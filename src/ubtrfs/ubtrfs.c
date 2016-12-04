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

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <winternl.h>
#include <devioctl.h>
#include <ntdddisk.h>

#define FSCTL_LOCK_VOLUME               CTL_CODE(FILE_DEVICE_FILE_SYSTEM,  6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_UNLOCK_VOLUME             CTL_CODE(FILE_DEVICE_FILE_SYSTEM,  7, METHOD_BUFFERED, FILE_ANY_ACCESS)

#ifdef __cplusplus
extern "C" {
#endif
NTSYSCALLAPI NTSTATUS NTAPI NtFsControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG FsControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength);
#ifdef __cplusplus
}
#endif

HMODULE module;

// the following definitions come from fmifs.h in ReactOS

typedef struct {
    ULONG Lines;
    PCHAR Output;
} TEXTOUTPUT, *PTEXTOUTPUT;

typedef enum {
    FMIFS_UNKNOWN0,
    FMIFS_UNKNOWN1,
    FMIFS_UNKNOWN2,
    FMIFS_UNKNOWN3,
    FMIFS_UNKNOWN4,
    FMIFS_UNKNOWN5,
    FMIFS_UNKNOWN6,
    FMIFS_UNKNOWN7,
    FMIFS_FLOPPY,
    FMIFS_UNKNOWN9,
    FMIFS_UNKNOWN10,
    FMIFS_REMOVABLE,
    FMIFS_HARDDISK,
    FMIFS_UNKNOWN13,
    FMIFS_UNKNOWN14,
    FMIFS_UNKNOWN15,
    FMIFS_UNKNOWN16,
    FMIFS_UNKNOWN17,
    FMIFS_UNKNOWN18,
    FMIFS_UNKNOWN19,
    FMIFS_UNKNOWN20,
    FMIFS_UNKNOWN21,
    FMIFS_UNKNOWN22,
    FMIFS_UNKNOWN23,
} FMIFS_MEDIA_FLAG;

typedef enum {
    PROGRESS,
    DONEWITHSTRUCTURE,
    UNKNOWN2,
    UNKNOWN3,
    UNKNOWN4,
    UNKNOWN5,
    INSUFFICIENTRIGHTS,
    FSNOTSUPPORTED,
    VOLUMEINUSE,
    UNKNOWN9,
    UNKNOWNA,
    DONE,
    UNKNOWNC,
    UNKNOWND,
    OUTPUT,
    STRUCTUREPROGRESS,
    CLUSTERSIZETOOSMALL,
} CALLBACKCOMMAND;

typedef BOOLEAN (NTAPI* PFMIFSCALLBACK)(CALLBACKCOMMAND Command, ULONG SubAction, PVOID ActionInfo);

NTSTATUS WINAPI ChkdskEx(PUNICODE_STRING DriveRoot, BOOLEAN FixErrors, BOOLEAN Verbose, BOOLEAN CheckOnlyIfDirty,
                         BOOLEAN ScanDrive, PFMIFSCALLBACK Callback) {
    // STUB
    
    if (Callback) {
        TEXTOUTPUT TextOut;
        
        TextOut.Lines = 1;
        TextOut.Output = "stub, not implemented";
        
        Callback(OUTPUT, 0, &TextOut);
    }
    
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI FormatEx(PUNICODE_STRING DriveRoot, FMIFS_MEDIA_FLAG MediaFlag, PUNICODE_STRING Label,
                        BOOLEAN QuickFormat, ULONG ClusterSize, PFMIFSCALLBACK Callback)
{
    NTSTATUS Status;
    HANDLE h;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    GET_LENGTH_INFORMATION gli;
    
    DebugBreak();
    
    InitializeObjectAttributes(&attr, DriveRoot, 0, NULL, NULL);
    
    Status = NtOpenFile(&h, FILE_GENERIC_READ | FILE_GENERIC_WRITE, &attr, &iosb,
                        FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_ALERT);
    
    if (!NT_SUCCESS(Status))
        return Status;

    Status = NtDeviceIoControlFile(h, NULL, NULL, NULL, &iosb, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &gli, sizeof(gli));
    
    if (!NT_SUCCESS(Status)) {
        NtClose(h);
        return Status;
    }
    
    if (Callback) {
        ULONG pc = 0;
        Callback(PROGRESS, 0, (PVOID)&pc);
    }
    
    NtFsControlFile(h, NULL, NULL, NULL, &iosb, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0);
    
    // FIXME - write
    
    NtFsControlFile(h, NULL, NULL, NULL, &iosb, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0);
    
    NtClose(h);
    
    if (Callback) {
        BOOL success = NT_SUCCESS(Status);
        Callback(DONE, 0, (PVOID)&success);
    }
    
    return STATUS_NOT_IMPLEMENTED;
}

BOOL APIENTRY DllMain(HANDLE hModule, DWORD dwReason, void* lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH)
        module = (HMODULE)hModule;
        
    return TRUE;
}
