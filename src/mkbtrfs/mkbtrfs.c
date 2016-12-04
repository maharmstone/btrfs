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

#include <windef.h>
#include <winbase.h>
#include <winternl.h>
#include <devioctl.h>
#include <ntdddisk.h>
#include <stdio.h>

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

typedef NTSTATUS (NTAPI* pFormatEx)(PUNICODE_STRING DriveRoot, FMIFS_MEDIA_FLAG MediaFlag,
                                    PUNICODE_STRING Label, BOOLEAN QuickFormat, ULONG ClusterSize,
                                    PFMIFSCALLBACK Callback);

int main() {
    HMODULE ubtrfs;
    NTSTATUS Status;
    UNICODE_STRING drive, label;
    pFormatEx FormatEx;
    
    ubtrfs = LoadLibraryW(L"ubtrfs.dll");
    
    if (!ubtrfs) {
#if defined(__i386) || defined(_M_IX86)
        ubtrfs = LoadLibraryW(L"Debug\\x86\\ubtrfs.dll");
#elif defined(__x86_64__) || defined(_M_X64)
        ubtrfs = LoadLibraryW(L"Debug\\x64\\ubtrfs.dll");
#endif
    }
    
    if (!ubtrfs) {
        fprintf(stderr, "unable to load ubtrfs.dll\n");
        return 1;
    }
    
    FormatEx = (pFormatEx)GetProcAddress(ubtrfs, "FormatEx");
    
    if (!FormatEx) {
        fprintf(stderr, "could not load function FormatEx in ubtrfs.dll\n");
        return 1;
    }
    
    drive.Buffer = L"\\??\\D:";
    drive.Length = drive.MaximumLength = wcslen(drive.Buffer) * sizeof(WCHAR);
    
    label.Buffer = L"test";
    label.Length = label.MaximumLength = wcslen(label.Buffer) * sizeof(WCHAR);
    
    Status = FormatEx(&drive, FMIFS_HARDDISK, &label, FALSE, 4096, NULL);
    
    if (!NT_SUCCESS(Status)) {
        fprintf(stderr, "FormatEx returned status %08lx\n", Status);
        return 1;
    }
    
    printf("Completed successfully.\n");
    
    return 0;
}
