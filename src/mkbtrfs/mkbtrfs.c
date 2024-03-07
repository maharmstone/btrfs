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

#include <windef.h>
#include <winbase.h>
#include <winternl.h>
#include <devioctl.h>
#include <ntdddisk.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stringapiset.h>
#include "resource.h"
#include "../btrfs.h"

#define UBTRFS_DLL L"ubtrfs.dll"

// These are undocumented, and what comes from format.exe
typedef struct {
    void* table;
    void* unk1;
    WCHAR* string;
} DSTRING;

typedef struct {
    void* table;
} STREAM_MESSAGE;

#define FORMAT_FLAG_QUICK_FORMAT        0x00000001
#define FORMAT_FLAG_UNKNOWN1            0x00000002
#define FORMAT_FLAG_DISMOUNT_FIRST      0x00000004
#define FORMAT_FLAG_UNKNOWN2            0x00000040
#define FORMAT_FLAG_LARGE_RECORDS       0x00000100
#define FORMAT_FLAG_INTEGRITY_DISABLE   0x00000100

typedef struct {
    uint16_t unk1;
    uint16_t unk2;
    uint32_t flags;
    DSTRING* label;
} options;

typedef BOOL (__stdcall* pFormatEx)(DSTRING* root, STREAM_MESSAGE* message, options* opts, uint32_t unk1);
typedef void (__stdcall* pSetSizes)(ULONG sector, ULONG node);
typedef void (__stdcall* pSetIncompatFlags)(uint64_t incompat_flags);
typedef void (__stdcall* pSetCompatROFlags)(uint64_t compat_ro_flags);
typedef void (__stdcall* pSetCsumType)(uint16_t csum_type);

static void print_string(FILE* f, int resid, ...) {
    WCHAR s[1024], t[1024];
    va_list ap;

    if (!LoadStringW(GetModuleHandle(NULL), resid, s, sizeof(s) / sizeof(WCHAR))) {
        fprintf(stderr, "LoadString failed (error %lu)\n", GetLastError());
        return;
    }

    va_start(ap, resid);
    vswprintf(t, sizeof(t) / sizeof(WCHAR), s, ap);

    fwprintf(f, L"%s\n", t);

    va_end(ap);
}

int main(int argc, char** argv) {
    HMODULE ubtrfs;
    bool baddrive = false, success;
    char *ds = NULL, *labels = NULL;
    WCHAR dsw[10], labelw[255], dsw2[255];
    UNICODE_STRING drive, label;
    pFormatEx FormatEx;
    options opts;
    DSTRING labelds, rootds;
    ULONG sector_size = 0, node_size = 0;
    int i;
    bool invalid_args = false;
    uint64_t incompat_flags = BTRFS_INCOMPAT_FLAGS_EXTENDED_IREF | BTRFS_INCOMPAT_FLAGS_SKINNY_METADATA;
    uint64_t compat_ro_flags = 0;
    uint16_t csum_type = CSUM_TYPE_CRC32C;
    pSetIncompatFlags SetIncompatFlags;
    pSetCsumType SetCsumType;

    if (argc >= 2) {
        for (i = 1; i < argc; i++) {
            if (argv[i][0] == '/' && argv[i][1] != 0) {
                char cmd[255], *colon;

                colon = strstr(argv[i], ":");

                if (colon) {
                    memcpy(cmd, argv[i] + 1, colon - argv[i] - 1);
                    cmd[colon - argv[i] - 1] = 0;
                } else
                    strcpy(cmd, argv[i] + 1);

                if (!_stricmp(cmd, "sectorsize")) {
                    if (!colon || colon[1] == 0) {
                        print_string(stdout, IDS_NO_SECTOR_SIZE);
                        invalid_args = true;
                        break;
                    } else
                        sector_size = atoi(&colon[1]);
                } else if (!_stricmp(cmd, "nodesize")) {
                    if (!colon || colon[1] == 0) {
                        print_string(stdout, IDS_NO_NODE_SIZE);
                        invalid_args = true;
                        break;
                    } else
                        node_size = atoi(&colon[1]);
                } else if (!_stricmp(cmd, "csum")) {
                    char* v;

                    if (!colon || colon[1] == 0) {
                        print_string(stdout, IDS_NO_CSUM);
                        invalid_args = true;
                        break;
                    }

                    v = &colon[1];

                    if (!_stricmp(v, "crc32c"))
                        csum_type = CSUM_TYPE_CRC32C;
                    else if (!_stricmp(v, "xxhash"))
                        csum_type = CSUM_TYPE_XXHASH;
                    else if (!_stricmp(v, "sha256"))
                        csum_type = CSUM_TYPE_SHA256;
                    else if (!_stricmp(v, "blake2"))
                        csum_type = CSUM_TYPE_BLAKE2;
                    else {
                        print_string(stdout, IDS_INVALID_CSUM_TYPE);
                        invalid_args = true;
                        break;
                    }
                } else if (!_stricmp(cmd, "mixed"))
                    incompat_flags |= BTRFS_INCOMPAT_FLAGS_MIXED_GROUPS;
                else if (!_stricmp(cmd, "notmixed"))
                    incompat_flags &= ~BTRFS_INCOMPAT_FLAGS_MIXED_GROUPS;
                else if (!_stricmp(cmd, "extiref"))
                    incompat_flags |= BTRFS_INCOMPAT_FLAGS_EXTENDED_IREF;
                else if (!_stricmp(cmd, "notextiref"))
                    incompat_flags &= ~BTRFS_INCOMPAT_FLAGS_EXTENDED_IREF;
                else if (!_stricmp(cmd, "skinnymetadata"))
                    incompat_flags |= BTRFS_INCOMPAT_FLAGS_SKINNY_METADATA;
                else if (!_stricmp(cmd, "notskinnymetadata"))
                    incompat_flags &= ~BTRFS_INCOMPAT_FLAGS_SKINNY_METADATA;
                else if (!_stricmp(cmd, "noholes"))
                    incompat_flags |= BTRFS_INCOMPAT_FLAGS_NO_HOLES;
                else if (!_stricmp(cmd, "notnoholes"))
                    incompat_flags &= ~BTRFS_INCOMPAT_FLAGS_NO_HOLES;
                else if (!_stricmp(cmd, "blockgrouptree"))
                    compat_ro_flags |= BTRFS_COMPAT_RO_FLAGS_BLOCK_GROUP_TREE;
                else if (!_stricmp(cmd, "notblockgrouptree"))
                    compat_ro_flags &= ~BTRFS_COMPAT_RO_FLAGS_BLOCK_GROUP_TREE;
                else {
                    print_string(stdout, IDS_UNKNOWN_ARG);
                    invalid_args = true;
                    break;
                }
            } else {
                if (!ds)
                    ds = argv[i];
                else if (!labels)
                    labels = argv[i];
                else {
                    print_string(stdout, IDS_TOO_MANY_ARGS);
                    invalid_args = true;
                    break;
                }
            }
        }
    } else
        invalid_args = true;

    if (!ds)
        invalid_args = true;

    if (invalid_args) {
        char* c = argv[0] + strlen(argv[0]) - 1;
        char* fn = NULL;
        WCHAR fnw[MAX_PATH], *s;
        int ret;

        while (c > argv[0]) {
            if (*c == '/' || *c == '\\') {
                fn = c + 1;
                break;
            }
            c--;
        }

        if (!fn)
            fn = argv[0];

        if (!MultiByteToWideChar(CP_OEMCP, MB_PRECOMPOSED, fn, -1, fnw, sizeof(fnw) / sizeof(WCHAR))) {
            print_string(stderr, IDS_MULTIBYTE_FAILED, GetLastError());
            return 1;
        }

        print_string(stdout, IDS_USAGE, fnw);

        ret = LoadStringW(GetModuleHandle(NULL), IDS_USAGE2, (WCHAR*)&s, 0);

        if (!ret) {
            fprintf(stderr, "LoadString failed (error %lu)\n", GetLastError());
            return 0;
        }

        fwprintf(stdout, L"%.*s\n", ret, s);

        return 0;
    }

    if (ds[0] != '\\') {
        if ((ds[0] >= 'A' && ds[0] <= 'Z') || (ds[0] >= 'a' && ds[0] <= 'z')) {
            if (ds[1] == 0 || (ds[1] == ':' && ds[2] == 0) || (ds[1] == ':' && ds[2] == '\\' && ds[3] == 0)) {
                dsw[0] = '\\';
                dsw[1] = '?';
                dsw[2] = '?';
                dsw[3] = '\\';
                dsw[4] = ds[0];
                dsw[5] = ':';
                dsw[6] = 0;

                drive.Buffer = dsw;
                drive.Length = drive.MaximumLength = (USHORT)(wcslen(drive.Buffer) * sizeof(WCHAR));
            } else
                baddrive = true;
        } else
            baddrive = true;
    } else {
        if (!MultiByteToWideChar(CP_OEMCP, MB_PRECOMPOSED, ds, -1, dsw2, sizeof(dsw2) / sizeof(WCHAR))) {
            print_string(stderr, IDS_MULTIBYTE_FAILED, GetLastError());
            return 1;
        }

        drive.Buffer = dsw2;
        drive.Length = drive.MaximumLength = (USHORT)(wcslen(drive.Buffer) * sizeof(WCHAR));
    }

    if (baddrive) {
        if (!MultiByteToWideChar(CP_OEMCP, MB_PRECOMPOSED, ds, -1, dsw2, sizeof(dsw2) / sizeof(WCHAR))) {
            print_string(stderr, IDS_MULTIBYTE_FAILED, GetLastError());
            return 1;
        }

        print_string(stderr, IDS_CANT_RECOGNIZE_DRIVE, dsw2);
        return 1;
    }

    if (labels) {
        if (!MultiByteToWideChar(CP_OEMCP, MB_PRECOMPOSED, labels, -1, labelw, sizeof(labelw) / sizeof(WCHAR))) {
            print_string(stderr, IDS_MULTIBYTE_FAILED, GetLastError());
            return 1;
        }

        label.Buffer = labelw;
        label.Length = label.MaximumLength = (USHORT)(wcslen(labelw) * sizeof(WCHAR));
    } else {
        label.Buffer = NULL;
        label.Length = label.MaximumLength = 0;
    }

    ubtrfs = LoadLibraryW(UBTRFS_DLL);

    if (!ubtrfs) {
#if defined(__i386) || defined(_M_IX86)
        ubtrfs = LoadLibraryW(L"Debug\\x86\\ubtrfs.dll");
#elif defined(__x86_64__) || defined(_M_X64)
        ubtrfs = LoadLibraryW(L"Debug\\x64\\ubtrfs.dll");
#endif
    }

    if (!ubtrfs) {
        print_string(stderr, IDS_CANT_LOAD_DLL, UBTRFS_DLL);
        return 1;
    }

    if (node_size != 0 || sector_size != 0) {
        pSetSizes SetSizes;

        SetSizes = (pSetSizes)GetProcAddress(ubtrfs, "SetSizes");

        if (!SetSizes) {
            print_string(stderr, IDS_CANT_FIND_SETSIZES, UBTRFS_DLL);
            return 1;
        }

        SetSizes(node_size, sector_size);
    }

    // From Linux btrfs/disk-io.c: "Artificial requirement for block-group-tree to force
    // newer features (free-space-tree, no-holes) so the test matrix is smaller."
    if (compat_ro_flags & BTRFS_COMPAT_RO_FLAGS_BLOCK_GROUP_TREE) {
        compat_ro_flags |= BTRFS_COMPAT_RO_FLAGS_FREE_SPACE_CACHE;
        compat_ro_flags |= BTRFS_COMPAT_RO_FLAGS_FREE_SPACE_CACHE_VALID;
        incompat_flags |= BTRFS_INCOMPAT_FLAGS_NO_HOLES;
    }

    SetIncompatFlags = (pSetIncompatFlags)GetProcAddress(ubtrfs, "SetIncompatFlags");

    if (!SetIncompatFlags) {
        print_string(stderr, IDS_CANT_FIND_FUNCTION, "SetIncompatFlags", UBTRFS_DLL);
        return 1;
    }

    SetIncompatFlags(incompat_flags);

    if (compat_ro_flags != 0) {
        pSetCompatROFlags SetCompatROFlags = (pSetIncompatFlags)GetProcAddress(ubtrfs, "SetCompatROFlags");

        if (!SetCompatROFlags) {
            print_string(stderr, IDS_CANT_FIND_FUNCTION, "SetCompatROFlags", UBTRFS_DLL);
            return 1;
        }

        SetCompatROFlags(compat_ro_flags);
    }

    SetCsumType = (pSetCsumType)GetProcAddress(ubtrfs, "SetCsumType");

    if (!SetCsumType) {
        print_string(stderr, IDS_CANT_FIND_FUNCTION, "SetCsumType", UBTRFS_DLL);
        return 1;
    }

    SetCsumType(csum_type);

    FormatEx = (pFormatEx)GetProcAddress(ubtrfs, "FormatEx");

    if (!FormatEx) {
        print_string(stderr, IDS_CANT_FIND_FORMATEX, UBTRFS_DLL);
        return 1;
    }

    memset(&opts, 0, sizeof(options));

    if (label.Length > 0) {
        labelds.string = label.Buffer;
        opts.label = &labelds;
    }

    rootds.string = drive.Buffer;

    success = FormatEx(&rootds, NULL, &opts, 0);

    if (!success) {
        print_string(stderr, IDS_FORMATEX_ERROR);
        return 1;
    }

    print_string(stdout, IDS_SUCCESS);

    return 0;
}
