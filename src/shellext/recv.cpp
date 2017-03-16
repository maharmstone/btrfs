/* Copyright (c) Mark Harmstone 2017
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

#include "shellext.h"
#include <windows.h>
#include <string>
#include "recv.h"
#include "resource.h"

static BOOL find_tlv(UINT8* data, ULONG datalen, UINT16 type, void** value, ULONG* len) {
    ULONG off = 0;

    while (off < datalen) {
        btrfs_send_tlv* tlv = (btrfs_send_tlv*)(data + off);
        UINT8* payload = data + off + sizeof(btrfs_send_tlv);

        // FIXME - make sure no overflow

        if (tlv->type == type) {
            *value = payload;
            *len = tlv->length;
            return TRUE;
        }

        off += sizeof(btrfs_send_tlv) + tlv->length;
    }
    
    return FALSE;
}

static BOOL utf8_to_utf16(HWND hwnd, char* utf8, ULONG utf8len, std::wstring* utf16) {
    NTSTATUS Status;
    ULONG utf16len;
    WCHAR* buf;
    
    Status = RtlUTF8ToUnicodeN(NULL, 0, &utf16len, utf8, utf8len);
    if (!NT_SUCCESS(Status)) {
        ShowStringError(hwnd, IDS_RECV_RTLUTF8TOUNICODEN_FAILED, Status);
        return FALSE;
    }
    
    buf = (WCHAR*)malloc(utf16len + sizeof(WCHAR));
    
    if (!buf) {
        ShowStringError(hwnd, IDS_OUT_OF_MEMORY);
        return FALSE;
    }

    Status = RtlUTF8ToUnicodeN(buf, utf16len, &utf16len, utf8, utf8len);
    if (!NT_SUCCESS(Status)) {
        ShowStringError(hwnd, IDS_RECV_RTLUTF8TOUNICODEN_FAILED, Status);
        free(buf);
        return FALSE;
    }
    
    buf[utf16len / sizeof(WCHAR)] = 0;
    
    *utf16 = buf;
    
    free(buf);
    
    return TRUE;
}

BOOL BtrfsRecv::cmd_subvol(HWND hwnd, btrfs_send_command* cmd, UINT8* data) {
    char* name;
    ULONG namelen;
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    std::wstring nameu;

    if (!find_tlv(data, cmd->length, BTRFS_SEND_TLV_PATH, (void**)&name, &namelen)) {
        ShowStringError(hwnd, IDS_RECV_MISSING_PARAM, funcname, L"path");
        return FALSE;
    }
    // FIXME - uuid
    // FIXME - transid

    if (!utf8_to_utf16(hwnd, name, namelen, &nameu))
        return FALSE;

    // FIXME - make sure case-sensitive and that Linux-only names allowed
    Status = NtFsControlFile(dir, NULL, NULL, NULL, &iosb, FSCTL_BTRFS_CREATE_SUBVOL, NULL, 0,
                             (PVOID)nameu.c_str(), nameu.length() * sizeof(WCHAR));
    if (!NT_SUCCESS(Status)) {
        ShowStringError(hwnd, IDS_RECV_CREATE_SUBVOL_FAILED, Status);
        return FALSE;
    }

    subvolpath = dirpath;
    subvolpath += L"\\";
    subvolpath += nameu;

    CloseHandle(dir);

    dir = CreateFileW(subvolpath.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                      NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (dir == INVALID_HANDLE_VALUE) {
        ShowStringError(hwnd, IDS_RECV_CANT_OPEN_PATH, subvolpath.c_str(), GetLastError());
        return FALSE;
    }

    subvolpath += L"\\";

    return TRUE;
}

void BtrfsRecv::Open(HWND hwnd, WCHAR* file, WCHAR* path) {
    HANDLE f;
    btrfs_send_header header;

    f = CreateFileW(file, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        ShowStringError(hwnd, IDS_RECV_CANT_OPEN_FILE, file, GetLastError());
        return;
    }
    
    if (!ReadFile(f, &header, sizeof(btrfs_send_header), NULL, NULL)) {
        ShowStringError(hwnd, IDS_RECV_READFILE_FAILED, GetLastError());
        CloseHandle(f);
        return;
    }
    
    // FIXME - check magic and version are acceptable

    dir = CreateFileW(path, FILE_ADD_SUBDIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                      NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (dir == INVALID_HANDLE_VALUE) {
        ShowStringError(hwnd, IDS_RECV_CANT_OPEN_PATH, path, GetLastError());
        CloseHandle(f);
        return;
    }

    dirpath = path;
    subvolpath = L"";
    
    while (TRUE) {
        BOOL b;
        btrfs_send_command cmd;
        UINT8* data;

        if (!ReadFile(f, &cmd, sizeof(btrfs_send_command), NULL, NULL)) {
            if (GetLastError() != ERROR_HANDLE_EOF) {
                ShowStringError(hwnd, IDS_RECV_READFILE_FAILED, GetLastError());
                break;
            }
            
            break;
        }

        if (cmd.cmd == BTRFS_SEND_CMD_END)
            break;

        // FIXME - check csum
        // FIXME - check length doesn't go beyond file

        if (cmd.length > 0) {
            data = (UINT8*)malloc(cmd.length);
            if (!data) {
                ShowStringError(hwnd, IDS_OUT_OF_MEMORY);
                break;
            }

            if (!ReadFile(f, data, cmd.length, NULL, NULL)) {
                ShowStringError(hwnd, IDS_RECV_READFILE_FAILED, GetLastError());
                break;
            }
        } else
            data = NULL;

        switch (cmd.cmd) {
            case BTRFS_SEND_CMD_SUBVOL:
                b = cmd_subvol(hwnd, &cmd, data);
            break;
            
            // FIXME - BTRFS_SEND_CMD_SNAPSHOT
            // FIXME - BTRFS_SEND_CMD_MKFILE
            // FIXME - BTRFS_SEND_CMD_MKDIR
            // FIXME - BTRFS_SEND_CMD_MKNOD
            // FIXME - BTRFS_SEND_CMD_MKFIFO
            // FIXME - BTRFS_SEND_CMD_MKSOCK
            // FIXME - BTRFS_SEND_CMD_SYMLINK
            // FIXME - BTRFS_SEND_CMD_RENAME
            // FIXME - BTRFS_SEND_CMD_LINK
            // FIXME - BTRFS_SEND_CMD_UNLINK
            // FIXME - BTRFS_SEND_CMD_RMDIR
            // FIXME - BTRFS_SEND_CMD_SET_XATTR
            // FIXME - BTRFS_SEND_CMD_REMOVE_XATTR
            // FIXME - BTRFS_SEND_CMD_WRITE
            // FIXME - BTRFS_SEND_CMD_CLONE
            // FIXME - BTRFS_SEND_CMD_TRUNCATE
            // FIXME - BTRFS_SEND_CMD_CHMOD
            // FIXME - BTRFS_SEND_CMD_CHOWN
            // FIXME - BTRFS_SEND_CMD_UTIMES
            // FIXME - BTRFS_SEND_CMD_UPDATE_EXTENT

            default:
                ShowStringError(hwnd, IDS_RECV_UNKNOWN_COMMAND, cmd.cmd);
                b = FALSE;
            break;
        }

        if (data) free(data);

        if (!b)
            break;
    }

    CloseHandle(dir);
    CloseHandle(f);
}
