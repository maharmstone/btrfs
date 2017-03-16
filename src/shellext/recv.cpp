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
#include <stddef.h>
#include <sys/stat.h>
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

BOOL BtrfsRecv::cmd_mkfile(HWND hwnd, btrfs_send_command* cmd, UINT8* data) {
    char *name, *pathlink;
    UINT64 *inode, *rdev = NULL, *mode = NULL;
    ULONG namelen, inodelen, bmnsize;
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    btrfs_mknod* bmn;
    std::wstring nameu, pathlinku;

    if (!find_tlv(data, cmd->length, BTRFS_SEND_TLV_PATH, (void**)&name, &namelen)) {
        ShowStringError(hwnd, IDS_RECV_MISSING_PARAM, funcname, L"path");
        return FALSE;
    }

    if (!find_tlv(data, cmd->length, BTRFS_SEND_TLV_INODE, (void**)&inode, &inodelen)) {
        ShowStringError(hwnd, IDS_RECV_MISSING_PARAM, funcname, L"inode");
        return FALSE;
    }
    
    if (inodelen < sizeof(UINT64)) {
        ShowStringError(hwnd, IDS_RECV_SHORT_PARAM, funcname, L"inode", inodelen, sizeof(UINT64));
        return FALSE;
    }

    if (cmd->cmd == BTRFS_SEND_CMD_MKNOD || cmd->cmd == BTRFS_SEND_CMD_MKFIFO || cmd->cmd == BTRFS_SEND_CMD_MKSOCK) {
        ULONG rdevlen, modelen;
        
        if (!find_tlv(data, cmd->length, BTRFS_SEND_TLV_RDEV, (void**)&rdev, &rdevlen)) {
            ShowStringError(hwnd, IDS_RECV_MISSING_PARAM, funcname, L"rdev");
            return FALSE;
        }
        
        if (rdevlen < sizeof(UINT64)) {
            ShowStringError(hwnd, IDS_RECV_SHORT_PARAM, funcname, L"rdev", rdev, sizeof(UINT64));
            return FALSE;
        }

        if (!find_tlv(data, cmd->length, BTRFS_SEND_TLV_MODE, (void**)&mode, &modelen)) {
            ShowStringError(hwnd, IDS_RECV_MISSING_PARAM, funcname, L"mode");
            return FALSE;
        }

        if (modelen < sizeof(UINT64)) {
            ShowStringError(hwnd, IDS_RECV_SHORT_PARAM, funcname, L"mode", modelen, sizeof(UINT64));
            return FALSE;
        }
    } else if (cmd->cmd == BTRFS_SEND_CMD_SYMLINK) {
        ULONG pathlinklen;
        
        if (!find_tlv(data, cmd->length, BTRFS_SEND_TLV_PATH_LINK, (void**)&pathlink, &pathlinklen)) {
            ShowStringError(hwnd, IDS_RECV_MISSING_PARAM, funcname, L"path_link");
            return FALSE;
        }

        if (!utf8_to_utf16(hwnd, pathlink, pathlinklen, &pathlinku))
            return FALSE;
    }

    if (!utf8_to_utf16(hwnd, name, namelen, &nameu))
        return FALSE;

    bmnsize = sizeof(btrfs_mknod) - sizeof(WCHAR) + (nameu.length() * sizeof(WCHAR));
    bmn = (btrfs_mknod*)malloc(bmnsize);

    bmn->inode = *inode;

    if (cmd->cmd == BTRFS_SEND_CMD_MKDIR)
        bmn->type = BTRFS_TYPE_DIRECTORY;
    else if (cmd->cmd == BTRFS_SEND_CMD_MKNOD)
        bmn->type = *mode & S_IFCHR ? BTRFS_TYPE_CHARDEV : BTRFS_TYPE_BLOCKDEV;
    else if (cmd->cmd == BTRFS_SEND_CMD_MKFIFO)
        bmn->type = BTRFS_TYPE_FIFO;
    else if (cmd->cmd == BTRFS_SEND_CMD_MKSOCK)
        bmn->type = BTRFS_TYPE_SOCKET;
    else
        bmn->type = BTRFS_TYPE_FILE;

    // FIXME - for mknod and mkfifo, do chmod afterwards

    bmn->st_rdev = rdev ? *rdev : 0;
    bmn->namelen = nameu.length() * sizeof(WCHAR);
    memcpy(bmn->name, nameu.c_str(), bmn->namelen);

    Status = NtFsControlFile(dir, NULL, NULL, NULL, &iosb, FSCTL_BTRFS_MKNOD, bmn, bmnsize, NULL, 0);
    if (!NT_SUCCESS(Status)) {
        ShowStringError(hwnd, IDS_RECV_MKNOD_FAILED, Status);
        free(bmn);
        return FALSE;
    }

    free(bmn);
    
    if (cmd->cmd == BTRFS_SEND_CMD_SYMLINK) {
        HANDLE h;
        REPARSE_DATA_BUFFER* rdb;
        ULONG rdblen;
        
        rdblen = offsetof(REPARSE_DATA_BUFFER, SymbolicLinkReparseBuffer.PathBuffer[0]) + (2 * pathlinku.length() * sizeof(WCHAR));
        
        rdb = (REPARSE_DATA_BUFFER*)malloc(rdblen);
        
        rdb->ReparseTag = IO_REPARSE_TAG_SYMLINK;
        rdb->ReparseDataLength = rdblen - offsetof(REPARSE_DATA_BUFFER, SymbolicLinkReparseBuffer);
        rdb->Reserved = 0;
        rdb->SymbolicLinkReparseBuffer.SubstituteNameOffset = 0;
        rdb->SymbolicLinkReparseBuffer.SubstituteNameLength = pathlinku.length() * sizeof(WCHAR);
        rdb->SymbolicLinkReparseBuffer.PrintNameOffset = pathlinku.length() * sizeof(WCHAR);
        rdb->SymbolicLinkReparseBuffer.PrintNameLength = pathlinku.length() * sizeof(WCHAR);
        rdb->SymbolicLinkReparseBuffer.Flags = SYMLINK_FLAG_RELATIVE;
        
        memcpy(rdb->SymbolicLinkReparseBuffer.PathBuffer, pathlinku.c_str(), rdb->SymbolicLinkReparseBuffer.SubstituteNameLength);
        memcpy(rdb->SymbolicLinkReparseBuffer.PathBuffer + (rdb->SymbolicLinkReparseBuffer.SubstituteNameLength / sizeof(WCHAR)),
                pathlinku.c_str(), rdb->SymbolicLinkReparseBuffer.PrintNameLength);

        h = CreateFileW((subvolpath + nameu).c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
        if (h == INVALID_HANDLE_VALUE) {
            ShowStringError(hwnd, IDS_RECV_CANT_OPEN_FILE, (subvolpath + nameu).c_str(), GetLastError());
            free(rdb);
            return FALSE;
        }
        
        Status = NtFsControlFile(h, NULL, NULL, NULL, &iosb, FSCTL_SET_REPARSE_POINT, rdb, rdblen, NULL, 0);
        if (!NT_SUCCESS(Status)) {
            ShowStringError(hwnd, IDS_RECV_SET_REPARSE_POINT_FAILED, Status);
            free(rdb);
            CloseHandle(h);
            return FALSE;
        }
        
        free(rdb);
        CloseHandle(h);
    }

    return TRUE;
}

BOOL BtrfsRecv::cmd_rename(HWND hwnd, btrfs_send_command* cmd, UINT8* data) {
    char *path, *path_to;
    ULONG path_len, path_to_len;
    std::wstring pathu, path_tou;

    if (!find_tlv(data, cmd->length, BTRFS_SEND_TLV_PATH, (void**)&path, &path_len)) {
        ShowStringError(hwnd, IDS_RECV_MISSING_PARAM, funcname, L"path");
        return FALSE;
    }
    
    if (!find_tlv(data, cmd->length, BTRFS_SEND_TLV_PATH_TO, (void**)&path_to, &path_to_len)) {
        ShowStringError(hwnd, IDS_RECV_MISSING_PARAM, funcname, L"path_to");
        return FALSE;
    }

    if (!utf8_to_utf16(hwnd, path, path_len, &pathu))
        return FALSE;

    if (!utf8_to_utf16(hwnd, path_to, path_to_len, &path_tou))
        return FALSE;

    if (!MoveFileW((subvolpath + pathu).c_str(), (subvolpath + path_tou).c_str())) {
        ShowStringError(hwnd, IDS_RECV_MOVEFILE_FAILED, pathu.c_str(), path_tou.c_str(), GetLastError());
        return FALSE;
    }

    return TRUE;
}

BOOL BtrfsRecv::cmd_link(HWND hwnd, btrfs_send_command* cmd, UINT8* data) {
    char *path, *path_link;
    ULONG path_len, path_link_len;
    std::wstring pathu, path_linku;
    
    if (!find_tlv(data, cmd->length, BTRFS_SEND_TLV_PATH, (void**)&path, &path_len)) {
        ShowStringError(hwnd, IDS_RECV_MISSING_PARAM, funcname, L"path");
        return FALSE;
    }
    
    if (!find_tlv(data, cmd->length, BTRFS_SEND_TLV_PATH_LINK, (void**)&path_link, &path_link_len)) {
        ShowStringError(hwnd, IDS_RECV_MISSING_PARAM, funcname, L"path_link");
        return FALSE;
    }
    
    if (!utf8_to_utf16(hwnd, path, path_len, &pathu))
        return FALSE;
    
    if (!utf8_to_utf16(hwnd, path_link, path_link_len, &path_linku))
        return FALSE;

    if (!CreateHardLinkW((subvolpath + pathu).c_str(), (subvolpath + path_linku).c_str(), NULL)) {
        ShowStringError(hwnd, IDS_RECV_CREATEHARDLINK_FAILED, pathu.c_str(), path_linku.c_str(), GetLastError());
        return FALSE;
    }
    
    return TRUE;
}

BOOL BtrfsRecv::cmd_setxattr(HWND hwnd, btrfs_send_command* cmd, UINT8* data) {
    // FIXME

    return TRUE;
}

BOOL BtrfsRecv::cmd_write(HWND hwnd, btrfs_send_command* cmd, UINT8* data) {
    char* path;
    UINT64* offset;
    UINT8* writedata;
    ULONG pathlen, offsetlen, datalen;
    std::wstring pathu;
    HANDLE h;
    LARGE_INTEGER offli;

    if (!find_tlv(data, cmd->length, BTRFS_SEND_TLV_PATH, (void**)&path, &pathlen)) {
        ShowStringError(hwnd, IDS_RECV_MISSING_PARAM, funcname, L"path");
        return FALSE;
    }

    if (!find_tlv(data, cmd->length, BTRFS_SEND_TLV_OFFSET, (void**)&offset, &offsetlen)) {
        ShowStringError(hwnd, IDS_RECV_MISSING_PARAM, funcname, L"offset");
        return FALSE;
    }

    if (offsetlen < sizeof(UINT64)) {
        ShowStringError(hwnd, IDS_RECV_SHORT_PARAM, funcname, L"offset", offsetlen, sizeof(UINT64));
        return FALSE;
    }

    if (!find_tlv(data, cmd->length, BTRFS_SEND_TLV_DATA, (void**)&writedata, &datalen)) {
        ShowStringError(hwnd, IDS_RECV_MISSING_PARAM, funcname, L"data");
        return FALSE;
    }

    if (!utf8_to_utf16(hwnd, path, pathlen, &pathu))
        return FALSE;

    h = CreateFileW((subvolpath + pathu).c_str(), FILE_WRITE_DATA, 0, NULL, OPEN_EXISTING,
                        FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        ShowStringError(hwnd, IDS_RECV_CANT_OPEN_FILE, pathu.c_str(), GetLastError());
        return FALSE;
    }

    offli.QuadPart = *offset;

    if (SetFilePointer(h, offli.LowPart, &offli.HighPart, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        ShowStringError(hwnd, IDS_RECV_SETFILEPOINTER_FAILED, GetLastError());
        CloseHandle(h);
        return FALSE;
    }

    if (!WriteFile(h, writedata, datalen, NULL, NULL)) {
        ShowStringError(hwnd, IDS_RECV_WRITEFILE_FAILED, GetLastError());
        CloseHandle(h);
        return FALSE;
    }

    CloseHandle(h);

    return TRUE;
}

BOOL BtrfsRecv::cmd_truncate(HWND hwnd, btrfs_send_command* cmd, UINT8* data) {
    // FIXME

    return TRUE;
}

BOOL BtrfsRecv::cmd_chmod(HWND hwnd, btrfs_send_command* cmd, UINT8* data) {
    // FIXME

    return TRUE;
}

BOOL BtrfsRecv::cmd_chown(HWND hwnd, btrfs_send_command* cmd, UINT8* data) {
    // FIXME

    return TRUE;
}

BOOL BtrfsRecv::cmd_utimes(HWND hwnd, btrfs_send_command* cmd, UINT8* data) {
    // FIXME

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

            case BTRFS_SEND_CMD_MKFILE:
            case BTRFS_SEND_CMD_MKDIR:
            case BTRFS_SEND_CMD_MKNOD:
            case BTRFS_SEND_CMD_MKFIFO:
            case BTRFS_SEND_CMD_MKSOCK:
            case BTRFS_SEND_CMD_SYMLINK:
                b = cmd_mkfile(hwnd, &cmd, data);
            break;

            case BTRFS_SEND_CMD_RENAME:
                b = cmd_rename(hwnd, &cmd, data);
            break;

            case BTRFS_SEND_CMD_LINK:
                b = cmd_link(hwnd, &cmd, data);
            break;

            // FIXME - BTRFS_SEND_CMD_UNLINK
            // FIXME - BTRFS_SEND_CMD_RMDIR

            case BTRFS_SEND_CMD_SET_XATTR:
                b = cmd_setxattr(hwnd, &cmd, data);
            break;

            // FIXME - BTRFS_SEND_CMD_REMOVE_XATTR

            case BTRFS_SEND_CMD_WRITE:
                b = cmd_write(hwnd, &cmd, data);
            break;

            // FIXME - BTRFS_SEND_CMD_CLONE

            case BTRFS_SEND_CMD_TRUNCATE:
                b = cmd_truncate(hwnd, &cmd, data);
            break;

            case BTRFS_SEND_CMD_CHMOD:
                b = cmd_chmod(hwnd, &cmd, data);
            break;

            case BTRFS_SEND_CMD_CHOWN:
                b = cmd_chown(hwnd, &cmd, data);
            break;

            case BTRFS_SEND_CMD_UTIMES:
                b = cmd_utimes(hwnd, &cmd, data);
            break;

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
