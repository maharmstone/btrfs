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

#define EA_NTACL "security.NTACL"
#define EA_DOSATTRIB "user.DOSATTRIB"
#define EA_REPARSE "system.reparse"
#define EA_EA "user.EA"
#define XATTR_USER "user."

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

BOOL BtrfsRecv::utf8_to_utf16(HWND hwnd, char* utf8, ULONG utf8len, std::wstring* utf16) {
    NTSTATUS Status;
    ULONG utf16len;
    WCHAR* buf;
    
    Status = RtlUTF8ToUnicodeN(NULL, 0, &utf16len, utf8, utf8len);
    if (!NT_SUCCESS(Status)) {
        ShowRecvError(IDS_RECV_RTLUTF8TOUNICODEN_FAILED, Status);
        return FALSE;
    }
    
    buf = (WCHAR*)malloc(utf16len + sizeof(WCHAR));
    
    if (!buf) {
        ShowRecvError(IDS_OUT_OF_MEMORY);
        return FALSE;
    }

    Status = RtlUTF8ToUnicodeN(buf, utf16len, &utf16len, utf8, utf8len);
    if (!NT_SUCCESS(Status)) {
        ShowRecvError(IDS_RECV_RTLUTF8TOUNICODEN_FAILED, Status);
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
        ShowRecvError(IDS_RECV_MISSING_PARAM, funcname, L"path");
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
        ShowRecvError(IDS_RECV_CREATE_SUBVOL_FAILED, Status);
        return FALSE;
    }

    subvolpath = dirpath;
    subvolpath += L"\\";
    subvolpath += nameu;

    CloseHandle(dir);

    dir = CreateFileW(subvolpath.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                      NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (dir == INVALID_HANDLE_VALUE) {
        ShowRecvError(IDS_RECV_CANT_OPEN_PATH, subvolpath.c_str(), GetLastError());
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
        ShowRecvError(IDS_RECV_MISSING_PARAM, funcname, L"path");
        return FALSE;
    }

    if (!find_tlv(data, cmd->length, BTRFS_SEND_TLV_INODE, (void**)&inode, &inodelen)) {
        ShowRecvError(IDS_RECV_MISSING_PARAM, funcname, L"inode");
        return FALSE;
    }
    
    if (inodelen < sizeof(UINT64)) {
        ShowRecvError(IDS_RECV_SHORT_PARAM, funcname, L"inode", inodelen, sizeof(UINT64));
        return FALSE;
    }

    if (cmd->cmd == BTRFS_SEND_CMD_MKNOD || cmd->cmd == BTRFS_SEND_CMD_MKFIFO || cmd->cmd == BTRFS_SEND_CMD_MKSOCK) {
        ULONG rdevlen, modelen;
        
        if (!find_tlv(data, cmd->length, BTRFS_SEND_TLV_RDEV, (void**)&rdev, &rdevlen)) {
            ShowRecvError(IDS_RECV_MISSING_PARAM, funcname, L"rdev");
            return FALSE;
        }
        
        if (rdevlen < sizeof(UINT64)) {
            ShowRecvError(IDS_RECV_SHORT_PARAM, funcname, L"rdev", rdev, sizeof(UINT64));
            return FALSE;
        }

        if (!find_tlv(data, cmd->length, BTRFS_SEND_TLV_MODE, (void**)&mode, &modelen)) {
            ShowRecvError(IDS_RECV_MISSING_PARAM, funcname, L"mode");
            return FALSE;
        }

        if (modelen < sizeof(UINT64)) {
            ShowRecvError(IDS_RECV_SHORT_PARAM, funcname, L"mode", modelen, sizeof(UINT64));
            return FALSE;
        }
    } else if (cmd->cmd == BTRFS_SEND_CMD_SYMLINK) {
        ULONG pathlinklen;
        
        if (!find_tlv(data, cmd->length, BTRFS_SEND_TLV_PATH_LINK, (void**)&pathlink, &pathlinklen)) {
            ShowRecvError(IDS_RECV_MISSING_PARAM, funcname, L"path_link");
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
        ShowRecvError(IDS_RECV_MKNOD_FAILED, Status);
        free(bmn);
        return FALSE;
    }

    free(bmn);
    
    if (cmd->cmd == BTRFS_SEND_CMD_SYMLINK) {
        HANDLE h;
        REPARSE_DATA_BUFFER* rdb;
        ULONG rdblen;
        btrfs_set_inode_info bsii;
        
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

        h = CreateFileW((subvolpath + nameu).c_str(), GENERIC_WRITE | WRITE_DAC, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
        if (h == INVALID_HANDLE_VALUE) {
            ShowRecvError(IDS_RECV_CANT_OPEN_FILE, (subvolpath + nameu).c_str(), GetLastError());
            free(rdb);
            return FALSE;
        }
        
        Status = NtFsControlFile(h, NULL, NULL, NULL, &iosb, FSCTL_SET_REPARSE_POINT, rdb, rdblen, NULL, 0);
        if (!NT_SUCCESS(Status)) {
            ShowRecvError(IDS_RECV_SET_REPARSE_POINT_FAILED, Status);
            free(rdb);
            CloseHandle(h);
            return FALSE;
        }

        memset(&bsii, 0, sizeof(btrfs_set_inode_info));

        bsii.mode_changed = TRUE;
        bsii.st_mode = 0777;

        Status = NtFsControlFile(h, NULL, NULL, NULL, &iosb, FSCTL_BTRFS_SET_INODE_INFO, NULL, 0,
                                 &bsii, sizeof(btrfs_set_inode_info));
        if (!NT_SUCCESS(Status)) {
            ShowRecvError(IDS_RECV_SETINODEINFO_FAILED, Status);
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
        ShowRecvError(IDS_RECV_MISSING_PARAM, funcname, L"path");
        return FALSE;
    }
    
    if (!find_tlv(data, cmd->length, BTRFS_SEND_TLV_PATH_TO, (void**)&path_to, &path_to_len)) {
        ShowRecvError(IDS_RECV_MISSING_PARAM, funcname, L"path_to");
        return FALSE;
    }

    if (!utf8_to_utf16(hwnd, path, path_len, &pathu))
        return FALSE;

    if (!utf8_to_utf16(hwnd, path_to, path_to_len, &path_tou))
        return FALSE;

    if (!MoveFileW((subvolpath + pathu).c_str(), (subvolpath + path_tou).c_str())) {
        ShowRecvError(IDS_RECV_MOVEFILE_FAILED, pathu.c_str(), path_tou.c_str(), GetLastError());
        return FALSE;
    }

    return TRUE;
}

BOOL BtrfsRecv::cmd_link(HWND hwnd, btrfs_send_command* cmd, UINT8* data) {
    char *path, *path_link;
    ULONG path_len, path_link_len;
    std::wstring pathu, path_linku;
    
    if (!find_tlv(data, cmd->length, BTRFS_SEND_TLV_PATH, (void**)&path, &path_len)) {
        ShowRecvError(IDS_RECV_MISSING_PARAM, funcname, L"path");
        return FALSE;
    }
    
    if (!find_tlv(data, cmd->length, BTRFS_SEND_TLV_PATH_LINK, (void**)&path_link, &path_link_len)) {
        ShowRecvError(IDS_RECV_MISSING_PARAM, funcname, L"path_link");
        return FALSE;
    }
    
    if (!utf8_to_utf16(hwnd, path, path_len, &pathu))
        return FALSE;
    
    if (!utf8_to_utf16(hwnd, path_link, path_link_len, &path_linku))
        return FALSE;

    if (!CreateHardLinkW((subvolpath + pathu).c_str(), (subvolpath + path_linku).c_str(), NULL)) {
        ShowRecvError(IDS_RECV_CREATEHARDLINK_FAILED, pathu.c_str(), path_linku.c_str(), GetLastError());
        return FALSE;
    }
    
    return TRUE;
}

BOOL BtrfsRecv::cmd_setxattr(HWND hwnd, btrfs_send_command* cmd, UINT8* data) {
    char *path, *xattrname;
    UINT8* xattrdata;
    ULONG pathlen, xattrnamelen, xattrdatalen;
    std::wstring pathu;

    if (!find_tlv(data, cmd->length, BTRFS_SEND_TLV_PATH, (void**)&path, &pathlen)) {
        ShowRecvError(IDS_RECV_MISSING_PARAM, funcname, L"path");
        return FALSE;
    }

    if (!find_tlv(data, cmd->length, BTRFS_SEND_TLV_XATTR_NAME, (void**)&xattrname, &xattrnamelen)) {
        ShowRecvError(IDS_RECV_MISSING_PARAM, funcname, L"xattr_name");
        return FALSE;
    }

    if (!find_tlv(data, cmd->length, BTRFS_SEND_TLV_XATTR_DATA, (void**)&xattrdata, &xattrdatalen)) {
        ShowRecvError(IDS_RECV_MISSING_PARAM, funcname, L"xattr_data");
        return FALSE;
    }

    if (!utf8_to_utf16(hwnd, path, pathlen, &pathu))
        return FALSE;

    if (xattrnamelen == strlen(EA_NTACL) && !memcmp(xattrname, EA_NTACL, xattrnamelen)) {
        // FIXME - security.NTACL
    } else if (xattrnamelen == strlen(EA_DOSATTRIB) && !memcmp(xattrname, EA_DOSATTRIB, xattrnamelen)) {
        if (xattrdatalen > 2 && xattrdata[0] == '0' && xattrdata[1] == 'x') {
            DWORD attrib = 0;
            ULONG xp = 2;
            BOOL valid = TRUE;
            
            while (xp < xattrdatalen) {
                attrib <<= 4;
                
                if (xattrdata[xp] >= '0' && xattrdata[xp] <= '9')
                    attrib += xattrdata[xp] - '0';
                else if (xattrdata[xp] >= 'a' && xattrdata[xp] <= 'f')
                    attrib += xattrdata[xp] - 'a' + 0xa;
                else if (xattrdata[xp] >= 'A' && xattrdata[xp] <= 'F')
                    attrib += xattrdata[xp] - 'A' + 0xa;
                else {
                    valid = FALSE;
                    break;
                }
                
                xp++;
            }
            
            if (valid) {
                if (pathu == L"")
                    attrib &= ~FILE_ATTRIBUTE_READONLY;
                
                if (!SetFileAttributesW((subvolpath + pathu).c_str(), attrib)) {
                    ShowRecvError(IDS_RECV_SETFILEATTRIBUTES_FAILED, GetLastError());
                    return FALSE;
                }
            }
        }
    } else if (xattrnamelen == strlen(EA_REPARSE) && !memcmp(xattrname, EA_REPARSE, xattrnamelen)) {
        // FIXME - system.reparse
    } else if (xattrnamelen == strlen(EA_EA) && !memcmp(xattrname, EA_EA, xattrnamelen)) {
        // FIXME - user.EA
    } else if (xattrnamelen > strlen(XATTR_USER) && !memcmp(xattrname, XATTR_USER, strlen(XATTR_USER))) {
        HANDLE h;
        std::wstring streamname;

        if (!utf8_to_utf16(hwnd, xattrname, xattrnamelen, &streamname))
            return FALSE;

        streamname = streamname.substr(5);

        h = CreateFileW((subvolpath + pathu + L":" + streamname).c_str(), GENERIC_WRITE, 0,
                        NULL, CREATE_ALWAYS, 0, NULL);
        if (h == INVALID_HANDLE_VALUE) {
            ShowRecvError(IDS_RECV_CANT_CREATE_FILE, (pathu + L":" + streamname).c_str(), GetLastError());
            return FALSE;
        }

        if (xattrdatalen > 0) {
            if (!WriteFile(h, xattrdata, xattrdatalen, NULL, NULL)) {
                ShowRecvError(IDS_RECV_WRITEFILE_FAILED, GetLastError());
                CloseHandle(h);
                return FALSE;
            }
        }

        CloseHandle(h);
    } else {
        // FIXME - hidden xattrs
    }

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
        ShowRecvError(IDS_RECV_MISSING_PARAM, funcname, L"path");
        return FALSE;
    }

    if (!find_tlv(data, cmd->length, BTRFS_SEND_TLV_OFFSET, (void**)&offset, &offsetlen)) {
        ShowRecvError(IDS_RECV_MISSING_PARAM, funcname, L"offset");
        return FALSE;
    }

    if (offsetlen < sizeof(UINT64)) {
        ShowRecvError(IDS_RECV_SHORT_PARAM, funcname, L"offset", offsetlen, sizeof(UINT64));
        return FALSE;
    }

    if (!find_tlv(data, cmd->length, BTRFS_SEND_TLV_DATA, (void**)&writedata, &datalen)) {
        ShowRecvError(IDS_RECV_MISSING_PARAM, funcname, L"data");
        return FALSE;
    }

    if (!utf8_to_utf16(hwnd, path, pathlen, &pathu))
        return FALSE;
    
    if (lastwritepath != pathu) {
        FILE_BASIC_INFO fbi;
        
        if (lastwriteatt & FILE_ATTRIBUTE_READONLY) {
            if (!SetFileAttributesW((subvolpath + lastwritepath).c_str(), lastwriteatt)) {
                ShowRecvError(IDS_RECV_SETFILEATTRIBUTES_FAILED, GetLastError());
                return FALSE;
            }
        }
        
        CloseHandle(lastwritefile);
        
        lastwriteatt = GetFileAttributesW((subvolpath + pathu).c_str());
        if (lastwriteatt == INVALID_FILE_ATTRIBUTES) {
            ShowRecvError(IDS_RECV_GETFILEATTRIBUTES_FAILED, GetLastError());
            return FALSE;
        }
        
        if (lastwriteatt & FILE_ATTRIBUTE_READONLY) {
            if (!SetFileAttributesW((subvolpath + pathu).c_str(), lastwriteatt & ~FILE_ATTRIBUTE_READONLY)) {
                ShowRecvError(IDS_RECV_SETFILEATTRIBUTES_FAILED, GetLastError());
                return FALSE;
            }
        }

        h = CreateFileW((subvolpath + pathu).c_str(), FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES, 0, NULL, OPEN_EXISTING,
                            FILE_FLAG_BACKUP_SEMANTICS, NULL);
        if (h == INVALID_HANDLE_VALUE) {
            ShowRecvError(IDS_RECV_CANT_OPEN_FILE, pathu.c_str(), GetLastError());
            return FALSE;
        }
        
        lastwritepath = pathu;
        lastwritefile = h;
        
        memset(&fbi, 0, sizeof(FILE_BASIC_INFO));
        
        fbi.LastWriteTime.QuadPart = -1;

        if (!SetFileInformationByHandle(h, FileBasicInfo, &fbi, sizeof(FILE_BASIC_INFO))) {
            ShowRecvError(IDS_RECV_SETFILEINFO_FAILED, GetLastError());
            return FALSE;
        }
    } else
        h = lastwritefile;

    offli.QuadPart = *offset;

    if (SetFilePointer(h, offli.LowPart, &offli.HighPart, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        ShowRecvError(IDS_RECV_SETFILEPOINTER_FAILED, GetLastError());
        return FALSE;
    }

    if (!WriteFile(h, writedata, datalen, NULL, NULL)) {
        ShowRecvError(IDS_RECV_WRITEFILE_FAILED, GetLastError());
        return FALSE;
    }

    return TRUE;
}

BOOL BtrfsRecv::cmd_truncate(HWND hwnd, btrfs_send_command* cmd, UINT8* data) {
    char* path;
    UINT64* size;
    ULONG pathlen, sizelen;
    std::wstring pathu;
    HANDLE h;
    LARGE_INTEGER sizeli;
    DWORD att;

    if (!find_tlv(data, cmd->length, BTRFS_SEND_TLV_PATH, (void**)&path, &pathlen)) {
        ShowRecvError(IDS_RECV_MISSING_PARAM, funcname, L"path");
        return FALSE;
    }

    if (!find_tlv(data, cmd->length, BTRFS_SEND_TLV_SIZE, (void**)&size, &sizelen)) {
        ShowRecvError(IDS_RECV_MISSING_PARAM, funcname, L"size");
        return FALSE;
    }

    if (sizelen < sizeof(UINT64)) {
        ShowRecvError(IDS_RECV_SHORT_PARAM, funcname, L"size", sizelen, sizeof(UINT64));
        return FALSE;
    }

    if (!utf8_to_utf16(hwnd, path, pathlen, &pathu))
        return FALSE;
    
    att = GetFileAttributesW((subvolpath + pathu).c_str());
    if (att == INVALID_FILE_ATTRIBUTES) {
        ShowRecvError(IDS_RECV_GETFILEATTRIBUTES_FAILED, GetLastError());
        return FALSE;
    }
    
    if (att & FILE_ATTRIBUTE_READONLY) {
        if (!SetFileAttributesW((subvolpath + pathu).c_str(), att & ~FILE_ATTRIBUTE_READONLY)) {
            ShowRecvError(IDS_RECV_SETFILEATTRIBUTES_FAILED, GetLastError());
            return FALSE;
        }
    }

    h = CreateFileW((subvolpath + pathu).c_str(), FILE_WRITE_DATA, 0, NULL, OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        ShowRecvError(IDS_RECV_CANT_OPEN_FILE, pathu.c_str(), GetLastError());
        return FALSE;
    }

    sizeli.QuadPart = *size;

    if (SetFilePointer(h, sizeli.LowPart, &sizeli.HighPart, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        ShowRecvError(IDS_RECV_SETFILEPOINTER_FAILED, GetLastError());
        CloseHandle(h);
        return FALSE;
    }

    if (!SetEndOfFile(h)) {
        ShowRecvError(IDS_RECV_SETENDOFFILE_FAILED, GetLastError());
        CloseHandle(h);
        return FALSE;
    }

    CloseHandle(h);

    if (att & FILE_ATTRIBUTE_READONLY) {
        if (!SetFileAttributesW((subvolpath + pathu).c_str(), att)) {
            ShowRecvError(IDS_RECV_SETFILEATTRIBUTES_FAILED, GetLastError());
            return FALSE;
        }
    }

    return TRUE;
}

BOOL BtrfsRecv::cmd_chmod(HWND hwnd, btrfs_send_command* cmd, UINT8* data) {
    HANDLE h;
    char* path;
    UINT32* mode;
    ULONG pathlen, modelen;
    std::wstring pathu;
    btrfs_set_inode_info bsii;
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    
    if (!find_tlv(data, cmd->length, BTRFS_SEND_TLV_PATH, (void**)&path, &pathlen)) {
        ShowRecvError(IDS_RECV_MISSING_PARAM, funcname, L"path");
        return FALSE;
    }
    
    if (!find_tlv(data, cmd->length, BTRFS_SEND_TLV_MODE, (void**)&mode, &modelen)) {
        ShowRecvError(IDS_RECV_MISSING_PARAM, funcname, L"mode");
        return FALSE;
    }
    
    if (modelen < sizeof(UINT32)) {
        ShowRecvError(IDS_RECV_SHORT_PARAM, funcname, L"mode", modelen, sizeof(UINT32));
        return FALSE;
    }
    
    if (!utf8_to_utf16(hwnd, path, pathlen, &pathu))
        return FALSE;
    
    h = CreateFileW((subvolpath + pathu).c_str(), WRITE_DAC, 0, NULL, OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_OPEN_REPARSE_POINT, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        ShowRecvError(IDS_RECV_CANT_OPEN_FILE, pathu.c_str(), GetLastError());
        return FALSE;
    }
    
    memset(&bsii, 0, sizeof(btrfs_set_inode_info));
    
    bsii.mode_changed = TRUE;
    bsii.st_mode = *mode;
    
    Status = NtFsControlFile(h, NULL, NULL, NULL, &iosb, FSCTL_BTRFS_SET_INODE_INFO, NULL, 0,
                             &bsii, sizeof(btrfs_set_inode_info));
    if (!NT_SUCCESS(Status)) {
        ShowRecvError(IDS_RECV_SETINODEINFO_FAILED, Status);
        CloseHandle(h);
        return FALSE;
    }

    CloseHandle(h);

    return TRUE;
}

BOOL BtrfsRecv::cmd_chown(HWND hwnd, btrfs_send_command* cmd, UINT8* data) {
    // FIXME

    return TRUE;
}

static __inline UINT64 unix_time_to_win(BTRFS_TIME* t) {
    return (t->seconds * 10000000) + (t->nanoseconds / 100) + 116444736000000000;
}

BOOL BtrfsRecv::cmd_utimes(HWND hwnd, btrfs_send_command* cmd, UINT8* data) {
    char* path;
    ULONG pathlen;
    std::wstring pathu;
    HANDLE h;
    FILE_BASIC_INFO fbi;
    BTRFS_TIME* time;
    ULONG timelen;
    
    if (!find_tlv(data, cmd->length, BTRFS_SEND_TLV_PATH, (void**)&path, &pathlen)) {
        ShowRecvError(IDS_RECV_MISSING_PARAM, funcname, L"path");
        return FALSE;
    }
    
    if (!utf8_to_utf16(hwnd, path, pathlen, &pathu))
        return FALSE;
    
    h = CreateFileW((subvolpath + pathu).c_str(), FILE_WRITE_ATTRIBUTES, 0, NULL, OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_OPEN_REPARSE_POINT, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        ShowRecvError(IDS_RECV_CANT_OPEN_FILE, pathu.c_str(), GetLastError());
        return FALSE;
    }
    
    memset(&fbi, 0, sizeof(FILE_BASIC_INFO));

    if (find_tlv(data, cmd->length, BTRFS_SEND_TLV_OTIME, (void**)&time, &timelen) && timelen >= sizeof(BTRFS_TIME))
        fbi.CreationTime.QuadPart = unix_time_to_win(time);
    
    if (find_tlv(data, cmd->length, BTRFS_SEND_TLV_ATIME, (void**)&time, &timelen) && timelen >= sizeof(BTRFS_TIME))
        fbi.LastAccessTime.QuadPart = unix_time_to_win(time);
    
    if (find_tlv(data, cmd->length, BTRFS_SEND_TLV_MTIME, (void**)&time, &timelen) && timelen >= sizeof(BTRFS_TIME))
        fbi.LastWriteTime.QuadPart = unix_time_to_win(time);

    if (find_tlv(data, cmd->length, BTRFS_SEND_TLV_CTIME, (void**)&time, &timelen) && timelen >= sizeof(BTRFS_TIME))
        fbi.ChangeTime.QuadPart = unix_time_to_win(time);

    if (!SetFileInformationByHandle(h, FileBasicInfo, &fbi, sizeof(FILE_BASIC_INFO))) {
        ShowRecvError(IDS_RECV_SETFILEINFO_FAILED, GetLastError());
        CloseHandle(h);
        return FALSE;
    }
    
    CloseHandle(h);

    return TRUE;
}

void BtrfsRecv::ShowRecvError(int resid, ...) {
    WCHAR s[1024], t[1024];
    va_list ap;
    
    if (!LoadStringW(module, resid, s, sizeof(s) / sizeof(WCHAR))) {
        ShowError(hwnd, GetLastError());
        return;
    }
    
    va_start(ap, resid);
    vswprintf(t, sizeof(t) / sizeof(WCHAR), s, ap);
    
    SetDlgItemTextW(hwnd, IDC_RECV_MSG, t);
    
    va_end(ap);
    
    SendMessageW(GetDlgItem(hwnd, IDC_RECV_PROGRESS), PBM_SETSTATE, PBST_ERROR, 0);
}

static void delete_directory(std::wstring dir) {
    HANDLE h;
    WIN32_FIND_DATAW fff;

    h = FindFirstFileW((dir + L"*").c_str(), &fff);

    if (h == INVALID_HANDLE_VALUE)
        return;

    do {
        std::wstring file;
        
        file = fff.cFileName;
        
        if (file != L"." && file != L"..") {
            if (fff.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                delete_directory(dir + file + L"\\");
            else
                DeleteFileW((dir + file).c_str());
        }
    } while (FindNextFileW(h, &fff));

    FindClose(h);

    RemoveDirectoryW(dir.c_str());
}

DWORD BtrfsRecv::recv_thread() {
    HANDLE f;
    btrfs_send_header header;
    BOOL b = TRUE;
    LARGE_INTEGER size;
    UINT64 pos = 0;

    f = CreateFileW(streamfile.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        ShowRecvError(IDS_RECV_CANT_OPEN_FILE, streamfile.c_str(), GetLastError());
        goto end;
    }
    
    size.LowPart = GetFileSize(f, (LPDWORD)&size.HighPart);
    
    if (!ReadFile(f, &header, sizeof(btrfs_send_header), NULL, NULL)) {
        ShowRecvError(IDS_RECV_READFILE_FAILED, GetLastError());
        CloseHandle(f);
        goto end;
    }
    
    pos = sizeof(btrfs_send_header);

    // FIXME - check magic and version are acceptable

    dir = CreateFileW(dirpath.c_str(), FILE_ADD_SUBDIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                      NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (dir == INVALID_HANDLE_VALUE) {
        ShowRecvError(IDS_RECV_CANT_OPEN_PATH, dirpath.c_str(), GetLastError());
        CloseHandle(f);
        goto end;
    }
    
    SendMessageW(GetDlgItem(hwnd, IDC_RECV_PROGRESS), PBM_SETRANGE32, 0, (LPARAM)65536);
    
    lastwritefile = INVALID_HANDLE_VALUE;
    lastwritepath = L"";
    lastwriteatt = 0;
    
    while (TRUE) {
        btrfs_send_command cmd;
        UINT8* data;
        ULONG progress;

        progress = (ULONG)((float)pos * 65536.0f / (float)size.QuadPart);
        SendMessageW(GetDlgItem(hwnd, IDC_RECV_PROGRESS), PBM_SETPOS, progress, 0);

        if (!ReadFile(f, &cmd, sizeof(btrfs_send_command), NULL, NULL)) {
            if (GetLastError() != ERROR_HANDLE_EOF) {
                ShowRecvError(IDS_RECV_READFILE_FAILED, GetLastError());
                break;
            }
            
            break;
        }
        
        pos += sizeof(btrfs_send_command);

        if (cmd.cmd == BTRFS_SEND_CMD_END)
            break;

        // FIXME - check csum
        // FIXME - check length doesn't go beyond file

        if (cmd.length > 0) {
            data = (UINT8*)malloc(cmd.length);
            if (!data) {
                ShowRecvError(IDS_OUT_OF_MEMORY);
                break;
            }

            if (!ReadFile(f, data, cmd.length, NULL, NULL)) {
                ShowRecvError(IDS_RECV_READFILE_FAILED, GetLastError());
                break;
            }
            
            pos += cmd.length;
        } else
            data = NULL;
        
        if (lastwritefile != INVALID_HANDLE_VALUE && cmd.cmd != BTRFS_SEND_CMD_WRITE) {
            if (lastwriteatt & FILE_ATTRIBUTE_READONLY) {
                if (!SetFileAttributesW((subvolpath + lastwritepath).c_str(), lastwriteatt)) {
                    ShowRecvError(IDS_RECV_SETFILEATTRIBUTES_FAILED, GetLastError());
                    return FALSE;
                }
            }

            CloseHandle(lastwritefile);

            lastwritefile = INVALID_HANDLE_VALUE;
            lastwritepath = L"";
            lastwriteatt = 0;
        }

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
                ShowRecvError(IDS_RECV_UNKNOWN_COMMAND, cmd.cmd);
                b = FALSE;
            break;
        }

        if (data) free(data);

        if (!b)
            break;
    }
    
    if (lastwritefile != INVALID_HANDLE_VALUE) {
        if (lastwriteatt & FILE_ATTRIBUTE_READONLY) {
            if (!SetFileAttributesW((subvolpath + lastwritepath).c_str(), lastwriteatt)) {
                ShowRecvError(IDS_RECV_SETFILEATTRIBUTES_FAILED, GetLastError());
                return FALSE;
            }
        }

        CloseHandle(lastwritefile);
    }
    
    if (b) {
        WCHAR s[255];
        
        SendMessageW(GetDlgItem(hwnd, IDC_RECV_PROGRESS), PBM_SETPOS, 65536, 0);
        
        if (!LoadStringW(module, IDS_RECV_SUCCESS, s, sizeof(s) / sizeof(WCHAR)))
            ShowError(hwnd, GetLastError());
        else
            SetDlgItemTextW(hwnd, IDC_RECV_MSG, s);
        
        if (!LoadStringW(module, IDS_RECV_BUTTON_OK, s, sizeof(s) / sizeof(WCHAR)))
            ShowError(hwnd, GetLastError());
        else
            SetDlgItemTextW(hwnd, IDCANCEL, s);
    }

    CloseHandle(dir);
    CloseHandle(f);
    
    if (!b && subvolpath != L"")
        delete_directory(subvolpath);

end:
    thread = NULL;

    return 0;
}

static DWORD WINAPI global_recv_thread(LPVOID lpParameter) {
    BtrfsRecv* br = (BtrfsRecv*)lpParameter;

    return br->recv_thread();
}

INT_PTR CALLBACK BtrfsRecv::RecvProgressDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_INITDIALOG:
            this->hwnd = hwndDlg;
            thread = CreateThread(NULL, 0, global_recv_thread, this, 0, NULL);

            if (!thread) {
                ShowError(hwndDlg, GetLastError()); // FIXME - set error message on dialog box
            }
        break;

        case WM_COMMAND:
            switch (HIWORD(wParam)) {
                case BN_CLICKED:
                    switch (LOWORD(wParam)) {
                        case IDOK:
                        case IDCANCEL:
                            // FIXME - cancel if still running
                            EndDialog(hwndDlg, 1);
                            return TRUE;
                    }
                break;
            }
        break;
    }

    return FALSE;
}

static INT_PTR CALLBACK stub_RecvProgressDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    BtrfsRecv* br;

    if (uMsg == WM_INITDIALOG) {
        SetWindowLongPtr(hwndDlg, GWLP_USERDATA, (LONG_PTR)lParam);
        br = (BtrfsRecv*)lParam;
    } else {
        br = (BtrfsRecv*)GetWindowLongPtr(hwndDlg, GWLP_USERDATA);
    }

    if (br)
        return br->RecvProgressDlgProc(hwndDlg, uMsg, wParam, lParam);
    else
        return FALSE;
}

void BtrfsRecv::Open(HWND hwnd, WCHAR* file, WCHAR* path) {
    streamfile = file;
    dirpath = path;
    subvolpath = L"";

    if (DialogBoxParamW(module, MAKEINTRESOURCEW(IDD_RECV_PROGRESS), hwnd, stub_RecvProgressDlgProc, (LPARAM)this) <= 0)
        ShowError(hwnd, GetLastError());
}
