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

#pragma once

#include <shlobj.h>
#include <string>
#include <vector>
#include "../btrfs.h"

extern LONG objs_loaded;

typedef struct {
    BTRFS_UUID uuid;
    uint64_t transid;
    wstring path;
} subvol_cache;

class BtrfsRecv {
public:
    BtrfsRecv() {
        thread = nullptr;
        master = INVALID_HANDLE_VALUE;
        dir = INVALID_HANDLE_VALUE;
        running = FALSE;
        cancelling = FALSE;
        stransid = 0;
        num_received = 0;
        hwnd = nullptr;
        cache.clear();
    }

    virtual ~BtrfsRecv() {
        cache.clear();
    }

    void Open(HWND hwnd, WCHAR* file, WCHAR* path, BOOL quiet);
    DWORD recv_thread();
    INT_PTR CALLBACK RecvProgressDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

private:
    BOOL cmd_subvol(HWND hwnd, btrfs_send_command* cmd, uint8_t* data);
    BOOL cmd_snapshot(HWND hwnd, btrfs_send_command* cmd, uint8_t* data);
    BOOL cmd_mkfile(HWND hwnd, btrfs_send_command* cmd, uint8_t* data);
    BOOL cmd_rename(HWND hwnd, btrfs_send_command* cmd, uint8_t* data);
    BOOL cmd_link(HWND hwnd, btrfs_send_command* cmd, uint8_t* data);
    BOOL cmd_unlink(HWND hwnd, btrfs_send_command* cmd, uint8_t* data);
    BOOL cmd_rmdir(HWND hwnd, btrfs_send_command* cmd, uint8_t* data);
    BOOL cmd_setxattr(HWND hwnd, btrfs_send_command* cmd, uint8_t* data);
    BOOL cmd_removexattr(HWND hwnd, btrfs_send_command* cmd, uint8_t* data);
    BOOL cmd_write(HWND hwnd, btrfs_send_command* cmd, uint8_t* data);
    BOOL cmd_clone(HWND hwnd, btrfs_send_command* cmd, uint8_t* data);
    BOOL cmd_truncate(HWND hwnd, btrfs_send_command* cmd, uint8_t* data);
    BOOL cmd_chmod(HWND hwnd, btrfs_send_command* cmd, uint8_t* data);
    BOOL cmd_chown(HWND hwnd, btrfs_send_command* cmd, uint8_t* data);
    BOOL cmd_utimes(HWND hwnd, btrfs_send_command* cmd, uint8_t* data);
    void add_cache_entry(BTRFS_UUID* uuid, uint64_t transid, const wstring& path);
    BOOL utf8_to_utf16(HWND hwnd, char* utf8, ULONG utf8len, wstring& utf16);
    void ShowRecvError(int resid, ...);
    BOOL find_tlv(uint8_t* data, ULONG datalen, uint16_t type, void** value, ULONG* len);
    BOOL do_recv(HANDLE f, uint64_t* pos, uint64_t size);

    HANDLE dir, parent, master, thread, lastwritefile;
    HWND hwnd;
    wstring streamfile, dirpath, subvolpath, lastwritepath;
    DWORD lastwriteatt;
    ULONG num_received;
    uint64_t stransid;
    BTRFS_UUID subvol_uuid;
    BOOL running, cancelling;
    vector<subvol_cache> cache;
};
