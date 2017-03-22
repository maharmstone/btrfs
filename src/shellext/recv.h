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

#include <shlobj.h>
#include "../btrfs.h"

extern LONG objs_loaded;

class BtrfsRecv {
public:
    BtrfsRecv() {
        thread = NULL;
        master = INVALID_HANDLE_VALUE;
        dir = INVALID_HANDLE_VALUE;
        running = FALSE;
        cancelling = FALSE;
        stransid = 0;
    }

    virtual ~BtrfsRecv() {
    }
    
    void Open(HWND hwnd, WCHAR* file, WCHAR* path);
    DWORD recv_thread();
    INT_PTR CALLBACK RecvProgressDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
    
private:
    BOOL cmd_subvol(HWND hwnd, btrfs_send_command* cmd, UINT8* data);
    BOOL cmd_snapshot(HWND hwnd, btrfs_send_command* cmd, UINT8* data);
    BOOL cmd_mkfile(HWND hwnd, btrfs_send_command* cmd, UINT8* data);
    BOOL cmd_rename(HWND hwnd, btrfs_send_command* cmd, UINT8* data);
    BOOL cmd_link(HWND hwnd, btrfs_send_command* cmd, UINT8* data);
    BOOL cmd_unlink(HWND hwnd, btrfs_send_command* cmd, UINT8* data);
    BOOL cmd_rmdir(HWND hwnd, btrfs_send_command* cmd, UINT8* data);
    BOOL cmd_setxattr(HWND hwnd, btrfs_send_command* cmd, UINT8* data);
    BOOL cmd_write(HWND hwnd, btrfs_send_command* cmd, UINT8* data);
    BOOL cmd_truncate(HWND hwnd, btrfs_send_command* cmd, UINT8* data);
    BOOL cmd_chmod(HWND hwnd, btrfs_send_command* cmd, UINT8* data);
    BOOL cmd_chown(HWND hwnd, btrfs_send_command* cmd, UINT8* data);
    BOOL cmd_utimes(HWND hwnd, btrfs_send_command* cmd, UINT8* data);
    BOOL utf8_to_utf16(HWND hwnd, char* utf8, ULONG utf8len, std::wstring* utf16);
    void ShowRecvError(int resid, ...);
    BOOL find_tlv(UINT8* data, ULONG datalen, UINT16 type, void** value, ULONG* len);

    HANDLE dir, parent, master, thread, lastwritefile;
    HWND hwnd;
    std::wstring streamfile, dirpath, subvolpath, lastwritepath;
    DWORD lastwriteatt;
    UINT64 stransid;
    BTRFS_UUID subvol_uuid;
    BOOL running, cancelling;
};
