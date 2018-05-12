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

#include "../btrfs.h"
#include <string>
#include <vector>

class BtrfsSend {
public:
    BtrfsSend() {
        started = FALSE;
        file[0] = 0;
        dirh = INVALID_HANDLE_VALUE;
        stream = INVALID_HANDLE_VALUE;
        subvol = L"";
        buf = NULL;
        incremental = FALSE;
    }

    ~BtrfsSend() {
        if (buf)
            free(buf);
    }

    void Open(HWND hwnd, WCHAR* path);
    INT_PTR SendDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
    DWORD Thread();

private:
    void StartSend(HWND hwnd);
    void Browse(HWND hwnd);
    void BrowseParent(HWND hwnd);
    void AddClone(HWND hwnd);
    void RemoveClone(HWND hwnd);
    void ShowSendError(UINT msg, ...);

    BOOL started;
    BOOL incremental;
    WCHAR file[MAX_PATH], closetext[255];
    HANDLE thread, dirh, stream;
    HWND hwnd;
    std::wstring subvol;
    char* buf;
    std::vector <std::wstring> clones;
};
