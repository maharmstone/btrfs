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
#include "send.h"
#include "resource.h"

INT_PTR BtrfsSend::SendDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_COMMAND:
            switch (HIWORD(wParam)) {
                case BN_CLICKED:
                    switch (LOWORD(wParam)) {
                        case IDOK:
                        case IDCANCEL:
                            EndDialog(hwndDlg, 1);
                        return TRUE;
                    }
                break;
            }
        break;
    }

    return FALSE;
}

static INT_PTR CALLBACK stub_SendDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    BtrfsSend* bs;

    if (uMsg == WM_INITDIALOG) {
        SetWindowLongPtr(hwndDlg, GWLP_USERDATA, (LONG_PTR)lParam);
        bs = (BtrfsSend*)lParam;
    } else
        bs = (BtrfsSend*)GetWindowLongPtr(hwndDlg, GWLP_USERDATA);

    if (bs)
        return bs->SendDlgProc(hwndDlg, uMsg, wParam, lParam);
    else
        return FALSE;
}

void BtrfsSend::Open(HWND hwnd, LPWSTR path) {
    if (DialogBoxParamW(module, MAKEINTRESOURCEW(IDD_SEND_SUBVOL), hwnd, stub_SendDlgProc, (LPARAM)this) <= 0)
        ShowError(hwnd, GetLastError());
}

void CALLBACK SendSubvolW(HWND hwnd, HINSTANCE hinst, LPWSTR lpszCmdLine, int nCmdShow) {   
    BtrfsSend* bs;

    set_dpi_aware();

    bs = new BtrfsSend;

    bs->Open(hwnd, lpszCmdLine);

    delete bs;
}
