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
#include "scrub.h"
#include "resource.h"
#include "../btrfsioctl.h"
#include <shlobj.h>
#include <uxtheme.h>
#include <stdio.h>
#include <strsafe.h>
#include <winternl.h>

#define NO_SHLWAPI_STRFCNS
#include <shlwapi.h>
#include <uxtheme.h>

INT_PTR CALLBACK BtrfsScrub::ScrubDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {    
    return FALSE;
}

static INT_PTR CALLBACK stub_BalanceDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    BtrfsScrub* bs;
    
    if (uMsg == WM_INITDIALOG) {
        SetWindowLongPtr(hwndDlg, GWLP_USERDATA, (LONG_PTR)lParam);
        bs = (BtrfsScrub*)lParam;
    } else {
        bs = (BtrfsScrub*)GetWindowLongPtr(hwndDlg, GWLP_USERDATA);
    }
    
    if (bs)
        return bs->ScrubDlgProc(hwndDlg, uMsg, wParam, lParam);
    else
        return FALSE;
}

void BtrfsScrub::ShowScrub(HWND hwndDlg) {
    DialogBoxParamW(module, MAKEINTRESOURCEW(IDD_SCRUB), hwndDlg, stub_BalanceDlgProc, (LPARAM)this);
}
