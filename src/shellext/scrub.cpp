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

void BtrfsScrub::RefreshScrubDlg(HWND hwndDlg, BOOL first_time) {
    HANDLE h;
    btrfs_query_scrub bqs;
    
    h = CreateFileW(fn, FILE_TRAVERSE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        NTSTATUS Status;
        IO_STATUS_BLOCK iosb;

        Status = NtFsControlFile(h, NULL, NULL, NULL, &iosb, FSCTL_BTRFS_QUERY_SCRUB, NULL, 0, &bqs, sizeof(btrfs_query_scrub));
        
        if (Status != STATUS_SUCCESS) {
            ShowNtStatusError(hwndDlg, Status);
            CloseHandle(h);
            return;
        }
        
        CloseHandle(h);
    } else {
        ShowError(hwndDlg, GetLastError());
        return;
    }
    
    if (first_time || status != bqs.status) {
        WCHAR s[255];
        int message;
        
        if (bqs.status == BTRFS_SCRUB_STOPPED) {
            EnableWindow(GetDlgItem(hwndDlg, IDC_START_SCRUB), TRUE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_PAUSE_SCRUB), FALSE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_CANCEL_SCRUB), FALSE);
            
            message = bqs.total_chunks == 0 ? IDS_NO_SCRUB : IDS_SCRUB_FINISHED;
        } else {
            EnableWindow(GetDlgItem(hwndDlg, IDC_START_SCRUB), FALSE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_PAUSE_SCRUB), TRUE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_CANCEL_SCRUB), TRUE);
            
            message = bqs.status == BTRFS_SCRUB_PAUSED ? IDS_SCRUB_PAUSED : IDS_SCRUB_RUNNING;
        }
        
        if (!LoadStringW(module, message, s, sizeof(s) / sizeof(WCHAR))) {
            ShowError(hwndDlg, GetLastError());
            return;
        }
        
        SetDlgItemTextW(hwndDlg, IDC_SCRUB_STATUS, s);
        
        // FIXME - progress bar
        // FIXME - textbox
        
        status = bqs.status;
    }
}

INT_PTR CALLBACK BtrfsScrub::ScrubDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_INITDIALOG:
            RefreshScrubDlg(hwndDlg, TRUE);
            SetTimer(hwndDlg, 1, 1000, NULL);
        break;
        
        case WM_TIMER:
            RefreshScrubDlg(hwndDlg, FALSE);
        break;
    }
    
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
