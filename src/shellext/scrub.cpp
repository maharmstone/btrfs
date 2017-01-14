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
        
        if (first_time || status != bqs.status) {
            EnableWindow(GetDlgItem(hwndDlg, IDC_SCRUB_PROGRESS), bqs.status != BTRFS_SCRUB_STOPPED);
            
            if (bqs.status != BTRFS_SCRUB_STOPPED) {
                SendMessageW(GetDlgItem(hwndDlg, IDC_SCRUB_PROGRESS), PBM_SETRANGE32, 0, (LPARAM)bqs.total_chunks);
                SendMessageW(GetDlgItem(hwndDlg, IDC_SCRUB_PROGRESS), PBM_SETPOS, (WPARAM)(bqs.total_chunks - bqs.chunks_left), 0);
                
                if (bqs.status == BTRFS_SCRUB_PAUSED)
                    SendMessageW(GetDlgItem(hwndDlg, IDC_SCRUB_PROGRESS), PBM_SETSTATE, PBST_PAUSED, 0);
                else
                    SendMessageW(GetDlgItem(hwndDlg, IDC_SCRUB_PROGRESS), PBM_SETSTATE, PBST_NORMAL, 0);
            } else
                SendMessageW(GetDlgItem(hwndDlg, IDC_SCRUB_PROGRESS), PBM_SETPOS, 0, 0);
                        
            status = bqs.status;
            chunks_left = bqs.chunks_left;
        }
        
        // FIXME - textbox
    }
           
    if (bqs.status != BTRFS_SCRUB_STOPPED && chunks_left != bqs.chunks_left) {
        SendMessageW(GetDlgItem(hwndDlg, IDC_SCRUB_PROGRESS), PBM_SETPOS, (WPARAM)(bqs.total_chunks - bqs.chunks_left), 0);
        chunks_left = bqs.chunks_left;
    }
}

void BtrfsScrub::StartScrub(HWND hwndDlg) {
    HANDLE h;
    
    h = CreateFileW(fn, FILE_TRAVERSE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        NTSTATUS Status;
        IO_STATUS_BLOCK iosb;

        Status = NtFsControlFile(h, NULL, NULL, NULL, &iosb, FSCTL_BTRFS_START_SCRUB, NULL, 0, NULL, 0);
        
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
}

void BtrfsScrub::PauseScrub(HWND hwndDlg) {
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
        
        if (bqs.status == BTRFS_SCRUB_PAUSED)
            Status = NtFsControlFile(h, NULL, NULL, NULL, &iosb, FSCTL_BTRFS_RESUME_SCRUB, NULL, 0, NULL, 0);
        else
            Status = NtFsControlFile(h, NULL, NULL, NULL, &iosb, FSCTL_BTRFS_PAUSE_SCRUB, NULL, 0, NULL, 0);
        
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
}

void BtrfsScrub::StopScrub(HWND hwndDlg) {
    HANDLE h;
    
    h = CreateFileW(fn, FILE_TRAVERSE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        NTSTATUS Status;
        IO_STATUS_BLOCK iosb;

        Status = NtFsControlFile(h, NULL, NULL, NULL, &iosb, FSCTL_BTRFS_STOP_SCRUB, NULL, 0, NULL, 0);
        
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
}

INT_PTR CALLBACK BtrfsScrub::ScrubDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_INITDIALOG:
            RefreshScrubDlg(hwndDlg, TRUE);
            SetTimer(hwndDlg, 1, 1000, NULL);
        break;
        
        case WM_COMMAND:
            switch (HIWORD(wParam)) {
                case BN_CLICKED:
                    switch (LOWORD(wParam)) {
                        case IDOK:
                        case IDCANCEL:
                            EndDialog(hwndDlg, 0);
                        return TRUE;
                        
                        case IDC_START_SCRUB:
                            StartScrub(hwndDlg);
                        return TRUE;
                        
                        case IDC_PAUSE_SCRUB:
                            PauseScrub(hwndDlg);
                        return TRUE;
                        
                        case IDC_CANCEL_SCRUB:
                            StopScrub(hwndDlg);
                        return TRUE;
                    }
                break;
            }
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
