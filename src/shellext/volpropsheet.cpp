/* Copyright (c) Mark Harmstone 2016
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

#define ISOLATION_AWARE_ENABLED 1
#define STRSAFE_NO_DEPRECATE

#define NTDDI_VERSION 0x06010000
#define _WIN32_WINNT 0x0601
#define WINVER 0x0601

#include <windows.h>
#include <strsafe.h>
#include <winternl.h>

#define NO_SHLWAPI_STRFCNS
#include <shlwapi.h>
#include <uxtheme.h>

#include "volpropsheet.h"
#include "resource.h"

#ifdef __cplusplus
extern "C" {
#endif
NTSYSCALLAPI NTSTATUS NTAPI NtFsControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG FsControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength);
#ifdef __cplusplus
}
#endif

#define STATUS_SUCCESS          (NTSTATUS)0x00000000
#define STATUS_BUFFER_OVERFLOW  (NTSTATUS)0x80000005
extern HMODULE module;

extern void format_size(UINT64 size, WCHAR* s, ULONG len, BOOL show_bytes);
extern void ShowNtStatusError(HWND hwnd, NTSTATUS Status);

#define BLOCK_FLAG_DATA         0x001
#define BLOCK_FLAG_SYSTEM       0x002
#define BLOCK_FLAG_METADATA     0x004
#define BLOCK_FLAG_RAID0        0x008
#define BLOCK_FLAG_RAID1        0x010
#define BLOCK_FLAG_DUPLICATE    0x020
#define BLOCK_FLAG_RAID10       0x040
#define BLOCK_FLAG_RAID5        0x080
#define BLOCK_FLAG_RAID6        0x100

static UINT64 convtypes2[] = { BLOCK_FLAG_SINGLE, BLOCK_FLAG_DUPLICATE, BLOCK_FLAG_RAID0, BLOCK_FLAG_RAID1, BLOCK_FLAG_RAID5, BLOCK_FLAG_RAID6, BLOCK_FLAG_RAID10 };

HRESULT __stdcall BtrfsVolPropSheet::QueryInterface(REFIID riid, void **ppObj) {
    if (riid == IID_IUnknown || riid == IID_IShellPropSheetExt) {
        *ppObj = static_cast<IShellPropSheetExt*>(this); 
        AddRef();
        return S_OK;
    } else if (riid == IID_IShellExtInit) {
        *ppObj = static_cast<IShellExtInit*>(this); 
        AddRef();
        return S_OK;
    }

    *ppObj = NULL;
    return E_NOINTERFACE;
}

HRESULT __stdcall BtrfsVolPropSheet::Initialize(PCIDLIST_ABSOLUTE pidlFolder, IDataObject* pdtobj, HKEY hkeyProgID) {
    HANDLE h;
    ULONG num_files;
    FORMATETC format = { CF_HDROP, NULL, DVASPECT_CONTENT, -1, TYMED_HGLOBAL };
    HDROP hdrop;
    
    if (pidlFolder)
        return E_FAIL;
    
    if (!pdtobj)
        return E_FAIL;
    
    stgm.tymed = TYMED_HGLOBAL;
    
    if (FAILED(pdtobj->GetData(&format, &stgm)))
        return E_INVALIDARG;
    
    stgm_set = TRUE;
    
    hdrop = (HDROP)GlobalLock(stgm.hGlobal);
    
    if (!hdrop) {
        ReleaseStgMedium(&stgm);
        stgm_set = FALSE;
        return E_INVALIDARG;
    }
        
    num_files = DragQueryFileW((HDROP)stgm.hGlobal, 0xFFFFFFFF, NULL, 0);
    
    if (num_files > 1)
        return E_FAIL;
    
    if (DragQueryFileW((HDROP)stgm.hGlobal, 0, fn, sizeof(fn) / sizeof(MAX_PATH))) {
        h = CreateFileW(fn, FILE_TRAVERSE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);

        if (h != INVALID_HANDLE_VALUE) {
            NTSTATUS Status;
            IO_STATUS_BLOCK iosb;
            ULONG devsize, i;
            
            i = 0;
            devsize = 1024;
            
            devices = (btrfs_device*)malloc(devsize);

            while (TRUE) {
                Status = NtFsControlFile(h, NULL, NULL, NULL, &iosb, FSCTL_BTRFS_GET_DEVICES, NULL, 0, devices, devsize);
                if (Status == STATUS_BUFFER_OVERFLOW) {
                    if (i < 8) {
                        devsize += 1024;
                        
                        free(devices);
                        devices = (btrfs_device*)malloc(devsize);
                        
                        i++;
                    } else
                        return E_FAIL;
                } else
                    break;
            }
            
            if (Status != STATUS_SUCCESS) {
                CloseHandle(h);
                return E_FAIL;
            }
            
            ignore = FALSE;

            CloseHandle(h);
        } else
            return E_FAIL;
    } else
        return E_FAIL;

    return S_OK;
}

static void ShowError(HWND hwnd, ULONG err) {
    WCHAR* buf;
    
    if (FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL,
                       err, 0, (WCHAR*)&buf, 0, NULL) == 0) {
        MessageBoxW(hwnd, L"FormatMessage failed", L"Error", MB_ICONERROR);
        return;
    }
    
    MessageBoxW(hwnd, buf, L"Error", MB_ICONERROR);
    
    LocalFree(buf);
}

typedef struct {
    UINT64 dev_id;
    ULONG namelen;
    WCHAR* name;
    UINT64 alloc;
    UINT64 size;
} dev;

void BtrfsVolPropSheet::FormatUsage(HWND hwndDlg, WCHAR* s, ULONG size, btrfs_usage* usage) {
    UINT8 i, j;
    UINT64 num_devs, k, dev_size, dev_alloc, data_size, data_alloc, metadata_size, metadata_alloc;
    btrfs_device* bd;
    dev* devs = NULL;
    btrfs_usage* bue;
    WCHAR t[255], u[255], v[255];
    
    static const UINT64 types[] = { BLOCK_FLAG_DATA, BLOCK_FLAG_DATA | BLOCK_FLAG_METADATA, BLOCK_FLAG_METADATA, BLOCK_FLAG_SYSTEM };
    static const ULONG typestrings[] = { IDS_USAGE_DATA, IDS_USAGE_MIXED, IDS_USAGE_METADATA, IDS_USAGE_SYSTEM };
    static const UINT64 duptypes[] = { 0, BLOCK_FLAG_DUPLICATE, BLOCK_FLAG_RAID0, BLOCK_FLAG_RAID1, BLOCK_FLAG_RAID10, BLOCK_FLAG_RAID5, BLOCK_FLAG_RAID6 };
    static const ULONG dupstrings[] = { IDS_SINGLE, IDS_DUP, IDS_RAID0, IDS_RAID1, IDS_RAID10, IDS_RAID5, IDS_RAID6 };

    s[0] = 0;
    
    num_devs = 0;
    bd = devices;
    
    while (TRUE) {
        num_devs++;
        
        if (bd->next_entry > 0)
            bd = (btrfs_device*)((UINT8*)bd + bd->next_entry);
        else
            break;
    }
    
    devs = (dev*)malloc(sizeof(dev) * num_devs);
    
    bd = devices;
    k = 0;
    
    dev_size = 0;
    
    while (TRUE) {
        devs[k].dev_id = bd->dev_id;
        devs[k].namelen = bd->namelen;
        devs[k].name = bd->name;
        devs[k].alloc = 0;
        devs[k].size = bd->size;
        
        dev_size += bd->size;
        
        k++;
        
        if (bd->next_entry > 0)
            bd = (btrfs_device*)((UINT8*)bd + bd->next_entry);
        else
            break;
    }
    
    dev_alloc = 0;
    data_size = data_alloc = 0;
    metadata_size = metadata_alloc = 0;
    
    bue = usage;
    while (TRUE) {
        for (k = 0; k < bue->num_devices; k++) {
            dev_alloc += bue->devices[k].alloc;
            
            if (bue->type & BLOCK_FLAG_DATA) {
                data_alloc += bue->devices[k].alloc;
            }
            
            if (bue->type & BLOCK_FLAG_METADATA) {
                metadata_alloc += bue->devices[k].alloc;
            }
        }
        
        if (bue->type & BLOCK_FLAG_DATA) {
            data_size += bue->size;
        }
        
        if (bue->type & BLOCK_FLAG_METADATA) {
            metadata_size += bue->size;
        }
        
        if (bue->next_entry > 0)
            bue = (btrfs_usage*)((UINT8*)bue + bue->next_entry);
        else
            break;
    }
    
    // device size
    
    if (!LoadStringW(module, IDS_USAGE_DEV_SIZE, u, sizeof(u) / sizeof(WCHAR))) {
        ShowError(hwndDlg, GetLastError());
        goto end;
    }
    
    format_size(dev_size, v, sizeof(v) / sizeof(WCHAR), FALSE);
    
    if (StringCchPrintfW(t, sizeof(t) / sizeof(WCHAR), u, v) == STRSAFE_E_INSUFFICIENT_BUFFER)
        goto end;

    if (StringCchCatW(s, size, t) == STRSAFE_E_INSUFFICIENT_BUFFER)
        goto end;
    
    if (StringCchCatW(s, size, L"\r\n") == STRSAFE_E_INSUFFICIENT_BUFFER)
        goto end;
    
    // device allocated
    
    if (!LoadStringW(module, IDS_USAGE_DEV_ALLOC, u, sizeof(u) / sizeof(WCHAR))) {
        ShowError(hwndDlg, GetLastError());
        goto end;
    }
    
    format_size(dev_alloc, v, sizeof(v) / sizeof(WCHAR), FALSE);
    
    if (StringCchPrintfW(t, sizeof(t) / sizeof(WCHAR), u, v) == STRSAFE_E_INSUFFICIENT_BUFFER)
        goto end;

    if (StringCchCatW(s, size, t) == STRSAFE_E_INSUFFICIENT_BUFFER)
        goto end;
    
    if (StringCchCatW(s, size, L"\r\n") == STRSAFE_E_INSUFFICIENT_BUFFER)
        goto end;
    
    // device unallocated
    
    if (!LoadStringW(module, IDS_USAGE_DEV_UNALLOC, u, sizeof(u) / sizeof(WCHAR))) {
        ShowError(hwndDlg, GetLastError());
        goto end;
    }
    
    format_size(dev_size - dev_alloc, v, sizeof(v) / sizeof(WCHAR), FALSE);
    
    if (StringCchPrintfW(t, sizeof(t) / sizeof(WCHAR), u, v) == STRSAFE_E_INSUFFICIENT_BUFFER)
        goto end;

    if (StringCchCatW(s, size, t) == STRSAFE_E_INSUFFICIENT_BUFFER)
        goto end;
    
    if (StringCchCatW(s, size, L"\r\n") == STRSAFE_E_INSUFFICIENT_BUFFER)
        goto end;
    
    // data ratio
    
    if (!LoadStringW(module, IDS_USAGE_DATA_RATIO, u, sizeof(u) / sizeof(WCHAR))) {
        ShowError(hwndDlg, GetLastError());
        goto end;
    }
    
    if (StringCchPrintfW(t, sizeof(t) / sizeof(WCHAR), u, (float)data_alloc / (float)data_size) == STRSAFE_E_INSUFFICIENT_BUFFER)
        goto end;

    if (StringCchCatW(s, size, t) == STRSAFE_E_INSUFFICIENT_BUFFER)
        goto end;
    
    if (StringCchCatW(s, size, L"\r\n") == STRSAFE_E_INSUFFICIENT_BUFFER)
        goto end;
    
    // metadata ratio
    
    if (!LoadStringW(module, IDS_USAGE_METADATA_RATIO, u, sizeof(u) / sizeof(WCHAR))) {
        ShowError(hwndDlg, GetLastError());
        goto end;
    }
    
    if (StringCchPrintfW(t, sizeof(t) / sizeof(WCHAR), u, (float)metadata_alloc / (float)metadata_size) == STRSAFE_E_INSUFFICIENT_BUFFER)
        goto end;

    if (StringCchCatW(s, size, t) == STRSAFE_E_INSUFFICIENT_BUFFER)
        goto end;
    
    if (StringCchCatW(s, size, L"\r\n") == STRSAFE_E_INSUFFICIENT_BUFFER)
        goto end;
    
    if (StringCchCatW(s, size, L"\r\n") == STRSAFE_E_INSUFFICIENT_BUFFER)
        goto end;
    
    for (i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
        for (j = 0; j < sizeof(duptypes) / sizeof(duptypes[0]); j++) {
            bue = usage;
            
            while (TRUE) {
                if ((bue->type & types[i]) == types[i] &&
                    ((duptypes[j] == 0 && (bue->type & (BLOCK_FLAG_DUPLICATE | BLOCK_FLAG_RAID0 | BLOCK_FLAG_RAID1 | BLOCK_FLAG_RAID10 | BLOCK_FLAG_RAID5 | BLOCK_FLAG_RAID6)) == 0)
                    || bue->type & duptypes[j])) {
                    WCHAR typestring[255], dupstring[255], sizestring[255], usedstring[255];

                    if (!LoadStringW(module, typestrings[i], typestring, sizeof(typestring) / sizeof(WCHAR))) {
                        ShowError(hwndDlg, GetLastError());
                        goto end;
                    }
                    
                    if (!LoadStringW(module, dupstrings[j], dupstring, sizeof(dupstring) / sizeof(WCHAR))) {
                        ShowError(hwndDlg, GetLastError());
                        goto end;
                    }
                    
                    format_size(bue->size, sizestring, sizeof(sizestring) / sizeof(WCHAR), FALSE);
                    format_size(bue->used, usedstring, sizeof(usedstring) / sizeof(WCHAR), FALSE);
                    
                    if (StringCchPrintfW(t, sizeof(t) / sizeof(WCHAR), typestring, dupstring, sizestring, usedstring) == STRSAFE_E_INSUFFICIENT_BUFFER)
                        goto end;

                    if (StringCchCatW(s, size, t) == STRSAFE_E_INSUFFICIENT_BUFFER)
                        goto end;
                    
                    if (StringCchCatW(s, size, L"\r\n") == STRSAFE_E_INSUFFICIENT_BUFFER)
                        goto end;
                    
                    for (k = 0; k < bue->num_devices; k++) {
                        UINT64 l;
                        BOOL found = FALSE;
                        
                        format_size(bue->devices[k].alloc, sizestring, sizeof(sizestring) / sizeof(WCHAR), FALSE);
                        
                        for (l = 0; l < num_devs; l++) {
                            if (devs[l].dev_id == bue->devices[k].dev_id) {
                                if (StringCchPrintfW(t, sizeof(t) / sizeof(WCHAR), L"%.*s\t%s", devs[l].namelen / sizeof(WCHAR), devs[l].name, sizestring) == STRSAFE_E_INSUFFICIENT_BUFFER)
                                    goto end;

                                if (StringCchCatW(s, size, t) == STRSAFE_E_INSUFFICIENT_BUFFER)
                                    goto end;
                                
                                if (StringCchCatW(s, size, L"\r\n") == STRSAFE_E_INSUFFICIENT_BUFFER)
                                    goto end;
                                
                                devs[l].alloc += bue->devices[k].alloc;
                                
                                found = TRUE;
                                break;
                            }
                        }
                        
                        if (!found) {
                            if (!LoadStringW(module, IDS_UNKNOWN_DEVICE, typestring, sizeof(typestring) / sizeof(WCHAR))) {
                                ShowError(hwndDlg, GetLastError());
                                goto end;
                            }
                            
                            if (StringCchPrintfW(t, sizeof(t) / sizeof(WCHAR), typestring, bue->devices[k].dev_id) == STRSAFE_E_INSUFFICIENT_BUFFER)
                                goto end;
                            
                            if (StringCchCatW(s, size, t) == STRSAFE_E_INSUFFICIENT_BUFFER)
                                goto end;
                            
                            if (StringCchCatW(s, size, L"\t") == STRSAFE_E_INSUFFICIENT_BUFFER)
                                goto end;
                            
                            if (StringCchCatW(s, size, sizestring) == STRSAFE_E_INSUFFICIENT_BUFFER)
                                goto end;
                            
                            if (StringCchCatW(s, size, L"\r\n") == STRSAFE_E_INSUFFICIENT_BUFFER)
                                goto end;
                        }
                    }

                    if (StringCchCatW(s, size, L"\r\n") == STRSAFE_E_INSUFFICIENT_BUFFER)
                        goto end;
                    
                    break;
                }
                
                if (bue->next_entry > 0)
                    bue = (btrfs_usage*)((UINT8*)bue + bue->next_entry);
                else
                    break;
            }
        }
    }
    
    if (!LoadStringW(module, IDS_USAGE_UNALLOC, t, sizeof(t) / sizeof(WCHAR))) {
        ShowError(hwndDlg, GetLastError());
        goto end;
    }
    
    if (StringCchCatW(s, size, t) == STRSAFE_E_INSUFFICIENT_BUFFER)
        goto end;
    
    if (StringCchCatW(s, size, L"\r\n") == STRSAFE_E_INSUFFICIENT_BUFFER)
        goto end;
    
    for (k = 0; k < num_devs; k++) {
        WCHAR sizestring[255];
        
        format_size(devs[k].size - devs[k].alloc, sizestring, sizeof(sizestring) / sizeof(WCHAR), FALSE);
        
        if (StringCchPrintfW(t, sizeof(t) / sizeof(WCHAR), L"%.*s\t%s", devs[k].namelen / sizeof(WCHAR), devs[k].name, sizestring) == STRSAFE_E_INSUFFICIENT_BUFFER)
            goto end;

        if (StringCchCatW(s, size, t) == STRSAFE_E_INSUFFICIENT_BUFFER)
            goto end;
        
        if (StringCchCatW(s, size, L"\r\n") == STRSAFE_E_INSUFFICIENT_BUFFER)
            goto end;
    }
    
end:
    if (devs)
        free(devs);
}

void BtrfsVolPropSheet::RefreshUsage(HWND hwndDlg) {
    HANDLE h;
    WCHAR s[4096];
    btrfs_usage* usage;
    
    h = CreateFileW(fn, FILE_TRAVERSE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);

    if (h != INVALID_HANDLE_VALUE) {
        NTSTATUS Status;
        IO_STATUS_BLOCK iosb;
        ULONG devsize, usagesize, i;
        
        i = 0;
        devsize = 1024;
        
        devices = (btrfs_device*)malloc(devsize);

        while (TRUE) {
            Status = NtFsControlFile(h, NULL, NULL, NULL, &iosb, FSCTL_BTRFS_GET_DEVICES, NULL, 0, devices, devsize);
            if (Status == STATUS_BUFFER_OVERFLOW) {
                if (i < 8) {
                    devsize += 1024;
                    
                    free(devices);
                    devices = (btrfs_device*)malloc(devsize);
                    
                    i++;
                } else
                    return;
            } else
                break;
        }
        
        if (Status != STATUS_SUCCESS) {
            CloseHandle(h);
            return;
        }
        
        i = 0;
        usagesize = 1024;
        
        usage = (btrfs_usage*)malloc(usagesize);

        while (TRUE) {
            Status = NtFsControlFile(h, NULL, NULL, NULL, &iosb, FSCTL_BTRFS_GET_USAGE, NULL, 0, usage, usagesize);
            if (Status == STATUS_BUFFER_OVERFLOW) {
                if (i < 8) {
                    usagesize += 1024;
                    
                    free(usage);
                    usage = (btrfs_usage*)malloc(usagesize);
                    
                    i++;
                } else
                    return;
            } else
                break;
        }
        
        if (Status != STATUS_SUCCESS) {
            free(usage);
            CloseHandle(h);
            return;
        }
        
        ignore = FALSE;

        CloseHandle(h);
    } else
        return;
    
    FormatUsage(hwndDlg, s, sizeof(s) / sizeof(WCHAR), usage);
    
    SetDlgItemTextW(hwndDlg, IDC_USAGE_BOX, s);
    
    free(usage);
}

INT_PTR CALLBACK BtrfsVolPropSheet::UsageDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_INITDIALOG:
        {
            WCHAR s[4096];
            int i;
            ULONG usagesize;
            NTSTATUS Status;
            HANDLE h;
            IO_STATUS_BLOCK iosb;
            
            EnableThemeDialogTexture(hwndDlg, ETDT_ENABLETAB);
            
            h = CreateFileW(fn, FILE_TRAVERSE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);

            if (h != INVALID_HANDLE_VALUE) {
                btrfs_usage* usage;
                
                i = 0;
                usagesize = 1024;
                
                usage = (btrfs_usage*)malloc(usagesize);

                while (TRUE) {
                    Status = NtFsControlFile(h, NULL, NULL, NULL, &iosb, FSCTL_BTRFS_GET_USAGE, NULL, 0, usage, usagesize);
                    if (Status == STATUS_BUFFER_OVERFLOW) {
                        if (i < 8) {
                            usagesize += 1024;
                            
                            free(usage);
                            usage = (btrfs_usage*)malloc(usagesize);
                            
                            i++;
                        } else
                            break;
                    } else
                        break;
                }
                
                if (Status != STATUS_SUCCESS) {
                    free(usage);
                    CloseHandle(h);
                    break;
                }
                
                CloseHandle(h);
                
                FormatUsage(hwndDlg, s, sizeof(s) / sizeof(WCHAR), usage);
                
                SetDlgItemTextW(hwndDlg, IDC_USAGE_BOX, s);
                
                free(usage);
            }
            
            break;
        }
        
        case WM_COMMAND:
            switch (HIWORD(wParam)) {
                case BN_CLICKED:
                    switch (LOWORD(wParam)) {
                        case IDOK:
                        case IDCANCEL:
                            EndDialog(hwndDlg, 0);
                        return TRUE;
                            
                        case IDC_USAGE_REFRESH:
                            RefreshUsage(hwndDlg);
                        return TRUE;
                    }
                break;
            }
        break;
    }
    
    return FALSE;
}

static INT_PTR CALLBACK stub_UsageDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    BtrfsVolPropSheet* bvps;
    
    if (uMsg == WM_INITDIALOG) {
        SetWindowLongPtr(hwndDlg, GWLP_USERDATA, (LONG_PTR)lParam);
        bvps = (BtrfsVolPropSheet*)lParam;
    } else {
        bvps = (BtrfsVolPropSheet*)GetWindowLongPtr(hwndDlg, GWLP_USERDATA);
    }
    
    if (bvps)
        return bvps->UsageDlgProc(hwndDlg, uMsg, wParam, lParam);
    else
        return FALSE;
}

void BtrfsVolPropSheet::ShowUsage(HWND hwndDlg) {
   DialogBoxParamW(module, MAKEINTRESOURCEW(IDD_VOL_USAGE), hwndDlg, stub_UsageDlgProc, (LPARAM)this);
}

void BtrfsVolPropSheet::StartBalance(HWND hwndDlg) {
    HANDLE h;
    
    h = CreateFileW(fn, FILE_TRAVERSE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);

    if (h != INVALID_HANDLE_VALUE) {
        NTSTATUS Status;
        IO_STATUS_BLOCK iosb;
        btrfs_start_balance bsb;
        
        RtlCopyMemory(&bsb.opts[0], &data_opts, sizeof(btrfs_balance_opts));
        RtlCopyMemory(&bsb.opts[1], &metadata_opts, sizeof(btrfs_balance_opts));
        RtlCopyMemory(&bsb.opts[2], &system_opts, sizeof(btrfs_balance_opts));
        
        if (IsDlgButtonChecked(hwndDlg, IDC_DATA) == BST_CHECKED)
            bsb.opts[0].flags |= BTRFS_BALANCE_OPTS_ENABLED;
        else
            bsb.opts[0].flags &= ~BTRFS_BALANCE_OPTS_ENABLED;
        
        if (IsDlgButtonChecked(hwndDlg, IDC_METADATA) == BST_CHECKED)
            bsb.opts[1].flags |= BTRFS_BALANCE_OPTS_ENABLED;
        else
            bsb.opts[1].flags &= ~BTRFS_BALANCE_OPTS_ENABLED;
        
        if (IsDlgButtonChecked(hwndDlg, IDC_SYSTEM) == BST_CHECKED)
            bsb.opts[2].flags |= BTRFS_BALANCE_OPTS_ENABLED;
        else
            bsb.opts[2].flags &= ~BTRFS_BALANCE_OPTS_ENABLED;
        
        Status = NtFsControlFile(h, NULL, NULL, NULL, &iosb, FSCTL_BTRFS_START_BALANCE, &bsb, sizeof(btrfs_start_balance), NULL, 0);
        cancelling = FALSE;
        
        if (Status != STATUS_SUCCESS) {
            ShowNtStatusError(hwndDlg, Status);
            CloseHandle(h);
            return;
        }
    } else {
        ShowError(hwndDlg, GetLastError());
        return;
    }
}

void BtrfsVolPropSheet::PauseBalance(HWND hwndDlg) {
    HANDLE h;
    
    h = CreateFileW(fn, FILE_TRAVERSE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);

    if (h != INVALID_HANDLE_VALUE) {
        NTSTATUS Status;
        IO_STATUS_BLOCK iosb;
        btrfs_query_balance bqb2;
        
        Status = NtFsControlFile(h, NULL, NULL, NULL, &iosb, FSCTL_BTRFS_QUERY_BALANCE, NULL, 0, &bqb2, sizeof(btrfs_query_balance));
        if (Status != STATUS_SUCCESS) {
            ShowNtStatusError(hwndDlg, Status);
            CloseHandle(h);
            return;
        }
        
        if (bqb2.status == BTRFS_BALANCE_PAUSED)
            Status = NtFsControlFile(h, NULL, NULL, NULL, &iosb, FSCTL_BTRFS_RESUME_BALANCE, NULL, 0, NULL, 0);
        else if (bqb2.status == BTRFS_BALANCE_RUNNING)
            Status = NtFsControlFile(h, NULL, NULL, NULL, &iosb, FSCTL_BTRFS_PAUSE_BALANCE, NULL, 0, NULL, 0);
        else
            return;
        
        if (Status != STATUS_SUCCESS) {
            ShowNtStatusError(hwndDlg, Status);
            CloseHandle(h);
            return;
        }
    } else {
        ShowError(hwndDlg, GetLastError());
        return;
    }
}

void BtrfsVolPropSheet::StopBalance(HWND hwndDlg) {
    HANDLE h;
    
    h = CreateFileW(fn, FILE_TRAVERSE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);

    if (h != INVALID_HANDLE_VALUE) {
        NTSTATUS Status;
        IO_STATUS_BLOCK iosb;
        btrfs_query_balance bqb2;
        
        Status = NtFsControlFile(h, NULL, NULL, NULL, &iosb, FSCTL_BTRFS_QUERY_BALANCE, NULL, 0, &bqb2, sizeof(btrfs_query_balance));
        if (Status != STATUS_SUCCESS) {
            ShowNtStatusError(hwndDlg, Status);
            CloseHandle(h);
            return;
        }
        
        if (bqb2.status == BTRFS_BALANCE_PAUSED || bqb2.status == BTRFS_BALANCE_RUNNING)
            Status = NtFsControlFile(h, NULL, NULL, NULL, &iosb, FSCTL_BTRFS_STOP_BALANCE, NULL, 0, NULL, 0);
        else
            return;
        
        if (Status != STATUS_SUCCESS) {
            ShowNtStatusError(hwndDlg, Status);
            CloseHandle(h);
            return;
        }
        
        cancelling = TRUE;
    } else {
        ShowError(hwndDlg, GetLastError());
        return;
    }
}

void BtrfsVolPropSheet::RefreshBalanceDlg(HWND hwndDlg, BOOL first) {
    HANDLE h;
    BOOL balancing = FALSE;
    WCHAR s[255], t[255];
    
    h = CreateFileW(fn, FILE_TRAVERSE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        NTSTATUS Status;
        IO_STATUS_BLOCK iosb;

        Status = NtFsControlFile(h, NULL, NULL, NULL, &iosb, FSCTL_BTRFS_QUERY_BALANCE, NULL, 0, &bqb, sizeof(btrfs_query_balance));
        
        if (Status != STATUS_SUCCESS) {
            ShowNtStatusError(hwndDlg, Status);
            CloseHandle(h);
            return;
        }
    } else {
        ShowError(hwndDlg, GetLastError());
        return;
    }
    
    if (cancelling)
        bqb.status = BTRFS_BALANCE_STOPPED;
    
    balancing = bqb.status != BTRFS_BALANCE_STOPPED;
    
    if (!balancing) {
        if (first || balance_status != BTRFS_BALANCE_STOPPED) {
            EnableWindow(GetDlgItem(hwndDlg, IDC_PAUSE_BALANCE), FALSE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_CANCEL_BALANCE), FALSE);
            SendMessageW(GetDlgItem(hwndDlg, IDC_BALANCE_PROGRESS), PBM_SETSTATE, PBST_NORMAL, 0);
            EnableWindow(GetDlgItem(hwndDlg, IDC_BALANCE_PROGRESS), FALSE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_DATA), TRUE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_METADATA), TRUE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_SYSTEM), TRUE);
            
            if (balance_status != BTRFS_BALANCE_STOPPED) {
                CheckDlgButton(hwndDlg, IDC_DATA, BST_UNCHECKED);
                CheckDlgButton(hwndDlg, IDC_METADATA, BST_UNCHECKED);
                CheckDlgButton(hwndDlg, IDC_SYSTEM, BST_UNCHECKED);
                
                SendMessage(GetDlgItem(hwndDlg, IDC_BALANCE_PROGRESS), PBM_SETPOS, 0, 0);
            }
            
            EnableWindow(GetDlgItem(hwndDlg, IDC_DATA_OPTIONS), IsDlgButtonChecked(hwndDlg, IDC_DATA) == BST_CHECKED ? TRUE : FALSE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_METADATA_OPTIONS), IsDlgButtonChecked(hwndDlg, IDC_METADATA) == BST_CHECKED ? TRUE : FALSE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_SYSTEM_OPTIONS), IsDlgButtonChecked(hwndDlg, IDC_SYSTEM) == BST_CHECKED ? TRUE : FALSE);
            
            if (!LoadStringW(module, cancelling ? IDS_BALANCE_CANCELLED : (balance_status != BTRFS_BALANCE_STOPPED ? IDS_BALANCE_COMPLETE : IDS_NO_BALANCE),
                             s, sizeof(s) / sizeof(WCHAR))) {
                ShowError(hwndDlg, GetLastError());
                return;
            }
            
            SetDlgItemTextW(hwndDlg, IDC_BALANCE_STATUS, s);
            
            EnableWindow(GetDlgItem(hwndDlg, IDC_START_BALANCE), IsDlgButtonChecked(hwndDlg, IDC_DATA) == BST_CHECKED ||
                         IsDlgButtonChecked(hwndDlg, IDC_METADATA) == BST_CHECKED || IsDlgButtonChecked(hwndDlg, IDC_SYSTEM) == BST_CHECKED ? TRUE: FALSE); 
            
            balance_status = bqb.status;
            cancelling = FALSE;
        }
        
        return;
    }
    
    if (first || balance_status == BTRFS_BALANCE_STOPPED) {
        EnableWindow(GetDlgItem(hwndDlg, IDC_PAUSE_BALANCE), TRUE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_CANCEL_BALANCE), TRUE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_BALANCE_PROGRESS), TRUE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_DATA), FALSE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_METADATA), FALSE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_SYSTEM), FALSE);
        
        CheckDlgButton(hwndDlg, IDC_DATA, bqb.data_opts.flags & BTRFS_BALANCE_OPTS_ENABLED ? BST_CHECKED : BST_UNCHECKED);
        CheckDlgButton(hwndDlg, IDC_METADATA, bqb.metadata_opts.flags & BTRFS_BALANCE_OPTS_ENABLED ? BST_CHECKED : BST_UNCHECKED);
        CheckDlgButton(hwndDlg, IDC_SYSTEM, bqb.system_opts.flags & BTRFS_BALANCE_OPTS_ENABLED ? BST_CHECKED : BST_UNCHECKED);
        
        EnableWindow(GetDlgItem(hwndDlg, IDC_DATA_OPTIONS), bqb.data_opts.flags & BTRFS_BALANCE_OPTS_ENABLED ? TRUE : FALSE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_METADATA_OPTIONS), bqb.metadata_opts.flags & BTRFS_BALANCE_OPTS_ENABLED ? TRUE : FALSE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_SYSTEM_OPTIONS), bqb.system_opts.flags & BTRFS_BALANCE_OPTS_ENABLED ? TRUE : FALSE);
        
        EnableWindow(GetDlgItem(hwndDlg, IDC_START_BALANCE), FALSE);
    }
    
    SendMessageW(GetDlgItem(hwndDlg, IDC_BALANCE_PROGRESS), PBM_SETRANGE32, 0, (LPARAM)bqb.total_chunks);
    
    if (bqb.status == BTRFS_BALANCE_PAUSED && balance_status != bqb.status)
        SendMessageW(GetDlgItem(hwndDlg, IDC_BALANCE_PROGRESS), PBM_SETSTATE, PBST_PAUSED, 0);
    else if (bqb.status != BTRFS_BALANCE_PAUSED && balance_status == BTRFS_BALANCE_PAUSED)
        SendMessageW(GetDlgItem(hwndDlg, IDC_BALANCE_PROGRESS), PBM_SETSTATE, PBST_NORMAL, 0);
    
    balance_status = bqb.status;
    
    if (!LoadStringW(module, balance_status == BTRFS_BALANCE_PAUSED ? IDS_BALANCE_PAUSED : IDS_BALANCE_RUNNING, s, sizeof(s) / sizeof(WCHAR))) {
        ShowError(hwndDlg, GetLastError());
        return;
    }
    
    SendMessageW(GetDlgItem(hwndDlg, IDC_BALANCE_PROGRESS), PBM_SETPOS, (WPARAM)(bqb.total_chunks - bqb.chunks_left), 0);
    
    if (StringCchPrintfW(t, sizeof(t) / sizeof(WCHAR), s, bqb.total_chunks - bqb.chunks_left,
        bqb.total_chunks, (float)(bqb.total_chunks - bqb.chunks_left) * 100.0f / (float)bqb.total_chunks) == STRSAFE_E_INSUFFICIENT_BUFFER)
        return;
    
    SetDlgItemTextW(hwndDlg, IDC_BALANCE_STATUS, t);
}

void ShowStringError(HWND hwndDlg, int num) {
    WCHAR title[255], s[255];
    
    if (!LoadStringW(module, IDS_ERROR, title, sizeof(title) / sizeof(WCHAR))) {
        ShowError(hwndDlg, GetLastError());
        return;
    }
    
    if (!LoadStringW(module, num, s, sizeof(s) / sizeof(WCHAR))) {
        ShowError(hwndDlg, GetLastError());
        return;
    }
    
    MessageBoxW(hwndDlg, s, title, MB_ICONERROR);
}

void BtrfsVolPropSheet::SaveBalanceOpts(HWND hwndDlg) {
    btrfs_balance_opts* opts;
    
    switch (opts_type) {
        case 1:
            opts = &data_opts;
        break;
        
        case 2:
            opts = &metadata_opts;
        break;
        
        case 3:
            opts = &system_opts;
        break;
        
        default:
            return;
    }
    
    RtlZeroMemory(opts, sizeof(btrfs_balance_opts));
    
    if (IsDlgButtonChecked(hwndDlg, IDC_PROFILES) == BST_CHECKED) {
        opts->flags |= BTRFS_BALANCE_OPTS_PROFILES;
        
        if (IsDlgButtonChecked(hwndDlg, IDC_PROFILES_SINGLE) == BST_CHECKED) opts->profiles |= BLOCK_FLAG_SINGLE;
        if (IsDlgButtonChecked(hwndDlg, IDC_PROFILES_DUP) == BST_CHECKED) opts->profiles |= BLOCK_FLAG_DUPLICATE;
        if (IsDlgButtonChecked(hwndDlg, IDC_PROFILES_RAID0) == BST_CHECKED) opts->profiles |= BLOCK_FLAG_RAID0;
        if (IsDlgButtonChecked(hwndDlg, IDC_PROFILES_RAID1) == BST_CHECKED) opts->profiles |= BLOCK_FLAG_RAID1;
        if (IsDlgButtonChecked(hwndDlg, IDC_PROFILES_RAID10) == BST_CHECKED) opts->profiles |= BLOCK_FLAG_RAID10;
        if (IsDlgButtonChecked(hwndDlg, IDC_PROFILES_RAID5) == BST_CHECKED) opts->profiles |= BLOCK_FLAG_RAID5;
        if (IsDlgButtonChecked(hwndDlg, IDC_PROFILES_RAID6) == BST_CHECKED) opts->profiles |= BLOCK_FLAG_RAID6;
    }

    if (IsDlgButtonChecked(hwndDlg, IDC_DEVID) == BST_CHECKED) {
        int sel;
        
        opts->flags |= BTRFS_BALANCE_OPTS_DEVID;
        
        sel = SendMessageW(GetDlgItem(hwndDlg, IDC_DEVID_COMBO), CB_GETCURSEL, 0, 0);
        
        if (sel == CB_ERR)
            opts->flags &= ~BTRFS_BALANCE_OPTS_DEVID;
        else {
            btrfs_device* bd = devices;
            int i = 0;
            
            while (TRUE) {
                if (i == sel) {
                    opts->devid = bd->dev_id;
                    break;
                }

                i++;
                
                if (bd->next_entry > 0)
                    bd = (btrfs_device*)((UINT8*)bd + bd->next_entry);
                else
                    break;
            }
            
            if (opts->devid == 0)
                opts->flags &= ~BTRFS_BALANCE_OPTS_DEVID;
        }
    }

    if (IsDlgButtonChecked(hwndDlg, IDC_DRANGE) == BST_CHECKED) {
        WCHAR s[255];
        
        opts->flags |= BTRFS_BALANCE_OPTS_DRANGE;
        
        GetWindowTextW(GetDlgItem(hwndDlg, IDC_DRANGE_START), s, sizeof(s) / sizeof(WCHAR));
        opts->drange_start = _wtoi64(s);
        
        GetWindowTextW(GetDlgItem(hwndDlg, IDC_DRANGE_END), s, sizeof(s) / sizeof(WCHAR));
        opts->drange_end = _wtoi64(s);
        
        if (opts->drange_end < opts->drange_start) {
            ShowStringError(hwndDlg, IDS_DRANGE_END_BEFORE_START);
            return;
        }
    }
    
    if (IsDlgButtonChecked(hwndDlg, IDC_VRANGE) == BST_CHECKED) {
        WCHAR s[255];
        
        opts->flags |= BTRFS_BALANCE_OPTS_VRANGE;
        
        GetWindowTextW(GetDlgItem(hwndDlg, IDC_VRANGE_START), s, sizeof(s) / sizeof(WCHAR));
        opts->vrange_start = _wtoi64(s);
        
        GetWindowTextW(GetDlgItem(hwndDlg, IDC_VRANGE_END), s, sizeof(s) / sizeof(WCHAR));
        opts->vrange_end = _wtoi64(s);
        
        if (opts->vrange_end < opts->vrange_start) {
            ShowStringError(hwndDlg, IDS_VRANGE_END_BEFORE_START);
            return;
        }
    }
    
    if (IsDlgButtonChecked(hwndDlg, IDC_LIMIT) == BST_CHECKED) {
        WCHAR s[255];
        
        opts->flags |= BTRFS_BALANCE_OPTS_LIMIT;
        
        GetWindowTextW(GetDlgItem(hwndDlg, IDC_LIMIT_START), s, sizeof(s) / sizeof(WCHAR));
        opts->limit_start = _wtoi64(s);
        
        GetWindowTextW(GetDlgItem(hwndDlg, IDC_LIMIT_END), s, sizeof(s) / sizeof(WCHAR));
        opts->limit_end = _wtoi64(s);
        
        if (opts->limit_end < opts->limit_start) {
            ShowStringError(hwndDlg, IDS_LIMIT_END_BEFORE_START);
            return;
        }
    }
    
    if (IsDlgButtonChecked(hwndDlg, IDC_STRIPES) == BST_CHECKED) {
        WCHAR s[255];
        
        opts->flags |= BTRFS_BALANCE_OPTS_STRIPES;
        
        GetWindowTextW(GetDlgItem(hwndDlg, IDC_STRIPES_START), s, sizeof(s) / sizeof(WCHAR));
        opts->stripes_start = _wtoi(s);
        
        GetWindowTextW(GetDlgItem(hwndDlg, IDC_STRIPES_END), s, sizeof(s) / sizeof(WCHAR));
        opts->stripes_end = _wtoi(s);
        
        if (opts->stripes_end < opts->stripes_start) {
            ShowStringError(hwndDlg, IDS_STRIPES_END_BEFORE_START);
            return;
        }
    }
    
    if (IsDlgButtonChecked(hwndDlg, IDC_USAGE) == BST_CHECKED) {
        WCHAR s[255];
        
        opts->flags |= BTRFS_BALANCE_OPTS_USAGE;
        
        GetWindowTextW(GetDlgItem(hwndDlg, IDC_USAGE_START), s, sizeof(s) / sizeof(WCHAR));
        opts->usage_start = _wtoi(s);
        
        GetWindowTextW(GetDlgItem(hwndDlg, IDC_USAGE_END), s, sizeof(s) / sizeof(WCHAR));
        opts->usage_end = _wtoi(s);
        
        if (opts->usage_end < opts->usage_start) {
            ShowStringError(hwndDlg, IDS_USAGE_END_BEFORE_START);
            return;
        }
    }
    
    if (IsDlgButtonChecked(hwndDlg, IDC_CONVERT) == BST_CHECKED) {
        int sel;
        
        opts->flags |= BTRFS_BALANCE_OPTS_CONVERT;
        
        sel = SendMessageW(GetDlgItem(hwndDlg, IDC_CONVERT_COMBO), CB_GETCURSEL, 0, 0);
        
        if (sel == CB_ERR || (unsigned int)sel >= sizeof(convtypes2) / sizeof(convtypes2[0]))
            opts->flags &= ~BTRFS_BALANCE_OPTS_CONVERT;
        else {
            opts->convert = convtypes2[sel];
            
            if (IsDlgButtonChecked(hwndDlg, IDC_SOFT) == BST_CHECKED) opts->flags |= BTRFS_BALANCE_OPTS_SOFT;
        }
    }
    
    EndDialog(hwndDlg, 0);
}

INT_PTR CALLBACK BtrfsVolPropSheet::BalanceOptsDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_INITDIALOG:
        {
            HWND devcb, convcb;
            btrfs_device* bd;
            btrfs_balance_opts* opts;
            static int convtypes[] = { IDS_SINGLE2, IDS_DUP, IDS_RAID0, IDS_RAID1, IDS_RAID5, IDS_RAID6, IDS_RAID10, 0 };
            int i, num_devices = 0, num_writeable_devices = 0;
            WCHAR s[255], u[255];
            BOOL balance_started = balance_status != BTRFS_BALANCE_STOPPED;
            
            switch (opts_type) {
                case 1:
                    opts = balance_started ? &bqb.data_opts : &data_opts;
                break;
                
                case 2:
                    opts = balance_started ? &bqb.metadata_opts : &metadata_opts;
                break;
                
                case 3:
                    opts = balance_started ? &bqb.system_opts : &system_opts;
                break;
                
                default:
                    return TRUE;
            }
            
            EnableThemeDialogTexture(hwndDlg, ETDT_ENABLETAB);
            
            devcb = GetDlgItem(hwndDlg, IDC_DEVID_COMBO);
            
            if (!LoadStringW(module, IDS_DEVID_LIST, u, sizeof(u) / sizeof(WCHAR))) {
                ShowError(hwndDlg, GetLastError());
                return TRUE;
            }
            
            bd = devices;
            while (TRUE) {
                WCHAR t[255];
                
                RtlCopyMemory(s, bd->name, bd->namelen);
                s[bd->namelen / sizeof(WCHAR)] = 0;
                
                if (StringCchPrintfW(t, sizeof(t) / sizeof(WCHAR), u, bd->dev_id, s) == STRSAFE_E_INSUFFICIENT_BUFFER)
                    break;

                SendMessage(devcb, CB_ADDSTRING, NULL, (LPARAM)t);
                
                if (opts->devid == bd->dev_id)
                    SendMessage(devcb, CB_SETCURSEL, num_devices, 0);
                
                num_devices++;
                
                if (!bd->readonly)
                    num_writeable_devices++;
                
                if (bd->next_entry > 0)
                    bd = (btrfs_device*)((UINT8*)bd + bd->next_entry);
                else
                    break;
            }
            
            convcb = GetDlgItem(hwndDlg, IDC_CONVERT_COMBO);
                        
            i = 0;
            while (convtypes[i] != 0) {
                if (!LoadStringW(module, convtypes[i], s, sizeof(s) / sizeof(WCHAR))) {
                    ShowError(hwndDlg, GetLastError());
                    break;
                }
                
                SendMessage(convcb, CB_ADDSTRING, NULL, (LPARAM)s);
                
                if (opts->convert == convtypes2[i])
                    SendMessage(convcb, CB_SETCURSEL, i, 0);
                
                i++;
                
                if (num_writeable_devices < 2 && i == 2)
                    break;
                else if (num_writeable_devices < 3 && i == 4)
                    break;
                else if (num_writeable_devices < 4 && i == 6)
                    break;
            }
            
            // profiles
            
            CheckDlgButton(hwndDlg, IDC_PROFILES, opts->flags & BTRFS_BALANCE_OPTS_PROFILES ? BST_CHECKED : BST_UNCHECKED);
            CheckDlgButton(hwndDlg, IDC_PROFILES_SINGLE, opts->profiles & BLOCK_FLAG_SINGLE ? BST_CHECKED : BST_UNCHECKED);
            CheckDlgButton(hwndDlg, IDC_PROFILES_DUP, opts->profiles & BLOCK_FLAG_DUPLICATE ? BST_CHECKED : BST_UNCHECKED);
            CheckDlgButton(hwndDlg, IDC_PROFILES_RAID0, opts->profiles & BLOCK_FLAG_RAID0 ? BST_CHECKED : BST_UNCHECKED);
            CheckDlgButton(hwndDlg, IDC_PROFILES_RAID1, opts->profiles & BLOCK_FLAG_RAID1 ? BST_CHECKED : BST_UNCHECKED);
            CheckDlgButton(hwndDlg, IDC_PROFILES_RAID10, opts->profiles & BLOCK_FLAG_RAID10 ? BST_CHECKED : BST_UNCHECKED);
            CheckDlgButton(hwndDlg, IDC_PROFILES_RAID5, opts->profiles & BLOCK_FLAG_RAID5 ? BST_CHECKED : BST_UNCHECKED);
            CheckDlgButton(hwndDlg, IDC_PROFILES_RAID6, opts->profiles & BLOCK_FLAG_RAID6 ? BST_CHECKED : BST_UNCHECKED);
            
            EnableWindow(GetDlgItem(hwndDlg, IDC_PROFILES_SINGLE), !balance_started && opts->flags & BTRFS_BALANCE_OPTS_PROFILES ? TRUE : FALSE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_PROFILES_DUP), !balance_started && opts->flags & BTRFS_BALANCE_OPTS_PROFILES ? TRUE : FALSE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_PROFILES_RAID0), !balance_started && opts->flags & BTRFS_BALANCE_OPTS_PROFILES ? TRUE : FALSE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_PROFILES_RAID1), !balance_started && opts->flags & BTRFS_BALANCE_OPTS_PROFILES ? TRUE : FALSE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_PROFILES_RAID10), !balance_started && opts->flags & BTRFS_BALANCE_OPTS_PROFILES ? TRUE : FALSE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_PROFILES_RAID5), !balance_started && opts->flags & BTRFS_BALANCE_OPTS_PROFILES ? TRUE : FALSE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_PROFILES_RAID6), !balance_started && opts->flags & BTRFS_BALANCE_OPTS_PROFILES ? TRUE : FALSE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_PROFILES), balance_started ? FALSE : TRUE);
            
            // usage
            
            CheckDlgButton(hwndDlg, IDC_USAGE, opts->flags & BTRFS_BALANCE_OPTS_USAGE ? BST_CHECKED : BST_UNCHECKED);
            
            _itow(opts->usage_start, s, 10);
            SetDlgItemTextW(hwndDlg, IDC_USAGE_START, s);
            SendMessageW(GetDlgItem(hwndDlg, IDC_USAGE_START_SPINNER), UDM_SETRANGE32, 0, 100);
            
            _itow(opts->usage_end, s, 10);
            SetDlgItemTextW(hwndDlg, IDC_USAGE_END, s);
            SendMessageW(GetDlgItem(hwndDlg, IDC_USAGE_END_SPINNER), UDM_SETRANGE32, 0, 100);
            
            EnableWindow(GetDlgItem(hwndDlg, IDC_USAGE_START), !balance_started && opts->flags & BTRFS_BALANCE_OPTS_USAGE ? TRUE : FALSE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_USAGE_START_SPINNER), !balance_started && opts->flags & BTRFS_BALANCE_OPTS_USAGE ? TRUE : FALSE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_USAGE_END), !balance_started && opts->flags & BTRFS_BALANCE_OPTS_USAGE ? TRUE : FALSE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_USAGE_END_SPINNER), !balance_started && opts->flags & BTRFS_BALANCE_OPTS_USAGE ? TRUE : FALSE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_USAGE), balance_started ? FALSE : TRUE);
            
            // devid
            
            if (num_devices < 2 || balance_started)
                EnableWindow(GetDlgItem(hwndDlg, IDC_DEVID), FALSE);

            CheckDlgButton(hwndDlg, IDC_DEVID, opts->flags & BTRFS_BALANCE_OPTS_DEVID ? BST_CHECKED : BST_UNCHECKED);
            EnableWindow(devcb, (opts->flags & BTRFS_BALANCE_OPTS_DEVID && num_devices >= 2 && !balance_started) ? TRUE : FALSE);
            
            // drange
            
            CheckDlgButton(hwndDlg, IDC_DRANGE, opts->flags & BTRFS_BALANCE_OPTS_DRANGE ? BST_CHECKED : BST_UNCHECKED);
            
            _itow(opts->drange_start, s, 10);
            SetDlgItemTextW(hwndDlg, IDC_DRANGE_START, s);
            
            _itow(opts->drange_end, s, 10);
            SetDlgItemTextW(hwndDlg, IDC_DRANGE_END, s);
            
            EnableWindow(GetDlgItem(hwndDlg, IDC_DRANGE_START), !balance_started && opts->flags & BTRFS_BALANCE_OPTS_DRANGE ? TRUE : FALSE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_DRANGE_END), !balance_started && opts->flags & BTRFS_BALANCE_OPTS_DRANGE ? TRUE : FALSE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_DRANGE), balance_started ? FALSE : TRUE);
            
            // vrange
            
            CheckDlgButton(hwndDlg, IDC_VRANGE, opts->flags & BTRFS_BALANCE_OPTS_VRANGE ? BST_CHECKED : BST_UNCHECKED);
            
            _itow(opts->vrange_start, s, 10);
            SetDlgItemTextW(hwndDlg, IDC_VRANGE_START, s);
            
            _itow(opts->vrange_end, s, 10);
            SetDlgItemTextW(hwndDlg, IDC_VRANGE_END, s);
            
            EnableWindow(GetDlgItem(hwndDlg, IDC_VRANGE_START), !balance_started && opts->flags & BTRFS_BALANCE_OPTS_VRANGE ? TRUE : FALSE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_VRANGE_END), !balance_started && opts->flags & BTRFS_BALANCE_OPTS_VRANGE ? TRUE : FALSE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_VRANGE), balance_started ? FALSE : TRUE);
            
            // limit
            
            CheckDlgButton(hwndDlg, IDC_LIMIT, opts->flags & BTRFS_BALANCE_OPTS_LIMIT ? BST_CHECKED : BST_UNCHECKED);
            
            _itow(opts->limit_start, s, 10);
            SetDlgItemTextW(hwndDlg, IDC_LIMIT_START, s);
            SendMessageW(GetDlgItem(hwndDlg, IDC_LIMIT_START_SPINNER), UDM_SETRANGE32, 0, 0x7fffffff);
            
            _itow(opts->limit_end, s, 10);
            SetDlgItemTextW(hwndDlg, IDC_LIMIT_END, s);
            SendMessageW(GetDlgItem(hwndDlg, IDC_LIMIT_END_SPINNER), UDM_SETRANGE32, 0, 0x7fffffff);
            
            EnableWindow(GetDlgItem(hwndDlg, IDC_LIMIT_START), !balance_started && opts->flags & BTRFS_BALANCE_OPTS_LIMIT ? TRUE : FALSE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_LIMIT_START_SPINNER), !balance_started && opts->flags & BTRFS_BALANCE_OPTS_LIMIT ? TRUE : FALSE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_LIMIT_END), !balance_started && opts->flags & BTRFS_BALANCE_OPTS_LIMIT ? TRUE : FALSE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_LIMIT_END_SPINNER), !balance_started && opts->flags & BTRFS_BALANCE_OPTS_LIMIT ? TRUE : FALSE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_LIMIT), balance_started ? FALSE : TRUE);
            
            // stripes
            
            CheckDlgButton(hwndDlg, IDC_STRIPES, opts->flags & BTRFS_BALANCE_OPTS_STRIPES ? BST_CHECKED : BST_UNCHECKED);
            
            _itow(opts->stripes_start, s, 10);
            SetDlgItemTextW(hwndDlg, IDC_STRIPES_START, s);
            SendMessageW(GetDlgItem(hwndDlg, IDC_STRIPES_START_SPINNER), UDM_SETRANGE32, 0, 0xffff);
            
            _itow(opts->stripes_end, s, 10);
            SetDlgItemTextW(hwndDlg, IDC_STRIPES_END, s);
            SendMessageW(GetDlgItem(hwndDlg, IDC_STRIPES_END_SPINNER), UDM_SETRANGE32, 0, 0xffff);
            
            EnableWindow(GetDlgItem(hwndDlg, IDC_STRIPES_START), !balance_started && opts->flags & BTRFS_BALANCE_OPTS_STRIPES ? TRUE : FALSE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_STRIPES_START_SPINNER), !balance_started && opts->flags & BTRFS_BALANCE_OPTS_STRIPES ? TRUE : FALSE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_STRIPES_END), !balance_started && opts->flags & BTRFS_BALANCE_OPTS_STRIPES ? TRUE : FALSE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_STRIPES_END_SPINNER), !balance_started && opts->flags & BTRFS_BALANCE_OPTS_STRIPES ? TRUE : FALSE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_STRIPES), balance_started ? FALSE : TRUE);
            
            // convert
            
            CheckDlgButton(hwndDlg, IDC_CONVERT, opts->flags & BTRFS_BALANCE_OPTS_CONVERT ? BST_CHECKED : BST_UNCHECKED);
            CheckDlgButton(hwndDlg, IDC_SOFT, opts->flags & BTRFS_BALANCE_OPTS_SOFT ? BST_CHECKED : BST_UNCHECKED);
            
            EnableWindow(GetDlgItem(hwndDlg, IDC_SOFT), !balance_started && opts->flags & BTRFS_BALANCE_OPTS_CONVERT ? TRUE : FALSE);
            EnableWindow(convcb, !balance_started && opts->flags & BTRFS_BALANCE_OPTS_CONVERT ? TRUE : FALSE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_CONVERT), balance_started ? FALSE : TRUE);
              
            break;
        }
        
        case WM_COMMAND:
            switch (HIWORD(wParam)) {
                case BN_CLICKED:
                    switch (LOWORD(wParam)) {
                        case IDOK:
                            if (balance_status != BTRFS_BALANCE_STOPPED)
                                EndDialog(hwndDlg, 0);
                            else
                                SaveBalanceOpts(hwndDlg);
                        return TRUE;
                        
                        case IDCANCEL:
                            EndDialog(hwndDlg, 0);
                        return TRUE;
                        
                        case IDC_PROFILES: {
                            BOOL enabled = IsDlgButtonChecked(hwndDlg, IDC_PROFILES) == BST_CHECKED ? TRUE : FALSE;
                            
                            EnableWindow(GetDlgItem(hwndDlg, IDC_PROFILES_SINGLE), enabled);
                            EnableWindow(GetDlgItem(hwndDlg, IDC_PROFILES_DUP), enabled);
                            EnableWindow(GetDlgItem(hwndDlg, IDC_PROFILES_RAID0), enabled);
                            EnableWindow(GetDlgItem(hwndDlg, IDC_PROFILES_RAID1), enabled);
                            EnableWindow(GetDlgItem(hwndDlg, IDC_PROFILES_RAID10), enabled);
                            EnableWindow(GetDlgItem(hwndDlg, IDC_PROFILES_RAID5), enabled);
                            EnableWindow(GetDlgItem(hwndDlg, IDC_PROFILES_RAID6), enabled);
                            break;
                        }
                        
                        case IDC_USAGE: {
                            BOOL enabled = IsDlgButtonChecked(hwndDlg, IDC_USAGE) == BST_CHECKED ? TRUE : FALSE;
                            
                            EnableWindow(GetDlgItem(hwndDlg, IDC_USAGE_START), enabled);
                            EnableWindow(GetDlgItem(hwndDlg, IDC_USAGE_START_SPINNER), enabled);
                            EnableWindow(GetDlgItem(hwndDlg, IDC_USAGE_END), enabled);
                            EnableWindow(GetDlgItem(hwndDlg, IDC_USAGE_END_SPINNER), enabled);
                            break;
                        }
                        
                        case IDC_DEVID: {
                            BOOL enabled = IsDlgButtonChecked(hwndDlg, IDC_DEVID) == BST_CHECKED ? TRUE : FALSE;
                            
                            EnableWindow(GetDlgItem(hwndDlg, IDC_DEVID_COMBO), enabled);
                            break;
                        }
                        
                        case IDC_DRANGE: {
                            BOOL enabled = IsDlgButtonChecked(hwndDlg, IDC_DRANGE) == BST_CHECKED ? TRUE : FALSE;
                            
                            EnableWindow(GetDlgItem(hwndDlg, IDC_DRANGE_START), enabled);
                            EnableWindow(GetDlgItem(hwndDlg, IDC_DRANGE_END), enabled);
                            break;
                        }
                        
                        case IDC_VRANGE: {
                            BOOL enabled = IsDlgButtonChecked(hwndDlg, IDC_VRANGE) == BST_CHECKED ? TRUE : FALSE;
                            
                            EnableWindow(GetDlgItem(hwndDlg, IDC_VRANGE_START), enabled);
                            EnableWindow(GetDlgItem(hwndDlg, IDC_VRANGE_END), enabled);
                            break;
                        }
                        
                        case IDC_LIMIT: {
                            BOOL enabled = IsDlgButtonChecked(hwndDlg, IDC_LIMIT) == BST_CHECKED ? TRUE : FALSE;
                            
                            EnableWindow(GetDlgItem(hwndDlg, IDC_LIMIT_START), enabled);
                            EnableWindow(GetDlgItem(hwndDlg, IDC_LIMIT_START_SPINNER), enabled);
                            EnableWindow(GetDlgItem(hwndDlg, IDC_LIMIT_END), enabled);
                            EnableWindow(GetDlgItem(hwndDlg, IDC_LIMIT_END_SPINNER), enabled);
                            break;
                        }
                        
                        case IDC_STRIPES: {
                            BOOL enabled = IsDlgButtonChecked(hwndDlg, IDC_STRIPES) == BST_CHECKED ? TRUE : FALSE;
                            
                            EnableWindow(GetDlgItem(hwndDlg, IDC_STRIPES_START), enabled);
                            EnableWindow(GetDlgItem(hwndDlg, IDC_STRIPES_START_SPINNER), enabled);
                            EnableWindow(GetDlgItem(hwndDlg, IDC_STRIPES_END), enabled);
                            EnableWindow(GetDlgItem(hwndDlg, IDC_STRIPES_END_SPINNER), enabled);
                            break;
                        }
                        
                        case IDC_CONVERT: {
                            BOOL enabled = IsDlgButtonChecked(hwndDlg, IDC_CONVERT) == BST_CHECKED ? TRUE : FALSE;
                            
                            EnableWindow(GetDlgItem(hwndDlg, IDC_CONVERT_COMBO), enabled);
                            EnableWindow(GetDlgItem(hwndDlg, IDC_SOFT), enabled);
                            break;
                        }
                    }
                break;
            }
        break;
    }
    
    return FALSE;
}

static INT_PTR CALLBACK stub_BalanceOptsDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    BtrfsVolPropSheet* bvps;
    
    if (uMsg == WM_INITDIALOG) {
        SetWindowLongPtr(hwndDlg, GWLP_USERDATA, (LONG_PTR)lParam);
        bvps = (BtrfsVolPropSheet*)lParam;
    } else {
        bvps = (BtrfsVolPropSheet*)GetWindowLongPtr(hwndDlg, GWLP_USERDATA);
    }
    
    if (bvps)
        return bvps->BalanceOptsDlgProc(hwndDlg, uMsg, wParam, lParam);
    else
        return FALSE;
}

void BtrfsVolPropSheet::ShowBalanceOptions(HWND hwndDlg, UINT8 type) {
    opts_type = type;
    DialogBoxParamW(module, MAKEINTRESOURCEW(IDD_BALANCE_OPTIONS), hwndDlg, stub_BalanceOptsDlgProc, (LPARAM)this);
}

INT_PTR CALLBACK BtrfsVolPropSheet::BalanceDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_INITDIALOG:
        {
            EnableThemeDialogTexture(hwndDlg, ETDT_ENABLETAB);
            
            RtlZeroMemory(&data_opts, sizeof(btrfs_balance_opts));
            RtlZeroMemory(&metadata_opts, sizeof(btrfs_balance_opts));
            RtlZeroMemory(&system_opts, sizeof(btrfs_balance_opts));
            
            balance_status = BTRFS_BALANCE_STOPPED;
            cancelling = FALSE;
            RefreshBalanceDlg(hwndDlg, TRUE);
            
            if (readonly) {
                EnableWindow(GetDlgItem(hwndDlg, IDC_START_BALANCE), FALSE);
                EnableWindow(GetDlgItem(hwndDlg, IDC_PAUSE_BALANCE), FALSE);
                EnableWindow(GetDlgItem(hwndDlg, IDC_CANCEL_BALANCE), FALSE);
            }
            
            SetTimer(hwndDlg, 1, 1000, NULL);
            
            break;
        }
        
        case WM_COMMAND:
            switch (HIWORD(wParam)) {
                case BN_CLICKED:
                    switch (LOWORD(wParam)) {
                        case IDOK:
                        case IDCANCEL:
                            KillTimer(hwndDlg, 1);
                            EndDialog(hwndDlg, 0);
                        return TRUE;
                        
                        case IDC_DATA:
                            EnableWindow(GetDlgItem(hwndDlg, IDC_DATA_OPTIONS), IsDlgButtonChecked(hwndDlg, IDC_DATA) == BST_CHECKED ? TRUE : FALSE);
                            
                            EnableWindow(GetDlgItem(hwndDlg, IDC_START_BALANCE), IsDlgButtonChecked(hwndDlg, IDC_DATA) == BST_CHECKED ||
                            IsDlgButtonChecked(hwndDlg, IDC_METADATA) == BST_CHECKED || IsDlgButtonChecked(hwndDlg, IDC_SYSTEM) == BST_CHECKED ? TRUE: FALSE); 
                        return TRUE;
                        
                        case IDC_METADATA:
                            EnableWindow(GetDlgItem(hwndDlg, IDC_METADATA_OPTIONS), IsDlgButtonChecked(hwndDlg, IDC_METADATA) == BST_CHECKED ? TRUE : FALSE);
                            
                            EnableWindow(GetDlgItem(hwndDlg, IDC_START_BALANCE), IsDlgButtonChecked(hwndDlg, IDC_DATA) == BST_CHECKED ||
                            IsDlgButtonChecked(hwndDlg, IDC_METADATA) == BST_CHECKED || IsDlgButtonChecked(hwndDlg, IDC_SYSTEM) == BST_CHECKED ? TRUE: FALSE);
                        return TRUE;
                        
                        case IDC_SYSTEM:
                            EnableWindow(GetDlgItem(hwndDlg, IDC_SYSTEM_OPTIONS), IsDlgButtonChecked(hwndDlg, IDC_SYSTEM) == BST_CHECKED ? TRUE : FALSE);
                            
                            EnableWindow(GetDlgItem(hwndDlg, IDC_START_BALANCE), IsDlgButtonChecked(hwndDlg, IDC_DATA) == BST_CHECKED ||
                            IsDlgButtonChecked(hwndDlg, IDC_METADATA) == BST_CHECKED || IsDlgButtonChecked(hwndDlg, IDC_SYSTEM) == BST_CHECKED ? TRUE: FALSE);
                        return TRUE;
                        
                        case IDC_DATA_OPTIONS:
                            ShowBalanceOptions(hwndDlg, 1);
                        return TRUE;
                        
                        case IDC_METADATA_OPTIONS:
                            ShowBalanceOptions(hwndDlg, 2);
                        return TRUE;
                        
                        case IDC_SYSTEM_OPTIONS:
                            ShowBalanceOptions(hwndDlg, 3);
                        return TRUE;
                        
                        case IDC_START_BALANCE:
                            StartBalance(hwndDlg);
                        return TRUE;
                        
                        case IDC_PAUSE_BALANCE:
                            PauseBalance(hwndDlg);
                            RefreshBalanceDlg(hwndDlg, FALSE);
                        return TRUE;
                        
                        case IDC_CANCEL_BALANCE:
                            StopBalance(hwndDlg);
                            RefreshBalanceDlg(hwndDlg, FALSE);
                        return TRUE;
                    }
                break;
            }
        break;
        
        case WM_TIMER:
            RefreshBalanceDlg(hwndDlg, FALSE);
            break;
    }
    
    return FALSE;
}

static INT_PTR CALLBACK stub_BalanceDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    BtrfsVolPropSheet* bvps;
    
    if (uMsg == WM_INITDIALOG) {
        SetWindowLongPtr(hwndDlg, GWLP_USERDATA, (LONG_PTR)lParam);
        bvps = (BtrfsVolPropSheet*)lParam;
    } else {
        bvps = (BtrfsVolPropSheet*)GetWindowLongPtr(hwndDlg, GWLP_USERDATA);
    }
    
    if (bvps)
        return bvps->BalanceDlgProc(hwndDlg, uMsg, wParam, lParam);
    else
        return FALSE;
}

void BtrfsVolPropSheet::ShowBalance(HWND hwndDlg) {
   DialogBoxParamW(module, MAKEINTRESOURCEW(IDD_BALANCE), hwndDlg, stub_BalanceDlgProc, (LPARAM)this);
}

static void add_lv_column(HWND list, int string, int cx) {
    LVCOLUMNW lvc;
    WCHAR s[255];
    
    if (!LoadStringW(module, string, s, sizeof(s) / sizeof(WCHAR))) {
        ShowError(GetParent(list), GetLastError());
        return;
    }
    
    lvc.mask = LVCF_TEXT|LVCF_WIDTH;
    lvc.pszText = s;
    lvc.cx = cx;
    SendMessageW(list, LVM_INSERTCOLUMNW, 0, (LPARAM)&lvc);
}

static int CALLBACK lv_sort(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort) {
    if (lParam1 < lParam2)
        return -1;
    else if (lParam1 > lParam2)
        return 1;
    else
        return 0;
}

static UINT64 find_dev_alloc(UINT64 dev_id, btrfs_usage* usage) {
    btrfs_usage* bue;
    UINT64 alloc;
    
    alloc = 0;
    
    bue = usage;
    while (TRUE) {
        UINT64 k;
        
        for (k = 0; k < bue->num_devices; k++) {
            if (bue->devices[k].dev_id == dev_id)
                alloc += bue->devices[k].alloc;
        }

        if (bue->next_entry > 0)
            bue = (btrfs_usage*)((UINT8*)bue + bue->next_entry);
        else
            break;
    }
    
    return alloc;
}

void BtrfsVolPropSheet::RefreshDevList(HWND devlist) {
    HANDLE h;
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    ULONG usagesize;
    btrfs_usage* usage;
    btrfs_device* bd = devices;
    int i;
    
    h = CreateFileW(fn, FILE_TRAVERSE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    
    if (h == INVALID_HANDLE_VALUE) {
        ShowError(GetParent(devlist), GetLastError());
        return;
    }

    i = 0;
    usagesize = 1024;
    
    usage = (btrfs_usage*)malloc(usagesize);

    while (TRUE) {
        Status = NtFsControlFile(h, NULL, NULL, NULL, &iosb, FSCTL_BTRFS_GET_USAGE, NULL, 0, usage, usagesize);
        if (Status == STATUS_BUFFER_OVERFLOW) {
            if (i < 8) {
                usagesize += 1024;
                
                free(usage);
                usage = (btrfs_usage*)malloc(usagesize);
                
                i++;
            } else {
                free(usage);
                CloseHandle(h);
                return;
            }
        } else
            break;
    }
    
    if (Status != STATUS_SUCCESS) {
        free(usage);
        CloseHandle(h);
        return;
    }

    CloseHandle(h);
    
    i = 0;
    while (TRUE) {
        LVITEMW lvi;
        WCHAR s[255];
        ULONG namelen;
        UINT64 alloc;
        
        // ID
        
        RtlZeroMemory(&lvi, sizeof(LVITEMW));
        lvi.mask = LVIF_TEXT | LVIF_PARAM;
        lvi.iItem = SendMessageW(devlist, LVM_GETITEMCOUNT, 0, 0);
        lvi.lParam = bd->dev_id;
        
        StringCchPrintfW(s, sizeof(s) / sizeof(WCHAR), L"%llu", bd->dev_id);
        lvi.pszText = s;

        SendMessageW(devlist, LVM_INSERTITEMW, 0, (LPARAM)&lvi);
        
        // name
        
        lvi.mask = LVIF_TEXT;
        lvi.iSubItem = 1;
        
        namelen = bd->namelen / sizeof(WCHAR);
        
        if (namelen > 254)
            namelen = 254;
        
        memcpy(s, bd->name, namelen * sizeof(WCHAR));
        s[namelen] = 0;
        lvi.pszText = s;
        
        SendMessageW(devlist, LVM_SETITEMW, 0, (LPARAM)&lvi);
        
        // readonly
        
        lvi.iSubItem = 2;
        LoadStringW(module, bd->readonly ? IDS_DEVLIST_READONLY_YES : IDS_DEVLIST_READONLY_NO, s, sizeof(s) / sizeof(WCHAR));
        lvi.pszText = s;
        SendMessageW(devlist, LVM_SETITEMW, 0, (LPARAM)&lvi);
        
        // size
        
        lvi.iSubItem = 3;
        format_size(bd->size, s, sizeof(s) / sizeof(WCHAR), FALSE);
        lvi.pszText = s;
        SendMessageW(devlist, LVM_SETITEMW, 0, (LPARAM)&lvi);
        
        // alloc
        
        alloc = find_dev_alloc(bd->dev_id, usage);
        
        lvi.iSubItem = 4;
        format_size(alloc, s, sizeof(s) / sizeof(WCHAR), FALSE);
        lvi.pszText = s;
        SendMessageW(devlist, LVM_SETITEMW, 0, (LPARAM)&lvi);
        
        // alloc %
        
        StringCchPrintfW(s, sizeof(s) / sizeof(WCHAR), L"%1.1f%%", (float)alloc * 100.0f / (float)bd->size);
        lvi.iSubItem = 5;
        lvi.pszText = s;
        SendMessageW(devlist, LVM_SETITEMW, 0, (LPARAM)&lvi);

        i++;
        
        if (bd->next_entry > 0)
            bd = (btrfs_device*)((UINT8*)bd + bd->next_entry);
        else
            break;
    }
    
    free(usage);
    
    SendMessageW(devlist, LVM_SORTITEMS, 0, (LPARAM)lv_sort);
}

INT_PTR CALLBACK BtrfsVolPropSheet::DeviceDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_INITDIALOG:
        {
            HWND devlist;
            
            EnableThemeDialogTexture(hwndDlg, ETDT_ENABLETAB);
            
            devlist = GetDlgItem(hwndDlg, IDC_DEVLIST);
            
            add_lv_column(devlist, IDS_DEVLIST_ALLOC_PC, 50);
            add_lv_column(devlist, IDS_DEVLIST_ALLOC, 60);
            add_lv_column(devlist, IDS_DEVLIST_SIZE, 60);
            add_lv_column(devlist, IDS_DEVLIST_READONLY, 70);
            add_lv_column(devlist, IDS_DEVLIST_NAME, 160);
            add_lv_column(devlist, IDS_DEVLIST_ID, 40);
            
            RefreshDevList(devlist);
            
            break;
        }
        
        case WM_COMMAND:
            switch (HIWORD(wParam)) {
                case BN_CLICKED:
                    switch (LOWORD(wParam)) {
                        case IDOK:
                        case IDCANCEL:
                            KillTimer(hwndDlg, 1);
                            EndDialog(hwndDlg, 0);
                        return TRUE;
                    }
                break;
            }
        break;
    }
    
    return FALSE;
}

static INT_PTR CALLBACK stub_DeviceDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    BtrfsVolPropSheet* bvps;
    
    if (uMsg == WM_INITDIALOG) {
        SetWindowLongPtr(hwndDlg, GWLP_USERDATA, (LONG_PTR)lParam);
        bvps = (BtrfsVolPropSheet*)lParam;
    } else {
        bvps = (BtrfsVolPropSheet*)GetWindowLongPtr(hwndDlg, GWLP_USERDATA);
    }
    
    if (bvps)
        return bvps->DeviceDlgProc(hwndDlg, uMsg, wParam, lParam);
    else
        return FALSE;
}

void BtrfsVolPropSheet::ShowDevices(HWND hwndDlg) {
   DialogBoxParamW(module, MAKEINTRESOURCEW(IDD_DEVICES), hwndDlg, stub_DeviceDlgProc, (LPARAM)this);
}

static INT_PTR CALLBACK PropSheetDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_INITDIALOG:
        {
            PROPSHEETPAGE* psp = (PROPSHEETPAGE*)lParam;
            BtrfsVolPropSheet* bps = (BtrfsVolPropSheet*)psp->lParam;
            btrfs_device* bd;
            
            EnableThemeDialogTexture(hwndDlg, ETDT_ENABLETAB);
            
            SetWindowLongPtr(hwndDlg, GWLP_USERDATA, (LONG_PTR)bps);

            bps->readonly = TRUE;
            bd = bps->devices;

            while (TRUE) {
                if (!bd->readonly) {
                    bps->readonly = FALSE;
                    break;
                }

                if (bd->next_entry > 0)
                    bd = (btrfs_device*)((UINT8*)bd + bd->next_entry);
                else
                    break;
            }

            return FALSE;
        }
        
        case WM_NOTIFY:
        {
            switch (((LPNMHDR)lParam)->code) {
                case PSN_KILLACTIVE:
                    SetWindowLongPtrW(hwndDlg, DWLP_MSGRESULT, FALSE);
                break;
            }
            break;
        }
        
        case WM_COMMAND:
        {
            BtrfsVolPropSheet* bps = (BtrfsVolPropSheet*)GetWindowLongPtr(hwndDlg, GWLP_USERDATA);
            
            if (bps) {
                switch (HIWORD(wParam)) {
                    case BN_CLICKED: {
                        switch (LOWORD(wParam)) {
                            case IDC_VOL_SHOW_USAGE:
                                bps->ShowUsage(hwndDlg);
                            break;
                            
                            case IDC_VOL_BALANCE:
                                bps->ShowBalance(hwndDlg);
//                                 bps->Balance(hwndDlg);
                            break;
                            
                            case IDC_VOL_DEVICES:
                                bps->ShowDevices(hwndDlg);
                            break;
                        }
                    }
                }
            }
            
            break;
        }
    }
    
    return FALSE;
}

HRESULT __stdcall BtrfsVolPropSheet::AddPages(LPFNADDPROPSHEETPAGE pfnAddPage, LPARAM lParam) {
    PROPSHEETPAGE psp;
    HPROPSHEETPAGE hPage;
    INITCOMMONCONTROLSEX icex;
    
    if (ignore)
        return S_OK;
    
    icex.dwSize = sizeof(icex);
    icex.dwICC = ICC_LINK_CLASS;
    
    if (!InitCommonControlsEx(&icex))
        MessageBoxW(NULL, L"InitCommonControlsEx failed", L"Error", MB_ICONERROR);
    
    psp.dwSize = sizeof(psp);
    psp.dwFlags = PSP_USEREFPARENT | PSP_USETITLE;
    psp.hInstance = module;
    psp.pszTemplate = MAKEINTRESOURCE(IDD_VOL_PROP_SHEET);
    psp.hIcon = 0;
    psp.pszTitle = MAKEINTRESOURCE(IDS_VOL_PROP_SHEET_TITLE);
    psp.pfnDlgProc = (DLGPROC)PropSheetDlgProc;
    psp.pcRefParent = (UINT*)&objs_loaded;
    psp.pfnCallback = NULL;
    psp.lParam = (LPARAM)this;

    hPage = CreatePropertySheetPage(&psp);
            
    if (hPage) {
        if (pfnAddPage(hPage, lParam)) {
            this->AddRef();
            return S_OK;
        } else
            DestroyPropertySheetPage(hPage);
    } else
        return E_OUTOFMEMORY;
    
    return E_FAIL;
}

HRESULT __stdcall BtrfsVolPropSheet::ReplacePage(UINT uPageID, LPFNADDPROPSHEETPAGE pfnReplacePage, LPARAM lParam) {
    return S_OK;
}
