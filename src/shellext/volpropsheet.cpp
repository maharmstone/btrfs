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

#define BLOCK_FLAG_DATA         0x001
#define BLOCK_FLAG_SYSTEM       0x002
#define BLOCK_FLAG_METADATA     0x004
#define BLOCK_FLAG_RAID0        0x008
#define BLOCK_FLAG_RAID1        0x010
#define BLOCK_FLAG_DUPLICATE    0x020
#define BLOCK_FLAG_RAID10       0x040
#define BLOCK_FLAG_RAID5        0x080
#define BLOCK_FLAG_RAID6        0x100

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
    WCHAR fn[MAX_PATH];
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
                        return E_FAIL;
                } else
                    break;
            }
            
            if (Status != STATUS_SUCCESS) {
                CloseHandle(h);
                return E_FAIL;
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
        } else {
            CloseHandle(h);
            return E_FAIL;
        }
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

void BtrfsVolPropSheet::FormatUsage(HWND hwndDlg, WCHAR* s, ULONG size) {
    UINT8 i, j;
    UINT64 num_devs, k;
    btrfs_device* bd;
    dev* devs = NULL;
    btrfs_usage* bue;
    WCHAR t[255];
    
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
    
    while (TRUE) {
        devs[k].dev_id = bd->dev_id;
        devs[k].namelen = bd->namelen;
        devs[k].name = bd->name;
        devs[k].alloc = 0;
        devs[k].size = bd->size;
        
        k++;
        
        if (bd->next_entry > 0)
            bd = (btrfs_device*)((UINT8*)bd + bd->next_entry);
        else
            break;
    }
    
    // FIXME - show header
    
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

static INT_PTR CALLBACK PropSheetDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_INITDIALOG:
        {
            PROPSHEETPAGE* psp = (PROPSHEETPAGE*)lParam;
            BtrfsVolPropSheet* bps = (BtrfsVolPropSheet*)psp->lParam;
            WCHAR s[4096];
            
            EnableThemeDialogTexture(hwndDlg, ETDT_ENABLETAB);
            
            SetWindowLongPtr(hwndDlg, GWLP_USERDATA, (LONG_PTR)bps);
            
            bps->FormatUsage(hwndDlg, s, sizeof(s) / sizeof(WCHAR));
            
            SetDlgItemTextW(hwndDlg, IDC_USAGE_BOX, s);

            return FALSE;
        }
        
        case WM_NOTIFY:
        {
            switch (((LPNMHDR)lParam)->code) {
                case PSN_KILLACTIVE:
                    SetWindowLongPtrW(hwndDlg, DWLP_MSGRESULT, FALSE);
                break;
            }
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
