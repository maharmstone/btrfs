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

#include <shlobj.h>
#include "../btrfsioctl.h"

extern LONG objs_loaded;

class BtrfsVolPropSheet : public IShellExtInit, IShellPropSheetExt {
public:
    BtrfsVolPropSheet() {
        refcount = 0;
        ignore = TRUE;
        stgm_set = FALSE;
        devices = NULL;
        usage = NULL;
        
        InterlockedIncrement(&objs_loaded);
    }

    virtual ~BtrfsVolPropSheet() {
        if (stgm_set) {
            GlobalUnlock(stgm.hGlobal);
            ReleaseStgMedium(&stgm);
        }
        
        if (devices)
            free(devices);
        
        if (usage)
            free(usage);
        
        InterlockedDecrement(&objs_loaded);
    }

    // IUnknown
    
    HRESULT __stdcall QueryInterface(REFIID riid, void **ppObj);
    
    ULONG __stdcall AddRef() {
        return InterlockedIncrement(&refcount);
    }

    ULONG __stdcall Release() {
        LONG rc = InterlockedDecrement(&refcount);
        
        if (rc == 0)
            delete this;
        
        return rc;
    }
    
    // IShellExtInit
    
    virtual HRESULT __stdcall Initialize(PCIDLIST_ABSOLUTE pidlFolder, IDataObject* pdtobj, HKEY hkeyProgID);
    
    // IShellPropSheetExt
    
    virtual HRESULT __stdcall AddPages(LPFNADDPROPSHEETPAGE pfnAddPage, LPARAM lParam);
    virtual HRESULT __stdcall ReplacePage(UINT uPageID, LPFNADDPROPSHEETPAGE pfnReplacePage, LPARAM lParam);
    
    void FormatUsage(HWND hwndDlg, WCHAR* s, ULONG size);
    void RefreshUsage(HWND hwndDlg);
    void ShowUsage(HWND hwndDlg);
    INT_PTR CALLBACK UsageDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
    void StartBalance(HWND hwndDlg);
    INT_PTR CALLBACK BalanceDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
    void ShowBalance(HWND hwndDlg);
    void RefreshBalanceDlg(HWND hwndDlg, BOOL first);
    void ShowBalanceOptions(HWND hwndDlg, UINT8 type);
    INT_PTR CALLBACK BalanceOptsDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
    void SaveBalanceOpts(HWND hwndDlg);
    void PauseBalance(HWND hwndDlg);
    void StopBalance(HWND hwndDlg);
    
    btrfs_device* devices;
    
private:
    LONG refcount;
    BOOL ignore;
    STGMEDIUM stgm;
    BOOL stgm_set;
    btrfs_usage* usage;
    WCHAR fn[MAX_PATH];
    UINT32 balance_status;
    btrfs_balance_opts data_opts, metadata_opts, system_opts;
    UINT8 opts_type;
    btrfs_query_balance bqb;
    BOOL cancelling;
};
