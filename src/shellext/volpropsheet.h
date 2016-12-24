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
#include "balance.h"

extern LONG objs_loaded;

class BtrfsVolPropSheet : public IShellExtInit, IShellPropSheetExt {
public:
    BtrfsVolPropSheet() {
        refcount = 0;
        ignore = TRUE;
        stgm_set = FALSE;
        devices = NULL;
        
        InterlockedIncrement(&objs_loaded);
        
        balance = NULL;
    }

    virtual ~BtrfsVolPropSheet() {
        if (stgm_set) {
            GlobalUnlock(stgm.hGlobal);
            ReleaseStgMedium(&stgm);
        }
        
        if (devices)
            free(devices);
        
        InterlockedDecrement(&objs_loaded);
        
        if (balance)
            delete balance;
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
    
    void FormatUsage(HWND hwndDlg, WCHAR* s, ULONG size, btrfs_usage* usage);
    void RefreshUsage(HWND hwndDlg);
    void ShowUsage(HWND hwndDlg);
    INT_PTR CALLBACK UsageDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
    void RefreshDevList(HWND devlist);
    INT_PTR CALLBACK DeviceDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
    void ShowDevices(HWND hwndDlg);
    
    btrfs_device* devices;
    BOOL readonly;
    BtrfsBalance* balance;
    
private:
    LONG refcount;
    BOOL ignore;
    STGMEDIUM stgm;
    BOOL stgm_set;
    WCHAR fn[MAX_PATH];
};
