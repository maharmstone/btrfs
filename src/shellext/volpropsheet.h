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
    
private:
    LONG refcount;
    BOOL ignore;
    STGMEDIUM stgm;
    BOOL stgm_set;
    btrfs_device* devices;
    btrfs_usage* usage;
    WCHAR fn[MAX_PATH];
};
