#include <windows.h>
#include <strsafe.h>
#include <winternl.h>
#include <shlwapi.h>
#include <uxtheme.h>

#include "propsheet.h"
#include "resource.h"

extern HMODULE module;

HRESULT __stdcall BtrfsPropSheet::QueryInterface(REFIID riid, void **ppObj) {
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

HRESULT __stdcall BtrfsPropSheet::Initialize(PCIDLIST_ABSOLUTE pidlFolder, IDataObject* pdtobj, HKEY hkeyProgID) {
    return S_OK;
}

static INT_PTR CALLBACK PropSheetDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_INITDIALOG:
            EnableThemeDialogTexture(hwndDlg, ETDT_ENABLETAB);
            return FALSE;
    }
    
    return FALSE;
}

HRESULT __stdcall BtrfsPropSheet::AddPages(LPFNADDPROPSHEETPAGE pfnAddPage, LPARAM lParam) {
    PROPSHEETPAGE  psp;
    HPROPSHEETPAGE hPage;
    
    psp.dwSize = sizeof(psp);
    psp.dwFlags = PSP_USEREFPARENT | PSP_USETITLE;
    psp.hInstance = module;
    psp.pszTemplate = MAKEINTRESOURCE(IDD_PROP_SHEET);
    psp.hIcon = 0;
    psp.pszTitle = MAKEINTRESOURCE(IDS_PROP_SHEET_TITLE);
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

HRESULT __stdcall BtrfsPropSheet::ReplacePage(UINT uPageID, LPFNADDPROPSHEETPAGE pfnReplacePage, LPARAM lParam) {
    return S_OK;
}
