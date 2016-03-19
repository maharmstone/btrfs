#include <windows.h>
#include "iconoverlay.h"

HRESULT __stdcall BtrfsIconOverlay::QueryInterface(REFIID riid, void **ppObj) {
    if (riid == IID_IUnknown || riid == IID_IShellIconOverlayIdentifier) {
        *ppObj = static_cast<IShellIconOverlayIdentifier*>(this); 
        AddRef();
        return S_OK;
    }

    *ppObj = NULL;
    return E_NOINTERFACE;
}

HRESULT __stdcall BtrfsIconOverlay::GetOverlayInfo(PWSTR pwszIconFile, int cchMax, int* pIndex, DWORD* pdwFlags) {
    MessageBoxW(0, L"BtrfsIconOverlay::GetOverlayInfo", NULL, 0);
    return E_FAIL;
}

HRESULT __stdcall BtrfsIconOverlay::GetPriority(int *pPriority) {
    MessageBoxW(0, L"BtrfsIconOverlay::GetPriority", NULL, 0);
    return E_FAIL;
}

HRESULT __stdcall BtrfsIconOverlay::IsMemberOf(PCWSTR pwszPath, DWORD dwAttrib) {
    MessageBoxW(0, L"BtrfsIconOverlay::IsMemberOf", NULL, 0);
    return E_FAIL;
}
