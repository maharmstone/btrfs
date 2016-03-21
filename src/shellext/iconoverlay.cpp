#include <windows.h>
#include "iconoverlay.h"

extern HMODULE module;

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
    WCHAR dllpath[MAX_PATH];
    
    GetModuleFileNameW(module, dllpath, sizeof(dllpath));
    
    if (cchMax < wcslen(dllpath))
        return E_INVALIDARG;
    
    if (!pIndex)
        return E_INVALIDARG;
    
    if (!pdwFlags)
        return E_INVALIDARG;
    
    wcscpy(pwszIconFile, dllpath);
    *pIndex = 0;
    *pdwFlags = ISIOI_ICONFILE | ISIOI_ICONINDEX;
    
    return S_OK;
}

HRESULT __stdcall BtrfsIconOverlay::GetPriority(int *pPriority) {
    if (!pPriority)
        return E_INVALIDARG;
    
    *pPriority = 0;
    
    return S_OK;
}

HRESULT __stdcall BtrfsIconOverlay::IsMemberOf(PCWSTR pwszPath, DWORD dwAttrib) {
    // FIXME
    
    return S_OK;
}
