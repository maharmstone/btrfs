#include <windows.h>
#include "factory.h"
#include "iconoverlay.h"
#include "contextmenu.h"
#include "propsheet.h"

HRESULT __stdcall Factory::QueryInterface(const IID& iid, void** ppv) {    
    if (iid == IID_IUnknown || iid == IID_IClassFactory) {
        *ppv = static_cast<IClassFactory*>(this);
    } else {
        *ppv = NULL;
        return E_NOINTERFACE;
    }

    reinterpret_cast<IUnknown*>(*ppv)->AddRef();

    return S_OK;
}

HRESULT __stdcall Factory::LockServer(BOOL bLock) {
    return E_NOTIMPL;
}

HRESULT __stdcall Factory::CreateInstance(IUnknown* pUnknownOuter, const IID& iid, void** ppv) {
    if (pUnknownOuter)
        return CLASS_E_NOAGGREGATION;

    switch (type) {
        case FactoryIconHandler:
            if (iid == IID_IUnknown || iid == IID_IShellIconOverlayIdentifier) {
                BtrfsIconOverlay* bio = new BtrfsIconOverlay;
                if (!bio)
                    return E_OUTOFMEMORY;

                return bio->QueryInterface(iid, ppv);
            }
            break;
            
        case FactoryContextMenu:
            if (iid == IID_IUnknown || iid == IID_IContextMenu || iid == IID_IShellExtInit) {
                BtrfsContextMenu* bcm = new BtrfsContextMenu;
                if (!bcm)
                    return E_OUTOFMEMORY;
                
                return bcm->QueryInterface(iid, ppv);
            }
            break;
            
        case FactoryPropSheet:
            if (iid == IID_IUnknown || iid == IID_IShellPropSheetExt || iid == IID_IShellExtInit) {
                BtrfsPropSheet* bps = new BtrfsPropSheet;
                if (!bps)
                    return E_OUTOFMEMORY;
                
                return bps->QueryInterface(iid, ppv);
            }
            break;
            
        default:
            break;
    }
    
    *ppv = NULL;
    return E_NOINTERFACE;
}
