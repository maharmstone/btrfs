#include <shlobj.h>

extern LONG objs_loaded;

class BtrfsPropSheet : public IShellExtInit, IShellPropSheetExt {
public:
    BtrfsPropSheet() {
        refcount = 0;
        InterlockedIncrement(&objs_loaded);
    }

    virtual ~BtrfsPropSheet() {
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
 
private:
    LONG refcount;
};
