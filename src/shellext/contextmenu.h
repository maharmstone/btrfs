#include <shlobj.h>

extern LONG objs_loaded;

class BtrfsContextMenu : public IShellExtInit, IContextMenu {
public:
    BtrfsContextMenu() {
        refcount = 0;
        InterlockedIncrement(&objs_loaded);
    }

    virtual ~BtrfsContextMenu() {
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
    
    // IContextMenu
    
    virtual HRESULT __stdcall QueryContextMenu(HMENU hmenu, UINT indexMenu, UINT idCmdFirst, UINT idCmdLast, UINT uFlags);
    virtual HRESULT __stdcall InvokeCommand(LPCMINVOKECOMMANDINFO pici);
    virtual HRESULT __stdcall GetCommandString(UINT_PTR idCmd, UINT uFlags, UINT* pwReserved, LPSTR pszName, UINT cchMax);

private:
    LONG refcount;
};
