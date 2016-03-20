#define _WIN32_WINNT 0x0600

#include <windows.h>
#include "factory.h"

static const GUID CLSID_ShellBtrfs = { 0x2690b74f, 0xf353, 0x422d, { 0xbb, 0x12, 0x40, 0x15, 0x81, 0xee, 0xf8, 0xf9 } };

#define COM_DESCRIPTION L"WinBtrfs shell extension"
#define ICON_OVERLAY_NAME L"WinBtrfs"

HMODULE module;
LONG objs_loaded = 0;

#ifdef __cplusplus
extern "C" {
#endif

STDAPI DllCanUnloadNow(void) {
    return objs_loaded == 0 ? S_OK : S_FALSE;
}

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv) {
    if (rclsid == CLSID_ShellBtrfs) {
        Factory* fact = new Factory;
        if (!fact)
            return E_OUTOFMEMORY;
        else
            return fact->QueryInterface(riid, ppv);
    }

    return CLASS_E_CLASSNOTAVAILABLE;
}

static BOOL write_reg_key(HKEY root, const WCHAR* keyname, const WCHAR* val, DWORD type, const BYTE* data, DWORD datasize) {
    LONG l;
    HKEY hk;
    DWORD dispos;
   
    l = RegCreateKeyExW(root, keyname, NULL, NULL, 0, KEY_ALL_ACCESS, NULL, &hk, &dispos);
    if (l != ERROR_SUCCESS) {
        WCHAR s[255];
        wsprintfW(s, L"RegCreateKey returned %08x", l);
        MessageBoxW(0, s, NULL, MB_ICONERROR);
        
        return FALSE;
    }

    l = RegSetValueExW(hk, val, NULL, type, data, datasize);
    if (l != ERROR_SUCCESS) {
        WCHAR s[255];
        wsprintfW(s, L"RegSetValueEx returned %08x", l);
        MessageBoxW(0, s, NULL, MB_ICONERROR);
        
        return FALSE;
    }
    
    l = RegCloseKey(hk);
    if (l != ERROR_SUCCESS) {
        WCHAR s[255];
        wsprintfW(s, L"RegCloseKey returned %08x", l);
        MessageBoxW(0, s, NULL, MB_ICONERROR);
        
        return FALSE;
    }
    
    return TRUE;
}

static BOOL register_clsid(const GUID clsid, const WCHAR* description) {
    WCHAR* clsidstring;
    WCHAR inproc[MAX_PATH], progid[MAX_PATH], clsidkeyname[MAX_PATH], dllpath[MAX_PATH];
    BOOL ret = FALSE;
    
    StringFromCLSID(clsid, &clsidstring);
    
    wsprintfW(inproc, L"CLSID\\%s\\InprocServer32", clsidstring);
    wsprintfW(progid, L"CLSID\\%s\\ProgId", clsidstring);
    wsprintfW(clsidkeyname, L"CLSID\\%s", clsidstring);
    
    if (!write_reg_key(HKEY_CLASSES_ROOT, clsidkeyname, NULL, REG_SZ, (BYTE*)description, (wcslen(description) + 1) * sizeof(WCHAR)))
        goto end;
    
    GetModuleFileNameW(module, dllpath, sizeof(dllpath));
    
    if (!write_reg_key(HKEY_CLASSES_ROOT, inproc, NULL, REG_SZ, (BYTE*)dllpath, (wcslen(dllpath) + 1) * sizeof(WCHAR)))
        goto end;
    
    if (!write_reg_key(HKEY_CLASSES_ROOT, inproc, L"ThreadingModel", REG_SZ, (BYTE*)L"Apartment", (wcslen(L"Apartment") + 1) * sizeof(WCHAR)))
        goto end;
    
    ret = TRUE;
    
end:
    CoTaskMemFree(clsidstring);

    return ret;
}

static BOOL unregister_clsid(const GUID clsid) {
    WCHAR* clsidstring;
    WCHAR clsidkeyname[MAX_PATH];
    BOOL ret = FALSE;
    LONG l;
    
    StringFromCLSID(clsid, &clsidstring);
    wsprintfW(clsidkeyname, L"CLSID\\%s", clsidstring);
    
    l = RegDeleteTreeW(HKEY_CLASSES_ROOT, clsidkeyname);
    
    if (l != ERROR_SUCCESS) {
        WCHAR s[255];
        wsprintfW(s, L"RegDeleteTree returned %08x", l);
        MessageBoxW(0, s, NULL, MB_ICONERROR);
        
        ret = FALSE;
    } else    
        ret = TRUE;
    
    CoTaskMemFree(clsidstring);

    return ret;
}

static BOOL reg_icon_overlay(const GUID clsid, const WCHAR* name) {
    WCHAR path[MAX_PATH];
    WCHAR* clsidstring;
    BOOL ret = FALSE;
    
    StringFromCLSID(clsid, &clsidstring);
    
    wcscpy(path, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers\\");
    wcscat(path, name);
    
    if (!write_reg_key(HKEY_LOCAL_MACHINE, path, NULL, REG_SZ, (BYTE*)clsidstring, (wcslen(clsidstring) + 1) * sizeof(WCHAR)))
        goto end;

    ret = TRUE;
    
end:
    CoTaskMemFree(clsidstring);

    return ret;
}

static BOOL unreg_icon_overlay(const WCHAR* name) {
    WCHAR path[MAX_PATH];
    LONG l;
    
    wcscpy(path, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers\\");
    wcscat(path, name);
    
    l = RegDeleteTreeW(HKEY_LOCAL_MACHINE, path);
    
    if (l != ERROR_SUCCESS) {
        WCHAR s[255];
        wsprintfW(s, L"RegDeleteTree returned %08x", l);
        MessageBoxW(0, s, NULL, MB_ICONERROR);
        
        return FALSE;
    } else    
        return TRUE;
}

STDAPI DllRegisterServer(void) {
    if (!register_clsid(CLSID_ShellBtrfs, COM_DESCRIPTION))
        return E_FAIL;
    
    if (!reg_icon_overlay(CLSID_ShellBtrfs, ICON_OVERLAY_NAME)) {
        MessageBoxW(0, L"Failed to register icon overlay.", NULL, MB_ICONERROR);
        return E_FAIL;
    }
    
    return S_OK;
}

STDAPI DllUnregisterServer(void) {
    unreg_icon_overlay(ICON_OVERLAY_NAME);
    
    if (!unregister_clsid(CLSID_ShellBtrfs))
        return E_FAIL;

    return S_OK;
}

STDAPI DllInstall(BOOL bInstall, LPCWSTR pszCmdLine) {
    if (bInstall)
        return DllRegisterServer();
    else
        return DllUnregisterServer();
}

BOOL APIENTRY DllMain(HANDLE hModule, DWORD dwReason, void* lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH)
        module = (HMODULE)hModule;
        
    return TRUE;
}


#ifdef __cplusplus
}
#endif
