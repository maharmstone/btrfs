#define _WIN32_WINNT 0x0600

#include <windows.h>

static const GUID CLSID_ShellBtrfs = { 0x2690b74f, 0xf353, 0x422d, { 0xbb, 0x12, 0x40, 0x15, 0x81, 0xee, 0xf8, 0xf9 } };

#define COM_DESCRIPTION L"WinBtrfs shell extension"

HMODULE module;

#ifdef __cplusplus
extern "C" {
#endif

STDAPI __declspec(dllexport) DllCanUnloadNow(void) {
    // FIXME
    return E_FAIL;
}

STDAPI __declspec(dllexport) DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv) {
    // FIXME
    return E_FAIL;
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

STDAPI __declspec(dllexport) DllRegisterServer(void) {
    if (!register_clsid(CLSID_ShellBtrfs, COM_DESCRIPTION))
        return E_FAIL;
    
    return S_OK;
}

STDAPI __declspec(dllexport) DllUnregisterServer(void) {
    if (!unregister_clsid(CLSID_ShellBtrfs))
        return E_FAIL;

    return S_OK;
}

STDAPI __declspec(dllexport) DllInstall(BOOL bInstall, LPCWSTR pszCmdLine) {
    // FIXME
    
    return E_FAIL;
}

BOOL APIENTRY __declspec(dllexport) DllMain(HANDLE hModule, DWORD dwReason, void* lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH)
        module = (HMODULE)hModule;
        
    return TRUE;
}


#ifdef __cplusplus
}
#endif
