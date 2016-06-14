#include "btrfs_drv.h"

extern UNICODE_STRING log_device, log_file;

void STDCALL read_registry(PUNICODE_STRING regpath) {
    HANDLE h;
    UNICODE_STRING us;
    OBJECT_ATTRIBUTES oa;
    ULONG dispos;
    NTSTATUS Status;
    WCHAR* path;
    ULONG kvfilen, retlen, i;
    KEY_VALUE_FULL_INFORMATION* kvfi;
    
    const WCHAR mappings[] = L"\\Mappings";
    static WCHAR def_log_file[] = L"\\??\\C:\\btrfs.log";
    
    path = ExAllocatePoolWithTag(PagedPool, regpath->Length + (wcslen(mappings) * sizeof(WCHAR)), ALLOC_TAG);
    if (!path) {
        ERR("out of memory\n");
        return;
    }
    
    RtlCopyMemory(path, regpath->Buffer, regpath->Length);
    RtlCopyMemory((UINT8*)path + regpath->Length, mappings, wcslen(mappings) * sizeof(WCHAR));
    
    us.Buffer = path;
    us.Length = us.MaximumLength = regpath->Length + ((USHORT)wcslen(mappings) * sizeof(WCHAR));
    
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    
    // FIXME - keep open and do notify for changes
    Status = ZwCreateKey(&h, KEY_QUERY_VALUE, &oa, 0, NULL, REG_OPTION_NON_VOLATILE, &dispos);
    
    if (!NT_SUCCESS(Status)) {
        ERR("ZwCreateKey returned %08x\n", Status);
        ExFreePool(path);
        return;
    }

    if (dispos == REG_OPENED_EXISTING_KEY) {
        kvfilen = sizeof(KEY_VALUE_FULL_INFORMATION) + 256;
        kvfi = ExAllocatePoolWithTag(PagedPool, kvfilen, ALLOC_TAG);
        
        if (!kvfi) {
            ERR("out of memory\n");
            ExFreePool(path);
            ZwClose(h);
            return;
        }
        
        i = 0;
        do {
            Status = ZwEnumerateValueKey(h, i, KeyValueFullInformation, kvfi, kvfilen, &retlen);
            
            if (NT_SUCCESS(Status) && kvfi->DataLength > 0) {
                UINT32 val = 0;
                
                RtlCopyMemory(&val, (UINT8*)kvfi + kvfi->DataOffset, min(kvfi->DataLength, sizeof(UINT32)));
                
                TRACE("entry %u = %.*S = %u\n", i, kvfi->NameLength / sizeof(WCHAR), kvfi->Name, val);
                
                add_user_mapping(kvfi->Name, kvfi->NameLength / sizeof(WCHAR), val);
            }
            
            i = i + 1;
        } while (Status != STATUS_NO_MORE_ENTRIES);
    }
    
    ZwClose(h);

    ExFreePool(path);
    
#ifdef _DEBUG
    InitializeObjectAttributes(&oa, regpath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    
    Status = ZwCreateKey(&h, KEY_QUERY_VALUE, &oa, 0, NULL, REG_OPTION_NON_VOLATILE, &dispos);
    
    if (!NT_SUCCESS(Status)) {
        ERR("ZwCreateKey returned %08x\n", Status);
        return;
    }
    
    RtlInitUnicodeString(&us, L"DebugLogLevel");
    
    kvfi = NULL;
    kvfilen = 0;
    Status = ZwQueryValueKey(h, &us, KeyValueFullInformation, kvfi, kvfilen, &kvfilen);
    
    if ((Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW) && kvfilen > 0) {
        kvfi = ExAllocatePoolWithTag(PagedPool, kvfilen, ALLOC_TAG);
        
        if (!kvfi) {
            ERR("out of memory\n");
            ZwClose(h);
            return;
        }
        
        Status = ZwQueryValueKey(h, &us, KeyValueFullInformation, kvfi, kvfilen, &kvfilen);
        
        if (NT_SUCCESS(Status)) {
            if (kvfi->Type == REG_DWORD && kvfi->DataLength >= sizeof(UINT32)) {
                RtlCopyMemory(&debug_log_level, ((UINT8*)kvfi) + kvfi->DataOffset, sizeof(UINT32));
            } else {
                Status = ZwDeleteValueKey(h, &us);
                if (!NT_SUCCESS(Status)) {
                    ERR("ZwDeleteValueKey returned %08x\n", Status);
                }

                Status = ZwSetValueKey(h, &us, 0, REG_DWORD, &debug_log_level, sizeof(debug_log_level));
                if (!NT_SUCCESS(Status)) {
                    ERR("ZwSetValueKey reutrned %08x\n", Status);
                }
            }
        }
        
        ExFreePool(kvfi);
    } else if (Status == STATUS_OBJECT_NAME_NOT_FOUND) {
        Status = ZwSetValueKey(h, &us, 0, REG_DWORD, &debug_log_level, sizeof(debug_log_level));
        
        if (!NT_SUCCESS(Status)) {
            ERR("ZwSetValueKey reutrned %08x\n", Status);
        }
    } else {
        ERR("ZwQueryValueKey returned %08x\n", Status);
    }
    
    RtlInitUnicodeString(&us, L"LogDevice");
    
    kvfi = NULL;
    kvfilen = 0;
    Status = ZwQueryValueKey(h, &us, KeyValueFullInformation, kvfi, kvfilen, &kvfilen);
    
    if ((Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW) && kvfilen > 0) {
        kvfi = ExAllocatePoolWithTag(PagedPool, kvfilen, ALLOC_TAG);
        
        if (!kvfi) {
            ERR("out of memory\n");
            ZwClose(h);
            return;
        }
        
        Status = ZwQueryValueKey(h, &us, KeyValueFullInformation, kvfi, kvfilen, &kvfilen);
        
        if (NT_SUCCESS(Status)) {
            if ((kvfi->Type == REG_SZ || kvfi->Type == REG_EXPAND_SZ) && kvfi->DataLength >= sizeof(WCHAR)) {
                log_device.Length = log_device.MaximumLength = kvfi->DataLength;
                log_device.Buffer = ExAllocatePoolWithTag(PagedPool, kvfi->DataLength, ALLOC_TAG);
                
                if (!log_device.Buffer) {
                    ERR("out of memory\n");
                    ExFreePool(kvfi);
                    ZwClose(h);
                    return;
                }

                RtlCopyMemory(log_device.Buffer, ((UINT8*)kvfi) + kvfi->DataOffset, kvfi->DataLength);
                
                if (log_device.Buffer[(log_device.Length / sizeof(WCHAR)) - 1] == 0)
                    log_device.Length -= sizeof(WCHAR);
            } else {
                ERR("LogDevice was type %u, length %u\n", kvfi->Type, kvfi->DataLength);
                
                Status = ZwDeleteValueKey(h, &us);
                if (!NT_SUCCESS(Status)) {
                    ERR("ZwDeleteValueKey returned %08x\n", Status);
                }
            }
        }
        
        ExFreePool(kvfi);
    } else if (Status != STATUS_OBJECT_NAME_NOT_FOUND) {
        ERR("ZwQueryValueKey returned %08x\n", Status);
    }
    
    RtlInitUnicodeString(&us, L"LogFile");
    
    kvfi = NULL;
    kvfilen = 0;
    Status = ZwQueryValueKey(h, &us, KeyValueFullInformation, kvfi, kvfilen, &kvfilen);
    
    if ((Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW) && kvfilen > 0) {
        kvfi = ExAllocatePoolWithTag(PagedPool, kvfilen, ALLOC_TAG);
        
        if (!kvfi) {
            ERR("out of memory\n");
            ZwClose(h);
            return;
        }
        
        Status = ZwQueryValueKey(h, &us, KeyValueFullInformation, kvfi, kvfilen, &kvfilen);
        
        if (NT_SUCCESS(Status)) {
            if ((kvfi->Type == REG_SZ || kvfi->Type == REG_EXPAND_SZ) && kvfi->DataLength >= sizeof(WCHAR)) {
                log_file.Length = log_file.MaximumLength = kvfi->DataLength;
                log_file.Buffer = ExAllocatePoolWithTag(PagedPool, kvfi->DataLength, ALLOC_TAG);
                
                if (!log_file.Buffer) {
                    ERR("out of memory\n");
                    ExFreePool(kvfi);
                    ZwClose(h);
                    return;
                }

                RtlCopyMemory(log_file.Buffer, ((UINT8*)kvfi) + kvfi->DataOffset, kvfi->DataLength);
                
                if (log_file.Buffer[(log_file.Length / sizeof(WCHAR)) - 1] == 0)
                    log_file.Length -= sizeof(WCHAR);
            } else {
                ERR("LogFile was type %u, length %u\n", kvfi->Type, kvfi->DataLength);
                
                Status = ZwDeleteValueKey(h, &us);
                if (!NT_SUCCESS(Status)) {
                    ERR("ZwDeleteValueKey returned %08x\n", Status);
                }
            }
        }
        
        ExFreePool(kvfi);
    } else if (Status == STATUS_OBJECT_NAME_NOT_FOUND) {
        Status = ZwSetValueKey(h, &us, 0, REG_SZ, def_log_file, (wcslen(def_log_file) + 1) * sizeof(WCHAR));
        
        if (!NT_SUCCESS(Status)) {
            ERR("ZwSetValueKey returned %08x\n", Status);
        }
    } else {
        ERR("ZwQueryValueKey returned %08x\n", Status);
    }
    
    if (log_file.Length == 0) {
        log_file.Length = log_file.MaximumLength = wcslen(def_log_file) * sizeof(WCHAR);
        log_file.Buffer = ExAllocatePoolWithTag(PagedPool, log_file.MaximumLength, ALLOC_TAG);
        
        if (!log_file.Buffer) {
            ERR("out of memory\n");
            ZwClose(h);
            return;
        }
        
        RtlCopyMemory(log_file.Buffer, def_log_file, log_file.Length);
    }
    
    ZwClose(h);
#endif
}
