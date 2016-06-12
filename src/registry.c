#include "btrfs_drv.h"

extern UNICODE_STRING log_device, log_file, registry_path;

static WCHAR mounted[] = L"Mounted";

#define hex_digit(c) ((c) >= 0 && (c) <= 9) ? ((c) + '0') : ((c) - 10 + 'a')

NTSTATUS registry_mark_volume_mounted(BTRFS_UUID* uuid) {
    UNICODE_STRING path, mountedus;
    ULONG i, j;
    NTSTATUS Status;
    OBJECT_ATTRIBUTES oa;
    HANDLE h;
    DWORD data;
    
    path.Length = path.MaximumLength = registry_path.Length + (37 * sizeof(WCHAR));
    path.Buffer = ExAllocatePoolWithTag(PagedPool, path.Length, ALLOC_TAG);
    
    if (!path.Buffer) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    RtlCopyMemory(path.Buffer, registry_path.Buffer, registry_path.Length);
    i = registry_path.Length / sizeof(WCHAR);
    
    path.Buffer[i] = '\\';
    i++;
    
    for (j = 0; j < 16; j++) {
        path.Buffer[i] = hex_digit((uuid->uuid[j] & 0xF0) >> 4);
        path.Buffer[i+1] = hex_digit(uuid->uuid[j] & 0xF);
        
        i += 2;
        
        if (j == 3 || j == 5 || j == 7 || j == 9) {
            path.Buffer[i] = '-';
            i++;
        }
    }

    InitializeObjectAttributes(&oa, &path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    
    Status = ZwCreateKey(&h, KEY_SET_VALUE, &oa, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    if (!NT_SUCCESS(Status)) {
        ERR("ZwCreateKey returned %08x\n", Status);
        goto end;
    }
    
    mountedus.Buffer = mounted;
    mountedus.Length = mountedus.MaximumLength = wcslen(mounted) * sizeof(WCHAR);
    
    data = 1;
    
    Status = ZwSetValueKey(h, &mountedus, 0, REG_DWORD, &data, sizeof(DWORD));
    if (!NT_SUCCESS(Status)) {
        ERR("ZwSetValueKey returned %08x\n", Status);
        goto end2;
    }
        
    Status = STATUS_SUCCESS;

end2:
    ZwClose(h);
    
end:
    ExFreePool(path.Buffer);
    
    return Status;
}

static void reset_subkeys(HANDLE h) {
    NTSTATUS Status;
    KEY_BASIC_INFORMATION* kbi;
    ULONG kbilen = sizeof(KEY_BASIC_INFORMATION) - sizeof(WCHAR) + (255 * sizeof(WCHAR)), retlen, index = 0;
    
    kbi = ExAllocatePoolWithTag(PagedPool, kbilen, ALLOC_TAG);
    if (!kbi) {
        ERR("out of memory\n");
        return;
    }
    
    do {
        Status = ZwEnumerateKey(h, index, KeyBasicInformation, kbi, kbilen, &retlen);
        
        index++;
        
        if (NT_SUCCESS(Status)) {
            ERR("key: %.*S\n", kbi->NameLength / sizeof(WCHAR), kbi->Name);
            // FIXME - check name is GUID
            // FIXME - if any options there, set "Mounted" to 0. Otherwise delete whole key.
        } else if (Status != STATUS_NO_MORE_ENTRIES)
            ERR("ZwEnumerateKey returned %08x\n", Status);
    } while (NT_SUCCESS(Status));
    
    ExFreePool(kbi);
}

static void read_mappings(PUNICODE_STRING regpath) {
    WCHAR* path;
    UNICODE_STRING us;
    HANDLE h;
    OBJECT_ATTRIBUTES oa;
    ULONG dispos;
    NTSTATUS Status;
    ULONG kvfilen, retlen, i;
    KEY_VALUE_FULL_INFORMATION* kvfi;
    
    const WCHAR mappings[] = L"\\Mappings";
    
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
}

void STDCALL read_registry(PUNICODE_STRING regpath) {
    UNICODE_STRING us;
    OBJECT_ATTRIBUTES oa;
    NTSTATUS Status;
    HANDLE h;
    ULONG dispos;
    ULONG kvfilen;
    KEY_VALUE_FULL_INFORMATION* kvfi;
    
    static WCHAR def_log_file[] = L"\\??\\C:\\btrfs.log";
    
    read_mappings(regpath);
    
    InitializeObjectAttributes(&oa, regpath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    
    Status = ZwCreateKey(&h, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, &oa, 0, NULL, REG_OPTION_NON_VOLATILE, &dispos);
    
    if (!NT_SUCCESS(Status)) {
        ERR("ZwCreateKey returned %08x\n", Status);
        return;
    }
    
    reset_subkeys(h);
    
#ifdef _DEBUG
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
#endif
    
    ZwClose(h);
}
