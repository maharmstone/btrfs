#include "shellext.h"
#include "resource.h"
#include <windows.h>
#include <commctrl.h>
#include <sddl.h>
#include <ntstatus.h>
#define _NTDEF_
#include <ntsecapi.h>
#include <stdexcept>
#include <format>
#include <memory>
#include <span>
#include <array>

using namespace std;

static const WCHAR UID_REG_PATH[] = L"SYSTEM\\CurrentControlSet\\Services\\btrfs\\Mappings";
static const WCHAR GID_REG_PATH[] = L"SYSTEM\\CurrentControlSet\\Services\\btrfs\\GroupMappings";

class formatted_error : public exception {
public:
    template<typename... Args>
    formatted_error(string_view s, Args&&... args) : msg(vformat(s, make_format_args(args...))) {
    }

    const char* what() const noexcept {
        return msg.c_str();
    }

private:
    string msg;
};

class lsa_handle_closer {
public:
    using pointer = LSA_HANDLE;

    void operator()(LSA_HANDLE h) {
        LsaClose(h);
    }
};

using unique_lsa_handle = unique_ptr<LSA_HANDLE, lsa_handle_closer>;

template<typename T>
class lsa_pointer_freer {
public:
    using pointer = T;

    void operator()(T ptr) {
        LsaFreeMemory(ptr);
    }
};

using unique_lsa_translated_name = unique_ptr<LSA_TRANSLATED_NAME, lsa_pointer_freer<LSA_TRANSLATED_NAME*>>;
using unique_lsa_referenced_domain_list = unique_ptr<LSA_REFERENCED_DOMAIN_LIST, lsa_pointer_freer<LSA_REFERENCED_DOMAIN_LIST*>>;

class hkey_closer {
public:
    using pointer = HKEY;

    void operator()(HKEY key) {
        RegCloseKey(key);
    }
};

using unique_hkey = unique_ptr<HKEY, hkey_closer>;

template<typename T>
class local_freer {
public:
    using pointer = T;

    void operator()(T ptr) {
        LocalFree(ptr);
    }
};

using unique_sid = unique_ptr<PSID, local_freer<PSID>>;

struct mapping_entry {
    unique_sid sid;
    DWORD value;
    u16string domain;
    u16string name;
    SID_NAME_USE use;
};

static unique_lsa_handle lsa_open_policy(ACCESS_MASK access) {
    LSA_OBJECT_ATTRIBUTES oa;
    NTSTATUS Status;
    LSA_HANDLE h;

    memset(&oa, 0, sizeof(oa));

    Status = LsaOpenPolicy(nullptr, &oa, access, &h);

    if (Status != STATUS_SUCCESS)
        throw formatted_error("LsaOpenPolicy returned {:08x}", (uint32_t)Status);

    return unique_lsa_handle{h};
}

static void lsa_lookup_sids(LSA_HANDLE h, span<const PSID> sids,
                            unique_lsa_translated_name& names,
                            unique_lsa_referenced_domain_list& domains) {
    NTSTATUS Status;
    LSA_REFERENCED_DOMAIN_LIST* domains_ptr;
    LSA_TRANSLATED_NAME* names_ptr;

    Status = LsaLookupSids(h, sids.size(), (PSID*)sids.data(),
                           &domains_ptr, &names_ptr);
    if (Status != STATUS_SUCCESS && Status != STATUS_NONE_MAPPED && Status != STATUS_SOME_NOT_MAPPED)
        throw formatted_error("LsaLookupSids returned {:08x}", (uint32_t)Status);

    names.reset(names_ptr);
    domains.reset(domains_ptr);
}

static void resolve_names(span<mapping_entry> entries) {
    if (entries.empty())
        return;

    vector<PSID> sids;
    auto h = lsa_open_policy(POLICY_LOOKUP_NAMES);

    sids.reserve(entries.size());

    for (const auto& ent : entries) {
        sids.push_back(ent.sid.get());
    }

    unique_lsa_translated_name names;
    unique_lsa_referenced_domain_list domains;

    lsa_lookup_sids(h.get(), sids, names, domains);

    for (unsigned int i = 0; i < entries.size(); i++) {
        auto& ent = entries[i];

        const auto& n = names.get()[i];

        ent.use = n.Use;
        ent.name = u16string_view((char16_t*)n.Name.Buffer, n.Name.Length / sizeof(char16_t));

        if (n.DomainIndex >= 0 && (ULONG)n.DomainIndex < domains->Entries) {
            const auto& d = domains->Domains[n.DomainIndex];

            ent.domain = u16string_view((char16_t*)d.Name.Buffer, d.Name.Length / sizeof(char16_t));
        }
    }
}

static void populate_list(HWND hwnd) {
    LSTATUS ret;
    unique_hkey k;
    array<WCHAR, 1000> name;
    DWORD name_len, type;
    vector<mapping_entry> entries;
    wstring uidgid_str;
    LVCOLUMNW lvc;

    auto tab = GetDlgItem(hwnd, IDC_MAPPINGS_TAB);

    auto tabsel = SendMessageW(tab, TCM_GETCURSEL, 0, 0);
    auto groups = tabsel == 1;

    auto list = GetDlgItem(hwnd, IDC_MAPPINGS_LIST);

    // change column to UID or GID
    load_string(module, groups ? IDS_MAPPINGS_GID : IDS_MAPPINGS_UID, uidgid_str);
    lvc.iSubItem = 1;
    lvc.pszText = (WCHAR*)uidgid_str.c_str();
    lvc.mask = LVCF_TEXT;
    SendMessageW(list, LVM_SETCOLUMNW, 1, (LPARAM)&lvc);

    ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, groups ? GID_REG_PATH : UID_REG_PATH,
                        0, KEY_QUERY_VALUE, out_ptr(k));
    if (ret != ERROR_SUCCESS)
        throw formatted_error("RegOpenKeyEx failed (error {})", ret);

    for (DWORD index = 0; ; index++) {
        unique_sid sid;
        mapping_entry me;
        DWORD val, val_len;

        name_len = name.size();
        val_len = sizeof(val);

        ret = RegEnumValueW(k.get(), index, name.data(), &name_len, nullptr,
                            &type, (LPBYTE)&val, &val_len);

        if (ret == ERROR_NO_MORE_ITEMS)
            break;

        if ((ret == ERROR_SUCCESS || ret == ERROR_MORE_DATA) && type != REG_DWORD)
            continue;

        if (ret != ERROR_SUCCESS)
            throw formatted_error("RegEnumValue failed (error {})", ret);

        if (!ConvertStringSidToSidW(name.data(), out_ptr(sid)))
            continue;

        me.sid = std::move(sid);
        me.value = val;
        entries.emplace_back(std::move(me));
    }

    resolve_names(entries);

    SendMessageW(list, LVM_DELETEALLITEMS, 0, 0);
    SendMessageW(list, LVM_SETITEMCOUNT, entries.size(), 0);

    for (size_t i = 0; i < entries.size(); i++) {
        const auto& ent = entries[i];
        LVITEMW lvi;

        // FIXME - different icons for SID types

        u16string s;

        if (!ent.domain.empty())
            s = ent.domain + u"\\";

        s += ent.name;

        lvi.pszText = (WCHAR*)s.c_str();
        lvi.mask = LVIF_TEXT;
        lvi.iItem = i;
        lvi.iSubItem = 0;

        SendMessageW(list, LVM_INSERTITEMW, 0, (LPARAM)&lvi);

        auto s2 = to_wstring(ent.value);

        lvi.pszText = (WCHAR*)s2.c_str();
        lvi.mask = LVIF_TEXT;
        lvi.iSubItem = 1;

        SendMessageW(list, LVM_SETITEMTEXTW, i, (LPARAM)&lvi);
    }
}

static void init_dialog(HWND hwnd) {
    TCITEMW tie;
    LVCOLUMNW lvc;
    wstring uid_mappings_str, gid_mappings_str, principal_str, uid_str;

    load_string(module, IDS_MAPPINGS_UID_MAPPINGS, uid_mappings_str);
    load_string(module, IDS_MAPPINGS_GID_MAPPINGS, gid_mappings_str);
    load_string(module, IDS_MAPPINGS_PRINCIPAL, principal_str);
    load_string(module, IDS_MAPPINGS_UID, uid_str);

    auto tab = GetDlgItem(hwnd, IDC_MAPPINGS_TAB);

    memset(&tie, 0, sizeof(tie));

    tie.mask = TCIF_TEXT;
    tie.iImage = -1;
    tie.pszText = (WCHAR*)uid_mappings_str.c_str();
    SendMessageW(tab, TCM_INSERTITEMW, 0, (LPARAM)&tie);
    tie.pszText = (WCHAR*)gid_mappings_str.c_str();
    SendMessageW(tab, TCM_INSERTITEMW, 1, (LPARAM)&tie);

    auto list = GetDlgItem(hwnd, IDC_MAPPINGS_LIST);

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;

    lvc.iSubItem = 0;
    lvc.pszText = (WCHAR*)principal_str.c_str();
    lvc.cx = 300;
    lvc.fmt = LVCFMT_LEFT;
    SendMessageW(list, LVM_INSERTCOLUMNW, 0, (LPARAM)&lvc);

    lvc.iSubItem = 1;
    lvc.pszText = (WCHAR*)uid_str.c_str();
    lvc.cx = 100;
    lvc.fmt = LVCFMT_LEFT;
    SendMessageW(list, LVM_INSERTCOLUMNW, 1, (LPARAM)&lvc);

    try {
        populate_list(GetParent(list));
    } catch (const exception& e) {
        error_message(GetParent(list), e.what());
    }
}

static INT_PTR CALLBACK MappingsDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    try {
        switch (uMsg) {
            case WM_INITDIALOG:
                init_dialog(hwndDlg);
                return true;

            case WM_COMMAND:
                switch (HIWORD(wParam)) {
                    case BN_CLICKED:
                        switch (LOWORD(wParam)) {
                            case IDOK:
                            case IDCANCEL:
                                EndDialog(hwndDlg, 1);
                            return true;
                        }
                    break;
                }
            break;

            case WM_NOTIFY:
                switch (((LPNMHDR)lParam)->code) {
                    case TCN_SELCHANGE:
                        try {
                            populate_list(hwndDlg);
                        } catch (const exception& e) {
                            error_message(hwndDlg, e.what());
                        }
                    break;
                }
            break;
        }
    } catch (const exception& e) {
        error_message(hwndDlg, e.what());
    }

    return false;
}

extern "C"
void CALLBACK MappingsTest(HWND hwnd, HINSTANCE, LPWSTR, int) {
    try {
        set_dpi_aware();

        if (DialogBoxParamW(module, MAKEINTRESOURCEW(IDD_MAPPINGS), hwnd, MappingsDlgProc, 0) <= 0)
            throw last_error(GetLastError());
    } catch (const exception& e) {
        error_message(hwnd, e.what());
    }
}
