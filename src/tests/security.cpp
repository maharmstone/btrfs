#include "test.h"
#include <array>

using namespace std;

#ifdef _MSC_VER
#define ThreadImpersonationToken ((THREADINFOCLASS)5)
#endif

// S-1-1-0
static const uint8_t sid_everyone[] = { 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                                        0x00, 0x00, 0x00, 0x00 };

// S-1-5-21-2463132441-2848149277-1773138504-1001
static const uint8_t sid_test[] = { 0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
                                    0x15, 0x00, 0x00, 0x00, 0x19, 0x6b, 0xd0, 0x92,
                                    0x1d, 0x4f, 0xc3, 0xa9, 0x48, 0xf2, 0xaf, 0x69,
                                    0xe9, 0x03, 0x00, 0x00 };

// S-1-5-21-2463132441-2848149277-1773138504-2001
static const uint8_t sid_test2[] = { 0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
                                     0x15, 0x00, 0x00, 0x00, 0x19, 0x6b, 0xd0, 0x92,
                                     0x1d, 0x4f, 0xc3, 0xa9, 0x48, 0xf2, 0xaf, 0x69,
                                     0xd1, 0x07, 0x00, 0x00 };

// S-1-16-12288
static const uint8_t sid_high[] = { 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
                                    0x00, 0x30, 0x00, 0x00 };

// S-1-16-8192
static const uint8_t sid_medium[] = { 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
                                      0x00, 0x20, 0x00, 0x00 };

static unique_handle create_file_sd(u16string_view path, ACCESS_MASK access, ULONG atts, ULONG share,
                                    ULONG dispo, ULONG options, ULONG_PTR exp_info, const SECURITY_DESCRIPTOR& sd) {
    NTSTATUS Status;
    HANDLE h;
    IO_STATUS_BLOCK iosb;
    UNICODE_STRING us;
    OBJECT_ATTRIBUTES oa;

    memset(&oa, 0, sizeof(oa));
    oa.Length = sizeof(oa);
    oa.RootDirectory = nullptr;

    us.Length = us.MaximumLength = path.length() * sizeof(char16_t);
    us.Buffer = (WCHAR*)path.data();
    oa.ObjectName = &us;

    oa.Attributes = OBJ_CASE_INSENSITIVE;
    oa.SecurityDescriptor = (void*)&sd;
    oa.SecurityQualityOfService = nullptr;

    iosb.Information = 0xdeadbeef;

    Status = NtCreateFile(&h, access, &oa, &iosb, nullptr,
                          atts, share, dispo, options, nullptr, 0);

    if (Status != STATUS_SUCCESS) {
        if (NT_SUCCESS(Status)) // STATUS_OPLOCK_BREAK_IN_PROGRESS etc.
            NtClose(h);

        throw ntstatus_error(Status);
    }

    if (iosb.Information != exp_info)
        throw formatted_error("iosb.Information was {}, expected {}", iosb.Information, exp_info);

    return unique_handle(h);
}

static unique_handle create_file_with_acl(u16string_view path, ACCESS_MASK access, ULONG atts, ULONG share,
                                          ULONG dispo, ULONG options, ULONG_PTR exp_info, ACCESS_MASK ace_access,
                                          uint8_t ace_flags) {
    SECURITY_DESCRIPTOR sd;
    array<uint8_t, sizeof(ACL) + offsetof(ACCESS_ALLOWED_ACE, SidStart) + sizeof(sid_everyone)> aclbuf;

    if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
        throw formatted_error("InitializeSecurityDescriptor failed (error {})", GetLastError());

    auto& acl = *(ACL*)aclbuf.data();

    if (!InitializeAcl(&acl, aclbuf.size(), ACL_REVISION))
        throw formatted_error("InitializeAcl failed (error {})", GetLastError());

    acl.AceCount = 1;

    auto& ace = *(ACCESS_ALLOWED_ACE*)((uint8_t*)aclbuf.data() + sizeof(ACL));

    ace.Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
    ace.Header.AceFlags = ace_flags;
    ace.Header.AceSize = offsetof(ACCESS_ALLOWED_ACE, SidStart) + sizeof(sid_everyone);
    ace.Mask = ace_access;
    memcpy(&ace.SidStart, sid_everyone, sizeof(sid_everyone));

    if (!SetSecurityDescriptorDacl(&sd, true, &acl, false))
        throw formatted_error("SetSecurityDescriptorDacl failed (error {})", GetLastError());

    return create_file_sd(path, access, atts, share, dispo, options, exp_info, sd);
}

void set_dacl(HANDLE h, ACCESS_MASK access) {
    NTSTATUS Status;
    SECURITY_DESCRIPTOR sd;
    array<uint8_t, sizeof(ACL) + offsetof(ACCESS_ALLOWED_ACE, SidStart) + sizeof(sid_everyone)> aclbuf;

    if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
        throw formatted_error("InitializeSecurityDescriptor failed (error {})", GetLastError());

    auto& acl = *(ACL*)aclbuf.data();

    if (!InitializeAcl(&acl, aclbuf.size(), ACL_REVISION))
        throw formatted_error("InitializeAcl failed (error {})", GetLastError());

    if (access != 0) {
        acl.AceCount = 1;

        auto& ace = *(ACCESS_ALLOWED_ACE*)((uint8_t*)aclbuf.data() + sizeof(ACL));

        ace.Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
        ace.Header.AceFlags = 0;
        ace.Header.AceSize = offsetof(ACCESS_ALLOWED_ACE, SidStart) + sizeof(sid_everyone);
        ace.Mask = access;
        memcpy(&ace.SidStart, sid_everyone, sizeof(sid_everyone));
    }

    if (!SetSecurityDescriptorDacl(&sd, true, &acl, false))
        throw formatted_error("SetSecurityDescriptorDacl failed (error {})", GetLastError());

    Status = NtSetSecurityObject(h, DACL_SECURITY_INFORMATION, &sd);

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);
}

static vector<varbuf<ACE_HEADER>> get_acl(HANDLE h, unsigned int type) {
    NTSTATUS Status;
    ULONG needed = 0;
    vector<uint8_t> buf;
    vector<varbuf<ACE_HEADER>> ret;

    Status = NtQuerySecurityObject(h, type, nullptr, 0, &needed);

    if (Status != STATUS_BUFFER_TOO_SMALL)
        throw ntstatus_error(Status);

    buf.resize(needed);

    Status = NtQuerySecurityObject(h, type, buf.data(), buf.size(), &needed);

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);

    if (buf.size() < sizeof(SECURITY_DESCRIPTOR_RELATIVE))
        throw formatted_error("SD was {} bytes, expected at least {}", buf.size(), sizeof(SECURITY_DESCRIPTOR_RELATIVE));

    auto& sd = *(SECURITY_DESCRIPTOR_RELATIVE*)buf.data();

    if (sd.Revision != 1)
        throw formatted_error("SD revision was {}, expected 1", sd.Revision);

    auto off = type == DACL_SECURITY_INFORMATION ? sd.Dacl : sd.Sacl;

    if (off == 0)
        return {};

    if (off + sizeof(ACL) > buf.size())
        throw runtime_error("ACL extended beyond end of SD");

    auto& acl = *(ACL*)(buf.data() + off);

    if (acl.AclRevision != ACL_REVISION)
        throw formatted_error("ACL revision was {}, expected {}", acl.AclRevision, ACL_REVISION);

    if (acl.AclSize < sizeof(ACL))
        throw formatted_error("ACL size was {}, expected at least {}", acl.AclSize, sizeof(ACL));

    ret.resize(acl.AceCount);

    auto aclsp = span<const uint8_t>((uint8_t*)&acl + sizeof(ACL), acl.AclSize - sizeof(ACL));

    for (unsigned int i = 0; i < acl.AceCount; i++) {
        auto& ace = *(ACE_HEADER*)aclsp.data();

        if (aclsp.size() < sizeof(ACE_HEADER))
            throw formatted_error("Not enough bytes left for ACE ({} < {})", aclsp.size(), sizeof(ACE_HEADER));

        if (aclsp.size() < ace.AceSize)
            throw formatted_error("ACE overflowed end of SD ({} < {})", aclsp.size(), ace.AceSize);

        auto& b = ret[i].buf;

        b.resize(ace.AceSize);
        memcpy(b.data(), &ace, ace.AceSize);

        aclsp = aclsp.subspan(ace.AceSize);
    }

    return ret;
}

static string sid_to_string(span<const uint8_t> sid) {
    string s;
    auto& ss = *(SID*)sid.data();

    if (sid.size() < offsetof(SID, SubAuthority) || ss.Revision != SID_REVISION || sid.size() < offsetof(SID, SubAuthority) + (ss.SubAuthorityCount * sizeof(ULONG))) {
        for (auto b : sid) {
            if (!s.empty())
                s += " ";

#if __has_include(<format>)
            s += std::format("{:02x}", b);
#else
            s += fmt::format("{:02x}", b);
#endif
        }

        return "Malformed SID (" + s + ")";
    }

    uint64_t auth;

    auth = (uint64_t)sid[2] << 40;
    auth |= (uint64_t)sid[3] << 32;
    auth |= (uint64_t)sid[4] << 24;
    auth |= (uint64_t)sid[5] << 16;
    auth |= (uint64_t)sid[6] << 8;
    auth |= sid[7];

#if __has_include(<format>)
    s = std::format("S-1-{}", auth);
#else
    s = fmt::format("S-1-{}", auth);
#endif

    auto sub = span<const ULONG>(ss.SubAuthority, ss.SubAuthorityCount);

    for (auto n : sub) {
#if __has_include(<format>)
        s += std::format("-{}", n);
#else
        s += fmt::format("-{}", n);
#endif
    }

    return s;
}

static bool compare_sid(span<const uint8_t> sid1, span<const uint8_t> sid2) {
    if (sid1.size() < offsetof(SID, SubAuthority) || sid2.size() < offsetof(SID, SubAuthority))
        throw runtime_error("Malformed SID");

    auto& ss1 = *(SID*)sid1.data();
    auto& ss2 = *(SID*)sid2.data();

    if (ss1.Revision != 1 || ss2.Revision != 1)
        throw runtime_error("Unknown SID revision");

    auto len1 = offsetof(SID, SubAuthority) + (ss1.SubAuthorityCount * sizeof(ULONG));
    auto len2 = offsetof(SID, SubAuthority) + (ss2.SubAuthorityCount * sizeof(ULONG));

    if (len1 != len2)
        return false;

    return !memcmp(sid1.data(), sid2.data(), len1);
}

static void set_owner(HANDLE h, span<const uint8_t> sid) {
    NTSTATUS Status;
    SECURITY_DESCRIPTOR sd;

    if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
        throw formatted_error("InitializeSecurityDescriptor failed (error {})", GetLastError());

    if (!SetSecurityDescriptorOwner(&sd, (PSID)sid.data(), false))
        throw formatted_error("SetSecurityDescriptorOwner failed (error {})", GetLastError());

    Status = NtSetSecurityObject(h, OWNER_SECURITY_INFORMATION, &sd);

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);
}

static vector<uint8_t> get_owner(HANDLE h) {
    NTSTATUS Status;
    ULONG needed = 0;
    vector<uint8_t> buf;

    Status = NtQuerySecurityObject(h, OWNER_SECURITY_INFORMATION, nullptr, 0, &needed);

    if (Status != STATUS_BUFFER_TOO_SMALL)
        throw ntstatus_error(Status);

    buf.resize(needed);

    Status = NtQuerySecurityObject(h, OWNER_SECURITY_INFORMATION, buf.data(), buf.size(), &needed);

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);

    if (buf.size() < sizeof(SECURITY_DESCRIPTOR_RELATIVE))
        throw formatted_error("SD was {} bytes, expected at least {}", buf.size(), sizeof(SECURITY_DESCRIPTOR_RELATIVE));

    auto& sd = *(SECURITY_DESCRIPTOR_RELATIVE*)buf.data();

    if (sd.Revision != 1)
        throw formatted_error("SD revision was {}, expected 1", sd.Revision);

    if (sd.Owner == 0)
        throw runtime_error("No owner returned");

    if (sd.Owner + offsetof(SID, SubAuthority) > buf.size())
        throw runtime_error("SID extended beyond end of SD");

    auto& sid = *(SID*)(buf.data() + sd.Owner);

    if (sid.Revision != SID_REVISION)
        throw formatted_error("SID revision was {}, expected {}", sid.Revision, SID_REVISION);

    auto sp = span(buf.data() + sd.Owner, offsetof(SID, SubAuthority) + (sizeof(ULONG) * sid.SubAuthorityCount));

    vector<uint8_t> ret;

    ret.resize(sp.size());
    memcpy(ret.data(), sp.data(), sp.size());

    return ret;
}

static void set_group(HANDLE h, span<const uint8_t> sid) {
    NTSTATUS Status;
    SECURITY_DESCRIPTOR sd;

    if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
        throw formatted_error("InitializeSecurityDescriptor failed (error {})", GetLastError());

    if (!SetSecurityDescriptorGroup(&sd, (PSID)sid.data(), false))
        throw formatted_error("SetSecurityDescriptorGroup failed (error {})", GetLastError());

    Status = NtSetSecurityObject(h, GROUP_SECURITY_INFORMATION, &sd);

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);
}

static vector<uint8_t> get_group(HANDLE h) {
    NTSTATUS Status;
    ULONG needed = 0;
    vector<uint8_t> buf;

    Status = NtQuerySecurityObject(h, GROUP_SECURITY_INFORMATION, nullptr, 0, &needed);

    if (Status != STATUS_BUFFER_TOO_SMALL)
        throw ntstatus_error(Status);

    buf.resize(needed);

    Status = NtQuerySecurityObject(h, GROUP_SECURITY_INFORMATION, buf.data(), buf.size(), &needed);

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);

    if (buf.size() < sizeof(SECURITY_DESCRIPTOR_RELATIVE))
        throw formatted_error("SD was {} bytes, expected at least {}", buf.size(), sizeof(SECURITY_DESCRIPTOR_RELATIVE));

    auto& sd = *(SECURITY_DESCRIPTOR_RELATIVE*)buf.data();

    if (sd.Revision != 1)
        throw formatted_error("SD revision was {}, expected 1", sd.Revision);

    if (sd.Group == 0)
        throw runtime_error("No group returned");

    if (sd.Group + offsetof(SID, SubAuthority) > buf.size())
        throw runtime_error("SID extended beyond end of SD");

    auto& sid = *(SID*)(buf.data() + sd.Group);

    if (sid.Revision != SID_REVISION)
        throw formatted_error("SID revision was {}, expected {}", sid.Revision, SID_REVISION);

    auto sp = span(buf.data() + sd.Group, offsetof(SID, SubAuthority) + (sizeof(ULONG) * sid.SubAuthorityCount));

    vector<uint8_t> ret;

    ret.resize(sp.size());
    memcpy(ret.data(), sp.data(), sp.size());

    return ret;
}

template<size_t N>
static void set_audit(HANDLE h, ACCESS_MASK access, span<const uint8_t, N> sid) {
    NTSTATUS Status;
    SECURITY_DESCRIPTOR sd;
    array<uint8_t, sizeof(ACL) + offsetof(SYSTEM_AUDIT_ACE, SidStart) + sid.size()> aclbuf;

    if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
        throw formatted_error("InitializeSecurityDescriptor failed (error {})", GetLastError());

    auto& acl = *(ACL*)aclbuf.data();

    if (!InitializeAcl(&acl, aclbuf.size(), ACL_REVISION))
        throw formatted_error("InitializeAcl failed (error {})", GetLastError());

    if (access != 0) {
        acl.AceCount = 1;

        auto& ace = *(SYSTEM_AUDIT_ACE*)((uint8_t*)aclbuf.data() + sizeof(ACL));

        ace.Header.AceType = SYSTEM_AUDIT_ACE_TYPE;
        ace.Header.AceFlags = 0;
        ace.Header.AceSize = offsetof(SYSTEM_AUDIT_ACE, SidStart) + sid.size();
        ace.Mask = access;
        memcpy(&ace.SidStart, sid.data(), sid.size());
    }

    if (!SetSecurityDescriptorSacl(&sd, true, &acl, false))
        throw formatted_error("SetSecurityDescriptorSacl failed (error {})", GetLastError());

    Status = NtSetSecurityObject(h, SACL_SECURITY_INFORMATION, &sd);

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);
}

template<size_t N>
static void set_mandatory_access(HANDLE h, ACCESS_MASK access, span<const uint8_t, N> sid) {
    NTSTATUS Status;
    SECURITY_DESCRIPTOR sd;
    array<uint8_t, sizeof(ACL) + offsetof(SYSTEM_MANDATORY_LABEL_ACE, SidStart) + sid.size()> aclbuf;

    if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
        throw formatted_error("InitializeSecurityDescriptor failed (error {})", GetLastError());

    auto& acl = *(ACL*)aclbuf.data();

    if (!InitializeAcl(&acl, aclbuf.size(), ACL_REVISION))
        throw formatted_error("InitializeAcl failed (error {})", GetLastError());

    if (access != 0) {
        acl.AceCount = 1;

        auto& ace = *(SYSTEM_MANDATORY_LABEL_ACE*)((uint8_t*)aclbuf.data() + sizeof(ACL));

        ace.Header.AceType = SYSTEM_MANDATORY_LABEL_ACE_TYPE;
        ace.Header.AceFlags = 0;
        ace.Header.AceSize = offsetof(SYSTEM_MANDATORY_LABEL_ACE, SidStart) + sid.size();
        ace.Mask = access;
        memcpy(&ace.SidStart, sid.data(), sid.size());
    }

    if (!SetSecurityDescriptorSacl(&sd, true, &acl, false))
        throw formatted_error("SetSecurityDescriptorSacl failed (error {})", GetLastError());

    Status = NtSetSecurityObject(h, LABEL_SECURITY_INFORMATION, &sd);

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);
}

static unique_handle duplicate_token(HANDLE token) {
    NTSTATUS Status;
    OBJECT_ATTRIBUTES oa;
    HANDLE h;
    SECURITY_QUALITY_OF_SERVICE qos;

    memset(&qos, 0, sizeof(qos));
    qos.Length = sizeof(qos);
    qos.ImpersonationLevel = SecurityImpersonation;

    memset(&oa, 0, sizeof(oa));
    oa.Length = sizeof(oa);
    oa.SecurityQualityOfService = &qos;

    Status = NtDuplicateToken(token, MAXIMUM_ALLOWED, &oa, false,
                              TokenImpersonation, &h);

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);

    return unique_handle{h};
}

static void adjust_token_level(HANDLE token, const void* sid) {
    TOKEN_MANDATORY_LABEL label;
    NTSTATUS Status;

    label.Label.Sid = (PSID)sid;
    label.Label.Attributes = 0;

    Status = NtSetInformationToken(token, TokenIntegrityLevel, &label, sizeof(label));

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);
}

static void set_thread_token(HANDLE token) {
    NTSTATUS Status;

    Status = NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken,
                                    &token, sizeof(token));

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);
}

void test_security(HANDLE token, const u16string& dir) {
    unique_handle h, medium_token;

    test("Create file", [&]() {
        h = create_file(dir + u"\\sec1", GENERIC_READ, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Query FileAccessInformation", [&]() {
            auto fai = query_information<FILE_ACCESS_INFORMATION>(h.get());

            ACCESS_MASK exp = SYNCHRONIZE | READ_CONTROL | FILE_READ_ATTRIBUTES |
                              FILE_READ_EA | FILE_READ_DATA;

            if (fai.AccessFlags != exp)
                throw formatted_error("AccessFlags was {:x}, expected {:x}", fai.AccessFlags, exp);
        });

        h.reset();
    }

    test("Open file", [&]() {
        h = create_file(dir + u"\\sec1", GENERIC_WRITE, 0, 0, FILE_OPEN, 0, FILE_OPENED);
    });

    if (h) {
        test("Query FileAccessInformation", [&]() {
            auto fai = query_information<FILE_ACCESS_INFORMATION>(h.get());

            ACCESS_MASK exp = SYNCHRONIZE | READ_CONTROL | FILE_WRITE_ATTRIBUTES |
                              FILE_WRITE_EA | FILE_APPEND_DATA | FILE_WRITE_DATA;

            if (fai.AccessFlags != exp)
                throw formatted_error("AccessFlags was {:x}, expected {:x}", fai.AccessFlags, exp);
        });

        h.reset();
    }

    test("Open file", [&]() {
        h = create_file(dir + u"\\sec1", GENERIC_EXECUTE, 0, 0, FILE_OPEN, 0, FILE_OPENED);
    });

    if (h) {
        test("Query FileAccessInformation", [&]() {
            auto fai = query_information<FILE_ACCESS_INFORMATION>(h.get());

            ACCESS_MASK exp = SYNCHRONIZE | READ_CONTROL | FILE_READ_ATTRIBUTES |
                              FILE_EXECUTE;

            if (fai.AccessFlags != exp)
                throw formatted_error("AccessFlags was {:x}, expected {:x}", fai.AccessFlags, exp);
        });

        h.reset();
    }

    test("Open file", [&]() {
        h = create_file(dir + u"\\sec1", READ_CONTROL | WRITE_DAC, 0, 0, FILE_OPEN, 0, FILE_OPENED);
    });

    if (h) {
        ACCESS_MASK access = SYNCHRONIZE | WRITE_OWNER | WRITE_DAC | READ_CONTROL | DELETE |
                             FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES | FILE_DELETE_CHILD |
                             FILE_EXECUTE | FILE_WRITE_EA | FILE_READ_EA | FILE_APPEND_DATA |
                             FILE_WRITE_DATA | FILE_READ_DATA;

        test("Set DACL to maximum for Everyone", [&]() {
            set_dacl(h.get(), access);
        });

        test("Query DACL", [&]() {
            auto items = get_acl(h.get(), DACL_SECURITY_INFORMATION);

            if (items.size() != 1)
                throw formatted_error("{} items returned, expected 1", items.size());

            auto& ace = *static_cast<ACE_HEADER*>(items.front());

            if (ace.AceType != ACCESS_ALLOWED_ACE_TYPE)
                throw formatted_error("ACE type was {}, expected ACCESS_ALLOWED_ACE_TYPE", ace.AceType);

            if (ace.AceFlags != 0)
                throw formatted_error("AceFlags was {:x}, expected 0", ace.AceFlags);

            auto& aaa = *reinterpret_cast<ACCESS_ALLOWED_ACE*>(&ace);

            if (aaa.Mask != access)
                throw formatted_error("Mask was {:x}, expected {:x}", aaa.Mask, access);

            auto sid = span<const uint8_t>((uint8_t*)&aaa.SidStart, items.front().buf.size() - offsetof(ACCESS_ALLOWED_ACE, SidStart));

            if (!compare_sid(sid, sid_everyone))
                throw formatted_error("SID was {}, expected {}", sid_to_string(sid), sid_to_string(sid_everyone));
        });

        h.reset();
    }

    test("Open file", [&]() {
        h = create_file(dir + u"\\sec1", READ_CONTROL | WRITE_OWNER, 0, 0, FILE_OPEN, 0, FILE_OPENED);
    });

    if (h) {
        test("Try to set owner without SeRestorePrivilege", [&]() {
            exp_status([&]() {
                set_owner(h.get(), sid_test);
            }, STATUS_INVALID_OWNER);
        });

        test("Set group", [&]() {
            set_group(h.get(), sid_test2);
        });

        test("Query group", [&]() {
            auto sid = get_group(h.get());

            if (!compare_sid(sid, sid_test2))
                throw formatted_error("SID was {}, expected {}", sid_to_string(sid), sid_to_string(sid_test2));
        });

        h.reset();
    }

    test("Add SeRestorePrivilege to token", [&]() {
        LUID_AND_ATTRIBUTES laa;

        laa.Luid.LowPart = SE_RESTORE_PRIVILEGE;
        laa.Luid.HighPart = 0;
        laa.Attributes = SE_PRIVILEGE_ENABLED;

        adjust_token_privileges(token, laa);
    });

    test("Open file", [&]() {
        h = create_file(dir + u"\\sec1", READ_CONTROL | WRITE_OWNER, 0, 0, FILE_OPEN, 0, FILE_OPENED);
    });

    if (h) {
        test("Set owner", [&]() {
            set_owner(h.get(), sid_test);
        });

        test("Query owner", [&]() {
            auto sid = get_owner(h.get());

            if (!compare_sid(sid, sid_test))
                throw formatted_error("SID was {}, expected {}", sid_to_string(sid), sid_to_string(sid_test));
        });

        h.reset();
    }

    disable_token_privileges(token);

    test("Try to open file with ACCESS_SYSTEM_SECURITY without SeSecurityPrivilege", [&]() {
        exp_status([&]() {
            create_file(dir + u"\\sec1", ACCESS_SYSTEM_SECURITY, 0, 0, FILE_OPEN, 0, FILE_OPENED);
        }, STATUS_PRIVILEGE_NOT_HELD);
    });

    test("Add SeSecurityPrivilege to token", [&]() {
        LUID_AND_ATTRIBUTES laa;

        laa.Luid.LowPart = SE_SECURITY_PRIVILEGE;
        laa.Luid.HighPart = 0;
        laa.Attributes = SE_PRIVILEGE_ENABLED;

        adjust_token_privileges(token, laa);
    });

    test("Open file", [&]() {
        h = create_file(dir + u"\\sec1", ACCESS_SYSTEM_SECURITY, 0, 0, FILE_OPEN, 0, FILE_OPENED);
    });

    if (h) {
        test("Set audit", [&]() {
            set_audit(h.get(), SUCCESSFUL_ACCESS_ACE_FLAG | FAILED_ACCESS_ACE_FLAG, span(sid_everyone));
        });

        test("Query SACL", [&]() {
            auto items = get_acl(h.get(), SACL_SECURITY_INFORMATION);

            if (items.size() != 1)
                throw formatted_error("{} items returned, expected 1", items.size());

            auto& ace = *static_cast<ACE_HEADER*>(items.front());

            if (ace.AceType != SYSTEM_AUDIT_ACE_TYPE)
                throw formatted_error("ACE type was {}, expected SYSTEM_AUDIT_ACE_TYPE", ace.AceType);

            if (ace.AceFlags != 0)
                throw formatted_error("AceFlags was {:x}, expected 0", ace.AceFlags);

            auto& saa = *reinterpret_cast<SYSTEM_AUDIT_ACE*>(&ace);

            if (saa.Mask != (SUCCESSFUL_ACCESS_ACE_FLAG | FAILED_ACCESS_ACE_FLAG))
                throw formatted_error("Mask was {:x}, expected {:x}", saa.Mask, SUCCESSFUL_ACCESS_ACE_FLAG | FAILED_ACCESS_ACE_FLAG);

            auto sid = span<const uint8_t>((uint8_t*)&saa.SidStart, items.front().buf.size() - offsetof(ACCESS_ALLOWED_ACE, SidStart));

            if (!compare_sid(sid, sid_everyone))
                throw formatted_error("SID was {}, expected {}", sid_to_string(sid), sid_to_string(sid_everyone));
        });

        h.reset();
    }

    disable_token_privileges(token);

    test("Open file", [&]() {
        h = create_file(dir + u"\\sec1", READ_CONTROL | WRITE_OWNER, 0, 0, FILE_OPEN, 0, FILE_OPENED);
    });

    if (h) {
        test("Set mandatory access label", [&]() {
            set_mandatory_access(h.get(), SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, span(sid_high));
        });

        test("Query label", [&]() {
            auto items = get_acl(h.get(), LABEL_SECURITY_INFORMATION);

            if (items.size() != 1)
                throw formatted_error("{} items returned, expected 1", items.size());

            auto& ace = *static_cast<ACE_HEADER*>(items.front());

            if (ace.AceType != SYSTEM_MANDATORY_LABEL_ACE_TYPE)
                throw formatted_error("ACE type was {}, expected SYSTEM_MANDATORY_LABEL_ACE_TYPE", ace.AceType);

            if (ace.AceFlags != 0)
                throw formatted_error("AceFlags was {:x}, expected 0", ace.AceFlags);

            auto& smla = *reinterpret_cast<SYSTEM_MANDATORY_LABEL_ACE*>(&ace);

            if (smla.Mask != SYSTEM_MANDATORY_LABEL_NO_WRITE_UP)
                throw formatted_error("Mask was {:x}, expected {:x}", smla.Mask, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP);

            auto sid = span<const uint8_t>((uint8_t*)&smla.SidStart, items.front().buf.size() - offsetof(ACCESS_ALLOWED_ACE, SidStart));

            if (!compare_sid(sid, sid_high))
                throw formatted_error("SID was {}, expected {}", sid_to_string(sid), sid_to_string(sid_high));
        });

        h.reset();
    }

    test("Add SeSecurityPrivilege to token", [&]() {
        LUID_AND_ATTRIBUTES laa;

        laa.Luid.LowPart = SE_SECURITY_PRIVILEGE;
        laa.Luid.HighPart = 0;
        laa.Attributes = SE_PRIVILEGE_ENABLED;

        adjust_token_privileges(token, laa);
    });

    test("Open file", [&]() {
        h = create_file(dir + u"\\sec1", ACCESS_SYSTEM_SECURITY, 0, 0, FILE_OPEN, 0, FILE_OPENED);
    });

    if (h) {
        test("Check SACL still there", [&]() {
            auto items = get_acl(h.get(), SACL_SECURITY_INFORMATION);

            if (items.size() != 1)
                throw formatted_error("{} items returned, expected 1", items.size());

            auto& ace = *static_cast<ACE_HEADER*>(items.front());

            if (ace.AceType != SYSTEM_AUDIT_ACE_TYPE)
                throw formatted_error("ACE type was {}, expected SYSTEM_AUDIT_ACE_TYPE", ace.AceType);

            if (ace.AceFlags != 0)
                throw formatted_error("AceFlags was {:x}, expected 0", ace.AceFlags);

            auto& saa = *reinterpret_cast<SYSTEM_AUDIT_ACE*>(&ace);

            if (saa.Mask != (SUCCESSFUL_ACCESS_ACE_FLAG | FAILED_ACCESS_ACE_FLAG))
                throw formatted_error("Mask was {:x}, expected {:x}", saa.Mask, SUCCESSFUL_ACCESS_ACE_FLAG | FAILED_ACCESS_ACE_FLAG);

            auto sid = span<const uint8_t>((uint8_t*)&saa.SidStart, items.front().buf.size() - offsetof(ACCESS_ALLOWED_ACE, SidStart));

            if (!compare_sid(sid, sid_everyone))
                throw formatted_error("SID was {}, expected {}", sid_to_string(sid), sid_to_string(sid_everyone));
        });

        h.reset();
    }

    disable_token_privileges(token);

    test("Duplicate token", [&]() {
        medium_token = duplicate_token(token);
    });

    if (medium_token) {
        test("Adjust token label", [&]() {
            adjust_token_level(medium_token.get(), sid_medium);
        });

        test("Switch to new token", [&]() {
            set_thread_token(medium_token.get());
        });
    }

    test("Try to open file for writing with medium label", [&]() {
        exp_status([&]() {
            create_file(dir + u"\\sec1", FILE_WRITE_DATA, 0, 0, FILE_OPEN, 0, FILE_OPENED);
        }, STATUS_ACCESS_DENIED);
    });

    test("Open file with MAXIMUM_ALLOWED", [&]() {
        h = create_file(dir + u"\\sec1", MAXIMUM_ALLOWED, 0, 0, FILE_OPEN, 0, FILE_OPENED);
    });

    if (h) {
        test("Query FileAccessInformation", [&]() {
            auto fai = query_information<FILE_ACCESS_INFORMATION>(h.get());

            ACCESS_MASK exp = SYNCHRONIZE | READ_CONTROL | DELETE |
                              FILE_READ_ATTRIBUTES | FILE_EXECUTE |
                              FILE_READ_EA | FILE_READ_DATA;

            if (fai.AccessFlags != exp)
                throw formatted_error("AccessFlags was {:x}, expected {:x}", fai.AccessFlags, exp);
        });

        h.reset();
    }

    if (medium_token) {
        test("Switch back to old token", [&]() {
            set_thread_token(nullptr);
        });

        medium_token.reset();
    }

    test("Create file with SD", [&]() {
        h = create_file_with_acl(dir + u"\\sec2", READ_CONTROL, 0, 0, FILE_CREATE,
                                 0, FILE_CREATED, FILE_READ_DATA, 0);
    });

    if (h) {
        test("Query FileAccessInformation", [&]() {
            auto fai = query_information<FILE_ACCESS_INFORMATION>(h.get());

            ACCESS_MASK exp = READ_CONTROL;

            if (fai.AccessFlags != exp)
                throw formatted_error("AccessFlags was {:x}, expected {:x}", fai.AccessFlags, exp);
        });

        test("Query DACL", [&]() {
            auto items = get_acl(h.get(), DACL_SECURITY_INFORMATION);

            if (items.size() != 1)
                throw formatted_error("{} items returned, expected 1", items.size());

            auto& ace = *static_cast<ACE_HEADER*>(items.front());

            if (ace.AceType != ACCESS_ALLOWED_ACE_TYPE)
                throw formatted_error("ACE type was {}, expected ACCESS_ALLOWED_ACE_TYPE", ace.AceType);

            if (ace.AceFlags != 0)
                throw formatted_error("AceFlags was {:x}, expected 0", ace.AceFlags);

            auto& aaa = *reinterpret_cast<ACCESS_ALLOWED_ACE*>(&ace);

            if (aaa.Mask != FILE_READ_DATA)
                throw formatted_error("Mask was {:x}, expected FILE_READ_DATA", aaa.Mask);

            auto sid = span<const uint8_t>((uint8_t*)&aaa.SidStart, items.front().buf.size() - offsetof(ACCESS_ALLOWED_ACE, SidStart));

            if (!compare_sid(sid, sid_everyone))
                throw formatted_error("SID was {}, expected {}", sid_to_string(sid), sid_to_string(sid_everyone));
        });

        h.reset();
    }

    test("Try to create file with other user as owner", [&]() {
        SECURITY_DESCRIPTOR sd;

        if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
            throw formatted_error("InitializeSecurityDescriptor failed (error {})", GetLastError());

        if (!SetSecurityDescriptorOwner(&sd, (PSID)sid_test, false))
            throw formatted_error("SetSecurityDescriptorOwner failed (error {})", GetLastError());

        exp_status([&]() {
            create_file_sd(dir + u"\\sec3", READ_CONTROL, 0, 0, FILE_CREATE,
                           0, FILE_CREATED, sd);
        }, STATUS_INVALID_OWNER);
    });

    test("Create directory with OBJECT_INHERIT_ACE", [&]() {
        create_file_with_acl(dir + u"\\sec4", READ_CONTROL, 0, 0, FILE_CREATE,
                             FILE_DIRECTORY_FILE, FILE_CREATED,
                             FILE_TRAVERSE | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY,
                             OBJECT_INHERIT_ACE);
    });

    // READ_CONTROL gets given because we're the owner
    test("Create file", [&]() {
        h = create_file(dir + u"\\sec4\\file", READ_CONTROL, 0, 0, FILE_CREATE,
                        0, FILE_CREATED);
    });

    if (h) {
        test("Query DACL", [&]() {
            auto items = get_acl(h.get(), DACL_SECURITY_INFORMATION);

            if (items.size() != 1)
                throw formatted_error("{} items returned, expected 1", items.size());

            auto& ace = *static_cast<ACE_HEADER*>(items.front());

            if (ace.AceType != ACCESS_ALLOWED_ACE_TYPE)
                throw formatted_error("ACE type was {}, expected ACCESS_ALLOWED_ACE_TYPE", ace.AceType);

            if (ace.AceFlags != 0)
                throw formatted_error("AceFlags was {:x}, expected 0", ace.AceFlags);

            auto& aaa = *reinterpret_cast<ACCESS_ALLOWED_ACE*>(&ace);

            if (aaa.Mask != (FILE_TRAVERSE | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY))
                throw formatted_error("Mask was {:x}, expected FILE_TRAVERSE | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY", aaa.Mask);

            auto sid = span<const uint8_t>((uint8_t*)&aaa.SidStart, items.front().buf.size() - offsetof(ACCESS_ALLOWED_ACE, SidStart));

            if (!compare_sid(sid, sid_everyone))
                throw formatted_error("SID was {}, expected {}", sid_to_string(sid), sid_to_string(sid_everyone));
        });

        h.reset();
    }

    test("Create subdirectory", [&]() {
        h = create_file(dir + u"\\sec4\\dir", READ_CONTROL, 0, 0, FILE_CREATE,
                        FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Query DACL", [&]() {
            auto items = get_acl(h.get(), DACL_SECURITY_INFORMATION);

            if (items.size() != 1)
                throw formatted_error("{} items returned, expected 1", items.size());

            auto& ace = *static_cast<ACE_HEADER*>(items.front());

            if (ace.AceType != ACCESS_ALLOWED_ACE_TYPE)
                throw formatted_error("ACE type was {}, expected ACCESS_ALLOWED_ACE_TYPE", ace.AceType);

            if (ace.AceFlags != (INHERIT_ONLY_ACE | OBJECT_INHERIT_ACE))
                throw formatted_error("AceFlags was {:x}, expected INHERIT_ONLY_ACE | OBJECT_INHERIT_ACE", ace.AceFlags);

            auto& aaa = *reinterpret_cast<ACCESS_ALLOWED_ACE*>(&ace);

            if (aaa.Mask != (FILE_TRAVERSE | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY))
                throw formatted_error("Mask was {:x}, expected FILE_TRAVERSE | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY", aaa.Mask);

            auto sid = span<const uint8_t>((uint8_t*)&aaa.SidStart, items.front().buf.size() - offsetof(ACCESS_ALLOWED_ACE, SidStart));

            if (!compare_sid(sid, sid_everyone))
                throw formatted_error("SID was {}, expected {}", sid_to_string(sid), sid_to_string(sid_everyone));
        });

        h.reset();
    }

    test("Create directory with CONTAINER_INHERIT_ACE", [&]() {
        create_file_with_acl(dir + u"\\sec5", READ_CONTROL, 0, 0, FILE_CREATE,
                             FILE_DIRECTORY_FILE, FILE_CREATED,
                             FILE_TRAVERSE | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY,
                             OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE);
    });

    test("Create file", [&]() {
        h = create_file(dir + u"\\sec5\\file", READ_CONTROL, 0, 0, FILE_CREATE,
                        0, FILE_CREATED);
    });

    if (h) {
        test("Query DACL", [&]() {
            auto items = get_acl(h.get(), DACL_SECURITY_INFORMATION);

            if (items.size() != 1)
                throw formatted_error("{} items returned, expected 1", items.size());

            auto& ace = *static_cast<ACE_HEADER*>(items.front());

            if (ace.AceType != ACCESS_ALLOWED_ACE_TYPE)
                throw formatted_error("ACE type was {}, expected ACCESS_ALLOWED_ACE_TYPE", ace.AceType);

            if (ace.AceFlags != 0)
                throw formatted_error("AceFlags was {:x}, expected 0", ace.AceFlags);

            auto& aaa = *reinterpret_cast<ACCESS_ALLOWED_ACE*>(&ace);

            if (aaa.Mask != (FILE_TRAVERSE | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY))
                throw formatted_error("Mask was {:x}, expected FILE_TRAVERSE | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY", aaa.Mask);

            auto sid = span<const uint8_t>((uint8_t*)&aaa.SidStart, items.front().buf.size() - offsetof(ACCESS_ALLOWED_ACE, SidStart));

            if (!compare_sid(sid, sid_everyone))
                throw formatted_error("SID was {}, expected {}", sid_to_string(sid), sid_to_string(sid_everyone));
        });

        h.reset();
    }

    test("Create subdirectory", [&]() {
        h = create_file(dir + u"\\sec5\\dir", READ_CONTROL, 0, 0, FILE_CREATE,
                        FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Query DACL", [&]() {
            auto items = get_acl(h.get(), DACL_SECURITY_INFORMATION);

            if (items.size() != 1)
                throw formatted_error("{} items returned, expected 1", items.size());

            auto& ace = *static_cast<ACE_HEADER*>(items.front());

            if (ace.AceType != ACCESS_ALLOWED_ACE_TYPE)
                throw formatted_error("ACE type was {}, expected ACCESS_ALLOWED_ACE_TYPE", ace.AceType);

            if (ace.AceFlags != (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE))
                throw formatted_error("AceFlags was {:x}, expected OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE", ace.AceFlags);

            auto& aaa = *reinterpret_cast<ACCESS_ALLOWED_ACE*>(&ace);

            if (aaa.Mask != (FILE_TRAVERSE | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY))
                throw formatted_error("Mask was {:x}, expected FILE_TRAVERSE | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY", aaa.Mask);

            auto sid = span<const uint8_t>((uint8_t*)&aaa.SidStart, items.front().buf.size() - offsetof(ACCESS_ALLOWED_ACE, SidStart));

            if (!compare_sid(sid, sid_everyone))
                throw formatted_error("SID was {}, expected {}", sid_to_string(sid), sid_to_string(sid_everyone));
        });

        h.reset();
    }

    test("Create directory without FILE_TRAVERSE", [&]() {
        create_file_with_acl(dir + u"\\sec6", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE,
                             FILE_DIRECTORY_FILE, FILE_CREATED,
                             FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | WRITE_DAC,
                             0);
    });

    test("Try to create file within directory", [&]() {
        exp_status([&]() {
            create_file(dir + u"\\sec6\\file", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE,
                        0, FILE_CREATED);
        }, STATUS_ACCESS_DENIED);
    });

    test("Open directory", [&]() {
        h = create_file(dir + u"\\sec6", WRITE_DAC, 0, 0, FILE_OPEN,
                        0, FILE_OPENED);
    });

    if (h) {
        test("Add FILE_TRAVERSE", [&]() {
            set_dacl(h.get(), FILE_TRAVERSE | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | WRITE_DAC);
        });

        h.reset();
    }

    test("Create file within directory", [&]() {
        create_file(dir + u"\\sec6\\file", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE,
                    0, FILE_CREATED);
    });

    test("Open directory", [&]() {
        h = create_file(dir + u"\\sec6", WRITE_DAC, 0, 0, FILE_OPEN,
                        0, FILE_OPENED);
    });

    if (h) {
        test("Remove FILE_TRAVERSE", [&]() {
            set_dacl(h.get(), FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | WRITE_DAC);
        });

        h.reset();
    }

    test("Add SeChangeNotifyPrivilege to token", [&]() {
        LUID_AND_ATTRIBUTES laa;

        laa.Luid.LowPart = SE_CHANGE_NOTIFY_PRIVILEGE;
        laa.Luid.HighPart = 0;
        laa.Attributes = SE_PRIVILEGE_ENABLED;

        adjust_token_privileges(token, laa);
    });

    test("Create another file within directory", [&]() {
        create_file(dir + u"\\sec6\\file2", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE,
                    0, FILE_CREATED);
    });

    disable_token_privileges(token);

    test("Create file", [&]() {
        h = create_file(dir + u"\\sec7", FILE_READ_ATTRIBUTES, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Try to query owner", [&]() {
            exp_status([&]() {
                get_owner(h.get());
            }, STATUS_ACCESS_DENIED);
        });

        test("Try to query group", [&]() {
            exp_status([&]() {
                get_group(h.get());
            }, STATUS_ACCESS_DENIED);
        });

        test("Try to query SACL", [&]() {
            exp_status([&]() {
                get_acl(h.get(), SACL_SECURITY_INFORMATION);
            }, STATUS_ACCESS_DENIED);
        });

        test("Try to query DACL", [&]() {
            exp_status([&]() {
                get_acl(h.get(), DACL_SECURITY_INFORMATION);
            }, STATUS_ACCESS_DENIED);
        });

        test("Try to query label", [&]() {
            exp_status([&]() {
                get_acl(h.get(), LABEL_SECURITY_INFORMATION);
            }, STATUS_ACCESS_DENIED);
        });

        test("Try to set owner", [&]() {
            exp_status([&]() {
                set_owner(h.get(), sid_test);
            }, STATUS_ACCESS_DENIED);
        });

        test("Try to set group", [&]() {
            exp_status([&]() {
                set_group(h.get(), sid_test);
            }, STATUS_ACCESS_DENIED);
        });

        test("Try to set SACL", [&]() {
            exp_status([&]() {
                set_audit(h.get(), SUCCESSFUL_ACCESS_ACE_FLAG | FAILED_ACCESS_ACE_FLAG, span(sid_everyone));
            }, STATUS_ACCESS_DENIED);
        });

        test("Try to set DACL", [&]() {
            exp_status([&]() {
                set_dacl(h.get(), FILE_READ_DATA);
            }, STATUS_ACCESS_DENIED);
        });

        test("Try to set label", [&]() {
            exp_status([&]() {
                set_mandatory_access(h.get(), SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, span(sid_high));
            }, STATUS_ACCESS_DENIED);
        });

        h.reset();
    }
}
