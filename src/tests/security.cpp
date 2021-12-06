#include "test.h"

using namespace std;

static const uint8_t sid_everyone[] = { 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 }; // S-1-1-0

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

void test_security(const u16string& dir) {
    unique_handle h;

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

    // FIXME - querying SD
    // FIXME - setting SD (owner, group, SACL, DACL)
    // FIXME - creating file with SD
    // FIXME - inheriting SD
    // FIXME - open files asking for too many permissions
    // FIXME - MAXIMUM_ALLOWED
    // FIXME - backup and restore privileges
    // FIXME - traverse checking
    // FIXME - make sure mandatory access controls etc. obeyed (inc. when traverse-checking)
}
