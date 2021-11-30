#include "test.h"

#define FSCTL_SET_REPARSE_POINT CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 41, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define FSCTL_GET_REPARSE_POINT CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 42, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_DELETE_REPARSE_POINT CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 43, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

using namespace std;

static void set_symlink(HANDLE h, u16string_view substitute_name, u16string_view print_name, bool relative) {
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    vector<uint8_t> buf;

    buf.resize(offsetof(REPARSE_DATA_BUFFER, SymbolicLinkReparseBuffer.PathBuffer) + ((substitute_name.length() + print_name.length()) * sizeof(char16_t)));

    auto& rdb = *(REPARSE_DATA_BUFFER*)buf.data();

    rdb.ReparseTag = IO_REPARSE_TAG_SYMLINK;
    rdb.ReparseDataLength = buf.size() - offsetof(REPARSE_DATA_BUFFER, SymbolicLinkReparseBuffer);
    rdb.Reserved = 0;
    rdb.SymbolicLinkReparseBuffer.SubstituteNameOffset = 0;
    rdb.SymbolicLinkReparseBuffer.SubstituteNameLength = substitute_name.length() * sizeof(char16_t);
    rdb.SymbolicLinkReparseBuffer.PrintNameOffset = rdb.SymbolicLinkReparseBuffer.SubstituteNameLength;
    rdb.SymbolicLinkReparseBuffer.PrintNameLength = print_name.length() * sizeof(char16_t);
    rdb.SymbolicLinkReparseBuffer.Flags = relative ? SYMLINK_FLAG_RELATIVE : 0;

    memcpy((char*)rdb.SymbolicLinkReparseBuffer.PathBuffer + rdb.SymbolicLinkReparseBuffer.SubstituteNameOffset,
           substitute_name.data(), rdb.SymbolicLinkReparseBuffer.SubstituteNameLength);
    memcpy((char*)rdb.SymbolicLinkReparseBuffer.PathBuffer + rdb.SymbolicLinkReparseBuffer.PrintNameOffset,
           print_name.data(), rdb.SymbolicLinkReparseBuffer.PrintNameLength);

    auto ev = create_event();

    Status = NtFsControlFile(h, ev.get(), nullptr, nullptr, &iosb,
                             FSCTL_SET_REPARSE_POINT, buf.data(), buf.size(),
                             nullptr, 0);

    if (Status == STATUS_PENDING) {
        Status = NtWaitForSingleObject(ev.get(), false, nullptr);
        if (Status != STATUS_SUCCESS)
            throw ntstatus_error(Status);

        Status = iosb.Status;
    }

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);
}

static varbuf<REPARSE_DATA_BUFFER> query_reparse_point(HANDLE h) {
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    vector<uint8_t> buf;

    buf.resize(4096);

    auto ev = create_event();

    Status = NtFsControlFile(h, ev.get(), nullptr, nullptr, &iosb,
                             FSCTL_GET_REPARSE_POINT, nullptr, 0,
                             buf.data(), buf.size());

    if (Status == STATUS_PENDING) {
        Status = NtWaitForSingleObject(ev.get(), false, nullptr);
        if (Status != STATUS_SUCCESS)
            throw ntstatus_error(Status);

        Status = iosb.Status;
    }

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);

    auto& rdb = *(REPARSE_DATA_BUFFER*)buf.data();
    varbuf<REPARSE_DATA_BUFFER> ret;

    ret.buf.resize(offsetof(REPARSE_DATA_BUFFER, SymbolicLinkReparseBuffer) + rdb.ReparseDataLength);
    memcpy(ret.buf.data(), buf.data(), ret.buf.size());

    return ret;
}

static void delete_reparse_point(HANDLE h, uint32_t tag) {
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    REPARSE_DATA_BUFFER rdb;

    auto ev = create_event();

    rdb.ReparseTag = tag;
    rdb.ReparseDataLength = 0;
    rdb.Reserved = 0;

    Status = NtFsControlFile(h, ev.get(), nullptr, nullptr, &iosb,
                             FSCTL_DELETE_REPARSE_POINT, &rdb, sizeof(rdb),
                             nullptr, 0);

    if (Status == STATUS_PENDING) {
        Status = NtWaitForSingleObject(ev.get(), false, nullptr);
        if (Status != STATUS_SUCCESS)
            throw ntstatus_error(Status);

        Status = iosb.Status;
    }

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);
}

template<typename T>
static void check_reparse_dirent(const u16string& dir, u16string_view name, uint32_t tag) {
    auto items = query_dir<T>(dir, name);

    if (items.size() != 1)
        throw formatted_error("{} entries returned, expected 1.", items.size());

    auto& fdi = *static_cast<const T*>(items.front());

    if (fdi.FileNameLength != name.size() * sizeof(char16_t))
        throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

    if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
        throw runtime_error("FileName did not match.");

    if constexpr (requires { T::ReparsePointTag; }) {
        if (fdi.EaSize != 0)
            throw formatted_error("EaSize was {:08x}, expected 0", fdi.EaSize);

        if (fdi.ReparsePointTag != tag)
            throw formatted_error("ReparsePointTag was {:08x}, expected {:08x}", fdi.ReparsePointTag, tag);
    } else {
        if (fdi.EaSize != tag)
            throw formatted_error("EaSize was {:08x}, expected {:08x}", fdi.EaSize, tag);
    }
}

void test_reparse(HANDLE token, const u16string& dir) {
    unique_handle h;
    int64_t file1id = 0, file2id = 0;

    test("Add SeCreateSymbolicLinkPrivilege to token", [&]() {
        LUID_AND_ATTRIBUTES laa;

        laa.Luid.LowPart = SE_CREATE_SYMBOLIC_LINK_PRIVILEGE;
        laa.Luid.HighPart = 0;
        laa.Attributes = SE_PRIVILEGE_ENABLED;

        adjust_token_privileges(token, array{ laa });
    });

    test("Create file", [&]() {
        h = create_file(dir + u"\\reparse1", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE,
                        FILE_NON_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Get file ID", [&]() {
            auto fii = query_information<FILE_INTERNAL_INFORMATION>(h.get());

            file1id = fii.IndexNumber.QuadPart;
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\reparse2", FILE_WRITE_ATTRIBUTES, 0, 0, FILE_CREATE,
                        FILE_NON_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Get file ID", [&]() {
            auto fii = query_information<FILE_INTERNAL_INFORMATION>(h.get());

            file2id = fii.IndexNumber.QuadPart;
        });

        test("Set as symlink", [&]() {
            set_symlink(h.get(), u"reparse1", u"reparse1", true);
        });

        test("Query reparse point", [&]() {
            auto buf = query_reparse_point(h.get());
            auto& rdb = *static_cast<REPARSE_DATA_BUFFER*>(buf);

            if (rdb.ReparseTag != IO_REPARSE_TAG_SYMLINK)
                throw formatted_error("Reparse Tag was {:08x}, expected IO_REPARSE_TAG_SYMLINK", rdb.ReparseTag);

            auto& slrb = rdb.SymbolicLinkReparseBuffer;

            auto dest = u16string_view((char16_t*)((char*)slrb.PathBuffer + slrb.SubstituteNameOffset),
                                       slrb.SubstituteNameLength / sizeof(char16_t));

            if (dest != u"reparse1")
                throw formatted_error("Destination was \"{}\", expected \"reparse1\"", u16string_to_string(dest));

            if (slrb.Flags != SYMLINK_FLAG_RELATIVE)
                throw formatted_error("Flags value was {}, expected SYMLINK_FLAG_RELATIVE", slrb.Flags);
        });

        // Only works on specific NTFS metadata file - see section 2.1.5.5.2 of [MS-FSA]
        test("Try checking FileReparsePointInformation", [&]() {
            exp_status([&]() {
                query_dir<FILE_REPARSE_POINT_INFORMATION>(dir, u"reparse2");
            }, STATUS_INVALID_INFO_CLASS);
        });

        h.reset();
    }

    test("Open file", [&]() {
        h = create_file(dir + u"\\reparse2", FILE_READ_ATTRIBUTES, 0, 0, FILE_OPEN,
                        0, FILE_OPENED);
    });

    if (h) {
        test("Check ID", [&]() {
            auto fii = query_information<FILE_INTERNAL_INFORMATION>(h.get());

            if (fii.IndexNumber.QuadPart != file1id)
                throw runtime_error("File ID was not expected value");
        });

        h.reset();
    }

    test("Check directory entry (FILE_FULL_DIR_INFORMATION)", [&]() {
        check_reparse_dirent<FILE_FULL_DIR_INFORMATION>(dir, u"reparse2", IO_REPARSE_TAG_SYMLINK);
    });

    test("Check directory entry (FILE_ID_FULL_DIR_INFORMATION)", [&]() {
        check_reparse_dirent<FILE_ID_FULL_DIR_INFORMATION>(dir, u"reparse2", IO_REPARSE_TAG_SYMLINK);
    });

    test("Check directory entry (FILE_BOTH_DIR_INFORMATION)", [&]() {
        check_reparse_dirent<FILE_BOTH_DIR_INFORMATION>(dir, u"reparse2", IO_REPARSE_TAG_SYMLINK);
    });

    test("Check directory entry (FILE_ID_BOTH_DIR_INFORMATION)", [&]() {
        check_reparse_dirent<FILE_ID_BOTH_DIR_INFORMATION>(dir, u"reparse2", IO_REPARSE_TAG_SYMLINK);
    });

    test("Check directory entry (FILE_ID_EXTD_DIR_INFORMATION)", [&]() {
        check_reparse_dirent<FILE_ID_EXTD_DIR_INFORMATION>(dir, u"reparse2", IO_REPARSE_TAG_SYMLINK);
    });

    test("Check directory entry (FILE_ID_EXTD_BOTH_DIR_INFORMATION)", [&]() {
        check_reparse_dirent<FILE_ID_EXTD_BOTH_DIR_INFORMATION>(dir, u"reparse2", IO_REPARSE_TAG_SYMLINK);
    });

    test("Open file with FILE_OPEN_REPARSE_POINT", [&]() {
        h = create_file(dir + u"\\reparse2", FILE_WRITE_ATTRIBUTES, 0, 0, FILE_OPEN,
                        FILE_OPEN_REPARSE_POINT, FILE_OPENED);
    });

    if (h) {
        test("Check ID", [&]() {
            auto fii = query_information<FILE_INTERNAL_INFORMATION>(h.get());

            if (fii.IndexNumber.QuadPart != file2id)
                throw runtime_error("File ID was not expected value");
        });

        test("Try deleting reparse point with wrong tag", [&]() {
            exp_status([&]() {
                delete_reparse_point(h.get(), IO_REPARSE_TAG_MOUNT_POINT);
            }, STATUS_IO_REPARSE_TAG_MISMATCH);
        });

        test("Delete reparse point", [&]() {
            delete_reparse_point(h.get(), IO_REPARSE_TAG_SYMLINK);
        });

        h.reset();
    }

    test("Open file", [&]() {
        h = create_file(dir + u"\\reparse2", FILE_READ_ATTRIBUTES, 0, 0, FILE_OPEN,
                        0, FILE_OPENED);
    });

    if (h) {
        test("Check ID", [&]() {
            auto fii = query_information<FILE_INTERNAL_INFORMATION>(h.get());

            if (fii.IndexNumber.QuadPart != file2id)
                throw runtime_error("File ID was not expected value");
        });

        h.reset();
    }

    // FIXME - querying information?
    // FIXME - what happens if we try to overwrite symlink?

    // FIXME - absolute symlinks
    // FIXME - mount points (IO_REPARSE_TAG_MOUNT_POINT) (make sure can access files within directory)
    // FIXME - what happens if we try to make a file a mount point, or a directory a symlink?
    // FIXME - generic (i.e. non-Microsoft)
    // FIXME - setting reparse tag on non-empty directory (D bit)
    // FIXME - need FILE_WRITE_DATA or FILE_WRITE_ATTRIBUTES to set or delete reparse point?
    // FIXME - test without SeCreateSymbolicLinkPrivilege

    // FIXME - FSCTL_SET_REPARSE_POINT_EX
}
