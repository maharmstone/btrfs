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

static void set_mount_point(HANDLE h, u16string_view substitute_name, u16string_view print_name) {
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    vector<uint8_t> buf;

    // both substitute and print strings need to be null-terminated

    buf.resize(offsetof(REPARSE_DATA_BUFFER, MountPointReparseBuffer.PathBuffer) + ((substitute_name.length() + 1 + print_name.length() + 1) * sizeof(char16_t)));

    auto& rdb = *(REPARSE_DATA_BUFFER*)buf.data();

    rdb.ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    rdb.ReparseDataLength = buf.size() - offsetof(REPARSE_DATA_BUFFER, MountPointReparseBuffer);
    rdb.Reserved = 0;

    auto& mprb = rdb.MountPointReparseBuffer;

    mprb.SubstituteNameOffset = 0;
    mprb.SubstituteNameLength = substitute_name.length() * sizeof(char16_t);
    mprb.PrintNameOffset = mprb.SubstituteNameLength + sizeof(char16_t);
    mprb.PrintNameLength = print_name.length() * sizeof(char16_t);

    memcpy((char*)mprb.PathBuffer + mprb.SubstituteNameOffset,
           substitute_name.data(), mprb.SubstituteNameLength);
    mprb.PathBuffer[(mprb.SubstituteNameOffset + mprb.SubstituteNameLength) / sizeof(char16_t)] = 0;
    memcpy((char*)mprb.PathBuffer + mprb.PrintNameOffset,
           print_name.data(), mprb.PrintNameLength);
    mprb.PathBuffer[(mprb.PrintNameOffset + mprb.PrintNameLength) / sizeof(char16_t)] = 0;

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

static void write_ea(HANDLE h, string_view name, string_view value) {
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    vector<uint8_t> buf;

    buf.resize(offsetof(FILE_FULL_EA_INFORMATION, EaName) + name.size() + value.size() + 1);

    auto& ffeai = *(FILE_FULL_EA_INFORMATION*)buf.data();

    ffeai.NextEntryOffset = 0;
    ffeai.Flags = 0;
    ffeai.EaNameLength = name.size();
    ffeai.EaValueLength = value.size();

    memcpy(ffeai.EaName, name.data(), name.size());
    ffeai.EaName[name.size()] = 0;
    memcpy(ffeai.EaName + name.size() + 1, value.data(), value.size());

    Status = NtSetEaFile(h, &iosb, buf.data(), buf.size());

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);
}

static void set_basic_information(HANDLE h, int64_t creation_time, int64_t last_access_time,
                                  int64_t last_write_time, int64_t change_time, uint32_t attributes) {
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    FILE_BASIC_INFORMATION fbi;

    fbi.CreationTime.QuadPart = creation_time;
    fbi.LastAccessTime.QuadPart = last_access_time;
    fbi.LastWriteTime.QuadPart = last_write_time;
    fbi.ChangeTime.QuadPart = change_time;
    fbi.FileAttributes = attributes;

    Status = NtSetInformationFile(h, &iosb, &fbi, sizeof(fbi), FileBasicInformation);

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);

    if (iosb.Information != 0)
        throw formatted_error("iosb.Information was {}, expected 0", iosb.Information);
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
        h = create_file(dir + u"\\reparse2", FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES | FILE_READ_EA,
                        0, 0, FILE_CREATE, FILE_NON_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Get file ID", [&]() {
            auto fii = query_information<FILE_INTERNAL_INFORMATION>(h.get());

            file2id = fii.IndexNumber.QuadPart;
        });

        test("Clear archive flag", [&]() {
            set_basic_information(h.get(), 0, 0, 0, 0, FILE_ATTRIBUTE_NORMAL);
        });

        test("Query attributes", [&]() {
            auto fbi = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi.FileAttributes != FILE_ATTRIBUTE_NORMAL)
                throw formatted_error("FileAttributes was {:x}, expected FILE_ATTRIBUTE_NORMAL", fbi.FileAttributes);
        });

        test("Set as symlink", [&]() {
            set_symlink(h.get(), u"reparse1", u"reparse1", true);
        });

        test("Query attributes", [&]() {
            auto fbi = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi.FileAttributes != FILE_ATTRIBUTE_REPARSE_POINT)
                throw formatted_error("FileAttributes was {:x}, expected FILE_ATTRIBUTE_REPARSE_POINT", fbi.FileAttributes);
        });

        test("Query reparse point", [&]() {
            auto buf = query_reparse_point(h.get());
            auto& rdb = *static_cast<REPARSE_DATA_BUFFER*>(buf);

            if (rdb.ReparseTag != IO_REPARSE_TAG_SYMLINK)
                throw formatted_error("ReparseTag was {:08x}, expected IO_REPARSE_TAG_SYMLINK", rdb.ReparseTag);

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

        test("Query FileEaInformation", [&]() {
            auto feai = query_information<FILE_EA_INFORMATION>(h.get());

            if (feai.EaSize != 0)
                throw formatted_error("EaSize was {:08x}, expected 0", feai.EaSize);
        });

        // needs FILE_READ_ATTRIBUTES
        test("Query FileStatInformation", [&]() {
            auto fsi = query_information<FILE_STAT_INFORMATION>(h.get());

            if (fsi.ReparseTag != IO_REPARSE_TAG_SYMLINK)
                throw formatted_error("ReparseTag was {:08x}, expected IO_REPARSE_TAG_SYMLINK", fsi.ReparseTag);
        });

        // needs FILE_READ_EA as well
        test("Query FileStatLxInformation", [&]() {
            auto fsli = query_information<FILE_STAT_LX_INFORMATION>(h.get());

            if (fsli.ReparseTag != IO_REPARSE_TAG_SYMLINK)
                throw formatted_error("ReparseTag was {:08x}, expected IO_REPARSE_TAG_SYMLINK", fsli.ReparseTag);
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
        h = create_file(dir + u"\\reparse2", FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES, 0, 0, FILE_OPEN,
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

        test("Clear archive flag", [&]() {
            set_basic_information(h.get(), 0, 0, 0, 0, FILE_ATTRIBUTE_NORMAL);
        });

        test("Query attributes", [&]() {
            auto fbi = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi.FileAttributes != FILE_ATTRIBUTE_REPARSE_POINT)
                throw formatted_error("FileAttributes was {:x}, expected FILE_ATTRIBUTE_REPARSE_POINT", fbi.FileAttributes);
        });

        test("Delete reparse point", [&]() {
            delete_reparse_point(h.get(), IO_REPARSE_TAG_SYMLINK);
        });

        test("Query attributes", [&]() {
            auto fbi = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi.FileAttributes != FILE_ATTRIBUTE_NORMAL)
                throw formatted_error("FileAttributes was {:x}, expected FILE_ATTRIBUTE_NORMAL", fbi.FileAttributes);
        });

        test("Try to delete reparse point again", [&]() {
            exp_status([&]() {
                delete_reparse_point(h.get(), IO_REPARSE_TAG_SYMLINK);
            }, STATUS_NOT_A_REPARSE_POINT);
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

    test("Create file", [&]() {
        h = create_file(dir + u"\\reparse3", FILE_WRITE_ATTRIBUTES, 0, 0, FILE_CREATE,
                        FILE_NON_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Set as symlink", [&]() {
            set_symlink(h.get(), u"reparse1", u"reparse1", true);
        });

        h.reset();
    }

    test("Overwrite file through symlink", [&]() {
        create_file(dir + u"\\reparse3", FILE_WRITE_ATTRIBUTES, 0, 0, FILE_OVERWRITE,
                    FILE_NON_DIRECTORY_FILE, FILE_OVERWRITTEN);
    });

    test("Check target rather than symlink overwritten", [&]() {
        check_reparse_dirent<FILE_FULL_DIR_INFORMATION>(dir, u"reparse3", IO_REPARSE_TAG_SYMLINK);
    });

    test("Overwrite symlink", [&]() {
        create_file(dir + u"\\reparse3", FILE_WRITE_ATTRIBUTES, 0, 0, FILE_OVERWRITE,
                    FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT, FILE_OVERWRITTEN);
    });

    test("Check symlink overwritten", [&]() {
        check_reparse_dirent<FILE_FULL_DIR_INFORMATION>(dir, u"reparse3", 0);
    });

    test("Create file", [&]() {
        h = create_file(dir + u"\\reparse4", FILE_WRITE_DATA, 0, 0, FILE_CREATE,
                        FILE_NON_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Write to file", [&]() {
            write_file_wait(h.get(), random_data(4096), 0);
        });

        test("Set as symlink", [&]() {
            exp_status([&]() {
                set_symlink(h.get(), u"reparse1", u"reparse1", true);
            }, STATUS_IO_REPARSE_DATA_INVALID);
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\reparse5", FILE_WRITE_DATA, 0, 0, FILE_CREATE,
                        FILE_NON_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Set as symlink", [&]() {
            set_symlink(h.get(), u"reparse1", u"reparse1", true);
        });

        test("Write to file", [&]() {
            write_file_wait(h.get(), random_data(4096), 0);
        });

        h.reset();
    }

    test("Create directory", [&]() {
        h = create_file(dir + u"\\reparse6", FILE_WRITE_DATA, 0, 0, FILE_CREATE,
                        FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Set as symlink", [&]() {
            set_symlink(h.get(), u"reparse1", u"reparse1", true);
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\reparse7", FILE_WRITE_DATA | FILE_WRITE_EA, 0, 0, FILE_CREATE,
                        FILE_NON_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Write EA", [&]() {
            write_ea(h.get(), "hello", "world");
        });

        test("Set as symlink", [&]() {
            set_symlink(h.get(), u"reparse1", u"reparse1", true);
        });

        test("Write another EA", [&]() {
            write_ea(h.get(), "lemon", "curry");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\reparse8", FILE_WRITE_DATA, 0, 0, FILE_CREATE,
                        FILE_NON_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Set as symlink with invalid target", [&]() {
            set_symlink(h.get(), u"reparsenonsuch", u"reparsenonsuch", true);
        });

        h.reset();
    }

    test("Try to open invalid file through symlink", [&]() {
        exp_status([&]() {
            create_file(dir + u"\\reparse8", MAXIMUM_ALLOWED, 0, 0, FILE_OPEN,
                        FILE_NON_DIRECTORY_FILE, FILE_OPENED);
        }, STATUS_OBJECT_NAME_NOT_FOUND);
    });

    test("Create file", [&]() {
        h = create_file(dir + u"\\reparse9a", FILE_READ_ATTRIBUTES, 0, 0, FILE_CREATE,
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
        h = create_file(dir + u"\\reparse9b", FILE_WRITE_DATA, 0, 0, FILE_CREATE,
                        FILE_NON_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Set as absolute symlink", [&]() {
            set_symlink(h.get(), dir + u"\\reparse9a", u"reparse9a", false);
        });

        h.reset();
    }

    test("Open file through absolute symlink", [&]() {
        h = create_file(dir + u"\\reparse9b", FILE_READ_ATTRIBUTES, 0, 0, FILE_OPEN,
                        FILE_NON_DIRECTORY_FILE, FILE_OPENED);
    });

    if (h) {
        test("Get file ID", [&]() {
            auto fii = query_information<FILE_INTERNAL_INFORMATION>(h.get());

            if (fii.IndexNumber.QuadPart != file1id)
                throw runtime_error("File ID had unexpected value");
        });

        h.reset();
    }

    test("Create directory", [&]() {
        h = create_file(dir + u"\\reparse10a", FILE_READ_ATTRIBUTES, 0, 0, FILE_CREATE,
                        FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Get directory ID", [&]() {
            auto fii = query_information<FILE_INTERNAL_INFORMATION>(h.get());

            file1id = fii.IndexNumber.QuadPart;
        });

        h.reset();
    }

    test("Create file within directory", [&]() {
        create_file(dir + u"\\reparse10a\\file", FILE_READ_ATTRIBUTES, 0, 0, FILE_CREATE,
                    FILE_NON_DIRECTORY_FILE, FILE_CREATED);
    });

    test("Create directory", [&]() {
        h = create_file(dir + u"\\reparse10b", FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES | FILE_READ_EA,
                        0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Get directory ID", [&]() {
            auto fii = query_information<FILE_INTERNAL_INFORMATION>(h.get());

            file2id = fii.IndexNumber.QuadPart;
        });

        test("Clear archive flag", [&]() {
            set_basic_information(h.get(), 0, 0, 0, 0, FILE_ATTRIBUTE_NORMAL);
        });

        test("Query attributes", [&]() {
            auto fbi = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi.FileAttributes != FILE_ATTRIBUTE_DIRECTORY)
                throw formatted_error("FileAttributes was {:x}, expected FILE_ATTRIBUTE_DIRECTORY", fbi.FileAttributes);
        });

        test("Set as mount point", [&]() {
            set_mount_point(h.get(), dir + u"\\reparse10a", u"reparse10a");
        });

        test("Query attributes", [&]() {
            auto fbi = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi.FileAttributes != (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY))
                throw formatted_error("FileAttributes was {:x}, expected FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY", fbi.FileAttributes);
        });

        test("Query reparse point", [&]() {
            auto buf = query_reparse_point(h.get());
            auto& rdb = *static_cast<REPARSE_DATA_BUFFER*>(buf);

            if (rdb.ReparseTag != IO_REPARSE_TAG_MOUNT_POINT)
                throw formatted_error("ReparseTag was {:08x}, expected IO_REPARSE_TAG_MOUNT_POINT", rdb.ReparseTag);

            auto& mprb = rdb.MountPointReparseBuffer;

            auto dest = u16string_view((char16_t*)((char*)mprb.PathBuffer + mprb.SubstituteNameOffset),
                                       mprb.SubstituteNameLength / sizeof(char16_t));

            if (dest != dir + u"\\reparse10a")
                throw formatted_error("Destination was \"{}\", expected \"{}\"", u16string_to_string(dest), u16string_to_string(dir + u"\\reparse10a"));
        });

        test("Query FileEaInformation", [&]() {
            auto feai = query_information<FILE_EA_INFORMATION>(h.get());

            if (feai.EaSize != 0)
                throw formatted_error("EaSize was {:08x}, expected 0", feai.EaSize);
        });

        // needs FILE_READ_ATTRIBUTES
        test("Query FileStatInformation", [&]() {
            auto fsi = query_information<FILE_STAT_INFORMATION>(h.get());

            if (fsi.ReparseTag != IO_REPARSE_TAG_MOUNT_POINT)
                throw formatted_error("ReparseTag was {:08x}, expected IO_REPARSE_TAG_MOUNT_POINT", fsi.ReparseTag);
        });

        // needs FILE_READ_EA as well
        test("Query FileStatLxInformation", [&]() {
            auto fsli = query_information<FILE_STAT_LX_INFORMATION>(h.get());

            if (fsli.ReparseTag != IO_REPARSE_TAG_MOUNT_POINT)
                throw formatted_error("ReparseTag was {:08x}, expected IO_REPARSE_TAG_MOUNT_POINT", fsli.ReparseTag);
        });

        h.reset();
    }

    test("Check directory entry (FILE_FULL_DIR_INFORMATION)", [&]() {
        check_reparse_dirent<FILE_FULL_DIR_INFORMATION>(dir, u"reparse10b", IO_REPARSE_TAG_MOUNT_POINT);
    });

    test("Check directory entry (FILE_ID_FULL_DIR_INFORMATION)", [&]() {
        check_reparse_dirent<FILE_ID_FULL_DIR_INFORMATION>(dir, u"reparse10b", IO_REPARSE_TAG_MOUNT_POINT);
    });

    test("Check directory entry (FILE_BOTH_DIR_INFORMATION)", [&]() {
        check_reparse_dirent<FILE_BOTH_DIR_INFORMATION>(dir, u"reparse10b", IO_REPARSE_TAG_MOUNT_POINT);
    });

    test("Check directory entry (FILE_ID_BOTH_DIR_INFORMATION)", [&]() {
        check_reparse_dirent<FILE_ID_BOTH_DIR_INFORMATION>(dir, u"reparse10b", IO_REPARSE_TAG_MOUNT_POINT);
    });

    test("Check directory entry (FILE_ID_EXTD_DIR_INFORMATION)", [&]() {
        check_reparse_dirent<FILE_ID_EXTD_DIR_INFORMATION>(dir, u"reparse10b", IO_REPARSE_TAG_MOUNT_POINT);
    });

    test("Check directory entry (FILE_ID_EXTD_BOTH_DIR_INFORMATION)", [&]() {
        check_reparse_dirent<FILE_ID_EXTD_BOTH_DIR_INFORMATION>(dir, u"reparse10b", IO_REPARSE_TAG_MOUNT_POINT);
    });

    test("Open mount point without FILE_OPEN_REPARSE_POINT", [&]() {
        h = create_file(dir + u"\\reparse10b", FILE_READ_ATTRIBUTES,
                        0, 0, FILE_OPEN, 0, FILE_OPENED);
    });

    if (h) {
        test("Get directory ID", [&]() {
            auto fii = query_information<FILE_INTERNAL_INFORMATION>(h.get());

            if (fii.IndexNumber.QuadPart != file1id)
                throw runtime_error("Directory ID had unexpected value");
        });

        h.reset();
    }

    test("Open mount point with FILE_OPEN_REPARSE_POINT", [&]() {
        h = create_file(dir + u"\\reparse10b", FILE_READ_ATTRIBUTES,
                        0, 0, FILE_OPEN, FILE_OPEN_REPARSE_POINT, FILE_OPENED);
    });

    if (h) {
        test("Get directory ID", [&]() {
            auto fii = query_information<FILE_INTERNAL_INFORMATION>(h.get());

            if (fii.IndexNumber.QuadPart != file2id)
                throw runtime_error("Directory ID had unexpected value");
        });

        h.reset();
    }

    test("Open file through mount point (without FILE_OPEN_REPARSE_POINT)", [&]() {
        create_file(dir + u"\\reparse10b\\file", MAXIMUM_ALLOWED,
                    0, 0, FILE_OPEN, 0, FILE_OPENED);
    });

    test("Open file through mount point (with FILE_OPEN_REPARSE_POINT)", [&]() {
        create_file(dir + u"\\reparse10b\\file", MAXIMUM_ALLOWED,
                    0, 0, FILE_OPEN, FILE_OPEN_REPARSE_POINT, FILE_OPENED);
    });

    test("Open mount point with FILE_OPEN_REPARSE_POINT", [&]() {
        h = create_file(dir + u"\\reparse10b", FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
                        0, 0, FILE_OPEN, FILE_OPEN_REPARSE_POINT, FILE_OPENED);
    });

    if (h) {
        test("Clear archive flag", [&]() {
            set_basic_information(h.get(), 0, 0, 0, 0, FILE_ATTRIBUTE_NORMAL);
        });

        test("Query attributes", [&]() {
            auto fbi = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi.FileAttributes != (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY))
                throw formatted_error("FileAttributes was {:x}, expected FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY", fbi.FileAttributes);
        });

        test("Delete reparse point", [&]() {
            delete_reparse_point(h.get(), IO_REPARSE_TAG_MOUNT_POINT);
        });

        test("Query attributes", [&]() {
            auto fbi = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi.FileAttributes != FILE_ATTRIBUTE_DIRECTORY)
                throw formatted_error("FileAttributes was {:x}, expected FILE_ATTRIBUTE_DIRECTORY", fbi.FileAttributes);
        });

        test("Try to delete reparse point again", [&]() {
            exp_status([&]() {
                delete_reparse_point(h.get(), IO_REPARSE_TAG_MOUNT_POINT);
            }, STATUS_NOT_A_REPARSE_POINT);
        });

        h.reset();
    }

    test("Open directory with children", [&]() {
        h = create_file(dir + u"\\reparse10a", FILE_WRITE_ATTRIBUTES,
                        0, 0, FILE_OPEN, 0, FILE_OPENED);
    });

    if (h) {
        test("Try to set as mount point", [&]() {
            exp_status([&]() {
                set_mount_point(h.get(), dir + u"\\reparse10b", u"reparse10b");
            }, STATUS_DIRECTORY_NOT_EMPTY);
        });

        h.reset();
    }

    test("Open old mount point directory", [&]() {
        h = create_file(dir + u"\\reparse10b", FILE_WRITE_ATTRIBUTES,
                        0, 0, FILE_OPEN, 0, FILE_OPENED);
    });

    if (h) {
        test("Set as mount point", [&]() {
            set_mount_point(h.get(), dir + u"\\reparse10a", u"reparse10a");
        });

        test("Set as mount point again", [&]() {
            set_mount_point(h.get(), dir + u"\\reparse10c", u"reparse10c");
        });

        test("Set as symlink", [&]() {
            exp_status([&]() {
                set_symlink(h.get(), dir + u"\\reparse10a", u"reparse10a", false);
            }, STATUS_IO_REPARSE_TAG_MISMATCH);
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\reparse11", FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA,
                        0, 0, FILE_CREATE, FILE_NON_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Try to set as mount point", [&]() {
            exp_status([&]() {
                set_mount_point(h.get(), dir + u"\\reparse10a", u"reparse10a");
            }, STATUS_NOT_A_DIRECTORY);
        });

        h.reset();
    }

    // FIXME - generic (i.e. non-Microsoft)
    // FIXME - need FILE_WRITE_DATA or FILE_WRITE_ATTRIBUTES to set or delete reparse point
    // FIXME - setting reparse tag on non-empty directory (D bit)
    // FIXME - test validating InputBuffer size
    // FIXME - test without SeCreateSymbolicLinkPrivilege
    // FIXME - should return STATUS_IO_REPARSE_TAG_INVALID if IO_REPARSE_TAG_RESERVED_ZERO or IO_REPARSE_TAG_RESERVED_ONE

    // FIXME - FSCTL_SET_REPARSE_POINT_EX
}
