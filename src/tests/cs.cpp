#include "test.h"

using namespace std;

static void set_case_sensitive(HANDLE h, bool case_sensitive) {
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    FILE_CASE_SENSITIVE_INFORMATION fcsi;

    fcsi.Flags = case_sensitive ? FILE_CS_FLAG_CASE_SENSITIVE_DIR : 0;

    Status = NtSetInformationFile(h, &iosb, &fcsi, sizeof(fcsi), FileCaseSensitiveInformation);

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);

    if (iosb.Information != 0)
        throw formatted_error("iosb.Information was {}, expected 0", iosb.Information);
}

static unique_handle create_file_cs(u16string_view path, ACCESS_MASK access, ULONG atts,
                                    ULONG share, ULONG dispo, ULONG options, ULONG_PTR exp_info,
                                    optional<uint64_t> allocation = nullopt) {
    NTSTATUS Status;
    HANDLE h;
    IO_STATUS_BLOCK iosb;
    UNICODE_STRING us;
    OBJECT_ATTRIBUTES oa;
    LARGE_INTEGER alloc_size;

    oa.Length = sizeof(oa);
    oa.RootDirectory = nullptr; // FIXME - test

    us.Length = us.MaximumLength = path.length() * sizeof(char16_t);
    us.Buffer = (WCHAR*)path.data();
    oa.ObjectName = &us;

    oa.Attributes = 0; // not OBJ_CASE_INSENSITIVE
    oa.SecurityDescriptor = nullptr; // FIXME - test
    oa.SecurityQualityOfService = nullptr; // FIXME - test(?)

    if (allocation)
        alloc_size.QuadPart = allocation.value();

    // FIXME - EaBuffer and EaLength

    iosb.Information = 0xdeadbeef;

    Status = NtCreateFile(&h, access, &oa, &iosb, allocation ? &alloc_size : nullptr,
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

void test_cs(const u16string& dir) {
    unique_handle h;
    int64_t lc_id = 0, uc_id = 0;

    test("Create directory", [&]() {
        h = create_file(dir + u"\\csdir", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE,
                        FILE_CREATED);
    });

    if (h) {
        // returns STATUS_NOT_SUPPORTED unless HKLM\SYSTEM\CurrentControlSet\Control\FileSystem\NtfsEnableDirCaseSensitivity is set to 1

        test("Set case-sensitive flag", [&]() {
            set_case_sensitive(h.get(), true);
        });

        test("Query case-sensitive flag", [&]() {
            auto fcsi = query_information<FILE_CASE_SENSITIVE_INFORMATION>(h.get());

            if (fcsi.Flags != FILE_CS_FLAG_CASE_SENSITIVE_DIR)
                throw formatted_error("Flags was {:x}, expected FILE_CS_FLAG_CASE_SENSITIVE_DIR", fcsi.Flags);
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\csdir\\cs1", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE,
                        FILE_NON_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Get file ID", [&]() {
            auto fii = query_information<FILE_INTERNAL_INFORMATION>(h.get());

            lc_id = fii.IndexNumber.QuadPart;
        });

        h.reset();
    }

    test("Check directory entry", [&]() {
        u16string_view name = u"cs1";

        auto items = query_dir<FILE_ID_FULL_DIR_INFORMATION>(dir + u"\\csdir", name);

        if (items.size() != 1)
            throw formatted_error("{} entries returned, expected 1.", items.size());

        auto& fdi = *static_cast<const FILE_ID_FULL_DIR_INFORMATION*>(items.front());

        if (fdi.FileNameLength != name.size() * sizeof(char16_t))
            throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

        if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
            throw runtime_error("FileName did not match.");
    });

    test("Check directory entry with wrong case", [&]() {
        u16string_view name = u"CS1";

        exp_status([&]() {
            query_dir<FILE_ID_FULL_DIR_INFORMATION>(dir + u"\\csdir", name);
        }, STATUS_NO_SUCH_FILE);
    });

    test("Try opening file with wrong case (FILE_OPEN)", [&]() {
        exp_status([&]() {
            create_file(dir + u"\\csdir\\CS1", MAXIMUM_ALLOWED, 0, 0, FILE_OPEN,
                        FILE_NON_DIRECTORY_FILE, FILE_OPENED);
        }, STATUS_OBJECT_NAME_NOT_FOUND);
    });

    test("Try opening file with wrong case (FILE_OVERWRITE)", [&]() {
        exp_status([&]() {
            create_file(dir + u"\\csdir\\CS1", MAXIMUM_ALLOWED, 0, 0, FILE_OVERWRITE,
                        FILE_NON_DIRECTORY_FILE, FILE_OVERWRITTEN);
        }, STATUS_OBJECT_NAME_NOT_FOUND);
    });

    test("Create file with different case (FILE_CREATE)", [&]() {
        h = create_file(dir + u"\\csdir\\CS1", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE,
                        FILE_NON_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Get file ID", [&]() {
            auto fii = query_information<FILE_INTERNAL_INFORMATION>(h.get());

            uc_id = fii.IndexNumber.QuadPart;
        });

        h.reset();
    }

    test("Open uppercase file (FILE_OPEN_IF)", [&]() {
        h = create_file(dir + u"\\csdir\\CS1", MAXIMUM_ALLOWED, 0, 0, FILE_OPEN_IF,
                        FILE_NON_DIRECTORY_FILE, FILE_OPENED);
    });

    if (h) {
        test("Check file ID", [&]() {
            auto fii = query_information<FILE_INTERNAL_INFORMATION>(h.get());

            if (fii.IndexNumber.QuadPart != uc_id)
                throw runtime_error("Wrong file ID");
        });

        h.reset();
    }

    test("Open uppercase file (FILE_OVERWRITE_IF)", [&]() {
        h = create_file(dir + u"\\csdir\\CS1", MAXIMUM_ALLOWED, 0, 0, FILE_OVERWRITE_IF,
                        FILE_NON_DIRECTORY_FILE, FILE_OVERWRITTEN);
    });

    if (h) {
        test("Check file ID", [&]() {
            auto fii = query_information<FILE_INTERNAL_INFORMATION>(h.get());

            if (fii.IndexNumber.QuadPart != uc_id)
                throw runtime_error("Wrong file ID");
        });

        h.reset();
    }

    test("Open uppercase file (FILE_SUPERSEDE)", [&]() {
        h = create_file(dir + u"\\csdir\\CS1", MAXIMUM_ALLOWED, 0, 0, FILE_SUPERSEDE,
                        FILE_NON_DIRECTORY_FILE, FILE_SUPERSEDED);
    });

    if (h) {
        test("Check file ID", [&]() {
            auto fii = query_information<FILE_INTERNAL_INFORMATION>(h.get());

            if (fii.IndexNumber.QuadPart != uc_id)
                throw runtime_error("Wrong file ID");
        });

        h.reset();
    }

    test("Create subdir", [&]() {
        h = create_file(dir + u"\\csdir\\cs2", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE,
                        FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Check case-sensitive flag inherited", [&]() {
            auto fcsi = query_information<FILE_CASE_SENSITIVE_INFORMATION>(h.get());

            if (fcsi.Flags != FILE_CS_FLAG_CASE_SENSITIVE_DIR)
                throw formatted_error("Flags was {:x}, expected FILE_CS_FLAG_CASE_SENSITIVE_DIR", fcsi.Flags);
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\csdir\\cs3", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE,
                        FILE_NON_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Try to set case-sensitive flag on file", [&]() {
            exp_status([&]() {
                set_case_sensitive(h.get(), true);
            }, STATUS_INVALID_PARAMETER);
        });

        test("Query case-sensitive flag on file", [&]() {
            auto fcsi = query_information<FILE_CASE_SENSITIVE_INFORMATION>(h.get());

            if (fcsi.Flags != 0)
                throw formatted_error("Flags was {:x}, expected 0", fcsi.Flags);
        });

        h.reset();
    }

    test("Create subdir", [&]() {
        h = create_file(dir + u"\\csdir\\cs5", FILE_WRITE_ATTRIBUTES | WRITE_DAC, 0, 0, FILE_CREATE,
                        FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Set DACL to FILE_ADD_SUBDIRECTORY | FILE_DELETE_CHILD", [&]() {
            set_dacl(h.get(), FILE_ADD_SUBDIRECTORY | FILE_DELETE_CHILD);
        });

        test("Try to set case-sensitive flag", [&]() {
            exp_status([&]() {
                set_case_sensitive(h.get(), true);
            }, STATUS_ACCESS_DENIED);
        });

        test("Set DACL to FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY", [&]() {
            set_dacl(h.get(), FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY);
        });

        test("Try to set case-sensitive flag", [&]() {
            exp_status([&]() {
                set_case_sensitive(h.get(), true);
            }, STATUS_ACCESS_DENIED);
        });

        test("Set DACL to FILE_ADD_FILE | FILE_DELETE_CHILD", [&]() {
            set_dacl(h.get(), FILE_ADD_FILE | FILE_DELETE_CHILD);
        });

        test("Try to set case-sensitive flag", [&]() {
            exp_status([&]() {
                set_case_sensitive(h.get(), true);
            }, STATUS_ACCESS_DENIED);
        });

        test("Set DACL to FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_DELETE_CHILD", [&]() {
            set_dacl(h.get(), FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_DELETE_CHILD);
        });

        test("Set case-sensitive flag", [&]() {
            set_case_sensitive(h.get(), true);
        });

        h.reset();
    }

    test("Create subdir", [&]() {
        create_file(dir + u"\\csdir\\cs6", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE,
                    FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    test("Create file", [&]() {
        create_file(dir + u"\\csdir\\cs6\\file", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE,
                    FILE_NON_DIRECTORY_FILE, FILE_CREATED);
    });

    test("Open subdir", [&]() {
        h = create_file(dir + u"\\csdir\\cs6", FILE_WRITE_ATTRIBUTES, 0, 0, FILE_OPEN,
                        FILE_DIRECTORY_FILE, FILE_OPENED);
    });

    if (h) {
        test("Set case-sensitive flag on non-empty directory", [&]() {
            set_case_sensitive(h.get(), true);
        });

        test("Clear case-sensitive flag on non-empty directory", [&]() {
            set_case_sensitive(h.get(), false);
        });

        test("Set case-sensitive flag on non-empty directory again", [&]() {
            set_case_sensitive(h.get(), true);
        });

        h.reset();
    }

    test("Create file differing by case", [&]() {
        create_file(dir + u"\\csdir\\cs6\\FILE", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE,
                    FILE_NON_DIRECTORY_FILE, FILE_CREATED);
    });

    test("Open subdir", [&]() {
        h = create_file(dir + u"\\csdir\\cs6", FILE_WRITE_ATTRIBUTES, 0, 0, FILE_OPEN,
                        FILE_DIRECTORY_FILE, FILE_OPENED);
    });

    if (h) {
        test("Try to clear case-sensitive flag on directory with files differing in case", [&]() {
            exp_status([&]() {
                set_case_sensitive(h.get(), false);
            }, STATUS_CASE_DIFFERING_NAMES_IN_DIR);
        });

        h.reset();
    }

    test("Create file in normal dir without OBJ_CASE_INSENSITIVE", [&]() {
        create_file_cs(dir + u"\\cs7", MAXIMUM_ALLOWED, 0, 0, FILE_CREATED,
                       FILE_NON_DIRECTORY_FILE, FILE_CREATED);
    });

    test("Open file in normal dir without OBJ_CASE_INSENSITIVE", [&]() {
        create_file_cs(dir + u"\\cs7", MAXIMUM_ALLOWED, 0, 0, FILE_OPEN,
                       FILE_NON_DIRECTORY_FILE, FILE_OPENED);
    });

    // succeeds unless HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\ObCaseInsensitive set to 0

    test("Open file in normal dir without OBJ_CASE_INSENSITIVE with wrong case", [&]() {
        exp_status([&]() {
            create_file_cs(dir + u"\\CS7", MAXIMUM_ALLOWED, 0, 0, FILE_OPEN,
                           FILE_NON_DIRECTORY_FILE, FILE_OPENED);
        }, STATUS_OBJECT_NAME_NOT_FOUND);
    });

    test("Create stream in case-sensitive directory", [&]() {
        create_file(dir + u"\\csdir\\cs8:stream", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE,
                    FILE_NON_DIRECTORY_FILE, FILE_CREATED);
    });

    test("Open stream in case-sensitive directory with wrong case", [&]() { // succeeds!
        create_file(dir + u"\\csdir\\cs8:STREAM", MAXIMUM_ALLOWED, 0, 0, FILE_OPEN,
                    0, FILE_OPENED);
    });
}
