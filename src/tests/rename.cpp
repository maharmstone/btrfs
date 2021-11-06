#include "test.h"

using namespace std;

string u16string_to_string(const u16string_view& sv);

static void set_rename_information(HANDLE h, bool replace_if_exists, HANDLE root_dir, const u16string_view& filename) {
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    vector<uint8_t> buf(offsetof(FILE_RENAME_INFORMATION, FileName) + (filename.length() * sizeof(char16_t)));
    auto& fri = *(FILE_RENAME_INFORMATION*)buf.data();

    fri.ReplaceIfExists = replace_if_exists;
    fri.RootDirectory = root_dir;
    fri.FileNameLength = filename.length() * sizeof(char16_t);
    memcpy(fri.FileName, filename.data(), fri.FileNameLength);

    Status = NtSetInformationFile(h, &iosb, &fri, buf.size(), FileRenameInformation);

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);

    if (iosb.Information != 0)
        throw formatted_error("iosb.Information was {}, expected 0", iosb.Information);
}

void test_rename(const u16string& dir) {
    unique_handle h, h2;

    test("Create file", [&]() {
        h = create_file(dir + u"\\renamefile1", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Check name", [&]() {
            auto fn = query_file_name_information(h.get());

            static const u16string_view ends_with = u"\\renamefile1";

            if (fn.size() < ends_with.size() || fn.substr(fn.size() - ends_with.size()) != ends_with)
                throw runtime_error("Name did not end with \"\\renamefile1\".");
        });

        test("Check directory entry", [&]() {
            u16string_view name = u"renamefile1";

            auto items = query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& fdi = *static_cast<const FILE_DIRECTORY_INFORMATION*>(items.front());

            if (fdi.FileNameLength != name.size() * sizeof(char16_t))
                throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

            if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
                throw runtime_error("FileName did not match.");
        });

        test("Rename file", [&]() {
            set_rename_information(h.get(), false, nullptr, dir + u"\\renamefile1b");
        });

        test("Check name", [&]() {
            auto fn = query_file_name_information(h.get());

            static const u16string_view ends_with = u"\\renamefile1b";

            if (fn.size() < ends_with.size() || fn.substr(fn.size() - ends_with.size()) != ends_with)
                throw runtime_error("Name did not end with \"\\renamefile1b\".");
        });

        test("Check directory entry", [&]() {
            u16string_view name = u"renamefile1b";

            auto items = query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& fdi = *static_cast<const FILE_DIRECTORY_INFORMATION*>(items.front());

            if (fdi.FileNameLength != name.size() * sizeof(char16_t))
                throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

            if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
                throw runtime_error("FileName did not match.");
        });

        test("Check old directory entry not there", [&]() {
            u16string_view name = u"renamefile1";

            exp_status([&]() {
                query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);
            }, STATUS_NO_SUCH_FILE);
        });

        h.reset();
    }

    test("Create directory", [&]() {
        h = create_file(dir + u"\\renamedir1", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Check name", [&]() {
            auto fn = query_file_name_information(h.get());

            static const u16string_view ends_with = u"\\renamedir1";

            if (fn.size() < ends_with.size() || fn.substr(fn.size() - ends_with.size()) != ends_with)
                throw runtime_error("Name did not end with \"\\renamefile1\".");
        });

        test("Check directory entry", [&]() {
            u16string_view name = u"renamedir1";

            auto items = query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& fdi = *static_cast<const FILE_DIRECTORY_INFORMATION*>(items.front());

            if (fdi.FileNameLength != name.size() * sizeof(char16_t))
                throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

            if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
                throw runtime_error("FileName did not match.");
        });

        test("Rename file", [&]() {
            set_rename_information(h.get(), false, nullptr, dir + u"\\renamedir1b");
        });

        test("Check name", [&]() {
            auto fn = query_file_name_information(h.get());

            static const u16string_view ends_with = u"\\renamedir1b";

            if (fn.size() < ends_with.size() || fn.substr(fn.size() - ends_with.size()) != ends_with)
                throw runtime_error("Name did not end with \"\\renamedir1b\".");
        });

        test("Check directory entry", [&]() {
            u16string_view name = u"renamedir1b";

            auto items = query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& fdi = *static_cast<const FILE_DIRECTORY_INFORMATION*>(items.front());

            if (fdi.FileNameLength != name.size() * sizeof(char16_t))
                throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

            if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
                throw runtime_error("FileName did not match.");
        });

        test("Check old directory entry not there", [&]() {
            u16string_view name = u"renamedir1";

            exp_status([&]() {
                query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);
            }, STATUS_NO_SUCH_FILE);
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\renamefile2", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Check name", [&]() {
            auto fn = query_file_name_information(h.get());

            static const u16string_view ends_with = u"\\renamefile2";

            if (fn.size() < ends_with.size() || fn.substr(fn.size() - ends_with.size()) != ends_with)
                throw runtime_error("Name did not end with \"\\renamefile2\".");
        });

        test("Check directory entry", [&]() {
            u16string_view name = u"renamefile2";

            auto items = query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& fdi = *static_cast<const FILE_DIRECTORY_INFORMATION*>(items.front());

            if (fdi.FileNameLength != name.size() * sizeof(char16_t))
                throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

            if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
                throw runtime_error("FileName did not match.");
        });

        test("Rename file to same name", [&]() {
            set_rename_information(h.get(), false, nullptr, dir + u"\\renamefile2");
        });

        test("Check name", [&]() {
            auto fn = query_file_name_information(h.get());

            static const u16string_view ends_with = u"\\renamefile2";

            if (fn.size() < ends_with.size() || fn.substr(fn.size() - ends_with.size()) != ends_with)
                throw runtime_error("Name did not end with \"\\renamefile2\".");
        });

        test("Check directory entry", [&]() {
            u16string_view name = u"renamefile2";

            auto items = query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& fdi = *static_cast<const FILE_DIRECTORY_INFORMATION*>(items.front());

            if (fdi.FileNameLength != name.size() * sizeof(char16_t))
                throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

            if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
                throw runtime_error("FileName did not match.");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\renamefile3", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Check name", [&]() {
            auto fn = query_file_name_information(h.get());

            static const u16string_view ends_with = u"\\renamefile3";

            if (fn.size() < ends_with.size() || fn.substr(fn.size() - ends_with.size()) != ends_with)
                throw runtime_error("Name did not end with \"\\renamefile3\".");
        });

        test("Check directory entry", [&]() {
            u16string_view name = u"renamefile3";

            auto items = query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& fdi = *static_cast<const FILE_DIRECTORY_INFORMATION*>(items.front());

            if (fdi.FileNameLength != name.size() * sizeof(char16_t))
                throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

            if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
                throw runtime_error("FileName did not match.");
        });

        test("Rename file to different case", [&]() {
            set_rename_information(h.get(), false, nullptr, dir + u"\\RENAMEFILE3");
        });

        test("Check name", [&]() {
            auto fn = query_file_name_information(h.get());

            static const u16string_view ends_with = u"\\RENAMEFILE3";

            if (fn.size() < ends_with.size() || fn.substr(fn.size() - ends_with.size()) != ends_with)
                throw runtime_error("Name did not end with \"\\RENAMEFILE3\".");
        });

        test("Check directory entry", [&]() {
            u16string_view name = u"RENAMEFILE3";

            auto items = query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& fdi = *static_cast<const FILE_DIRECTORY_INFORMATION*>(items.front());

            if (fdi.FileNameLength != name.size() * sizeof(char16_t))
                throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

            if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
                throw runtime_error("FileName did not match.");
        });

        h.reset();
    }

    test("Create file 1", [&]() {
        create_file(dir + u"\\renamefile4a", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    test("Create file 2", [&]() {
        h = create_file(dir + u"\\renamefile4b", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Try renaming file 2 to file 1 without ReplaceIfExists set", [&]() {
            exp_status([&]() {
                set_rename_information(h.get(), false, nullptr, dir + u"\\renamefile4a");
            }, STATUS_OBJECT_NAME_COLLISION);
        });

        test("Rename file 2 to file 1", [&]() {
            set_rename_information(h.get(), true, nullptr, dir + u"\\renamefile4a");
        });

        test("Check name", [&]() {
            auto fn = query_file_name_information(h.get());

            static const u16string_view ends_with = u"\\renamefile4a";

            if (fn.size() < ends_with.size() || fn.substr(fn.size() - ends_with.size()) != ends_with)
                throw runtime_error("Name did not end with \"\\renamefile4a\".");
        });

        test("Check directory entry", [&]() {
            u16string_view name = u"renamefile4a";

            auto items = query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& fdi = *static_cast<const FILE_DIRECTORY_INFORMATION*>(items.front());

            if (fdi.FileNameLength != name.size() * sizeof(char16_t))
                throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

            if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
                throw runtime_error("FileName did not match.");
        });

        h.reset();
    }

    test("Create file 1", [&]() {
        h2 = create_file(dir + u"\\renamefile5a", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    test("Create file 2", [&]() {
        h = create_file(dir + u"\\renamefile5b", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Try renaming file 2 to file 1 without ReplaceIfExists set", [&]() {
            exp_status([&]() {
                set_rename_information(h.get(), false, nullptr, dir + u"\\renamefile5a");
            }, STATUS_OBJECT_NAME_COLLISION);
        });

        test("Try renaming file 2 to file 1 with file 1 open", [&]() {
            exp_status([&]() {
                set_rename_information(h.get(), true, nullptr, dir + u"\\renamefile5a");
            }, STATUS_ACCESS_DENIED);
        });

        h.reset();
    }

    h2.reset();

    // FIXME - RootDirectory
    // FIXME - permissions
    // FIXME - moving
    // FIXME - check invalid names (invalid characters, > 255 UTF-16, > 255 UTF-8, invalid UTF-16)
    // FIXME - FILE_RENAME_POSIX_SEMANTICS
    // FIXME - FILE_RENAME_REPLACE_IF_EXISTS
    // FIXME - FILE_RENAME_IGNORE_READONLY_ATTRIBUTE

    // FIXME - FILE_RENAME_SUPPRESS_PIN_STATE_INHERITANCE
    // FIXME - FILE_RENAME_SUPPRESS_STORAGE_RESERVE_INHERITANCE
    // FIXME - FILE_RENAME_NO_INCREASE_AVAILABLE_SPACE
    // FIXME - FILE_RENAME_NO_DECREASE_AVAILABLE_SPACE
    // FIXME - FILE_RENAME_FORCE_RESIZE_TARGET_SR
    // FIXME - FILE_RENAME_FORCE_RESIZE_SOURCE_SR
    // FIXME - FILE_RENAME_FORCE_RESIZE_SR
}
