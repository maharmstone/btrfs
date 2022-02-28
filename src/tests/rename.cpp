#include "test.h"

using namespace std;

void set_rename_information(HANDLE h, bool replace_if_exists, HANDLE root_dir, const u16string_view& filename) {
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

static void set_rename_information_ex(HANDLE h, ULONG flags, HANDLE root_dir, const u16string_view& filename) {
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    vector<uint8_t> buf(offsetof(FILE_RENAME_INFORMATION_EX, FileName) + (filename.length() * sizeof(char16_t)));
    auto& fri = *(FILE_RENAME_INFORMATION_EX*)buf.data();

    fri.Flags = flags;
    fri.RootDirectory = root_dir;
    fri.FileNameLength = filename.length() * sizeof(char16_t);
    memcpy(fri.FileName, filename.data(), fri.FileNameLength);

    Status = NtSetInformationFile(h, &iosb, &fri, buf.size(), FileRenameInformationEx);

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

    test("Create file 1", [&]() {
        create_file(dir + u"\\renamefile6a", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    test("Create file 2", [&]() {
        h = create_file(dir + u"\\renamefile6b", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Try renaming file 2 to file 1 uppercase without ReplaceIfExists set", [&]() {
            exp_status([&]() {
                set_rename_information(h.get(), false, nullptr, dir + u"\\RENAMEFILE6A");
            }, STATUS_OBJECT_NAME_COLLISION);
        });

        test("Rename file 2 to file 1 uppercase", [&]() {
            set_rename_information(h.get(), true, nullptr, dir + u"\\RENAMEFILE6A");
        });

        test("Check name", [&]() {
            auto fn = query_file_name_information(h.get());

            static const u16string_view ends_with = u"\\RENAMEFILE6A";

            if (fn.size() < ends_with.size() || fn.substr(fn.size() - ends_with.size()) != ends_with)
                throw runtime_error("Name did not end with \"\\RENAMEFILE6A\".");
        });

        test("Check directory entry", [&]() {
            u16string_view name = u"RENAMEFILE6A";

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

    test("Create directory", [&]() {
        create_file(dir + u"\\renamedir7", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    test("Create file", [&]() {
        h = create_file(dir + u"\\renamefile7", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Check name", [&]() {
            auto fn = query_file_name_information(h.get());

            static const u16string_view ends_with = u"\\renamefile7";

            if (fn.size() < ends_with.size() || fn.substr(fn.size() - ends_with.size()) != ends_with)
                throw runtime_error("Name did not end with \"\\renamefile7\".");
        });

        test("Check directory entry", [&]() {
            u16string_view name = u"renamefile7";

            auto items = query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& fdi = *static_cast<const FILE_DIRECTORY_INFORMATION*>(items.front());

            if (fdi.FileNameLength != name.size() * sizeof(char16_t))
                throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

            if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
                throw runtime_error("FileName did not match.");
        });

        test("Move file to subdir", [&]() {
            set_rename_information(h.get(), false, nullptr, dir + u"\\renamedir7\\renamefile7a");
        });

        test("Check name", [&]() {
            auto fn = query_file_name_information(h.get());

            static const u16string_view ends_with = u"\\renamedir7\\renamefile7a";

            if (fn.size() < ends_with.size() || fn.substr(fn.size() - ends_with.size()) != ends_with)
                throw runtime_error("Name did not end with \"\\renamedir7\\renamefile7a\".");
        });

        test("Check old directory entry gone", [&]() {
            u16string_view name = u"renamefile7";

            exp_status([&]() {
                query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);
            }, STATUS_NO_SUCH_FILE);
        });

        test("Check new directory entry", [&]() {
            u16string_view name = u"renamefile7a";

            auto items = query_dir<FILE_DIRECTORY_INFORMATION>(dir + u"\\renamedir7", name);

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& fdi = *static_cast<const FILE_DIRECTORY_INFORMATION*>(items.front());

            if (fdi.FileNameLength != name.size() * sizeof(char16_t))
                throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

            if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
                throw runtime_error("FileName did not match.");
        });

        test("Try overwriting directory with file without ReplaceIfExists set", [&]() {
            exp_status([&]() {
                set_rename_information(h.get(), false, nullptr, dir + u"\\renamedir7");
            }, STATUS_OBJECT_NAME_COLLISION);
        });

        test("Try overwriting directory with file with ReplaceIfExists set", [&]() {
            exp_status([&]() {
                set_rename_information(h.get(), true, nullptr, dir + u"\\renamedir7");
            }, STATUS_ACCESS_DENIED);
        });
    }

    test("Create directory 1", [&]() {
        create_file(dir + u"\\renamedir8", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    test("Create directory 2", [&]() {
        h = create_file(dir + u"\\renamedir8a", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    test("Create file", [&]() {
        create_file(dir + u"\\renamefile8", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Check directory entry", [&]() {
            u16string_view name = u"renamedir8a";

            auto items = query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& fdi = *static_cast<const FILE_DIRECTORY_INFORMATION*>(items.front());

            if (fdi.FileNameLength != name.size() * sizeof(char16_t))
                throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

            if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
                throw runtime_error("FileName did not match.");
        });

        test("Check name", [&]() {
            auto fn = query_file_name_information(h.get());

            static const u16string_view ends_with = u"\\renamedir8a";

            if (fn.size() < ends_with.size() || fn.substr(fn.size() - ends_with.size()) != ends_with)
                throw runtime_error("Name did not end with \"\\renamedir8a\".");
        });

        test("Move directory to subdir", [&]() {
            set_rename_information(h.get(), false, nullptr, dir + u"\\renamedir8\\renamedir8b");
        });

        test("Check name", [&]() {
            auto fn = query_file_name_information(h.get());

            static const u16string_view ends_with = u"\\renamedir8\\renamedir8b";

            if (fn.size() < ends_with.size() || fn.substr(fn.size() - ends_with.size()) != ends_with)
                throw runtime_error("Name did not end with \"\\renamedir8\\renamedir8b\".");
        });

        test("Check old directory entry gone", [&]() {
            u16string_view name = u"renamedir8a";

            exp_status([&]() {
                query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);
            }, STATUS_NO_SUCH_FILE);
        });

        test("Check new directory entry", [&]() {
            u16string_view name = u"renamedir8b";

            auto items = query_dir<FILE_DIRECTORY_INFORMATION>(dir + u"\\renamedir8", name);

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& fdi = *static_cast<const FILE_DIRECTORY_INFORMATION*>(items.front());

            if (fdi.FileNameLength != name.size() * sizeof(char16_t))
                throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

            if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
                throw runtime_error("FileName did not match.");
        });

        test("Try overwriting file with directory without ReplaceIfExists set", [&]() {
            exp_status([&]() {
                set_rename_information(h.get(), false, nullptr, dir + u"\\renamefile8");
            }, STATUS_OBJECT_NAME_COLLISION);
        });

        test("Try overwriting file with directory with ReplaceIfExists set", [&]() {
            exp_status([&]() {
                set_rename_information(h.get(), true, nullptr, dir + u"\\renamefile8");
            }, STATUS_ACCESS_DENIED);
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\renamefile9", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    test("Create directory", [&]() {
        h2 = create_file(dir + u"\\renamedir9", FILE_LIST_DIRECTORY | FILE_ADD_FILE, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h && h2) {
        test("Check directory entry", [&]() {
            u16string_view name = u"renamefile9";

            auto items = query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& fdi = *static_cast<const FILE_DIRECTORY_INFORMATION*>(items.front());

            if (fdi.FileNameLength != name.size() * sizeof(char16_t))
                throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

            if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
                throw runtime_error("FileName did not match.");
        });

        test("Check name", [&]() {
            auto fn = query_file_name_information(h.get());

            static const u16string_view ends_with = u"\\renamefile9";

            if (fn.size() < ends_with.size() || fn.substr(fn.size() - ends_with.size()) != ends_with)
                throw runtime_error("Name did not end with \"\\renamefile9\".");
        });

        test("Move file via RootDirectory handle", [&]() {
            set_rename_information(h.get(), false, h2.get(), u"renamefile9");
        });

        test("Check name", [&]() {
            auto fn = query_file_name_information(h.get());

            static const u16string_view ends_with = u"\\renamedir9\\renamefile9";

            if (fn.size() < ends_with.size() || fn.substr(fn.size() - ends_with.size()) != ends_with)
                throw runtime_error("Name did not end with \"\\renamedir9\\renamefile9\".");
        });

        test("Check old directory entry gone", [&]() {
            u16string_view name = u"renamefile9";

            exp_status([&]() {
                query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);
            }, STATUS_NO_SUCH_FILE);
        });

        test("Try checking new directory entry with handle still open", [&]() {
            u16string_view name = u"renamefile9";

            exp_status([&]() {
                query_dir<FILE_DIRECTORY_INFORMATION>(dir + u"\\renamedir9", name);
            }, STATUS_SHARING_VIOLATION);
        });

        h2.reset();

        test("Check new directory entry", [&]() {
            u16string_view name = u"renamefile9";

            auto items = query_dir<FILE_DIRECTORY_INFORMATION>(dir + u"\\renamedir9", name);

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

    test("Create directory", [&]() {
        h2 = create_file(dir + u"\\renamedir10", FILE_LIST_DIRECTORY | FILE_ADD_FILE, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    test("Create file", [&]() {
        h = create_file(dir + u"\\renamedir10\\renamefile10", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Try checking directory entry with handle open", [&]() {
            u16string_view name = u"renamefile10";

            exp_status([&]() {
                query_dir<FILE_DIRECTORY_INFORMATION>(dir + u"\\renamedir10", name);
            }, STATUS_SHARING_VIOLATION);
        });

        test("Check name", [&]() {
            auto fn = query_file_name_information(h.get());

            static const u16string_view ends_with = u"\\renamedir10\\renamefile10";

            if (fn.size() < ends_with.size() || fn.substr(fn.size() - ends_with.size()) != ends_with)
                throw runtime_error("Name did not end with \"\\renamedir10\\renamefile10\".");
        });

        test("Rename file via RootDirectory handle", [&]() {
            set_rename_information(h.get(), false, h2.get(), u"renamefile10a");
        });

        test("Check name", [&]() {
            auto fn = query_file_name_information(h.get());

            static const u16string_view ends_with = u"\\renamedir10\\renamefile10a";

            if (fn.size() < ends_with.size() || fn.substr(fn.size() - ends_with.size()) != ends_with)
                throw runtime_error("Name did not end with \"\\renamedir10\\renamefile10a\".");
        });

        h2.reset();

        test("Check old directory entry gone", [&]() {
            u16string_view name = u"renamefile10";

            exp_status([&]() {
                query_dir<FILE_DIRECTORY_INFORMATION>(dir + u"\\renamedir10", name);
            }, STATUS_NO_SUCH_FILE);
        });

        test("Check new directory entry", [&]() {
            u16string_view name = u"renamefile10a";

            auto items = query_dir<FILE_DIRECTORY_INFORMATION>(dir + u"\\renamedir10", name);

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& fdi = *static_cast<const FILE_DIRECTORY_INFORMATION*>(items.front());

            if (fdi.FileNameLength != name.size() * sizeof(char16_t))
                throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

            if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
                throw runtime_error("FileName did not match.");
        });
    }

    test("Create directory", [&]() {
        h2 = create_file(dir + u"\\renamedir11", WRITE_DAC, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    test("Create file", [&]() {
        h = create_file(dir + u"\\renamedir11\\renamefile11", DELETE, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h && h2) {
        test("Set directory permissions", [&]() {
            set_dacl(h2.get(), SYNCHRONIZE | FILE_ADD_FILE);
        });

        h2.reset();

        test("Rename file", [&]() {
            set_rename_information(h.get(), false, nullptr, dir + u"\\renamedir11\\renamefile11a");
        });

        h.reset();
    }

    test("Create directory", [&]() {
        h2 = create_file(dir + u"\\renamedir12", WRITE_DAC, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    test("Create file", [&]() {
        h = create_file(dir + u"\\renamedir12\\renamefile12", DELETE, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h && h2) {
        test("Clear directory permissions", [&]() {
            set_dacl(h2.get(), 0);
        });

        h2.reset();

        test("Try to rename file", [&]() {
            exp_status([&]() {
                set_rename_information(h.get(), false, nullptr, dir + u"\\renamedir12\\renamefile12a");
            }, STATUS_ACCESS_DENIED);
        });

        h.reset();
    }

    test("Create directory", [&]() {
        h2 = create_file(dir + u"\\renamedir13", WRITE_DAC, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    test("Create subdir", [&]() {
        h = create_file(dir + u"\\renamedir13\\renamesubdir13", DELETE, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h && h2) {
        test("Set directory permissions", [&]() {
            set_dacl(h2.get(), SYNCHRONIZE | FILE_ADD_SUBDIRECTORY);
        });

        h2.reset();

        test("Rename subdir", [&]() {
            set_rename_information(h.get(), false, nullptr, dir + u"\\renamedir13\\renamesubdir13a");
        });

        h.reset();
    }

    test("Create directory", [&]() {
        h2 = create_file(dir + u"\\renamedir14", WRITE_DAC, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    test("Create subdir", [&]() {
        h = create_file(dir + u"\\renamedir14\\renamesubdir14", DELETE, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h && h2) {
        test("Clear directory permissions", [&]() {
            set_dacl(h2.get(), 0);
        });

        h2.reset();

        test("Try to rename subdir", [&]() {
            exp_status([&]() {
                set_rename_information(h.get(), false, nullptr, dir + u"\\renamedir14\\renamefile14a");
            }, STATUS_ACCESS_DENIED);
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\renamefile15", FILE_READ_DATA, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Try renaming file without DELETE access", [&]() {
            exp_status([&]() {
                set_rename_information(h.get(), false, nullptr, dir + u"\\renamefile15a");
            }, STATUS_ACCESS_DENIED);
        });

        h.reset();
    }

    test("Create directory", [&]() {
        h = create_file(dir + u"\\renamedir16", FILE_LIST_DIRECTORY, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Try renaming directory without DELETE access", [&]() {
            exp_status([&]() {
                set_rename_information(h.get(), false, nullptr, dir + u"\\renamedir16a");
            }, STATUS_ACCESS_DENIED);
        });

        h.reset();
    }

    test("Create directory 1", [&]() {
        h2 = create_file(dir + u"\\renamedir17a", WRITE_DAC, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    test("Create file", [&]() {
        h = create_file(dir + u"\\renamedir17a\\file", DELETE, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h && h2) {
        test("Clear directory 1 permissions", [&]() {
            set_dacl(h2.get(), 0);
        });

        h2.reset();

        test("Create directory 2", [&]() {
            h2 = create_file(dir + u"\\renamedir17b", WRITE_DAC, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
        });

        if (h2) {
            test("Set directory 2 permissions", [&]() {
                set_dacl(h2.get(), SYNCHRONIZE | FILE_ADD_FILE);
            });

            h2.reset();
        }

        test("Move file to directory 2", [&]() {
            set_rename_information(h.get(), false, nullptr, dir + u"\\renamedir17b\\file");
        });

        test("Try to move back to directory 1", [&]() {
            exp_status([&]() {
                set_rename_information(h.get(), false, nullptr, dir + u"\\renamedir17a\\file");
            }, STATUS_ACCESS_DENIED);
        });

        h.reset();
    }

    test("Create directory 1", [&]() {
        h2 = create_file(dir + u"\\renamedir18a", WRITE_DAC, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    test("Create subdir", [&]() {
        h = create_file(dir + u"\\renamedir18a\\subdir", DELETE, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h && h2) {
        test("Clear directory 1 permissions", [&]() {
            set_dacl(h2.get(), 0);
        });

        h2.reset();

        test("Create directory 2", [&]() {
            h2 = create_file(dir + u"\\renamedir18b", WRITE_DAC, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
        });

        if (h2) {
            test("Set directory 2 permissions", [&]() {
                set_dacl(h2.get(), SYNCHRONIZE | FILE_ADD_SUBDIRECTORY);
            });

            h2.reset();
        }

        test("Move file to directory 2", [&]() {
            set_rename_information(h.get(), false, nullptr, dir + u"\\renamedir18b\\subdir");
        });

        test("Try to move back to directory 1", [&]() {
            exp_status([&]() {
                set_rename_information(h.get(), false, nullptr, dir + u"\\renamedir18a\\subdir");
            }, STATUS_ACCESS_DENIED);
        });

        h.reset();
    }

    test("Create directory", [&]() {
        h = create_file(dir + u"\\renamedir19", WRITE_DAC, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Set directory permissions", [&]() {
            set_dacl(h.get(), SYNCHRONIZE | FILE_TRAVERSE | FILE_ADD_FILE);
        });

        h.reset();

        test("Create file 1", [&]() {
            h = create_file(dir + u"\\renamedir19\\file1", DELETE, 0, 0, FILE_CREATE, 0, FILE_CREATED);
        });

        if (h) {
            test("Create file 2", [&]() {
                h2 = create_file(dir + u"\\renamedir19\\file2", WRITE_DAC, 0, 0, FILE_CREATE, 0, FILE_CREATED);
            });

            if (h2) {
                test("Clear file 2 permissions", [&]() {
                    set_dacl(h2.get(), 0);
                });

                h2.reset();

                test("Try to overwrite file 2 with file 1", [&]() {
                    exp_status([&]() {
                        set_rename_information(h.get(), true, nullptr, dir + u"\\renamedir19\\file2");
                    }, STATUS_ACCESS_DENIED);
                });
            }

            h.reset();
        }
    }

    test("Create directory", [&]() {
        h = create_file(dir + u"\\renamedir20", WRITE_DAC, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Set directory permissions (inc. FILE_DELETE_CHILD)", [&]() {
            set_dacl(h.get(), SYNCHRONIZE | FILE_TRAVERSE | FILE_ADD_FILE | FILE_DELETE_CHILD);
        });

        h.reset();

        test("Create file 1", [&]() {
            h = create_file(dir + u"\\renamedir20\\file1", DELETE, 0, 0, FILE_CREATE, 0, FILE_CREATED);
        });

        if (h) {
            test("Create file 2", [&]() {
                h2 = create_file(dir + u"\\renamedir20\\file2", WRITE_DAC, 0, 0, FILE_CREATE, 0, FILE_CREATED);
            });

            if (h2) {
                test("Clear file 2 permissions", [&]() {
                    set_dacl(h2.get(), 0);
                });

                h2.reset();

                test("Overwrite file 2 with file 1", [&]() {
                    set_rename_information(h.get(), true, nullptr, dir + u"\\renamedir20\\file2");
                });
            }

            h.reset();
        }
    }

    test("Create directory", [&]() {
        h = create_file(dir + u"\\renamedir21", WRITE_DAC, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Set directory permissions", [&]() {
            set_dacl(h.get(), SYNCHRONIZE | FILE_TRAVERSE | FILE_ADD_FILE);
        });

        h.reset();

        test("Create file 1", [&]() {
            h = create_file(dir + u"\\renamedir21\\file1", DELETE, 0, 0, FILE_CREATE, 0, FILE_CREATED);
        });

        if (h) {
            test("Create file 2", [&]() {
                h2 = create_file(dir + u"\\renamedir21\\file2", WRITE_DAC, 0, 0, FILE_CREATE, 0, FILE_CREATED);
            });

            if (h2) {
                test("Set file 2 permissions to DELETE", [&]() {
                    set_dacl(h2.get(), DELETE);
                });

                h2.reset();

                test("Overwrite file 2 with file 1", [&]() {
                    set_rename_information(h.get(), true, nullptr, dir + u"\\renamedir21\\file2");
                });
            }

            h.reset();
        }
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\renamefile22a", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Create readonly file", [&]() {
            create_file(dir + u"\\renamefile22b", MAXIMUM_ALLOWED, FILE_ATTRIBUTE_READONLY, 0, FILE_CREATE, 0, FILE_CREATED);
        });

        test("Try to overwrite readonly file", [&]() {
            exp_status([&]() {
                set_rename_information(h.get(), true, nullptr, dir + u"\\renamefile22b");
            }, STATUS_ACCESS_DENIED);
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\renamefile23a", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Create system file", [&]() {
            create_file(dir + u"\\renamefile23b", MAXIMUM_ALLOWED, FILE_ATTRIBUTE_SYSTEM, 0, FILE_CREATE, 0, FILE_CREATED);
        });

        test("Overwrite system file", [&]() {
            set_rename_information(h.get(), true, nullptr, dir + u"\\renamefile23b");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\renamefile24", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        struct {
            u16string name;
            string desc;
        } invalid_names[] = {
            { u"/", "slash" },
            { u":", "colon" },
            { u"<", "less than" },
            { u">", "greater than" },
            { u"\"", "quote" },
            { u"|", "pipe" },
            { u"?", "question mark" },
            { u"*", "asterisk" }
        };

        for (const auto& n : invalid_names) {
            test("Try renaming to invalid name (" + n.desc + ")", [&]() {
                auto fn = dir + u"\\renamefile24" + n.name;

                exp_status([&]() {
                    set_rename_information(h.get(), false, nullptr, fn);
                }, STATUS_OBJECT_NAME_INVALID);
            });
        }

        bool is_ntfs = fstype == fs_type::ntfs;

        test("Rename to file with more than 255 UTF-8 characters", [&]() {
            auto fn = dir + u"\\rename24";

            for (unsigned int i = 0; i < 64; i++) {
                fn += u"\U0001f525";
            }

            exp_status([&]() {
                set_rename_information(h.get(), false, nullptr, fn);
            }, is_ntfs ? STATUS_SUCCESS : STATUS_OBJECT_NAME_INVALID);
        });

        test("Rename to file with WTF-16 (1)", [&]() {
            auto fn = dir + u"\\rename24";

            fn += (char16_t)0xd83d;

            exp_status([&]() {
                set_rename_information(h.get(), false, nullptr, fn);
            }, is_ntfs ? STATUS_SUCCESS : STATUS_OBJECT_NAME_INVALID);
        });

        test("Rename to file with WTF-16 (2)", [&]() {
            auto fn = dir + u"\\rename24";

            fn += (char16_t)0xdd25;

            exp_status([&]() {
                set_rename_information(h.get(), false, nullptr, fn);
            }, is_ntfs ? STATUS_SUCCESS : STATUS_OBJECT_NAME_INVALID);
        });

        test("Rename to file with WTF-16 (3)", [&]() {
            auto fn = dir + u"\\rename24";

            fn += (char16_t)0xdd25;
            fn += (char16_t)0xd83d;

            exp_status([&]() {
                set_rename_information(h.get(), false, nullptr, fn);
            }, is_ntfs ? STATUS_SUCCESS : STATUS_OBJECT_NAME_INVALID);
        });

        h.reset();
    }

    test("Create directory 1", [&]() {
        h = create_file(dir + u"\\renamedir25a", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    test("Create directory 2", [&]() {
        h2 = create_file(dir + u"\\renamedir25b", MAXIMUM_ALLOWED, 0, FILE_SHARE_DELETE,
                         FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h && h2) {
        test("Try to overwrite directory 2", [&]() {
            exp_status([&]() {
                set_rename_information(h.get(), true, nullptr, dir + u"\\renamedir25b");
            }, STATUS_ACCESS_DENIED);
        });

        h.reset();
        h2.reset();
    }

    test("Create file 1", [&]() {
        create_file(dir + u"\\renamefile26a", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    test("Create file 2", [&]() {
        h = create_file(dir + u"\\renamefile26b", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Try to move file within other file", [&]() {
            exp_status([&]() {
                set_rename_information(h.get(), false, nullptr, dir + u"\\renamefile26a\\file");
            }, STATUS_INVALID_PARAMETER);
        });

        h.reset();
    }

    // FIXME - does SD change when file moved across directories?
    // FIXME - check can't rename root directory?
}

void test_rename_ex(HANDLE token, const u16string& dir) {
    unique_handle h, h2;

    // FileRenameInformationEx introduced with Windows 10 1709

    test("Create file 1", [&]() {
        create_file(dir + u"\\renamefileex1a", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    test("Create file 2", [&]() {
        h = create_file(dir + u"\\renamefileex1b", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Try renaming file 2 to file 1 without FILE_RENAME_REPLACE_IF_EXISTS set", [&]() {
            exp_status([&]() {
                set_rename_information_ex(h.get(), 0, nullptr, dir + u"\\renamefileex1a");
            }, STATUS_OBJECT_NAME_COLLISION);
        });

        test("Rename file 2 to file 1 with FILE_RENAME_REPLACE_IF_EXISTS", [&]() {
            set_rename_information_ex(h.get(), FILE_RENAME_REPLACE_IF_EXISTS, nullptr, dir + u"\\renamefileex1a");
        });

        test("Check name", [&]() {
            auto fn = query_file_name_information(h.get());

            static const u16string_view ends_with = u"\\renamefileex1a";

            if (fn.size() < ends_with.size() || fn.substr(fn.size() - ends_with.size()) != ends_with)
                throw runtime_error("Name did not end with \"\\renamefileex1a\".");
        });

        test("Check directory entry", [&]() {
            u16string_view name = u"renamefileex1a";

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
        h2 = create_file(dir + u"\\renamefileex2a", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    test("Create file 2", [&]() {
        h = create_file(dir + u"\\renamefileex2b", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Try renaming file 2 to file 1 without FILE_RENAME_REPLACE_IF_EXISTS", [&]() {
            exp_status([&]() {
                set_rename_information_ex(h.get(), 0, nullptr, dir + u"\\renamefileex2a");
            }, STATUS_OBJECT_NAME_COLLISION);
        });

        test("Try renaming file 2 to file 1 with FILE_RENAME_REPLACE_IF_EXISTS and file 1 open", [&]() {
            exp_status([&]() {
                set_rename_information_ex(h.get(), FILE_RENAME_REPLACE_IF_EXISTS, nullptr, dir + u"\\renamefileex2a");
            }, STATUS_ACCESS_DENIED);
        });

        h.reset();
    }

    h2.reset();

    test("Create file 1", [&]() {
        create_file(dir + u"\\renamefileex3a", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    test("Create file 2", [&]() {
        h = create_file(dir + u"\\renamefileex3b", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Try renaming file 2 to file 1 uppercase without FILE_RENAME_REPLACE_IF_EXISTS", [&]() {
            exp_status([&]() {
                set_rename_information_ex(h.get(), 0, nullptr, dir + u"\\RENAMEFILEEX3A");
            }, STATUS_OBJECT_NAME_COLLISION);
        });

        test("Rename file 2 to file 1 uppercase with FILE_RENAME_REPLACE_IF_EXISTS", [&]() {
            set_rename_information_ex(h.get(), FILE_RENAME_REPLACE_IF_EXISTS, nullptr, dir + u"\\RENAMEFILEEX3A");
        });

        test("Check name", [&]() {
            auto fn = query_file_name_information(h.get());

            static const u16string_view ends_with = u"\\RENAMEFILEEX3A";

            if (fn.size() < ends_with.size() || fn.substr(fn.size() - ends_with.size()) != ends_with)
                throw runtime_error("Name did not end with \"\\RENAMEFILEEX3A\".");
        });

        test("Check directory entry", [&]() {
            u16string_view name = u"RENAMEFILEEX3A";

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
        h = create_file(dir + u"\\renamefileex4a", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Create readonly file", [&]() {
            create_file(dir + u"\\renamefileex4b", MAXIMUM_ALLOWED, FILE_ATTRIBUTE_READONLY, 0, FILE_CREATE, 0, FILE_CREATED);
        });

        test("Try to overwrite readonly file", [&]() {
            exp_status([&]() {
                set_rename_information_ex(h.get(), FILE_RENAME_REPLACE_IF_EXISTS, nullptr, dir + u"\\renamefileex4b");
            }, STATUS_ACCESS_DENIED);
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\renamefileex5a", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Create readonly file", [&]() {
            create_file(dir + u"\\renamefileex5b", MAXIMUM_ALLOWED, FILE_ATTRIBUTE_READONLY, 0, FILE_CREATE, 0, FILE_CREATED);
        });

        test("Overwrite readonly file using FILE_RENAME_IGNORE_READONLY_ATTRIBUTE", [&]() {
            set_rename_information_ex(h.get(), FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_IGNORE_READONLY_ATTRIBUTE,
                                      nullptr, dir + u"\\renamefileex5b");
        });

        h.reset();
    }

    // traverse privilege needed to query hard links
    test("Add SeChangeNotifyPrivilege to token", [&]() {
        LUID_AND_ATTRIBUTES laa;

        laa.Luid.LowPart = SE_CHANGE_NOTIFY_PRIVILEGE;
        laa.Luid.HighPart = 0;
        laa.Attributes = SE_PRIVILEGE_ENABLED;

        adjust_token_privileges(token, laa);
    });

    test("Create file 1", [&]() {
        h = create_file(dir + u"\\renamefileex6a", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    test("Create file 2", [&]() {
        h2 = create_file(dir + u"\\renamefileex6b", SYNCHRONIZE | DELETE | FILE_READ_DATA | FILE_WRITE_DATA, 0,
                         FILE_SHARE_DELETE, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATED);
    });

    if (h && h2) {
        test("Overwrite file 2 using FILE_RENAME_POSIX_SEMANTICS", [&]() {
            set_rename_information_ex(h.get(), FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS,
                                      nullptr, dir + u"\\renamefileex6b");
        });

        test("Check name of file 1", [&]() {
            auto fn = query_file_name_information(h.get());

            static const u16string_view ends_with = u"\\renamefileex6b";

            if (fn.size() < ends_with.size() || fn.substr(fn.size() - ends_with.size()) != ends_with)
                throw runtime_error("Name did not end with \"\\renamefileex6b\".");
        });

        test("Check name of file 2", [&]() {
            auto fn = query_file_name_information(h2.get());

            static const u16string_view ends_with = u"\\renamefileex6b";

            // NTFS moves this to \$Extend\$Deleted directory

            if (fn.size() >= ends_with.size() && fn.substr(fn.size() - ends_with.size()) == ends_with)
                throw runtime_error("Name ended with \"\\renamefileex6b\".");
        });

        test("Check standard information of file 1", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if (fsi.NumberOfLinks != 1)
                throw formatted_error("NumberOfLinks was {}, expected 1", fsi.NumberOfLinks);

            if (fsi.DeletePending)
                throw runtime_error("DeletePending was true, expected false");
        });

        test("Check standard link information of file 1", [&]() {
            auto fsli = query_information<FILE_STANDARD_LINK_INFORMATION>(h.get());

            if (fsli.NumberOfAccessibleLinks != 1)
                throw formatted_error("NumberOfAccessibleLinks was {}, expected 1", fsli.NumberOfAccessibleLinks);

            if (fsli.TotalNumberOfLinks != 1)
                throw formatted_error("TotalNumberOfLinks was {}, expected 1", fsli.TotalNumberOfLinks);

            if (fsli.DeletePending)
                throw runtime_error("DeletePending was true, expected false");

            if (fsli.Directory)
                throw runtime_error("Directory was true, expected false");
        });

        test("Check standard information of file 2", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h2.get());

            if (fsi.NumberOfLinks != 0)
                throw formatted_error("NumberOfLinks was {}, expected 0", fsi.NumberOfLinks);

            if (!fsi.DeletePending)
                throw runtime_error("DeletePending was false, expected true");
        });

        test("Check standard link information of file 2", [&]() {
            auto fsli = query_information<FILE_STANDARD_LINK_INFORMATION>(h2.get());

            if (fsli.NumberOfAccessibleLinks != 0)
                throw formatted_error("NumberOfAccessibleLinks was {}, expected 0", fsli.NumberOfAccessibleLinks);

            if (fsli.TotalNumberOfLinks != 1)
                throw formatted_error("TotalNumberOfLinks was {}, expected 1", fsli.TotalNumberOfLinks);

            if (!fsli.DeletePending)
                throw runtime_error("DeletePending was false, expected true");

            if (fsli.Directory)
                throw runtime_error("Directory was true, expected false");
        });

        test("Check new directory entry", [&]() {
            u16string_view name = u"renamefileex6b";

            auto items = query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& fdi = *static_cast<const FILE_DIRECTORY_INFORMATION*>(items.front());

            if (fdi.FileNameLength != name.size() * sizeof(char16_t))
                throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

            if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
                throw runtime_error("FileName did not match.");
        });

        test("Check old directory entry gone", [&]() {
            u16string_view name = u"renamefileex6a";

            exp_status([&]() {
                query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);
            }, STATUS_NO_SUCH_FILE);
        });

        test("Try to clear delete bit on file 2", [&]() {
            exp_status([&]() {
                set_disposition_information(h2.get(), false);
            }, STATUS_FILE_DELETED);
        });

        test("Write to file 2", [&]() {
            static const vector<uint8_t> data = {'h','e','l','l','o'};

            write_file(h2.get(), data);
        });

        test("Read from file 2", [&]() {
            static const vector<uint8_t> exp = {'h','e','l','l','o'};

            auto buf = read_file(h2.get(), exp.size(), 0);

            if (buf.size() != exp.size())
                throw formatted_error("Read {} bytes, expected {}", buf.size(), exp.size());

            if (buf != exp)
                throw runtime_error("Data read did not match data written");
        });

        int64_t dir_id;

        test("Check file 1 hardlinks", [&]() {
            auto items = query_links(h.get());

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& item = items.front();

            if (item.second != u"renamefileex6b")
                throw formatted_error("Link was called {}, expected renamefileex6b", u16string_to_string(item.second));

            dir_id = item.first;
        });

        test("Check file 2 hardlinks", [&]() {
            auto items = query_links(h2.get());

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& item = items.front();

            if (item.second == u"renamefileex6b")
                throw formatted_error("Link was called renamefileex6b, expected something else", u16string_to_string(item.second));

            if (item.first == dir_id)
                throw runtime_error("Dir ID of orphaned inode is same as before");
        });

        h.reset();
        h2.reset();
    }

    test("Disable token privileges", [&]() {
        disable_token_privileges(token);
    });

    test("Create file 1", [&]() {
        h = create_file(dir + u"\\renamefileex7a", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    test("Create file 2 without FILE_SHARE_DELETE", [&]() {
        h2 = create_file(dir + u"\\renamefileex7b", MAXIMUM_ALLOWED, 0,
                         0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h && h2) {
        test("Try to overwrite file 2 using FILE_RENAME_POSIX_SEMANTICS", [&]() {
            exp_status([&]() {
                set_rename_information_ex(h.get(), FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS,
                                          nullptr, dir + u"\\renamefileex7b");
            }, STATUS_SHARING_VIOLATION);
        });

        h.reset();
        h2.reset();
    }

    test("Create directory 1", [&]() {
        h = create_file(dir + u"\\renamedirex8a", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    test("Create directory 2", [&]() {
        h2 = create_file(dir + u"\\renamedirex8b", MAXIMUM_ALLOWED, 0, FILE_SHARE_DELETE,
                         FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h && h2) {
        test("Try to overwrite directory 2", [&]() {
            exp_status([&]() {
                set_rename_information_ex(h.get(), FILE_RENAME_REPLACE_IF_EXISTS,
                                          nullptr, dir + u"\\renamedirex8b");
            }, STATUS_ACCESS_DENIED);
        });

        h.reset();
        h2.reset();
    }

    test("Create directory 1", [&]() {
        h = create_file(dir + u"\\renamedirex9a", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    test("Create directory 2", [&]() {
        h2 = create_file(dir + u"\\renamedirex9b", MAXIMUM_ALLOWED, 0, FILE_SHARE_DELETE,
                         FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h && h2) {
        test("Overwrite directory 2 using FILE_RENAME_POSIX_SEMANTICS", [&]() {
            set_rename_information_ex(h.get(), FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS,
                                      nullptr, dir + u"\\renamedirex9b");
        });

        h.reset();
        h2.reset();
    }

    test("Create directory 1", [&]() {
        h = create_file(dir + u"\\renamedirex10a", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    test("Create directory 2", [&]() {
        h2 = create_file(dir + u"\\renamedirex10b", MAXIMUM_ALLOWED, 0, FILE_SHARE_DELETE,
                         FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    test("Create file in directory 2", [&]() {
        create_file(dir + u"\\renamedirex10b\\file", MAXIMUM_ALLOWED, 0, FILE_SHARE_DELETE,
                    FILE_CREATE, 0, FILE_CREATED);
    });

    if (h && h2) {
        test("Try overwriting non-empty directory using FILE_RENAME_POSIX_SEMANTICS", [&]() {
            exp_status([&]() {
                set_rename_information_ex(h.get(), FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS,
                                          nullptr, dir + u"\\renamedirex10b");
            }, STATUS_DIRECTORY_NOT_EMPTY);
        });

        h.reset();
        h2.reset();
    }

    test("Create image file", [&]() {
        h = create_file(dir + u"\\renamefileex11a", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA,
                        0, 0, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATED);
    });

    test("Create file", [&]() {
        h2 = create_file(dir + u"\\renamefileex11b", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    auto img = pe_image(as_bytes(span("hello")));

    if (h && h2) {
        unique_handle sect;

        test("Write to file", [&]() {
            write_file(h.get(), img);
        });

        test("Create section", [&]() {
            sect = create_section(SECTION_ALL_ACCESS, nullopt, PAGE_READWRITE, SEC_IMAGE, h.get());
        });

        h.reset();

        if (sect) {
            test("Try overwriting mapped image file by rename", [&]() {
                exp_status([&]() {
                    set_rename_information_ex(h2.get(), FILE_RENAME_REPLACE_IF_EXISTS, nullptr, dir + u"\\renamefileex11a");
                }, STATUS_ACCESS_DENIED);
            });
        }

        h2.reset();
    }

    test("Create image file", [&]() {
        h = create_file(dir + u"\\renamefileex12a", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA,
                        0, 0, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATED);
    });

    test("Create file", [&]() {
        h2 = create_file(dir + u"\\renamefileex12b", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h && h2) {
        unique_handle sect;

        test("Write to file", [&]() {
            write_file(h.get(), img);
        });

        test("Create section", [&]() {
            sect = create_section(SECTION_ALL_ACCESS, nullopt, PAGE_READWRITE, SEC_IMAGE, h.get());
        });

        h.reset();

        if (sect) {
            test("Try overwriting mapped image file by POSIX rename", [&]() {
                exp_status([&]() {
                    set_rename_information_ex(h2.get(), FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS,
                                              nullptr, dir + u"\\renamefileex12a");
                }, STATUS_ACCESS_DENIED);
            });
        }

        h2.reset();
    }

    // FIXME - FILE_RENAME_SUPPRESS_PIN_STATE_INHERITANCE
    // FIXME - FILE_RENAME_SUPPRESS_STORAGE_RESERVE_INHERITANCE
    // FIXME - FILE_RENAME_NO_INCREASE_AVAILABLE_SPACE
    // FIXME - FILE_RENAME_NO_DECREASE_AVAILABLE_SPACE
    // FIXME - FILE_RENAME_FORCE_RESIZE_TARGET_SR
    // FIXME - FILE_RENAME_FORCE_RESIZE_SOURCE_SR
}
