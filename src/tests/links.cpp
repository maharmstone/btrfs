#include "test.h"

using namespace std;

vector<pair<int64_t, u16string>> query_links(HANDLE h) {
    IO_STATUS_BLOCK iosb;
    NTSTATUS Status;
    FILE_LINKS_INFORMATION fli;
    vector<pair<int64_t, u16string>> ret;

    fli.BytesNeeded = 0;

    Status = NtQueryInformationFile(h, &iosb, &fli, sizeof(fli), FileHardLinkInformation);

    if (Status != STATUS_SUCCESS && Status != STATUS_BUFFER_OVERFLOW)
        throw ntstatus_error(Status);

    if (fli.BytesNeeded == 0)
        throw runtime_error("fli.BytesNeeded was 0");

    vector<uint8_t> buf(fli.BytesNeeded);

    auto& fli2 = *reinterpret_cast<FILE_LINKS_INFORMATION*>(buf.data());

    Status = NtQueryInformationFile(h, &iosb, &fli2, buf.size(), FileHardLinkInformation);

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);

    if (iosb.Information != buf.size())
        throw formatted_error("iosb.Information was {}, expected {}", iosb.Information, buf.size());

    ret.resize(fli2.EntriesReturned);

    auto flei = &fli2.Entry;
    for (unsigned int i = 0; i < fli2.EntriesReturned; i++) {
        auto& p = ret[i];

        p.first = flei->ParentFileId;

        p.second.resize(flei->FileNameLength);
        memcpy(p.second.data(), flei->FileName, flei->FileNameLength * sizeof(char16_t));

        if (flei->NextEntryOffset == 0)
            break;

        flei = (FILE_LINK_ENTRY_INFORMATION*)((uint8_t*)flei + flei->NextEntryOffset);
    }

    return ret;
}

void set_link_information(HANDLE h, bool replace_if_exists, HANDLE root_dir, const u16string_view& filename) {
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    vector<uint8_t> buf(offsetof(FILE_LINK_INFORMATION, FileName) + (filename.length() * sizeof(char16_t)));
    auto& fli = *(FILE_LINK_INFORMATION*)buf.data();

    fli.ReplaceIfExists = replace_if_exists;
    fli.RootDirectory = root_dir;
    fli.FileNameLength = filename.length() * sizeof(char16_t);
    memcpy(fli.FileName, filename.data(), fli.FileNameLength);

    Status = NtSetInformationFile(h, &iosb, &fli, buf.size(), FileLinkInformation);

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);

    if (iosb.Information != 0)
        throw formatted_error("iosb.Information was {}, expected 0", iosb.Information);
}

void test_links(HANDLE token, const std::u16string& dir) {
    unique_handle h, h2;

    // traverse privilege needed to query hard links
    test("Add SeChangeNotifyPrivilege to token", [&]() {
        LUID_AND_ATTRIBUTES laa;

        laa.Luid.LowPart = SE_CHANGE_NOTIFY_PRIVILEGE;
        laa.Luid.HighPart = 0;
        laa.Attributes = SE_PRIVILEGE_ENABLED;

        adjust_token_privileges(token, array{ laa });
    });

    test("Create file", [&]() {
        h = create_file(dir + u"\\link1a", DELETE, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Check name", [&]() {
            auto fn = query_file_name_information(h.get());

            static const u16string_view ends_with = u"\\link1a";

            if (fn.size() < ends_with.size() || fn.substr(fn.size() - ends_with.size()) != ends_with)
                throw runtime_error("Name did not end with \"\\link1a\".");
        });

        test("Check standard information", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if (fsi.NumberOfLinks != 1)
                throw formatted_error("NumberOfLinks was {}, expected 1", fsi.NumberOfLinks);
        });

        test("Check links", [&]() {
            auto items = query_links(h.get());

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& item = items.front();

            if (item.second != u"link1a")
                throw formatted_error("Link was called {}, expected link1a", u16string_to_string(item.second));
        });

        test("Create link", [&]() {
            set_link_information(h.get(), false, nullptr, dir + u"\\link1b");
        });

        test("Check name", [&]() {
            auto fn = query_file_name_information(h.get());

            static const u16string_view ends_with = u"\\link1a";

            if (fn.size() < ends_with.size() || fn.substr(fn.size() - ends_with.size()) != ends_with)
                throw runtime_error("Name did not end with \"\\link1a\".");
        });

        test("Check standard information", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if (fsi.NumberOfLinks != 2)
                throw formatted_error("NumberOfLinks was {}, expected 2", fsi.NumberOfLinks);
        });

        test("Check links", [&]() {
            auto items = query_links(h.get());

            if (items.size() != 2)
                throw formatted_error("{} entries returned, expected 2.", items.size());

            auto& item1 = items[0];
            auto& item2 = items[1];

            if (item1.first != item2.first)
                throw runtime_error("Links were in different directories");

            if (!(item1.second == u"link1a" && item2.second == u"link1b") && !(item1.second == u"link1b" && item2.second == u"link1a"))
                throw runtime_error("Link names were not what was expected");
        });

        test("Open second link", [&]() {
            h2 = create_file(dir + u"\\link1b", FILE_READ_ATTRIBUTES, 0, 0, FILE_OPEN, 0, FILE_OPENED);
        });

        if (h2) {
            int64_t file_id = 0;

            test("Check index numbers are the same", [&]() {
                auto fii1 = query_information<FILE_INTERNAL_INFORMATION>(h.get());
                auto fii2 = query_information<FILE_INTERNAL_INFORMATION>(h2.get());

                if (fii1.IndexNumber.QuadPart != fii2.IndexNumber.QuadPart)
                    throw runtime_error("Index numbers did not match");

                file_id = fii1.IndexNumber.QuadPart;
            });

            test("Check name on second link", [&]() {
                auto fn = query_file_name_information(h2.get());

                static const u16string_view ends_with = u"\\link1b";

                if (fn.size() < ends_with.size() || fn.substr(fn.size() - ends_with.size()) != ends_with)
                    throw runtime_error("Name did not end with \"\\link1b\".");
            });

            test("Check directory entry of link 1", [&]() {
                u16string_view name = u"link1a";

                auto items = query_dir<FILE_ID_FULL_DIRECTORY_INFORMATION>(dir, name);

                if (items.size() != 1)
                    throw formatted_error("{} entries returned, expected 1.", items.size());

                auto& fdi = *static_cast<const FILE_ID_FULL_DIRECTORY_INFORMATION*>(items.front());

                if (fdi.FileNameLength != name.size() * sizeof(char16_t))
                    throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

                if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
                    throw runtime_error("FileName did not match.");

                if (fdi.FileId.QuadPart != file_id)
                    throw runtime_error("FileId did not match index number.");
            });

            test("Check directory entry of link 2", [&]() {
                u16string_view name = u"link1b";

                auto items = query_dir<FILE_ID_FULL_DIRECTORY_INFORMATION>(dir, name);

                if (items.size() != 1)
                    throw formatted_error("{} entries returned, expected 1.", items.size());

                auto& fdi = *static_cast<const FILE_ID_FULL_DIRECTORY_INFORMATION*>(items.front());

                if (fdi.FileNameLength != name.size() * sizeof(char16_t))
                    throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

                if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
                    throw runtime_error("FileName did not match.");

                if (fdi.FileId.QuadPart != file_id)
                    throw runtime_error("FileId did not match index number.");
            });

            test("Delete first link", [&]() {
                set_disposition_information(h.get(), true);
            });

            test("Check standard information of first link", [&]() {
                auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

                if (!fsi.DeletePending)
                    throw runtime_error("DeletePending was false, expected true");

                if (fsi.NumberOfLinks != 1)
                    throw formatted_error("NumberOfLinks was {}, expected 1", fsi.NumberOfLinks);
            });

            test("Check standard information of second link", [&]() {
                auto fsi = query_information<FILE_STANDARD_INFORMATION>(h2.get());

                if (fsi.DeletePending)
                    throw runtime_error("DeletePending was true, expected false");

                if (fsi.NumberOfLinks != 1)
                    throw formatted_error("NumberOfLinks was {}, expected 1", fsi.NumberOfLinks);
            });

            h2.reset();
        }

        h.reset();

        test("Check directory entry of link 1 gone", [&]() {
            u16string_view name = u"link1a";

            exp_status([&]() {
                query_dir<FILE_ID_FULL_DIRECTORY_INFORMATION>(dir, name);
            }, STATUS_NO_SUCH_FILE);
        });

        test("Check directory entry of link 2", [&]() {
            u16string_view name = u"link1b";

            auto items = query_dir<FILE_ID_FULL_DIRECTORY_INFORMATION>(dir, name);

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& fdi = *static_cast<const FILE_ID_FULL_DIRECTORY_INFORMATION*>(items.front());

            if (fdi.FileNameLength != name.size() * sizeof(char16_t))
                throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

            if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
                throw runtime_error("FileName did not match.");
        });
    }

    test("Create directory", [&]() {
        h = create_file(dir + u"\\link2dir", DELETE, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Create link", [&]() {
            exp_status([&]() {
                set_link_information(h.get(), false, nullptr, dir + u"\\link2dira");
            }, STATUS_FILE_IS_A_DIRECTORY);
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\link3a", DELETE, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Create second file", [&]() {
            create_file(dir + u"\\link3b", DELETE, 0, 0, FILE_CREATE, 0, FILE_CREATED);
        });

        test("Try overwrite by link without ReplaceIfExists set", [&]() {
            exp_status([&]() {
                set_link_information(h.get(), false, nullptr, dir + u"\\link3b");
            }, STATUS_OBJECT_NAME_COLLISION);
        });
    }

    test("Create file with FILE_DELETE_ON_CLOSE", [&]() {
        h = create_file(dir + u"\\link4a", DELETE, 0, 0, FILE_CREATE, FILE_DELETE_ON_CLOSE, FILE_CREATED);
    });

    if (h) {
        test("Create link", [&]() {
            set_link_information(h.get(), false, nullptr, dir + u"\\link4b");
        });

        test("Check standard information", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if (fsi.DeletePending)
                throw runtime_error("DeletePending was true, expected false");

            if (fsi.NumberOfLinks != 2)
                throw formatted_error("NumberOfLinks was {}, expected 2", fsi.NumberOfLinks);
        });

        h.reset();

        test("Check directory entry of created link after close", [&]() {
            u16string_view name = u"link4b";

            auto items = query_dir<FILE_ID_FULL_DIRECTORY_INFORMATION>(dir, name);

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& fdi = *static_cast<const FILE_ID_FULL_DIRECTORY_INFORMATION*>(items.front());

            if (fdi.FileNameLength != name.size() * sizeof(char16_t))
                throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

            if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
                throw runtime_error("FileName did not match.");
        });
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\link5file", DELETE, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    test("Create directory without FILE_SHARE_WRITE", [&]() {
        h2 = create_file(dir + u"\\link5dir", FILE_READ_DATA, 0, 0,
                         FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h && h2) {
        test("Try create link through directory handle", [&]() {
            exp_status([&]() {
                set_link_information(h.get(), false, h2.get(), u"file");
            }, STATUS_SHARING_VIOLATION);
        });

        h.reset();
        h2.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\link6file", DELETE, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    test("Create directory", [&]() {
        h2 = create_file(dir + u"\\link6dir", FILE_READ_DATA, 0, FILE_SHARE_WRITE,
                         FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h && h2) {
        test("Create link", [&]() {
            set_link_information(h.get(), false, h2.get(), u"file");
        });

        h2.reset();

        test("Check links", [&]() {
            auto items = query_links(h.get());

            if (items.size() != 2)
                throw formatted_error("{} entries returned, expected 2.", items.size());

            auto& item1 = items[0];
            auto& item2 = items[1];

            if (item1.first == item2.first)
                throw runtime_error("Links were in same directory");

            if (!(item1.second == u"link6file" && item2.second == u"file") && !(item1.second == u"file" && item2.second == u"link6file"))
                throw runtime_error("Link names were not what was expected");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\link6a", DELETE, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Create second file", [&]() {
            create_file(dir + u"\\link6b", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
        });

        test("Overwrite second file by link", [&]() {
            set_link_information(h.get(), true, nullptr, dir + u"\\link6b");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\link7a", DELETE, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Create directory", [&]() {
            create_file(dir + u"\\link7b", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
        });

        test("Try overwriting directory by link", [&]() {
            exp_status([&]() {
                set_link_information(h.get(), true, nullptr, dir + u"\\link7b");
            }, STATUS_ACCESS_DENIED);
        });
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\link8a", DELETE, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Create second file", [&]() {
            h2 = create_file(dir + u"\\link8b", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
        });

        if (h2) {
            test("Try to overwrite open file by link", [&]() {
                exp_status([&]() {
                    set_link_information(h.get(), true, nullptr, dir + u"\\link8b");
                }, STATUS_ACCESS_DENIED);
            });

            h2.reset();
        }

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\link9", DELETE, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Try creating link with same name without ReplaceIfExists", [&]() {
            exp_status([&]() {
                set_link_information(h.get(), false, nullptr, dir + u"\\link9");
            }, STATUS_OBJECT_NAME_COLLISION);
        });

        test("Create link with same name with ReplaceIfExists", [&]() {
            set_link_information(h.get(), true, nullptr, dir + u"\\link9"); // nop
        });

        test("Check standard information", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if (fsi.NumberOfLinks != 1)
                throw formatted_error("NumberOfLinks was {}, expected 1", fsi.NumberOfLinks);
        });

        test("Check name", [&]() {
            auto fn = query_file_name_information(h.get());

            static const u16string_view ends_with = u"\\link9";

            if (fn.size() < ends_with.size() || fn.substr(fn.size() - ends_with.size()) != ends_with)
                throw runtime_error("Name did not end with \"\\link9\".");
        });

        test("Create link with same name but different case", [&]() {
            set_link_information(h.get(), true, nullptr, dir + u"\\LINK9");
        });

        test("Check standard information", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if (fsi.NumberOfLinks != 1)
                throw formatted_error("NumberOfLinks was {}, expected 1", fsi.NumberOfLinks);
        });

        test("Check name", [&]() {
            auto fn = query_file_name_information(h.get());

            static const u16string_view ends_with = u"\\LINK9";

            if (fn.size() < ends_with.size() || fn.substr(fn.size() - ends_with.size()) != ends_with)
                throw runtime_error("Name did not end with \"\\LINK9\".");
        });
    }

    // FIXME - check invalid names (invalid characters, > 255 UTF-16, > 255 UTF-8, invalid UTF-16)

    // FIXME - FILE_LINK_REPLACE_IF_EXISTS
    // FIXME - FILE_LINK_POSIX_SEMANTICS
    // FIXME - FILE_LINK_IGNORE_READONLY_ATTRIBUTE

    // FIXME - FILE_LINK_SUPPRESS_STORAGE_RESERVE_INHERITANCE
    // FIXME - FILE_LINK_NO_INCREASE_AVAILABLE_SPACE
    // FIXME - FILE_LINK_NO_DECREASE_AVAILABLE_SPACE
    // FIXME - FILE_LINK_FORCE_RESIZE_TARGET_SR
    // FIXME - FILE_LINK_FORCE_RESIZE_SOURCE_SR

    disable_token_privileges(token);
}
