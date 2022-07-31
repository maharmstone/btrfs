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

void set_link_information(HANDLE h, bool replace_if_exists, HANDLE root_dir, u16string_view filename) {
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

static void set_link_information_ex(HANDLE h, ULONG flags, HANDLE root_dir, u16string_view filename) {
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    vector<uint8_t> buf(offsetof(FILE_LINK_INFORMATION_EX, FileName) + (filename.length() * sizeof(char16_t)));
    auto& fli = *(FILE_LINK_INFORMATION_EX*)buf.data();

    fli.Flags = flags;
    fli.RootDirectory = root_dir;
    fli.FileNameLength = filename.length() * sizeof(char16_t);
    memcpy(fli.FileName, filename.data(), fli.FileNameLength);

    Status = NtSetInformationFile(h, &iosb, &fli, buf.size(), FileLinkInformationEx);

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

        adjust_token_privileges(token, laa);
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

        test("Check standard link information", [&]() {
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

        test("Check standard link information", [&]() {
            auto fsli = query_information<FILE_STANDARD_LINK_INFORMATION>(h.get());

            if (fsli.NumberOfAccessibleLinks != 2)
                throw formatted_error("NumberOfAccessibleLinks was {}, expected 2", fsli.NumberOfAccessibleLinks);

            if (fsli.TotalNumberOfLinks != 2)
                throw formatted_error("TotalNumberOfLinks was {}, expected 2", fsli.TotalNumberOfLinks);

            if (fsli.DeletePending)
                throw runtime_error("DeletePending was true, expected false");

            if (fsli.Directory)
                throw runtime_error("Directory was true, expected false");
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

                auto items = query_dir<FILE_ID_FULL_DIR_INFORMATION>(dir, name);

                if (items.size() != 1)
                    throw formatted_error("{} entries returned, expected 1.", items.size());

                auto& fdi = *static_cast<const FILE_ID_FULL_DIR_INFORMATION*>(items.front());

                if (fdi.FileNameLength != name.size() * sizeof(char16_t))
                    throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

                if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
                    throw runtime_error("FileName did not match.");

                if (fdi.FileId.QuadPart != file_id)
                    throw runtime_error("FileId did not match index number.");
            });

            test("Check directory entry of link 2", [&]() {
                u16string_view name = u"link1b";

                auto items = query_dir<FILE_ID_FULL_DIR_INFORMATION>(dir, name);

                if (items.size() != 1)
                    throw formatted_error("{} entries returned, expected 1.", items.size());

                auto& fdi = *static_cast<const FILE_ID_FULL_DIR_INFORMATION*>(items.front());

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

            test("Check standard link information of first link", [&]() {
                auto fsli = query_information<FILE_STANDARD_LINK_INFORMATION>(h.get());

                if (fsli.NumberOfAccessibleLinks != 1)
                    throw formatted_error("NumberOfAccessibleLinks was {}, expected 1", fsli.NumberOfAccessibleLinks);

                if (fsli.TotalNumberOfLinks != 2)
                    throw formatted_error("TotalNumberOfLinks was {}, expected 2", fsli.TotalNumberOfLinks);

                if (!fsli.DeletePending)
                    throw runtime_error("DeletePending was false, expected true");

                if (fsli.Directory)
                    throw runtime_error("Directory was true, expected false");
            });

            test("Check standard information of second link", [&]() {
                auto fsi = query_information<FILE_STANDARD_INFORMATION>(h2.get());

                if (fsi.DeletePending)
                    throw runtime_error("DeletePending was true, expected false");

                if (fsi.NumberOfLinks != 1)
                    throw formatted_error("NumberOfLinks was {}, expected 1", fsi.NumberOfLinks);
            });

            test("Check standard link information of second link", [&]() {
                auto fsli = query_information<FILE_STANDARD_LINK_INFORMATION>(h2.get());

                if (fsli.NumberOfAccessibleLinks != 1)
                    throw formatted_error("NumberOfAccessibleLinks was {}, expected 1", fsli.NumberOfAccessibleLinks);

                if (fsli.TotalNumberOfLinks != 2)
                    throw formatted_error("TotalNumberOfLinks was {}, expected 1", fsli.TotalNumberOfLinks);

                if (fsli.DeletePending)
                    throw runtime_error("DeletePending was true, expected false");

                if (fsli.Directory)
                    throw runtime_error("Directory was true, expected false");
            });

            h2.reset();
        }

        h.reset();

        test("Check directory entry of link 1 gone", [&]() {
            u16string_view name = u"link1a";

            exp_status([&]() {
                query_dir<FILE_ID_FULL_DIR_INFORMATION>(dir, name);
            }, STATUS_NO_SUCH_FILE);
        });

        test("Check directory entry of link 2", [&]() {
            u16string_view name = u"link1b";

            auto items = query_dir<FILE_ID_FULL_DIR_INFORMATION>(dir, name);

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& fdi = *static_cast<const FILE_ID_FULL_DIR_INFORMATION*>(items.front());

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

        test("Check standard link information", [&]() {
            auto fsli = query_information<FILE_STANDARD_LINK_INFORMATION>(h.get());

            if (fsli.NumberOfAccessibleLinks != 2)
                throw formatted_error("NumberOfAccessibleLinks was {}, expected 2", fsli.NumberOfAccessibleLinks);

            if (fsli.TotalNumberOfLinks != 2)
                throw formatted_error("TotalNumberOfLinks was {}, expected 2", fsli.TotalNumberOfLinks);

            if (fsli.DeletePending)
                throw runtime_error("DeletePending was true, expected false");

            if (fsli.Directory)
                throw runtime_error("Directory was true, expected false");
        });

        h.reset();

        test("Check directory entry of created link after close", [&]() {
            u16string_view name = u"link4b";

            auto items = query_dir<FILE_ID_FULL_DIR_INFORMATION>(dir, name);

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& fdi = *static_cast<const FILE_ID_FULL_DIR_INFORMATION*>(items.front());

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
        h = create_file(dir + u"\\link9", FILE_READ_DATA, 0, 0, FILE_CREATE, 0, FILE_CREATED);
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

        test("Check standard link information", [&]() {
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

        test("Check standard link information", [&]() {
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

        test("Check name", [&]() {
            auto fn = query_file_name_information(h.get());

            static const u16string_view ends_with = u"\\LINK9";

            if (fn.size() < ends_with.size() || fn.substr(fn.size() - ends_with.size()) != ends_with)
                throw runtime_error("Name did not end with \"\\LINK9\".");
        });
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\link10", DELETE, 0, 0, FILE_CREATE, 0, FILE_CREATED);
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
            test("Try creating link to invalid name (" + n.desc + ")", [&]() {
                auto fn = dir + u"\\link10" + n.name;

                exp_status([&]() {
                    set_link_information(h.get(), false, nullptr, fn);
                }, STATUS_OBJECT_NAME_INVALID);
            });
        }

        bool is_ntfs = fstype == fs_type::ntfs;

        test("Create link with more than 255 UTF-8 characters", [&]() {
            auto fn = dir + u"\\link10";

            for (unsigned int i = 0; i < 64; i++) {
                fn += u"\U0001f525";
            }

            exp_status([&]() {
                set_link_information(h.get(), false, nullptr, fn);
            }, is_ntfs ? STATUS_SUCCESS : STATUS_OBJECT_NAME_INVALID);
        });

        test("Create link with WTF-16 (1)", [&]() {
            auto fn = dir + u"\\link10";

            fn += (char16_t)0xd83d;

            exp_status([&]() {
                set_link_information(h.get(), false, nullptr, fn);
            }, is_ntfs ? STATUS_SUCCESS : STATUS_OBJECT_NAME_INVALID);
        });

        test("Create link with WTF-16 (2)", [&]() {
            auto fn = dir + u"\\link10";

            fn += (char16_t)0xdd25;

            exp_status([&]() {
                set_link_information(h.get(), false, nullptr, fn);
            }, is_ntfs ? STATUS_SUCCESS : STATUS_OBJECT_NAME_INVALID);
        });

        test("Create link with WTF-16 (3)", [&]() {
            auto fn = dir + u"\\link10";

            fn += (char16_t)0xdd25;
            fn += (char16_t)0xd83d;

            exp_status([&]() {
                set_link_information(h.get(), false, nullptr, fn);
            }, is_ntfs ? STATUS_SUCCESS : STATUS_OBJECT_NAME_INVALID);
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\link11", DELETE, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Try linking into non-existent directory", [&]() {
            exp_status([&]() {
                set_link_information(h.get(), false, nullptr, dir + u"\\linknonsuch\\file");
            }, STATUS_OBJECT_PATH_NOT_FOUND);
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\link12a", DELETE, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Create readonly file", [&]() {
            create_file(dir + u"\\link12b", MAXIMUM_ALLOWED, FILE_ATTRIBUTE_READONLY, 0, FILE_CREATE, 0, FILE_CREATED);
        });

        test("Try overwriting readonly file by linking", [&]() {
            exp_status([&]() {
                set_link_information(h.get(), true, nullptr, dir + u"\\link12b");
            }, STATUS_ACCESS_DENIED);
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\link13", FILE_READ_DATA, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Create directory 1", [&]() {
            h2 = create_file(dir + u"\\link13dir1", WRITE_DAC, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
        });

        test("Set directory 1 ACL to SYNCHRONIZE | FILE_ADD_FILE", [&]() {
            set_dacl(h2.get(), SYNCHRONIZE | FILE_ADD_FILE);
        });

        h2.reset();

        test("Create link", [&]() {
            set_link_information(h.get(), false, nullptr, dir + u"\\link13dir1\\file");
        });

        test("Create directory 2", [&]() {
            h2 = create_file(dir + u"\\link13dir2", WRITE_DAC, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
        });

        test("Clear directory 2 ACL", [&]() {
            set_dacl(h2.get(), 0);
        });

        h2.reset();

        test("Try to create link", [&]() {
            exp_status([&]() {
                set_link_information(h.get(), false, nullptr, dir + u"\\link13dir2\\file");
            }, STATUS_ACCESS_DENIED);
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\link14", FILE_READ_DATA, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle h3;

        test("Create directory", [&]() {
            h2 = create_file(dir + u"\\link14dir", WRITE_DAC, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
        });

        test("Create file in directory", [&]() {
            h3 = create_file(dir + u"\\link14dir\\file", WRITE_DAC, 0, 0, FILE_CREATE, 0, FILE_CREATED);
        });

        test("Clear directory ACL", [&]() {
            set_dacl(h2.get(), 0);
        });

        h2.reset();

        test("Set file ACL to DELETE", [&]() {
            set_dacl(h3.get(), DELETE);
        });

        h3.reset();

        test("Try to create link", [&]() {
            exp_status([&]() {
                set_link_information(h.get(), true, nullptr, dir + u"\\link14dir\\file");
            }, STATUS_ACCESS_DENIED);
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\link15", FILE_READ_DATA, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle h3;

        test("Create directory", [&]() {
            h2 = create_file(dir + u"\\link15dir", WRITE_DAC, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
        });

        test("Create file in directory", [&]() {
            h3 = create_file(dir + u"\\link15dir\\file", WRITE_DAC, 0, 0, FILE_CREATE, 0, FILE_CREATED);
        });

        test("Set directory ACL to SYNCHRONIZE | FILE_ADD_FILE", [&]() {
            set_dacl(h2.get(), SYNCHRONIZE | FILE_ADD_FILE);
        });

        h2.reset();

        test("Clear file ACL", [&]() {
            set_dacl(h3.get(), 0);
        });

        h3.reset();

        test("Try to create link", [&]() {
            exp_status([&]() {
                set_link_information(h.get(), true, nullptr, dir + u"\\link15dir\\file");
            }, STATUS_ACCESS_DENIED);
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\link16", FILE_READ_DATA, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle h3;

        test("Create directory", [&]() {
            h2 = create_file(dir + u"\\link16dir", WRITE_DAC, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
        });

        test("Create file in directory", [&]() {
            h3 = create_file(dir + u"\\link16dir\\file", WRITE_DAC, 0, 0, FILE_CREATE, 0, FILE_CREATED);
        });

        test("Set directory ACL to SYNCHRONIZE | FILE_ADD_FILE", [&]() {
            set_dacl(h2.get(), SYNCHRONIZE | FILE_ADD_FILE);
        });

        h2.reset();

        test("Set file ACL to DELETE", [&]() {
            set_dacl(h3.get(), DELETE);
        });

        h3.reset();

        test("Create link", [&]() {
            set_link_information(h.get(), true, nullptr, dir + u"\\link16dir\\file");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\link17", FILE_READ_DATA, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        unique_handle h3;

        test("Create directory", [&]() {
            h2 = create_file(dir + u"\\link17dir", WRITE_DAC, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
        });

        test("Create file in directory", [&]() {
            h3 = create_file(dir + u"\\link17dir\\file", WRITE_DAC, 0, 0, FILE_CREATE, 0, FILE_CREATED);
        });

        test("Set directory ACL to SYNCHRONIZE | FILE_ADD_FILE | FILE_DELETE_CHILD", [&]() {
            set_dacl(h2.get(), SYNCHRONIZE | FILE_ADD_FILE | FILE_DELETE_CHILD);
        });

        h2.reset();

        test("Clear file ACL", [&]() {
            set_dacl(h3.get(), 0);
        });

        h3.reset();

        test("Create link", [&]() {
            set_link_information(h.get(), true, nullptr, dir + u"\\link17dir\\file");
        });

        h.reset();
    }

    test("Create file 1", [&]() {
        create_file(dir + u"\\link18a", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    test("Create file 2", [&]() {
        h = create_file(dir + u"\\link18b", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Try to link file within other file", [&]() {
            exp_status([&]() {
                set_rename_information(h.get(), false, nullptr, dir + u"\\link18a\\file");
            }, STATUS_INVALID_PARAMETER);
        });

        h.reset();
    }

    disable_token_privileges(token);
}

void test_links_ex(HANDLE token, const u16string& dir) {
    unique_handle h, h2;

    test("Create file", [&]() {
        h = create_file(dir + u"\\linkex1a", DELETE, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Create second file", [&]() {
            create_file(dir + u"\\linkex1b", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
        });

        test("Try overwrite by link without FILE_LINK_REPLACE_IF_EXISTS", [&]() {
            exp_status([&]() {
                set_link_information_ex(h.get(), 0, nullptr, dir + u"\\linkex1b");
            }, STATUS_OBJECT_NAME_COLLISION);
        });

        test("Overwrite by link with FILE_LINK_REPLACE_IF_EXISTS", [&]() {
            set_link_information_ex(h.get(), FILE_LINK_REPLACE_IF_EXISTS, nullptr, dir + u"\\linkex1b");
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\linkex2a", DELETE, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Create readonly file", [&]() {
            create_file(dir + u"\\linkex2b", MAXIMUM_ALLOWED, FILE_ATTRIBUTE_READONLY,
                        0, FILE_CREATE, 0, FILE_CREATED);
        });

        test("Try overwrite by link without FILE_LINK_IGNORE_READONLY_ATTRIBUTE", [&]() {
            exp_status([&]() {
                set_link_information_ex(h.get(), FILE_LINK_REPLACE_IF_EXISTS, nullptr, dir + u"\\linkex2b");
            }, STATUS_ACCESS_DENIED);
        });

        test("Overwrite by link with FILE_LINK_IGNORE_READONLY_ATTRIBUTE", [&]() {
            set_link_information_ex(h.get(), FILE_LINK_REPLACE_IF_EXISTS | FILE_LINK_IGNORE_READONLY_ATTRIBUTE, nullptr, dir + u"\\linkex2b");
        });

        h.reset();
    }

    // FIXME - FILE_LINK_POSIX_SEMANTICS

    // traverse privilege needed to query hard links
    test("Add SeChangeNotifyPrivilege to token", [&]() {
        LUID_AND_ATTRIBUTES laa;

        laa.Luid.LowPart = SE_CHANGE_NOTIFY_PRIVILEGE;
        laa.Luid.HighPart = 0;
        laa.Attributes = SE_PRIVILEGE_ENABLED;

        adjust_token_privileges(token, laa);
    });

    test("Create file 1", [&]() {
        h = create_file(dir + u"\\linkex3a", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    test("Create file 2", [&]() {
        h2 = create_file(dir + u"\\linkex3b", SYNCHRONIZE | DELETE | FILE_READ_DATA | FILE_WRITE_DATA, 0,
                         FILE_SHARE_DELETE, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATED);
    });

    if (h && h2) {
        test("Overwrite file 2 using FILE_LINK_POSIX_SEMANTICS", [&]() {
            set_link_information_ex(h.get(), FILE_LINK_REPLACE_IF_EXISTS | FILE_LINK_POSIX_SEMANTICS,
                                    nullptr, dir + u"\\linkex3b");
        });

        test("Check name of file 1", [&]() {
            auto fn = query_file_name_information(h.get());

            static const u16string_view ends_with = u"\\linkex3a";

            if (fn.size() < ends_with.size() || fn.substr(fn.size() - ends_with.size()) != ends_with)
                throw runtime_error("Name did not end with \"\\linkex3a\".");
        });

        test("Check name of file 2", [&]() {
            auto fn = query_file_name_information(h2.get());

            static const u16string_view ends_with = u"\\linkex3b";

            // NTFS moves this to \$Extend\$Deleted directory

            if (fn.size() >= ends_with.size() && fn.substr(fn.size() - ends_with.size()) == ends_with)
                throw runtime_error("Name ended with \"\\linkex3b\".");
        });

        test("Check standard information of file 1", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if (fsi.NumberOfLinks != 2)
                throw formatted_error("NumberOfLinks was {}, expected 2", fsi.NumberOfLinks);

            if (fsi.DeletePending)
                throw runtime_error("DeletePending was true, expected false");
        });

        test("Check standard link information of file 1", [&]() {
            auto fsli = query_information<FILE_STANDARD_LINK_INFORMATION>(h.get());

            if (fsli.NumberOfAccessibleLinks != 2)
                throw formatted_error("NumberOfAccessibleLinks was {}, expected 2", fsli.NumberOfAccessibleLinks);

            if (fsli.TotalNumberOfLinks != 2)
                throw formatted_error("TotalNumberOfLinks was {}, expected 2", fsli.TotalNumberOfLinks);

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
            u16string_view name = u"linkex3b";

            auto items = query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& fdi = *static_cast<const FILE_DIRECTORY_INFORMATION*>(items.front());

            if (fdi.FileNameLength != name.size() * sizeof(char16_t))
                throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

            if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
                throw runtime_error("FileName did not match.");
        });

        test("Check old directory entry", [&]() {
            u16string_view name = u"linkex3a";

            auto items = query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& fdi = *static_cast<const FILE_DIRECTORY_INFORMATION*>(items.front());

            if (fdi.FileNameLength != name.size() * sizeof(char16_t))
                throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

            if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
                throw runtime_error("FileName did not match.");
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

            if (items.size() != 2)
                throw formatted_error("{} entries returned, expected 2.", items.size());

            auto& item1 = items[0];
            auto& item2 = items[1];

            if (item1.first != item2.first)
                throw runtime_error("Links were in different directories");

            if (!(item1.second == u"linkex3a" && item2.second == u"linkex3b") && !(item1.second == u"linkex3b" && item2.second == u"linkex3a"))
                throw runtime_error("Link names were not what was expected");

            dir_id = item1.first;
        });

        test("Check file 2 hardlinks", [&]() {
            auto items = query_links(h2.get());

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& item = items.front();

            if (item.second == u"linkex3b")
                throw formatted_error("Link was called linkex3b, expected something else", u16string_to_string(item.second));

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
        h = create_file(dir + u"\\linkex4a", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    test("Create file 2 without FILE_SHARE_DELETE", [&]() {
        h2 = create_file(dir + u"\\linkex4b", MAXIMUM_ALLOWED, 0,
                         0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h && h2) {
        test("Try to overwrite file 2 using FILE_LINK_POSIX_SEMANTICS", [&]() {
            exp_status([&]() {
                set_link_information_ex(h.get(), FILE_LINK_REPLACE_IF_EXISTS | FILE_LINK_POSIX_SEMANTICS,
                                        nullptr, dir + u"\\linkex4b");
            }, STATUS_SHARING_VIOLATION);
        });

        h.reset();
        h2.reset();
    }

    test("Create image file", [&]() {
        h = create_file(dir + u"\\linkex5a", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA,
                        0, 0, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATED);
    });

    test("Create file", [&]() {
        h2 = create_file(dir + u"\\linkex5b", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
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
            test("Try overwriting mapped image file by link", [&]() {
                exp_status([&]() {
                    set_link_information_ex(h2.get(), FILE_LINK_REPLACE_IF_EXISTS, nullptr, dir + u"\\linkex5a");
                }, STATUS_ACCESS_DENIED);
            });
        }

        h2.reset();
    }

    test("Create image file", [&]() {
        h = create_file(dir + u"\\linkex6a", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA,
                        0, 0, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATED);
    });

    test("Create file", [&]() {
        h2 = create_file(dir + u"\\linkex6b", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
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
            test("Try overwriting mapped image file by POSIX link", [&]() {
                exp_status([&]() {
                    set_link_information_ex(h2.get(), FILE_LINK_REPLACE_IF_EXISTS | FILE_LINK_POSIX_SEMANTICS,
                                            nullptr, dir + u"\\linkex6a");
                }, STATUS_ACCESS_DENIED);
            });
        }

        h2.reset();
    }

    // FIXME - FILE_LINK_SUPPRESS_STORAGE_RESERVE_INHERITANCE
    // FIXME - FILE_LINK_NO_INCREASE_AVAILABLE_SPACE
    // FIXME - FILE_LINK_NO_DECREASE_AVAILABLE_SPACE
    // FIXME - FILE_LINK_FORCE_RESIZE_TARGET_SR
    // FIXME - FILE_LINK_FORCE_RESIZE_SOURCE_SR
}
