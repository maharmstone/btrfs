#include "test.h"

using namespace std;

void set_disposition_information(HANDLE h, bool delete_file) {
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    FILE_DISPOSITION_INFORMATION fdi;

    fdi.DoDeleteFile = delete_file;

    iosb.Information = 0xdeadbeef;

    Status = NtSetInformationFile(h, &iosb, &fdi, sizeof(fdi), FileDispositionInformation);

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);

    if (iosb.Information != 0)
        throw formatted_error("iosb.Information was {}, expected 0", iosb.Information);
}

void test_delete(const u16string& dir) {
    unique_handle h, h2;

    test("Create file", [&]() {
        h = create_file(dir + u"\\deletefile1", DELETE, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Check directory entry", [&]() {
            u16string_view name = u"deletefile1";

            auto items = query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& fdi = *static_cast<const FILE_DIRECTORY_INFORMATION*>(items.front());

            if (fdi.FileNameLength != name.size() * sizeof(char16_t))
                throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

            if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
                throw runtime_error("FileName did not match.");
        });

        test("Check standard information", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if (fsi.DeletePending)
                throw runtime_error("DeletePending was true, expected false");
        });

        test("Set disposition", [&]() {
            set_disposition_information(h.get(), true);
        });

        test("Check directory entry still there", [&]() {
            u16string_view name = u"deletefile1";

            auto items = query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& fdi = *static_cast<const FILE_DIRECTORY_INFORMATION*>(items.front());

            if (fdi.FileNameLength != name.size() * sizeof(char16_t))
                throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

            if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
                throw runtime_error("FileName did not match.");
        });

        test("Check standard information again", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if (!fsi.DeletePending)
                throw runtime_error("DeletePending was false, expected true");
        });

        h.reset();

        test("Check directory entry gone after close", [&]() {
            u16string_view name = u"deletefile1";

            exp_status([&]() {
                query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);
            }, STATUS_NO_SUCH_FILE);
        });
    }

    test("Create directory", [&]() {
        h = create_file(dir + u"\\deletedir2", DELETE, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Check directory entry", [&]() {
            u16string_view name = u"deletedir2";

            auto items = query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& fdi = *static_cast<const FILE_DIRECTORY_INFORMATION*>(items.front());

            if (fdi.FileNameLength != name.size() * sizeof(char16_t))
                throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

            if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
                throw runtime_error("FileName did not match.");
        });

        test("Check standard information", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if (fsi.DeletePending)
                throw runtime_error("DeletePending was true, expected false");
        });

        test("Set disposition", [&]() {
            set_disposition_information(h.get(), true);
        });

        test("Check directory entry still there", [&]() {
            u16string_view name = u"deletedir2";

            auto items = query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& fdi = *static_cast<const FILE_DIRECTORY_INFORMATION*>(items.front());

            if (fdi.FileNameLength != name.size() * sizeof(char16_t))
                throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

            if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
                throw runtime_error("FileName did not match.");
        });

        test("Check standard information again", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if (!fsi.DeletePending)
                throw runtime_error("DeletePending was false, expected true");
        });

        h.reset();

        test("Check directory entry gone after close", [&]() {
            u16string_view name = u"deletedir2";

            exp_status([&]() {
                query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);
            }, STATUS_NO_SUCH_FILE);
        });
    }

    test("Create directory", [&]() {
        h = create_file(dir + u"\\deletedir3", DELETE, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    test("Create file", [&]() {
        h2 = create_file(dir + u"\\deletedir3\\file", DELETE, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h && h2) {
        test("Try to set disposition on directory", [&]() {
            exp_status([&]() {
                set_disposition_information(h.get(), true);
            }, STATUS_DIRECTORY_NOT_EMPTY);
        });

        test("Set disposition on file", [&]() {
            set_disposition_information(h2.get(), true);
        });

        test("Try to set disposition on directory again", [&]() {
            exp_status([&]() {
                set_disposition_information(h.get(), true);
            }, STATUS_DIRECTORY_NOT_EMPTY);
        });

        h2.reset();

        test("Set disposition on directory now empty", [&]() {
            set_disposition_information(h.get(), true);
        });

        h.reset();

        test("Check directory entry gone after close", [&]() {
            u16string_view name = u"deletedir3";

            exp_status([&]() {
                query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);
            }, STATUS_NO_SUCH_FILE);
        });
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\deletefile4", DELETE, 0, FILE_SHARE_DELETE, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Set deletion flag on file", [&]() {
            set_disposition_information(h.get(), true);
        });

        test("Try to reopen file marked for deletion", [&]() {
            exp_status([&]() {
                create_file(dir + u"\\deletefile4", DELETE, 0, FILE_SHARE_DELETE, FILE_OPEN, 0, FILE_OPENED);
            }, STATUS_DELETE_PENDING);
        });

        test("Clear deletion flag on file", [&]() {
            set_disposition_information(h.get(), false);
        });

        test("Check standard information again", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if (fsi.DeletePending)
                throw runtime_error("DeletePending was true, expected false");
        });

        test("Reopen file now no longer marked for deletion", [&]() {
            h2 = create_file(dir + u"\\deletefile4", DELETE, 0, FILE_SHARE_DELETE, FILE_OPEN, 0, FILE_OPENED);
        });

        test("Set deletion flag again", [&]() {
            set_disposition_information(h.get(), true);
        });

        h.reset();

        test("Check directory entry after first handle closed", [&]() {
            u16string_view name = u"deletefile4";

            auto items = query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& fdi = *static_cast<const FILE_DIRECTORY_INFORMATION*>(items.front());

            if (fdi.FileNameLength != name.size() * sizeof(char16_t))
                throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

            if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
                throw runtime_error("FileName did not match.");
        });

        h2.reset();

        test("Check directory entry gone after second handle closed", [&]() {
            u16string_view name = u"deletefile4";

            exp_status([&]() {
                query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);
            }, STATUS_NO_SUCH_FILE);
        });
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\deletefile5", DELETE, 0, FILE_SHARE_DELETE, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Set deletion flag on file", [&]() {
            set_disposition_information(h.get(), true);
        });

        test("Clear deletion flag on file", [&]() {
            set_disposition_information(h.get(), false);
        });

        h.reset();

        test("Check directory entry", [&]() {
            u16string_view name = u"deletefile5";

            auto items = query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& fdi = *static_cast<const FILE_DIRECTORY_INFORMATION*>(items.front());

            if (fdi.FileNameLength != name.size() * sizeof(char16_t))
                throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

            if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
                throw runtime_error("FileName did not match.");
        });
    }

    test("Create file without DELETE flag", [&]() {
        h = create_file(dir + u"\\deletefile6", FILE_READ_DATA, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Try to set deletion flag on file", [&]() {
            exp_status([&]() {
                set_disposition_information(h.get(), true);
            }, STATUS_ACCESS_DENIED);
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\deletefile7", DELETE, 0, FILE_SHARE_DELETE, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Create stream on file", [&]() {
            h2 = create_file(dir + u"\\deletefile7:ads", DELETE, 0, FILE_SHARE_DELETE, FILE_CREATE, 0, FILE_CREATED);
        });

        test("Set deletion flag on file", [&]() {
            set_disposition_information(h.get(), true);
        });

        test("Check standard information on file", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if (!fsi.DeletePending)
                throw runtime_error("DeletePending was false, expected true");
        });

        test("Check standard information on stream", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h2.get());

            if (!fsi.DeletePending)
                throw runtime_error("DeletePending was false, expected true");
        });

        test("Clear deletion flag on stream", [&]() {
            set_disposition_information(h2.get(), false); // gets ignored
        });

        test("Check standard information on file", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if (!fsi.DeletePending)
                throw runtime_error("DeletePending was false, expected true");
        });

        test("Check standard information on stream", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h2.get());

            if (!fsi.DeletePending)
                throw runtime_error("DeletePending was false, expected true");
        });

        h.reset();

        test("Check directory entry still there after file handle closed", [&]() {
            u16string_view name = u"deletefile7";

            auto items = query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& fdi = *static_cast<const FILE_DIRECTORY_INFORMATION*>(items.front());

            if (fdi.FileNameLength != name.size() * sizeof(char16_t))
                throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

            if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
                throw runtime_error("FileName did not match.");
        });

        test("Clear deletion flag on stream", [&]() {
            set_disposition_information(h2.get(), false); // still ignored
        });

        test("Check standard information on stream", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h2.get());

            if (!fsi.DeletePending)
                throw runtime_error("DeletePending was false, expected true");
        });

        h2.reset();

        test("Check directory entry gone after stream handle closed", [&]() {
            u16string_view name = u"deletefile7";

            exp_status([&]() {
                query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);
            }, STATUS_NO_SUCH_FILE);
        });
    }

    test("Create file with FILE_DELETE_ON_CLOSE", [&]() {
        h = create_file(dir + u"\\deletefile8", DELETE, 0, 0, FILE_CREATE,
                        FILE_DELETE_ON_CLOSE, FILE_CREATED);
    });

    if (h) {
        test("Check standard information on file", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if (fsi.DeletePending)
                throw runtime_error("DeletePending was true, expected false");
        });

        h.reset();

        test("Check directory entry gone after file closed", [&]() {
            u16string_view name = u"deletefile8";

            exp_status([&]() {
                query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);
            }, STATUS_NO_SUCH_FILE);
        });
    }

    test("Create file with FILE_DELETE_ON_CLOSE", [&]() {
        h = create_file(dir + u"\\deletefile9", DELETE, 0, 0, FILE_CREATE,
                        FILE_DELETE_ON_CLOSE, FILE_CREATED);
    });

    if (h) {
        test("Check standard information", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if (fsi.DeletePending)
                throw runtime_error("DeletePending was true, expected false");
        });

        h.reset();

        test("Check directory entry gone after handle closed", [&]() {
            u16string_view name = u"deletefile9";

            exp_status([&]() {
                query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);
            }, STATUS_NO_SUCH_FILE);
        });
    }

    test("Create file with FILE_DELETE_ON_CLOSE", [&]() {
        h = create_file(dir + u"\\deletefile10", DELETE, 0, FILE_SHARE_DELETE, FILE_CREATE,
                        FILE_DELETE_ON_CLOSE, FILE_CREATED);
    });

    if (h) {
        test("Try to open second handle to file without FILE_SHARE_DELETE", [&]() {
            exp_status([&]() {
                create_file(dir + u"\\deletefile10", FILE_READ_DATA, 0, 0, FILE_OPEN,
                            0, FILE_OPENED);
            }, STATUS_SHARING_VIOLATION);
        });

        test("Open second handle to file with FILE_SHARE_DELETE", [&]() {
            h2 = create_file(dir + u"\\deletefile10", DELETE, 0, FILE_SHARE_DELETE,
                             FILE_OPEN, 0, FILE_OPENED);
        });

        test("Check standard information on second handle", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h2.get());

            if (fsi.DeletePending)
                throw runtime_error("DeletePending was true, expected false");
        });

        h.reset();

        test("Check standard information after first handle closed", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h2.get());

            if (!fsi.DeletePending)
                throw runtime_error("DeletePending was false, expected true");
        });

        test("Clear deletion flag", [&]() {
            set_disposition_information(h2.get(), false); // ignored
        });

        test("Check standard information again", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h2.get());

            if (fsi.DeletePending)
                throw runtime_error("DeletePending was true, expected false");
        });

        test("Try to open third handle to file", [&]() {
            exp_status([&]() {
                create_file(dir + u"\\deletefile10", FILE_READ_DATA, 0, 0, FILE_OPEN,
                            FILE_SHARE_DELETE, FILE_OPENED);
            }, STATUS_SHARING_VIOLATION);
        });

        h2.reset();

        test("Check directory entry still there after both handles closed", [&]() {
            u16string_view name = u"deletefile10";

            auto items = query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& fdi = *static_cast<const FILE_DIRECTORY_INFORMATION*>(items.front());

            if (fdi.FileNameLength != name.size() * sizeof(char16_t))
                throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

            if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
                throw runtime_error("FileName did not match.");
        });
    }

    test("Create readonly file", [&]() {
        create_file(dir + u"\\deletefile11", FILE_READ_DATA, FILE_ATTRIBUTE_READONLY, 0, FILE_CREATE,
                    0, FILE_CREATED);
    });

    test("Try to open readonly file with FILE_DELETE_ON_CLOSE", [&]() {
        exp_status([&]() {
            create_file(dir + u"\\deletefile11", DELETE, 0, 0, FILE_OPEN,
                        FILE_DELETE_ON_CLOSE, FILE_OPENED);
        }, STATUS_CANNOT_DELETE);
    });

    test("Create readonly file", [&]() {
        h = create_file(dir + u"\\deletefile12", DELETE, FILE_ATTRIBUTE_READONLY, 0, FILE_CREATE,
                        0, FILE_CREATED);
    });

    if (h) {
        test("Try to set deletion flag on readonly file", [&]() {
            exp_status([&]() {
                set_disposition_information(h.get(), true);
            }, STATUS_CANNOT_DELETE);
        });

        h.reset();
    }

    test("Create directory with FILE_DELETE_ON_CLOSE", [&]() {
        h = create_file(dir + u"\\deletedir13", DELETE, 0, 0, FILE_CREATE,
                        FILE_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE, FILE_CREATED);
    });

    if (h) {
        test("Check standard information", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if (fsi.DeletePending)
                throw runtime_error("DeletePending was true, expected false");
        });

        h.reset();

        test("Check directory entry gone after handle closed", [&]() {
            u16string_view name = u"deletedir13";

            exp_status([&]() {
                query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);
            }, STATUS_NO_SUCH_FILE);
        });
    }

    test("Create directory with FILE_DELETE_ON_CLOSE", [&]() {
        h = create_file(dir + u"\\deletedir14", DELETE, 0, 0, FILE_CREATE,
                        FILE_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE, FILE_CREATED);
    });

    if (h) {
        test("Create file in directory", [&]() {
            create_file(dir + u"\\deletedir14\\file", FILE_READ_DATA, 0, 0, FILE_CREATE,
                        0, FILE_CREATED);
        });

        h.reset();

        test("Check directory entry still there after handle closed", [&]() {
            u16string_view name = u"deletedir14";

            auto items = query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& fdi = *static_cast<const FILE_DIRECTORY_INFORMATION*>(items.front());

            if (fdi.FileNameLength != name.size() * sizeof(char16_t))
                throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

            if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
                throw runtime_error("FileName did not match.");
        });
    }

    // FIXME - can we map file marked for deletion?
    // FIXME - check can't delete files opened by ID
    // FIXME - POSIX deletion (inc. on mapped file)
    // FIXME - FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK
    // FIXME - FILE_DISPOSITION_ON_CLOSE
    // FIXME - FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE
}
