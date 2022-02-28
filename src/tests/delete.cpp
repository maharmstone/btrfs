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

void set_disposition_information_ex(HANDLE h, uint32_t flags) {
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    FILE_DISPOSITION_INFORMATION_EX fdie;

    fdie.Flags = flags;

    iosb.Information = 0xdeadbeef;

    Status = NtSetInformationFile(h, &iosb, &fdie, sizeof(fdie), FileDispositionInformationEx);

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

        test("Check standard link information", [&]() {
            auto fsli = query_information<FILE_STANDARD_LINK_INFORMATION>(h.get());

            if (fsli.NumberOfAccessibleLinks != 0)
                throw formatted_error("NumberOfAccessibleLinks was {}, expected 0", fsli.NumberOfAccessibleLinks);

            if (fsli.TotalNumberOfLinks != 1)
                throw formatted_error("TotalNumberOfLinks was {}, expected 1", fsli.TotalNumberOfLinks);

            if (!fsli.DeletePending)
                throw runtime_error("DeletePending was false, expected true");

            if (fsli.Directory)
                throw runtime_error("Directory was true, expected false");
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

        test("Check standard link information", [&]() {
            auto fsli = query_information<FILE_STANDARD_LINK_INFORMATION>(h.get());

            if (fsli.NumberOfAccessibleLinks != 1)
                throw formatted_error("NumberOfAccessibleLinks was {}, expected 1", fsli.NumberOfAccessibleLinks);

            if (fsli.TotalNumberOfLinks != 1)
                throw formatted_error("TotalNumberOfLinks was {}, expected 1", fsli.TotalNumberOfLinks);

            if (fsli.DeletePending)
                throw runtime_error("DeletePending was true, expected false");

            if (!fsli.Directory)
                throw runtime_error("Directory was false, expected true");
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

        test("Check standard link information again", [&]() {
            auto fsli = query_information<FILE_STANDARD_LINK_INFORMATION>(h.get());

            if (fsli.NumberOfAccessibleLinks != 0)
                throw formatted_error("NumberOfAccessibleLinks was {}, expected 1", fsli.NumberOfAccessibleLinks);

            if (fsli.TotalNumberOfLinks != 1)
                throw formatted_error("TotalNumberOfLinks was {}, expected 1", fsli.TotalNumberOfLinks);

            if (!fsli.DeletePending)
                throw runtime_error("DeletePending was false, expected true");

            if (!fsli.Directory)
                throw runtime_error("Directory was false, expected true");
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

        test("Check standard link information again", [&]() {
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

        test("Check standard link information on file", [&]() {
            auto fsli = query_information<FILE_STANDARD_LINK_INFORMATION>(h.get());

            if (fsli.NumberOfAccessibleLinks != 0)
                throw formatted_error("NumberOfAccessibleLinks was {}, expected 0", fsli.NumberOfAccessibleLinks);

            if (fsli.TotalNumberOfLinks != 1)
                throw formatted_error("TotalNumberOfLinks was {}, expected 1", fsli.TotalNumberOfLinks);

            if (!fsli.DeletePending)
                throw runtime_error("DeletePending was false, expected true");

            if (fsli.Directory)
                throw runtime_error("Directory was true, expected false");
        });

        test("Check standard information on stream", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h2.get());

            if (!fsi.DeletePending)
                throw runtime_error("DeletePending was false, expected true");
        });

        test("Check standard link information on stream", [&]() {
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

        test("Clear deletion flag on stream", [&]() {
            set_disposition_information(h2.get(), false); // gets ignored
        });

        test("Check standard information on file", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if (!fsi.DeletePending)
                throw runtime_error("DeletePending was false, expected true");
        });

        test("Check standard link information on file", [&]() {
            auto fsli = query_information<FILE_STANDARD_LINK_INFORMATION>(h.get());

            if (fsli.NumberOfAccessibleLinks != 0)
                throw formatted_error("NumberOfAccessibleLinks was {}, expected 0", fsli.NumberOfAccessibleLinks);

            if (fsli.TotalNumberOfLinks != 1)
                throw formatted_error("TotalNumberOfLinks was {}, expected 1", fsli.TotalNumberOfLinks);

            if (!fsli.DeletePending)
                throw runtime_error("DeletePending was false, expected true");

            if (fsli.Directory)
                throw runtime_error("Directory was true, expected false");
        });

        test("Check standard information on stream", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h2.get());

            if (!fsi.DeletePending)
                throw runtime_error("DeletePending was false, expected true");
        });

        test("Check standard link information on stream", [&]() {
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

        test("Check standard link information on stream", [&]() {
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

        test("Check standard link information on file", [&]() {
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

        h.reset();

        test("Check directory entry gone after file closed", [&]() {
            u16string_view name = u"deletefile8";

            exp_status([&]() {
                query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);
            }, STATUS_NO_SUCH_FILE);
        });
    }

    test("Create file with FILE_DELETE_ON_CLOSE", [&]() {
        h = create_file(dir + u"\\deletefile9", DELETE, 0, FILE_SHARE_DELETE, FILE_CREATE,
                        FILE_DELETE_ON_CLOSE, FILE_CREATED);
    });

    if (h) {
        test("Try to open second handle to file without FILE_SHARE_DELETE", [&]() {
            exp_status([&]() {
                create_file(dir + u"\\deletefile9", FILE_READ_DATA, 0, 0, FILE_OPEN,
                            0, FILE_OPENED);
            }, STATUS_SHARING_VIOLATION);
        });

        test("Open second handle to file with FILE_SHARE_DELETE", [&]() {
            h2 = create_file(dir + u"\\deletefile9", DELETE, 0, FILE_SHARE_DELETE,
                             FILE_OPEN, 0, FILE_OPENED);
        });

        test("Check standard information on second handle", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h2.get());

            if (fsi.DeletePending)
                throw runtime_error("DeletePending was true, expected false");
        });

        test("Check standard link information on second handle", [&]() {
            auto fsli = query_information<FILE_STANDARD_LINK_INFORMATION>(h2.get());

            if (fsli.NumberOfAccessibleLinks != 1)
                throw formatted_error("NumberOfAccessibleLinks was {}, expected 1", fsli.NumberOfAccessibleLinks);

            if (fsli.TotalNumberOfLinks != 1)
                throw formatted_error("TotalNumberOfLinks was {}, expected 1", fsli.TotalNumberOfLinks);

            if (fsli.DeletePending)
                throw runtime_error("DeletePending was true, expected false");

            if (fsli.Directory)
                throw runtime_error("Directory was true, expected false");
        });

        h.reset();

        test("Check standard information after first handle closed", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h2.get());

            if (!fsi.DeletePending)
                throw runtime_error("DeletePending was false, expected true");
        });

        test("Check standard link information after first handle closed", [&]() {
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

        test("Clear deletion flag", [&]() {
            set_disposition_information(h2.get(), false); // ignored
        });

        test("Check standard information again", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h2.get());

            if (fsi.DeletePending)
                throw runtime_error("DeletePending was true, expected false");
        });

        test("Check standard link information again", [&]() {
            auto fsli = query_information<FILE_STANDARD_LINK_INFORMATION>(h2.get());

            if (fsli.NumberOfAccessibleLinks != 1)
                throw formatted_error("NumberOfAccessibleLinks was {}, expected 1", fsli.NumberOfAccessibleLinks);

            if (fsli.TotalNumberOfLinks != 1)
                throw formatted_error("TotalNumberOfLinks was {}, expected 1", fsli.TotalNumberOfLinks);

            if (fsli.DeletePending)
                throw runtime_error("DeletePending was true, expected false");

            if (fsli.Directory)
                throw runtime_error("Directory was true, expected false");
        });

        test("Try to open third handle to file", [&]() {
            exp_status([&]() {
                create_file(dir + u"\\deletefile9", FILE_READ_DATA, 0, 0, FILE_OPEN,
                            FILE_SHARE_DELETE, FILE_OPENED);
            }, STATUS_SHARING_VIOLATION);
        });

        h2.reset();

        test("Check directory entry still there after both handles closed", [&]() {
            u16string_view name = u"deletefile9";

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
        create_file(dir + u"\\deletefile10", FILE_READ_DATA, FILE_ATTRIBUTE_READONLY, 0, FILE_CREATE,
                    0, FILE_CREATED);
    });

    test("Try to open readonly file with FILE_DELETE_ON_CLOSE", [&]() {
        exp_status([&]() {
            create_file(dir + u"\\deletefile10", DELETE, 0, 0, FILE_OPEN,
                        FILE_DELETE_ON_CLOSE, FILE_OPENED);
        }, STATUS_CANNOT_DELETE);
    });

    test("Create readonly file", [&]() {
        h = create_file(dir + u"\\deletefile11", DELETE, FILE_ATTRIBUTE_READONLY, 0, FILE_CREATE,
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
        h = create_file(dir + u"\\deletedir12", DELETE, 0, 0, FILE_CREATE,
                        FILE_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE, FILE_CREATED);
    });

    if (h) {
        test("Check standard information", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if (fsi.DeletePending)
                throw runtime_error("DeletePending was true, expected false");
        });

        test("Check standard link information", [&]() {
            auto fsli = query_information<FILE_STANDARD_LINK_INFORMATION>(h.get());

            if (fsli.NumberOfAccessibleLinks != 1)
                throw formatted_error("NumberOfAccessibleLinks was {}, expected 1", fsli.NumberOfAccessibleLinks);

            if (fsli.TotalNumberOfLinks != 1)
                throw formatted_error("TotalNumberOfLinks was {}, expected 1", fsli.TotalNumberOfLinks);

            if (fsli.DeletePending)
                throw runtime_error("DeletePending was true, expected false");

            if (!fsli.Directory)
                throw runtime_error("Directory was false, expected true");
        });

        h.reset();

        test("Check directory entry gone after handle closed", [&]() {
            u16string_view name = u"deletedir12";

            exp_status([&]() {
                query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);
            }, STATUS_NO_SUCH_FILE);
        });
    }

    test("Create directory with FILE_DELETE_ON_CLOSE", [&]() {
        h = create_file(dir + u"\\deletedir13", DELETE, 0, 0, FILE_CREATE,
                        FILE_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE, FILE_CREATED);
    });

    if (h) {
        test("Create file in directory", [&]() {
            create_file(dir + u"\\deletedir13\\file", FILE_READ_DATA, 0, 0, FILE_CREATE,
                        0, FILE_CREATED);
        });

        h.reset();

        test("Check directory entry still there after handle closed", [&]() {
            u16string_view name = u"deletedir13";

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
}

void test_delete_ex(HANDLE token, const u16string& dir) {
    unique_handle h, h2;

    test("Create file", [&]() {
        h = create_file(dir + u"\\deletefileex1", DELETE, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Check directory entry", [&]() {
            u16string_view name = u"deletefileex1";

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

        test("Set disposition", [&]() {
            set_disposition_information_ex(h.get(), FILE_DISPOSITION_DELETE);
        });

        test("Check directory entry still there", [&]() {
            u16string_view name = u"deletefileex1";

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

        test("Check standard link information again", [&]() {
            auto fsli = query_information<FILE_STANDARD_LINK_INFORMATION>(h.get());

            if (fsli.NumberOfAccessibleLinks != 0)
                throw formatted_error("NumberOfAccessibleLinks was {}, expected 0", fsli.NumberOfAccessibleLinks);

            if (fsli.TotalNumberOfLinks != 1)
                throw formatted_error("TotalNumberOfLinks was {}, expected 1", fsli.TotalNumberOfLinks);

            if (!fsli.DeletePending)
                throw runtime_error("DeletePending was false, expected true");

            if (fsli.Directory)
                throw runtime_error("Directory was true, expected false");
        });

        h.reset();

        test("Check directory entry gone after close", [&]() {
            u16string_view name = u"deletefileex1";

            exp_status([&]() {
                query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);
            }, STATUS_NO_SUCH_FILE);
        });
    }

    test("Create directory", [&]() {
        h = create_file(dir + u"\\deleteexdir2", DELETE, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Check directory entry", [&]() {
            u16string_view name = u"deleteexdir2";

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

        test("Check standard link information", [&]() {
            auto fsli = query_information<FILE_STANDARD_LINK_INFORMATION>(h.get());

            if (fsli.NumberOfAccessibleLinks != 1)
                throw formatted_error("NumberOfAccessibleLinks was {}, expected 1", fsli.NumberOfAccessibleLinks);

            if (fsli.TotalNumberOfLinks != 1)
                throw formatted_error("TotalNumberOfLinks was {}, expected 1", fsli.TotalNumberOfLinks);

            if (fsli.DeletePending)
                throw runtime_error("DeletePending was true, expected false");

            if (!fsli.Directory)
                throw runtime_error("Directory was false, expected true");
        });

        test("Set disposition", [&]() {
            set_disposition_information_ex(h.get(), FILE_DISPOSITION_DELETE);
        });

        test("Check directory entry still there", [&]() {
            u16string_view name = u"deleteexdir2";

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

        test("Check standard link information again", [&]() {
            auto fsli = query_information<FILE_STANDARD_LINK_INFORMATION>(h.get());

            if (fsli.NumberOfAccessibleLinks != 0)
                throw formatted_error("NumberOfAccessibleLinks was {}, expected 0", fsli.NumberOfAccessibleLinks);

            if (fsli.TotalNumberOfLinks != 1)
                throw formatted_error("TotalNumberOfLinks was {}, expected 1", fsli.TotalNumberOfLinks);

            if (!fsli.DeletePending)
                throw runtime_error("DeletePending was false, expected true");

            if (!fsli.Directory)
                throw runtime_error("Directory was false, expected true");
        });

        h.reset();

        test("Check directory entry gone after close", [&]() {
            u16string_view name = u"deleteexdir2";

            exp_status([&]() {
                query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);
            }, STATUS_NO_SUCH_FILE);
        });
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\deleteexfile3", DELETE, 0, FILE_SHARE_DELETE, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Set deletion flag on file", [&]() {
            set_disposition_information_ex(h.get(), FILE_DISPOSITION_DELETE);
        });

        test("Try to reopen file marked for deletion", [&]() {
            exp_status([&]() {
                create_file(dir + u"\\deleteexfile3", DELETE, 0, FILE_SHARE_DELETE, FILE_OPEN, 0, FILE_OPENED);
            }, STATUS_DELETE_PENDING);
        });

        test("Clear deletion flag on file", [&]() {
            set_disposition_information_ex(h.get(), FILE_DISPOSITION_DO_NOT_DELETE);
        });

        test("Check standard information again", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if (fsi.DeletePending)
                throw runtime_error("DeletePending was true, expected false");
        });

        test("Check standard link information again", [&]() {
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

        test("Reopen file now no longer marked for deletion", [&]() {
            h2 = create_file(dir + u"\\deleteexfile3", DELETE, 0, FILE_SHARE_DELETE, FILE_OPEN, 0, FILE_OPENED);
        });

        test("Set deletion flag again", [&]() {
            set_disposition_information_ex(h.get(), FILE_DISPOSITION_DELETE);
        });

        h.reset();

        test("Check directory entry after first handle closed", [&]() {
            u16string_view name = u"deleteexfile3";

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
            u16string_view name = u"deleteexfile3";

            exp_status([&]() {
                query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);
            }, STATUS_NO_SUCH_FILE);
        });
    }

    test("Create image file", [&]() {
        h = create_file(dir + u"\\deleteexfile4",
                        SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA | DELETE,
                        0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATED);
    });

    if (h) {
        unique_handle sect;

        test("Write to file", [&]() {
            auto img = pe_image(as_bytes(span("hello")));

            write_file(h.get(), img);
        });

        test("Create section", [&]() {
            sect = create_section(SECTION_ALL_ACCESS, nullopt, PAGE_READWRITE, SEC_IMAGE, h.get());
        });

        if (sect) {
            test("Try deleting mapped image file with 1 link and FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK", [&]() {
                exp_status([&]() {
                    set_disposition_information_ex(h.get(), FILE_DISPOSITION_DELETE | FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK);
                }, STATUS_CANNOT_DELETE);
            });

            test("Try deleting mapped image file with 1 link", [&]() {
                exp_status([&]() {
                    set_disposition_information_ex(h.get(), FILE_DISPOSITION_DELETE);
                }, STATUS_CANNOT_DELETE);
            });

            test("Create hard link", [&]() {
                set_link_information(h.get(), false, nullptr, dir + u"\\deleteexfile4a");
            });

            test("Try deleting mapped image file with 2 links and FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK", [&]() {
                exp_status([&]() {
                    set_disposition_information_ex(h.get(), FILE_DISPOSITION_DELETE | FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK);
                }, STATUS_CANNOT_DELETE);
            });

            test("Delete mapped image file with 2 links", [&]() {
                set_disposition_information_ex(h.get(), FILE_DISPOSITION_DELETE);
            });
        }

        h.reset();
    }

    test("Create readonly file", [&]() {
        h = create_file(dir + u"\\deleteexfile5", DELETE, FILE_ATTRIBUTE_READONLY, 0, FILE_CREATE,
                        0, FILE_CREATED);
    });

    if (h) {
        test("Try to set deletion flag on readonly file", [&]() {
            exp_status([&]() {
                set_disposition_information_ex(h.get(), FILE_DISPOSITION_DELETE);
            }, STATUS_CANNOT_DELETE);
        });

        test("Set deletion flag on readonly file with FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE", [&]() {
            set_disposition_information_ex(h.get(), FILE_DISPOSITION_DELETE | FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE);
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

    test("Create file", [&]() {
        h = create_file(dir + u"\\deleteexfile6", DELETE, 0, FILE_SHARE_DELETE, FILE_CREATE, 0, FILE_CREATED);
    });

    test("Open second handle to file", [&]() {
        h2 = create_file(dir + u"\\deleteexfile6", DELETE, 0, FILE_SHARE_DELETE, FILE_OPEN, 0, FILE_OPENED);
    });

    if (h) {
        test("Check directory entry", [&]() {
            u16string_view name = u"deleteexfile6";

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

            static const u16string_view ends_with = u"\\deleteexfile6";

            if (fn.size() < ends_with.size() || fn.substr(fn.size() - ends_with.size()) != ends_with)
                throw runtime_error("Name did not end with \"\\deleteexfile6\".");
        });

        int64_t dir_id;

        test("Check hardlinks", [&]() {
            auto items = query_links(h.get());

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& item = items.front();

            if (item.second != u"deleteexfile6")
                throw formatted_error("Link was called {}, expected deleteexfile6", u16string_to_string(item.second));

            dir_id = item.first;
        });

        test("Check standard information", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if (fsi.NumberOfLinks != 1)
                throw formatted_error("NumberOfLinks was {}, expected 1", fsi.NumberOfLinks);

            if (fsi.DeletePending)
                throw runtime_error("DeletePending was true, expected false");
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

        test("Set disposition with FILE_DISPOSITION_POSIX_SEMANTICS", [&]() {
            set_disposition_information_ex(h.get(), FILE_DISPOSITION_DELETE | FILE_DISPOSITION_POSIX_SEMANTICS);
        });

        test("Check directory entry still there", [&]() {
            u16string_view name = u"deleteexfile6";

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

            if (fsi.NumberOfLinks != 0)
                throw formatted_error("NumberOfLinks was {}, expected 0", fsi.NumberOfLinks);

            if (!fsi.DeletePending)
                throw runtime_error("DeletePending was false, expected true");
        });

        test("Check standard link information again", [&]() {
            auto fsli = query_information<FILE_STANDARD_LINK_INFORMATION>(h.get());

            if (fsli.NumberOfAccessibleLinks != 0)
                throw formatted_error("NumberOfAccessibleLinks was {}, expected 0", fsli.NumberOfAccessibleLinks);

            if (fsli.TotalNumberOfLinks != 1)
                throw formatted_error("TotalNumberOfLinks was {}, expected 1", fsli.TotalNumberOfLinks);

            if (!fsli.DeletePending)
                throw runtime_error("DeletePending was false, expected true");

            if (fsli.Directory)
                throw runtime_error("Directory was true, expected false");
        });

        h.reset();

        test("Check directory entry gone after close", [&]() {
            u16string_view name = u"deleteexfile6";

            exp_status([&]() {
                query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);
            }, STATUS_NO_SUCH_FILE);
        });

        test("Check name", [&]() {
            auto fn = query_file_name_information(h2.get());

            static const u16string_view ends_with = u"\\deleteexfile6";

            // NTFS moves this to \$Extend\$Deleted directory

            if (fn.size() >= ends_with.size() && fn.substr(fn.size() - ends_with.size()) == ends_with)
                throw runtime_error("Name ended with \"\\deleteexfile6\".");
        });

        test("Check hardlinks", [&]() {
            auto items = query_links(h2.get());

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& item = items.front();

            if (item.second == u"deleteexfile6")
                throw formatted_error("Link was called deleteexfile6, expected something else", u16string_to_string(item.second));

            if (item.first == dir_id)
                throw runtime_error("Dir ID of orphaned inode is same as before");
        });

        test("Check standard information on second handle", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h2.get());

            if (fsi.NumberOfLinks != 0)
                throw formatted_error("NumberOfLinks was {}, expected 0", fsi.NumberOfLinks);

            if (!fsi.DeletePending)
                throw runtime_error("DeletePending was false, expected true");
        });

        test("Check standard link information on second handle", [&]() {
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

        h2.reset();

        test("Try opening deleted file", [&]() {
            exp_status([&]() {
                create_file(dir + u"\\deleteexfile6", DELETE, 0, FILE_SHARE_DELETE, FILE_OPEN, 0, FILE_OPENED);
            }, STATUS_OBJECT_NAME_NOT_FOUND);
        });
    }

    disable_token_privileges(token);

    test("Create file with FILE_DELETE_ON_CLOSE", [&]() {
        h = create_file(dir + u"\\deleteexfile7", DELETE, 0, 0, FILE_CREATE,
                        FILE_DELETE_ON_CLOSE, FILE_CREATED);
    });

    if (h) {
        test("Check standard information on file", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if (fsi.DeletePending)
                throw runtime_error("DeletePending was true, expected false");
        });

        test("Check standard link information on file", [&]() {
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

        test("Clear delete on close flag", [&]() {
            set_disposition_information_ex(h.get(), FILE_DISPOSITION_DO_NOT_DELETE | FILE_DISPOSITION_ON_CLOSE);
        });

        test("Check standard information on file", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if (fsi.DeletePending)
                throw runtime_error("DeletePending was true, expected false");
        });

        test("Check standard link information on file", [&]() {
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

        h.reset();

        test("Check directory entry still there after file closed", [&]() {
            u16string_view name = u"deleteexfile7";

            query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);
        });
    }

    test("Create file without FILE_DELETE_ON_CLOSE", [&]() {
        h = create_file(dir + u"\\deleteexfile8", DELETE, 0, 0, FILE_CREATE,
                        0, FILE_CREATED);
    });

    if (h) {
        test("Check standard information on file", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if (fsi.DeletePending)
                throw runtime_error("DeletePending was true, expected false");
        });

        test("Check standard link information on file", [&]() {
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

        // see https://community.osr.com/discussion/comment/302155/#Comment_302155
        test("Try to set delete on close flag", [&]() {
            exp_status([&]() {
                set_disposition_information_ex(h.get(), FILE_DISPOSITION_DELETE | FILE_DISPOSITION_ON_CLOSE);
            }, STATUS_NOT_SUPPORTED);
        });

        h.reset();
    }

    test("Create file with FILE_DELETE_ON_CLOSE", [&]() {
        h = create_file(dir + u"\\deleteexfile9", DELETE, 0, 0, FILE_CREATE,
                        FILE_DELETE_ON_CLOSE, FILE_CREATED);
    });

    if (h) {
        test("Set delete on close flag", [&]() {
            set_disposition_information_ex(h.get(), FILE_DISPOSITION_DELETE | FILE_DISPOSITION_ON_CLOSE);
        });

        h.reset();
    }
}
