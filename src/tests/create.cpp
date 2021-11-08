#include "test.h"

using namespace std;

static OBJECT_BASIC_INFORMATION query_object_basic_information(HANDLE h) {
    NTSTATUS Status;
    OBJECT_BASIC_INFORMATION obi;
    ULONG len;

    Status = NtQueryObject(h, ObjectBasicInformation, &obi, sizeof(obi), &len);

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);

    if (len != sizeof(obi))
        throw formatted_error("returned length was {}, expected {}", len, sizeof(obi));

    return obi;
}

void test_create(const u16string& dir) {
    unique_handle h;

    test("Create file", [&]() {
        h = create_file(dir + u"\\file", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Create duplicate file", [&]() {
            exp_status([&]() {
                create_file(dir + u"\\file", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
            }, STATUS_OBJECT_NAME_COLLISION);
        });

        test("Create file differing in case", [&]() {
            exp_status([&]() {
                create_file(dir + u"\\FILE", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
            }, STATUS_OBJECT_NAME_COLLISION);
        });

        FILE_BASIC_INFORMATION fbi;

        test("Check attributes", [&]() {
            fbi = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi.FileAttributes != FILE_ATTRIBUTE_ARCHIVE) {
                throw formatted_error("attributes were {:x}, expected FILE_ATTRIBUTE_ARCHIVE",
                                      fbi.FileAttributes);
            }
        });

        FILE_STANDARD_INFORMATION fsi;

        test("Check standard information", [&]() {
            fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if (fsi.AllocationSize.QuadPart != 0)
                throw formatted_error("AllocationSize was {}, expected 0", fsi.AllocationSize.QuadPart);

            if (fsi.EndOfFile.QuadPart != 0)
                throw formatted_error("EndOfFile was {}, expected 0", fsi.EndOfFile.QuadPart);

            if (fsi.NumberOfLinks != 1)
                throw formatted_error("NumberOfLinks was {}, expected 1", fsi.NumberOfLinks);

            if (fsi.DeletePending)
                throw runtime_error("DeletePending was true, expected false");

            if (fsi.Directory)
                throw runtime_error("Directory was true, expected false");
        });

        test("Check name", [&]() {
            auto fn = query_file_name_information(h.get());

            static const u16string_view ends_with = u"\\file";

            if (fn.size() < ends_with.size() || fn.substr(fn.size() - ends_with.size()) != ends_with)
                throw runtime_error("Name did not end with \"\\file\".");
        });

        test("Check access information", [&]() {
            auto fai = query_information<FILE_ACCESS_INFORMATION>(h.get());

            ACCESS_MASK exp = SYNCHRONIZE | WRITE_OWNER | WRITE_DAC | READ_CONTROL | DELETE |
                              FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES | FILE_DELETE_CHILD |
                              FILE_EXECUTE | FILE_WRITE_EA | FILE_READ_EA | FILE_APPEND_DATA |
                              FILE_WRITE_DATA | FILE_READ_DATA;

            if (fai.AccessFlags != exp)
                throw formatted_error("AccessFlags was {:x}, expected {:x}", fai.AccessFlags, exp);
        });

        test("Check mode information", [&]() {
            auto fmi = query_information<FILE_MODE_INFORMATION>(h.get());

            if (fmi.Mode != 0)
                throw formatted_error("Mode was {:x}, expected 0", fmi.Mode);
        });

        test("Check alignment information", [&]() {
            auto fai = query_information<FILE_ALIGNMENT_INFORMATION>(h.get());

            if (fai.AlignmentRequirement != FILE_WORD_ALIGNMENT)
                throw formatted_error("AlignmentRequirement was {:x}, expected FILE_WORD_ALIGNMENT", fai.AlignmentRequirement);
        });

        test("Check position information", [&]() {
            auto fpi = query_information<FILE_POSITION_INFORMATION>(h.get());

            if (fpi.CurrentByteOffset.QuadPart != 0)
                throw formatted_error("CurrentByteOffset was {:x}, expected 0", fpi.CurrentByteOffset.QuadPart);
        });

        // FIXME - FileAllInformation
        // FIXME - FileAttributeTagInformation
        // FIXME - FileCompressionInformation
        // FIXME - FileEaInformation
        // FIXME - FileInternalInformation
        // FIXME - FileNetworkOpenInformation
        // FIXME - FileStreamInformation
        // FIXME - FileHardLinkInformation
        // FIXME - FileNormalizedNameInformation
        // FIXME - FileStandardLinkInformation
        // FIXME - FileIdInformation
        // FIXME - FileStatInformation
        // FIXME - FileStatLxInformation
        // FIXME - FileCaseSensitiveInformation
        // FIXME - FileHardLinkFullIdInformation
        // FIXME - FILE_STANDARD_INFORMATION_EX
        // FIXME - FileAlternateNameInformation
        // FIXME - FileSfioReserveInformation
        // FIXME - FileDesiredStorageClassInformation
        // FIXME - FileStorageReserveIdInformation
        // FIXME - FileKnownFolderInformation

        static const u16string_view name = u"file";

        test("Check directory entry (FILE_DIRECTORY_INFORMATION)", [&]() {
            check_dir_entry<FILE_DIRECTORY_INFORMATION>(dir, name, fbi, fsi);
        });

        test("Check directory entry (FILE_BOTH_DIR_INFORMATION)", [&]() {
            check_dir_entry<FILE_BOTH_DIR_INFORMATION>(dir, name, fbi, fsi);
        });

        test("Check directory entry (FILE_FULL_DIR_INFORMATION)", [&]() {
            check_dir_entry<FILE_FULL_DIR_INFORMATION>(dir, name, fbi, fsi);
        });

        test("Check directory entry (FILE_ID_BOTH_DIR_INFORMATION)", [&]() {
            check_dir_entry<FILE_ID_BOTH_DIR_INFORMATION>(dir, name, fbi, fsi);
        });

        test("Check directory entry (FILE_ID_FULL_DIR_INFORMATION)", [&]() {
            check_dir_entry<FILE_ID_FULL_DIR_INFORMATION>(dir, name, fbi, fsi);
        });

        test("Check directory entry (FILE_ID_EXTD_DIR_INFORMATION)", [&]() {
            check_dir_entry<FILE_ID_EXTD_DIR_INFORMATION>(dir, name, fbi, fsi);
        });

        test("Check directory entry (FILE_ID_EXTD_BOTH_DIR_INFORMATION)", [&]() {
            check_dir_entry<FILE_ID_EXTD_BOTH_DIR_INFORMATION>(dir, name, fbi, fsi);
        });

        test("Check directory entry (FILE_NAMES_INFORMATION)", [&]() {
            check_dir_entry<FILE_NAMES_INFORMATION>(dir, name, fbi, fsi);
        });

        // FIXME - FileObjectIdInformation
        // FIXME - FileQuotaInformation
        // FIXME - FileReparsePointInformation

        test("Check granted access", [&]() {
            auto obi = query_object_basic_information(h.get());

            ACCESS_MASK exp = SYNCHRONIZE | WRITE_OWNER | WRITE_DAC | READ_CONTROL | DELETE |
                              FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES | FILE_DELETE_CHILD |
                              FILE_EXECUTE | FILE_WRITE_EA | FILE_READ_EA | FILE_APPEND_DATA |
                              FILE_WRITE_DATA | FILE_READ_DATA;

            if (obi.GrantedAccess != exp)
                throw formatted_error("granted access was {:x}, expected {:x}", obi.GrantedAccess, exp);
        });

        h.reset();

        test("Open file", [&]() {
            create_file(dir + u"\\file", MAXIMUM_ALLOWED, 0, 0, FILE_OPEN, 0, FILE_OPENED);
        });
    }

    test("Create file (FILE_NON_DIRECTORY_FILE)", [&]() {
        h = create_file(dir + u"\\file2", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, FILE_NON_DIRECTORY_FILE,
                        FILE_CREATED);
    });

    if (h) {
        test("Check attributes", [&]() {
            auto fbi = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi.FileAttributes != FILE_ATTRIBUTE_ARCHIVE) {
                throw formatted_error("attributes were {:x}, expected FILE_ATTRIBUTE_ARCHIVE",
                                      fbi.FileAttributes);
            }
        });

        test("Check standard information", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if (fsi.AllocationSize.QuadPart != 0)
                throw formatted_error("AllocationSize was {}, expected 0", fsi.AllocationSize.QuadPart);

            if (fsi.EndOfFile.QuadPart != 0)
                throw formatted_error("EndOfFile was {}, expected 0", fsi.EndOfFile.QuadPart);

            if (fsi.NumberOfLinks != 1)
                throw formatted_error("NumberOfLinks was {}, expected 1", fsi.NumberOfLinks);

            if (fsi.DeletePending)
                throw runtime_error("DeletePending was true, expected false");

            if (fsi.Directory)
                throw runtime_error("Directory was true, expected false");
        });

        h.reset();
    }

    test("Create file (FILE_NON_DIRECTORY_FILE, FILE_ATTRIBUTE_DIRECTORY)", [&]() {
        h = create_file(dir + u"\\file3", MAXIMUM_ALLOWED, FILE_ATTRIBUTE_DIRECTORY, 0, FILE_CREATE,
                        FILE_NON_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Check attributes", [&]() {
            auto fbi = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi.FileAttributes != FILE_ATTRIBUTE_ARCHIVE) {
                throw formatted_error("attributes were {:x}, expected FILE_ATTRIBUTE_ARCHIVE",
                                      fbi.FileAttributes);
            }
        });

        test("Check standard information", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if (fsi.AllocationSize.QuadPart != 0)
                throw formatted_error("AllocationSize was {}, expected 0", fsi.AllocationSize.QuadPart);

            if (fsi.EndOfFile.QuadPart != 0)
                throw formatted_error("EndOfFile was {}, expected 0", fsi.EndOfFile.QuadPart);

            if (fsi.NumberOfLinks != 1)
                throw formatted_error("NumberOfLinks was {}, expected 1", fsi.NumberOfLinks);

            if (fsi.DeletePending)
                throw runtime_error("DeletePending was true, expected false");

            if (fsi.Directory)
                throw runtime_error("Directory was true, expected false");
        });

        h.reset();
    }

    test("Create directory (FILE_DIRECTORY_FILE)", [&]() {
        h = create_file(dir + u"\\dir", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE,
                        FILE_CREATED);
    });

    if (h) {
        test("Check attributes", [&]() {
            auto fbi = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi.FileAttributes != FILE_ATTRIBUTE_DIRECTORY) {
                throw formatted_error("attributes were {:x}, expected FILE_ATTRIBUTE_DIRECTORY",
                                      fbi.FileAttributes);
            }
        });

        test("Check standard information", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if (fsi.AllocationSize.QuadPart != 0)
                throw formatted_error("AllocationSize was {}, expected 0", fsi.AllocationSize.QuadPart);

            if (fsi.EndOfFile.QuadPart != 0)
                throw formatted_error("EndOfFile was {}, expected 0", fsi.EndOfFile.QuadPart);

            if (fsi.NumberOfLinks != 1)
                throw formatted_error("NumberOfLinks was {}, expected 1", fsi.NumberOfLinks);

            if (fsi.DeletePending)
                throw runtime_error("DeletePending was true, expected false");

            if (!fsi.Directory)
                throw runtime_error("Directory was false, expected true");
        });

        test("Check granted access", [&]() {
            auto obi = query_object_basic_information(h.get());

            ACCESS_MASK exp = SYNCHRONIZE | WRITE_OWNER | WRITE_DAC | READ_CONTROL | DELETE |
                              FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES | FILE_DELETE_CHILD |
                              FILE_EXECUTE | FILE_WRITE_EA | FILE_READ_EA | FILE_APPEND_DATA |
                              FILE_WRITE_DATA | FILE_READ_DATA;

            if (obi.GrantedAccess != exp)
                throw formatted_error("granted access was {:x}, expected {:x}", obi.GrantedAccess, exp);
        });

        h.reset();

        test("Open directory", [&]() {
            create_file(dir + u"\\dir", MAXIMUM_ALLOWED, 0, 0, FILE_OPEN, 0, FILE_OPENED);
        });
    }

    test("Create file (FILE_ATTRIBUTE_DIRECTORY)", [&]() {
        h = create_file(dir + u"\\file4", MAXIMUM_ALLOWED, FILE_ATTRIBUTE_DIRECTORY, 0, FILE_CREATE,
                        0, FILE_CREATED);
    });

    if (h) {
        test("Check attributes", [&]() {
            auto fbi = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi.FileAttributes != FILE_ATTRIBUTE_ARCHIVE) {
                throw formatted_error("attributes were {:x}, expected FILE_ATTRIBUTE_ARCHIVE",
                                      fbi.FileAttributes);
            }
        });

        test("Check standard information", [&]() {
            auto fsi = query_information<FILE_STANDARD_INFORMATION>(h.get());

            if (fsi.AllocationSize.QuadPart != 0)
                throw formatted_error("AllocationSize was {}, expected 0", fsi.AllocationSize.QuadPart);

            if (fsi.EndOfFile.QuadPart != 0)
                throw formatted_error("EndOfFile was {}, expected 0", fsi.EndOfFile.QuadPart);

            if (fsi.NumberOfLinks != 1)
                throw formatted_error("NumberOfLinks was {}, expected 1", fsi.NumberOfLinks);

            if (fsi.DeletePending)
                throw runtime_error("DeletePending was true, expected false");

            if (fsi.Directory)
                throw runtime_error("Directory was true, expected false");
        });

        h.reset();
    }

    test("Create file (FILE_ATTRIBUTE_HIDDEN)", [&]() {
        h = create_file(dir + u"\\filehidden", MAXIMUM_ALLOWED, FILE_ATTRIBUTE_HIDDEN, 0, FILE_CREATE,
                        0, FILE_CREATED);
    });

    if (h) {
        test("Check attributes", [&]() {
            auto fbi = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi.FileAttributes != (FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_HIDDEN)) {
                throw formatted_error("attributes were {:x}, expected FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_HIDDEN",
                                      fbi.FileAttributes);
            }
        });

        h.reset();
    }

    test("Create file (FILE_ATTRIBUTE_READONLY)", [&]() {
        h = create_file(dir + u"\\filero", MAXIMUM_ALLOWED, FILE_ATTRIBUTE_READONLY, 0, FILE_CREATE,
                        0, FILE_CREATED);
    });

    if (h) {
        test("Check attributes", [&]() {
            auto fbi = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi.FileAttributes != (FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_READONLY)) {
                throw formatted_error("attributes were {:x}, expected FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_READONLY",
                                      fbi.FileAttributes);
            }
        });

        h.reset();
    }

    test("Create file (FILE_ATTRIBUTE_SYSTEM)", [&]() {
        h = create_file(dir + u"\\filesys", MAXIMUM_ALLOWED, FILE_ATTRIBUTE_SYSTEM, 0, FILE_CREATE,
                        0, FILE_CREATED);
    });

    if (h) {
        test("Check attributes", [&]() {
            auto fbi = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi.FileAttributes != (FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_SYSTEM)) {
                throw formatted_error("attributes were {:x}, expected FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_SYSTEM",
                                      fbi.FileAttributes);
            }
        });

        h.reset();
    }

    test("Create file (FILE_ATTRIBUTE_NORMAL)", [&]() {
        h = create_file(dir + u"\\filenormal", MAXIMUM_ALLOWED, FILE_ATTRIBUTE_NORMAL, 0, FILE_CREATE,
                        0, FILE_CREATED);
    });

    if (h) {
        test("Check attributes", [&]() {
            auto fbi = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi.FileAttributes != FILE_ATTRIBUTE_ARCHIVE) {
                throw formatted_error("attributes were {:x}, expected FILE_ATTRIBUTE_ARCHIVE",
                                      fbi.FileAttributes);
            }
        });

        h.reset();
    }

    test("Create directory (FILE_ATTRIBUTE_HIDDEN)", [&]() {
        h = create_file(dir + u"\\dirhidden", MAXIMUM_ALLOWED, FILE_ATTRIBUTE_HIDDEN, 0, FILE_CREATE,
                        FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Check attributes", [&]() {
            auto fbi = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi.FileAttributes != (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_HIDDEN)) {
                throw formatted_error("attributes were {:x}, expected FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_HIDDEN",
                                      fbi.FileAttributes);
            }
        });

        h.reset();
    }

    test("Create directory (FILE_ATTRIBUTE_READONLY)", [&]() {
        h = create_file(dir + u"\\dirro", MAXIMUM_ALLOWED, FILE_ATTRIBUTE_READONLY, 0, FILE_CREATE,
                        FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Check attributes", [&]() {
            auto fbi = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi.FileAttributes != (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_READONLY)) {
                throw formatted_error("attributes were {:x}, expected FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_READONLY",
                                      fbi.FileAttributes);
            }
        });

        h.reset();
    }

    test("Create directory (FILE_ATTRIBUTE_SYSTEM)", [&]() {
        h = create_file(dir + u"\\dirsys", MAXIMUM_ALLOWED, FILE_ATTRIBUTE_SYSTEM, 0, FILE_CREATE,
                        FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Check attributes", [&]() {
            auto fbi = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi.FileAttributes != (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_SYSTEM)) {
                throw formatted_error("attributes were {:x}, expected FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_SYSTEM",
                                      fbi.FileAttributes);
            }
        });

        h.reset();
    }

    test("Create directory (FILE_ATTRIBUTE_NORMAL)", [&]() {
        h = create_file(dir + u"\\dirnormal", MAXIMUM_ALLOWED, FILE_ATTRIBUTE_NORMAL, 0, FILE_CREATE,
                        FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Check attributes", [&]() {
            auto fbi = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi.FileAttributes != FILE_ATTRIBUTE_DIRECTORY) {
                throw formatted_error("attributes were {:x}, expected FILE_ATTRIBUTE_DIRECTORY",
                                      fbi.FileAttributes);
            }
        });

        h.reset();
    }

    test("Create file (FILE_SHARE_READ)", [&]() {
        h = create_file(dir + u"\\fileshareread", FILE_READ_DATA, 0, FILE_SHARE_READ, FILE_CREATE,
                        0, FILE_CREATED);
    });

    if (h) {
        test("Open for read", [&]() {
            create_file(dir + u"\\fileshareread", FILE_READ_DATA, 0, FILE_SHARE_READ, FILE_OPEN,
                        0, FILE_OPENED);
        });

        test("Open for write", [&]() {
            exp_status([&]() {
                create_file(dir + u"\\fileshareread", FILE_WRITE_DATA, 0, FILE_SHARE_READ, FILE_OPEN,
                            0, FILE_OPENED);
            }, STATUS_SHARING_VIOLATION);
        });

        test("Open for delete", [&]() {
            exp_status([&]() {
                create_file(dir + u"\\fileshareread", DELETE, 0, FILE_SHARE_READ, FILE_OPEN,
                            0, FILE_OPENED);
            }, STATUS_SHARING_VIOLATION);
        });

        h.reset();
    }

    test("Create file (FILE_SHARE_WRITE)", [&]() {
        h = create_file(dir + u"\\filesharewrite", FILE_WRITE_DATA, 0, FILE_SHARE_WRITE, FILE_CREATE,
                        0, FILE_CREATED);
    });

    if (h) {
        test("Open for read", [&]() {
            exp_status([&]() {
                create_file(dir + u"\\filesharewrite", FILE_READ_DATA, 0, FILE_SHARE_WRITE, FILE_OPEN,
                            0, FILE_OPENED);
            }, STATUS_SHARING_VIOLATION);
        });

        test("Open for write", [&]() {
            create_file(dir + u"\\filesharewrite", FILE_WRITE_DATA, 0, FILE_SHARE_WRITE, FILE_OPEN,
                        0, FILE_OPENED);
        });

        test("Open for delete", [&]() {
            exp_status([&]() {
                create_file(dir + u"\\filesharewrite", DELETE, 0, FILE_SHARE_WRITE, FILE_OPEN,
                            0, FILE_OPENED);
            }, STATUS_SHARING_VIOLATION);
        });

        h.reset();
    }

    test("Create file (FILE_SHARE_DELETE)", [&]() {
        h = create_file(dir + u"\\filesharedelete", DELETE, 0, FILE_SHARE_DELETE, FILE_CREATE,
                        0, FILE_CREATED);
    });

    if (h) {
        test("Open for read", [&]() {
            exp_status([&]() {
                create_file(dir + u"\\filesharedelete", FILE_READ_DATA, 0, FILE_SHARE_DELETE, FILE_OPEN,
                            0, FILE_OPENED);
            }, STATUS_SHARING_VIOLATION);
        });

        test("Open for write", [&]() {
            exp_status([&]() {
                create_file(dir + u"\\filesharedelete", FILE_WRITE_DATA, 0, FILE_SHARE_DELETE, FILE_OPEN,
                            0, FILE_OPENED);
            }, STATUS_SHARING_VIOLATION);
        });

        test("Open for delete", [&]() {
            create_file(dir + u"\\filesharedelete", DELETE, 0, FILE_SHARE_DELETE, FILE_OPEN,
                        0, FILE_OPENED);
        });

        h.reset();
    }

    test("Create file in invalid path", [&]() {
        exp_status([&]() {
            create_file(dir + u"\\nosuchdir\\file", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, FILE_NON_DIRECTORY_FILE,
                        FILE_CREATED);
        }, STATUS_OBJECT_PATH_NOT_FOUND);
    });

    test("Create directory in invalid path", [&]() {
        exp_status([&]() {
            create_file(dir + u"\\nosuchdir\\file", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE,
                        FILE_CREATED);
        }, STATUS_OBJECT_PATH_NOT_FOUND);
    });

    test("Create file with FILE_OPEN_IF", [&]() {
        h = create_file(dir + u"\\openif", MAXIMUM_ALLOWED, 0, 0, FILE_OPEN_IF, 0, FILE_CREATED);
    });

    if (h) {
        h.reset();

        test("Open file with FILE_OPEN_IF", [&]() {
            create_file(dir + u"\\openif", MAXIMUM_ALLOWED, 0, 0, FILE_OPEN_IF, 0, FILE_OPENED);
        });
    }

    test("Create file with long name", [&]() {
        u16string longname(256, u'x');

        exp_status([&]() {
            create_file(dir + u"\\" + longname, MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
        }, STATUS_OBJECT_NAME_INVALID);
    });

    test("Create file with emoji", [&]() {
        create_file(dir + u"\\\U0001f525", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    /* The limits for Btrfs are more stringent than NTFS, to make sure we don't
     * create a filename that will confuse Linux. */
    bool is_ntfs = fstype == fs_type::ntfs;

    test("Create file with more than 255 UTF-8 characters", [&]() {
        auto fn = dir + u"\\";

        for (unsigned int i = 0; i < 64; i++) {
            fn += u"\U0001f525";
        }

        exp_status([&]() {
            create_file(fn, MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
        }, is_ntfs ? STATUS_SUCCESS : STATUS_OBJECT_NAME_INVALID);
    });

    test("Create file with WTF-16 (1)", [&]() {
        auto fn = dir + u"\\";

        fn += (char16_t)0xd83d;

        exp_status([&]() {
            create_file(fn, MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
        }, is_ntfs ? STATUS_SUCCESS : STATUS_OBJECT_NAME_INVALID);
    });

    test("Create file with WTF-16 (2)", [&]() {
        auto fn = dir + u"\\";

        fn += (char16_t)0xdd25;

        exp_status([&]() {
            create_file(fn, MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
        }, is_ntfs ? STATUS_SUCCESS : STATUS_OBJECT_NAME_INVALID);
    });

    test("Create file with WTF-16 (3)", [&]() {
        auto fn = dir + u"\\";

        fn += (char16_t)0xdd25;
        fn += (char16_t)0xd83d;

        exp_status([&]() {
            create_file(fn, MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
        }, is_ntfs ? STATUS_SUCCESS : STATUS_OBJECT_NAME_INVALID);
    });

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
        test("Create file with invalid name (" + n.desc + ")", [&]() {
            auto fn = dir + u"\\" + n.name;

            exp_status([&]() {
                create_file(fn, MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
            }, STATUS_OBJECT_NAME_INVALID);
        });
    }

    test("Create file called CON", [&]() { // allowed by NT API, not allowed by Win32 API
        create_file(dir + u"\\CON", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    // FIXME - if we try to open file with invalid name, do we get NOT_FOUND or INVALID?

    // FIXME - FILE_OPEN_BY_FILE_ID
    // FIXME - test all the variations of NtQueryInformationFile
    // FIXME - test NtOpenFile

    // FIXME - permissions needed to create file or subdirectory
    // FIXME - permissions needed when overwriting
    // FIXME - what exactly does FILE_DELETE_CHILD do?
}
