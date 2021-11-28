#include "test.h"

#define FSCTL_CREATE_OR_GET_OBJECT_ID CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 48, METHOD_BUFFERED, FILE_ANY_ACCESS)

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

    // FIXME - test all the variations of NtQueryInformationFile
    // FIXME - test NtOpenFile

    // FIXME - permissions needed to create file or subdirectory
    // FIXME - permissions needed when overwriting
    // FIXME - what exactly does FILE_DELETE_CHILD do?
    // FIXME - overwriting mapped file
}

template<typename T>
requires (is_same_v<T, uint64_t> || is_same_v<T, array<uint8_t, 16>>)
static unique_handle open_by_id(HANDLE dir, const T& id, ACCESS_MASK access, ULONG atts, ULONG share,
                                ULONG dispo, ULONG options, ULONG_PTR exp_info, optional<uint64_t> allocation = nullopt) {
    NTSTATUS Status;
    HANDLE h;
    IO_STATUS_BLOCK iosb;
    UNICODE_STRING us;
    OBJECT_ATTRIBUTES oa;
    LARGE_INTEGER alloc_size;

    oa.Length = sizeof(oa);
    oa.RootDirectory = dir;

    if constexpr (is_same_v<T, array<uint8_t, 16>>) {
        us.Length = us.MaximumLength = id.size();
        us.Buffer = (WCHAR*)id.data();
    } else {
        us.Length = us.MaximumLength = sizeof(id);
        us.Buffer = (WCHAR*)&id;
    }

    oa.ObjectName = &us;

    oa.Attributes = 0;
    oa.SecurityDescriptor = nullptr;
    oa.SecurityQualityOfService = nullptr;

    if (allocation)
        alloc_size.QuadPart = allocation.value();

    iosb.Information = 0xdeadbeef;

    Status = NtCreateFile(&h, access, &oa, &iosb, allocation ? &alloc_size : nullptr,
                          atts, share, dispo, options | FILE_OPEN_BY_FILE_ID, nullptr, 0);

    if (Status != STATUS_SUCCESS) {
        if (NT_SUCCESS(Status)) // STATUS_OPLOCK_BREAK_IN_PROGRESS etc.
            NtClose(h);

        throw ntstatus_error(Status);
    }

    if (iosb.Information != exp_info)
        throw formatted_error("iosb.Information was {}, expected {}", iosb.Information, exp_info);

    return unique_handle(h);
}

static array<uint8_t, 16> create_or_get_object_id(HANDLE h) {
    NTSTATUS Status;
    FILE_OBJECTID_BUFFER foib;
    IO_STATUS_BLOCK iosb;

    auto ev = create_event();

    Status = NtFsControlFile(h, ev.get(), nullptr, nullptr, &iosb,
                             FSCTL_CREATE_OR_GET_OBJECT_ID, nullptr, 0,
                             &foib, sizeof(foib));

    if (Status == STATUS_PENDING) {
        Status = NtWaitForSingleObject(ev.get(), false, nullptr);
        if (Status != STATUS_SUCCESS)
            throw ntstatus_error(Status);

        Status = iosb.Status;
    }

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);

    array<uint8_t, 16> ret;

    memcpy(ret.data(), foib.ObjectId, 16);

    return ret;
}

void test_open_id(HANDLE token, const u16string& dir) {
    unique_handle h, dirh;
    uint64_t file_id = 0;
    auto random = random_data(4096);

    // traverse privilege needed to query filename and hard links
    test("Add SeChangeNotifyPrivilege to token", [&]() {
        LUID_AND_ATTRIBUTES laa;

        laa.Luid.LowPart = SE_CHANGE_NOTIFY_PRIVILEGE;
        laa.Luid.HighPart = 0;
        laa.Attributes = SE_PRIVILEGE_ENABLED;

        adjust_token_privileges(token, array{ laa });
    });

    test("Create file", [&]() {
        h = create_file(dir + u"\\id1", SYNCHRONIZE | FILE_WRITE_DATA, 0, 0, FILE_CREATE,
                        FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATED);
    });

    if (h) {
        test("Write to file", [&]() {
            write_file(h.get(), random, 0);
        });

        test("Get file ID", [&]() {
            auto fii = query_information<FILE_INTERNAL_INFORMATION>(h.get());

            file_id = fii.IndexNumber.QuadPart;
        });

        h.reset();
    }

    test("Check directory entry", [&]() {
        u16string_view name = u"id1";

        auto items = query_dir<FILE_ID_FULL_DIRECTORY_INFORMATION>(dir, name);

        if (items.size() != 1)
            throw formatted_error("{} entries returned, expected 1.", items.size());

        auto& fdi = *static_cast<const FILE_ID_FULL_DIRECTORY_INFORMATION*>(items.front());

        if (fdi.FileNameLength != name.size() * sizeof(char16_t))
            throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

        if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
            throw runtime_error("FileName did not match.");

        if ((uint64_t)fdi.FileId.QuadPart != file_id)
            throw runtime_error("File IDs did not match.");
    });

    test("Try opening by ID without RootDirectory value", [&]() {
        exp_status([&]() {
            open_by_id(nullptr, file_id, MAXIMUM_ALLOWED, 0, 0, FILE_OPEN,
                       FILE_SYNCHRONOUS_IO_NONALERT, FILE_OPENED);
        }, STATUS_INVALID_PARAMETER);
    });

    test("Open directory", [&]() {
        dirh = create_file(dir, MAXIMUM_ALLOWED, 0,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           FILE_OPEN, FILE_DIRECTORY_FILE, FILE_OPENED);
    });

    test("Try to open by ID with FILE_DIRECTORY_FILE", [&]() {
        exp_status([&]() {
            open_by_id(dirh.get(), file_id, SYNCHRONIZE | MAXIMUM_ALLOWED, 0, 0, FILE_OPEN,
                       FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE, FILE_OPENED);
        }, STATUS_NOT_A_DIRECTORY);
    });

    test("Open by ID", [&]() {
        h = open_by_id(dirh.get(), file_id, SYNCHRONIZE | MAXIMUM_ALLOWED, 0, 0, FILE_OPEN,
                       FILE_SYNCHRONOUS_IO_NONALERT, FILE_OPENED);
    });

    dirh.reset();

    if (h) {
        test("Read file", [&]() {
            auto data = read_file(h.get(), random.size(), 0);

            if (data.size() != random.size())
                throw formatted_error("Read {} bytes, {} expected.", data.size(), random.size());

            if (memcmp(data.data(), random.data(), random.size()))
                throw runtime_error("Data read did not match data written");
        });

        test("Check filename", [&]() {
            auto fn = query_file_name_information(h.get());

            static const u16string_view ends_with = u"\\id1";

            if (fn.size() < ends_with.size() || fn.substr(fn.size() - ends_with.size()) != ends_with)
                throw runtime_error("Name did not end with \"\\id1\".");
        });

        test("Check links", [&]() {
            auto items = query_links(h.get());

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& item = items.front();

            if (item.second != u"id1")
                throw formatted_error("Link was called {}, expected id1", u16string_to_string(item.second));
        });

        test("Create hardlink", [&]() {
            set_link_information(h.get(), false, nullptr, dir + u"\\id1a");
        });

        test("Try renaming", [&]() {
            exp_status([&]() {
                set_rename_information(h.get(), false, nullptr, dir + u"\\id1b");
            }, STATUS_INVALID_PARAMETER);
        });

        test("Try deleting", [&]() {
            exp_status([&]() {
                set_disposition_information(h.get(), true);
            }, STATUS_INVALID_PARAMETER);
        });

        h.reset();
    }

    test("Open directory", [&]() {
        dirh = create_file(dir, MAXIMUM_ALLOWED, 0,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           FILE_OPEN, FILE_DIRECTORY_FILE, FILE_OPENED);
    });

    test("Open by ID with FILE_DELETE_ON_CLOSE", [&]() {
        h = open_by_id(dirh.get(), file_id, SYNCHRONIZE | DELETE, 0, 0, FILE_OPEN,
                       FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE,
                       FILE_OPENED);
    });

    dirh.reset();

    if (h) {
        h.reset();

        test("Check directory entry 1 still there", [&]() {
            u16string_view name = u"id1";

            auto items = query_dir<FILE_ID_FULL_DIRECTORY_INFORMATION>(dir, name);

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& fdi = *static_cast<const FILE_ID_FULL_DIRECTORY_INFORMATION*>(items.front());

            if (fdi.FileNameLength != name.size() * sizeof(char16_t))
                throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

            if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
                throw runtime_error("FileName did not match.");

            if ((uint64_t)fdi.FileId.QuadPart != file_id)
                throw runtime_error("File IDs did not match.");
        });

        test("Check directory entry 2 still there", [&]() {
            u16string_view name = u"id1a";

            auto items = query_dir<FILE_ID_FULL_DIRECTORY_INFORMATION>(dir, name);

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1.", items.size());

            auto& fdi = *static_cast<const FILE_ID_FULL_DIRECTORY_INFORMATION*>(items.front());

            if (fdi.FileNameLength != name.size() * sizeof(char16_t))
                throw formatted_error("FileNameLength was {}, expected {}.", fdi.FileNameLength, name.size() * sizeof(char16_t));

            if (name != u16string_view((char16_t*)fdi.FileName, fdi.FileNameLength / sizeof(char16_t)))
                throw runtime_error("FileName did not match.");

            if ((uint64_t)fdi.FileId.QuadPart != file_id)
                throw runtime_error("File IDs did not match.");
        });
    }

    test("Open directory", [&]() {
        dirh = create_file(dir, MAXIMUM_ALLOWED, 0,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           FILE_OPEN, FILE_DIRECTORY_FILE, FILE_OPENED);
    });

    test("Open by ID with FILE_OPEN_IF", [&]() {
        open_by_id(dirh.get(), file_id, MAXIMUM_ALLOWED, 0, 0, FILE_OPEN_IF,
                   0, FILE_OPENED);
    });

    test("Open by ID with FILE_OVERWRITE_IF", [&]() {
        open_by_id(dirh.get(), file_id, MAXIMUM_ALLOWED, 0, 0, FILE_OVERWRITE_IF,
                   0, FILE_OVERWRITTEN);
    });

    test("Open by ID with FILE_SUPERSEDE", [&]() {
        open_by_id(dirh.get(), file_id, MAXIMUM_ALLOWED, 0, 0, FILE_SUPERSEDE,
                   0, FILE_SUPERSEDED);
    });

    test("Try open by ID with FILE_CREATE", [&]() {
        exp_status([&]() {
            open_by_id(dirh.get(), file_id, MAXIMUM_ALLOWED, 0, 0, FILE_CREATE,
                       0, FILE_CREATED);
        }, STATUS_OBJECT_NAME_COLLISION);
    });

    test("Try open by ID with FILE_OVERWRITE", [&]() {
        open_by_id(dirh.get(), file_id, MAXIMUM_ALLOWED, 0, 0, FILE_OVERWRITE,
                    0, FILE_OVERWRITTEN);
    });

    dirh.reset();

    test("Create file", [&]() {
        h = create_file(dir + u"\\id2", FILE_READ_ATTRIBUTES | DELETE, 0, 0, FILE_CREATE,
                        0, FILE_CREATED);
    });

    if (h) {
        test("Get file ID", [&]() {
            auto fii = query_information<FILE_INTERNAL_INFORMATION>(h.get());

            file_id = fii.IndexNumber.QuadPart;
        });

        test("Delete file", [&]() {
            set_disposition_information(h.get(), true);
        });

        h.reset();
    }

    test("Open directory", [&]() {
        dirh = create_file(dir, MAXIMUM_ALLOWED, 0,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           FILE_OPEN, FILE_DIRECTORY_FILE, FILE_OPENED);
    });

    test("Try to open invalid ID with FILE_OPEN", [&]() {
        exp_status([&]() {
            open_by_id(dirh.get(), file_id, MAXIMUM_ALLOWED, 0, 0, FILE_OPEN,
                       0, FILE_OPENED);
        }, STATUS_INVALID_PARAMETER);
    });

    test("Try to open invalid ID with FILE_OPEN_IF", [&]() {
        exp_status([&]() {
            open_by_id(dirh.get(), file_id, MAXIMUM_ALLOWED, 0, 0, FILE_OPEN_IF,
                       0, FILE_OPENED);
        }, STATUS_INVALID_PARAMETER);
    });

    test("Try to open invalid ID with FILE_CREATE", [&]() {
        exp_status([&]() {
            open_by_id(dirh.get(), file_id, MAXIMUM_ALLOWED, 0, 0, FILE_CREATE,
                       0, FILE_CREATED);
        }, STATUS_INVALID_PARAMETER);
    });

    test("Try to open invalid ID with FILE_OVERWRITE", [&]() {
        exp_status([&]() {
            open_by_id(dirh.get(), file_id, MAXIMUM_ALLOWED, 0, 0, FILE_OVERWRITE,
                       0, FILE_OVERWRITTEN);
        }, STATUS_INVALID_PARAMETER);
    });

    test("Try to open invalid ID with FILE_OVERWRITE_IF", [&]() {
        exp_status([&]() {
            open_by_id(dirh.get(), file_id, MAXIMUM_ALLOWED, 0, 0, FILE_OVERWRITE_IF,
                       0, FILE_OVERWRITTEN);
        }, STATUS_INVALID_PARAMETER);
    });

    test("Try to open invalid ID with FILE_SUPERSEDE", [&]() {
        exp_status([&]() {
            open_by_id(dirh.get(), file_id, MAXIMUM_ALLOWED, 0, 0, FILE_SUPERSEDE,
                       0, FILE_SUPERSEDED);
        }, STATUS_INVALID_PARAMETER);
    });

    dirh.reset();

    test("Create directory", [&]() {
        h = create_file(dir + u"\\id3", FILE_READ_ATTRIBUTES, 0, 0, FILE_CREATE,
                        FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Get file ID", [&]() {
            auto fii = query_information<FILE_INTERNAL_INFORMATION>(h.get());

            file_id = fii.IndexNumber.QuadPart;
        });

        h.reset();

        test("Open directory", [&]() {
            dirh = create_file(dir, MAXIMUM_ALLOWED, 0,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               FILE_OPEN, FILE_DIRECTORY_FILE, FILE_OPENED);
        });

        test("Try to open subdirectory by ID with FILE_NON_DIRECTORY_FILE", [&]() {
            exp_status([&]() {
                open_by_id(dirh.get(), file_id, MAXIMUM_ALLOWED, 0, 0, FILE_OPEN,
                           FILE_NON_DIRECTORY_FILE, FILE_OPENED);
            }, STATUS_FILE_IS_A_DIRECTORY);
        });

        test("Open subdirectory by ID", [&]() {
            open_by_id(dirh.get(), file_id, MAXIMUM_ALLOWED, 0, 0, FILE_OPEN,
                       0, FILE_OPENED);
        });

        dirh.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\id4", FILE_READ_ATTRIBUTES, 0, 0, FILE_CREATE,
                        0, FILE_CREATED);
    });

    if (h) {
        unique_handle h2;

        test("Open second handle to file", [&]() {
            h2 = create_file(dir + u"\\id4", DELETE, 0, 0, FILE_OPEN,
                             0, FILE_OPENED);
        });

        test("Do POSIX deletion", [&]() {
            set_disposition_information_ex(h2.get(), FILE_DISPOSITION_DELETE | FILE_DISPOSITION_POSIX_SEMANTICS);
        });

        h2.reset();

        test("Get file ID", [&]() {
            auto fii = query_information<FILE_INTERNAL_INFORMATION>(h.get());

            file_id = fii.IndexNumber.QuadPart;
        });

        test("Open directory", [&]() {
            dirh = create_file(dir, MAXIMUM_ALLOWED, 0,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               FILE_OPEN, FILE_DIRECTORY_FILE, FILE_OPENED);
        });

        test("Try to open orphaned inode by file ID", [&]() {
            exp_status([&]() {
                open_by_id(dirh.get(), file_id, MAXIMUM_ALLOWED, 0, 0, FILE_OPEN,
                           0, FILE_OPENED);
            }, STATUS_DELETE_PENDING);
        });

        dirh.reset();

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\id5", FILE_READ_ATTRIBUTES, 0, 0, FILE_CREATE,
                        0, FILE_CREATED);
    });

    if (h) {
        array<uint8_t, 16> obj_id;

        test("Get object ID", [&]() {
            obj_id = create_or_get_object_id(h.get());
        });

        test("Open directory", [&]() {
            dirh = create_file(dir, MAXIMUM_ALLOWED, 0,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               FILE_OPEN, FILE_DIRECTORY_FILE, FILE_OPENED);
        });

        test("Open by object ID", [&]() {
            open_by_id(dirh.get(), obj_id, MAXIMUM_ALLOWED, 0, 0, FILE_OPEN,
                       0, FILE_OPENED);
        });

        dirh.reset();
        h.reset();
    }

    disable_token_privileges(token);

    test("Create file", [&]() {
        h = create_file(dir + u"\\id6", FILE_READ_ATTRIBUTES, 0, 0, FILE_CREATE,
                        0, FILE_CREATED);
    });

    if (h) {
        unique_handle h2;

        test("Get file ID", [&]() {
            auto fii = query_information<FILE_INTERNAL_INFORMATION>(h.get());

            file_id = fii.IndexNumber.QuadPart;
        });

        h.reset();

        test("Open directory", [&]() {
            dirh = create_file(dir, MAXIMUM_ALLOWED, 0,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               FILE_OPEN, FILE_DIRECTORY_FILE, FILE_OPENED);
        });

        test("Open file by ID", [&]() {
            h2 = open_by_id(dirh.get(), file_id, MAXIMUM_ALLOWED, 0, 0, FILE_OPEN,
                            0, FILE_OPENED);
        });

        test("Try to query filename without traverse privilege", [&]() {
            exp_status([&]() {
                query_file_name_information(h2.get());
            }, STATUS_ACCESS_DENIED);
        });

        dirh.reset();
    }
}
