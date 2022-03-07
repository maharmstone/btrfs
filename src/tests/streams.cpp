#include "test.h"

using namespace std;

#ifdef _MSC_VER
typedef struct _FILE_STREAM_INFORMATION {
    ULONG NextEntryOffset;
    ULONG StreamNameLength;
    LARGE_INTEGER StreamSize;
    LARGE_INTEGER StreamAllocationSize;
    WCHAR StreamName[1];
} FILE_STREAM_INFORMATION, *PFILE_STREAM_INFORMATION;
#endif

static vector<varbuf<FILE_STREAM_INFORMATION>> query_streams(HANDLE h) {
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    vector<uint8_t> buf(4096);
    vector<varbuf<FILE_STREAM_INFORMATION>> ret;

    while (true) {
        Status = NtQueryInformationFile(h, &iosb, buf.data(), buf.size(), FileStreamInformation);

        if (Status == STATUS_BUFFER_OVERFLOW) {
            buf.resize(buf.size() + 4096);
            continue;
        }

        if (Status != STATUS_SUCCESS)
            throw ntstatus_error(Status);

        break;
    }

    auto ptr = (FILE_STREAM_INFORMATION*)buf.data();

    do {
        varbuf<FILE_STREAM_INFORMATION> item;

        item.buf.resize(offsetof(FILE_STREAM_INFORMATION, StreamName) + ptr->StreamNameLength);

        memcpy(item.buf.data(), ptr, item.buf.size());

        ret.emplace_back(item);

        if (ptr->NextEntryOffset == 0)
            break;

        ptr = (FILE_STREAM_INFORMATION*)((uint8_t*)ptr + ptr->NextEntryOffset);
    } while (true);

    return ret;
}

void test_streams(const u16string& dir) {
    unique_handle h;
    int64_t fileid;

    test("Create file", [&]() {
        h = create_file(dir + u"\\stream1", FILE_READ_ATTRIBUTES, 0, 0, FILE_CREATE,
                        FILE_NON_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Get file ID", [&]() {
            auto fii = query_information<FILE_INTERNAL_INFORMATION>(h.get());

            fileid = fii.IndexNumber.QuadPart;
        });

        test("Query streams", [&]() {
            auto items = query_streams(h.get());

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1", items.size());

            auto& fsi = *static_cast<FILE_STREAM_INFORMATION*>(items.front());

            if (fsi.StreamSize.QuadPart != 0)
                throw formatted_error("StreamSize was {}, expected 0", fsi.StreamSize.QuadPart);

            if (fsi.StreamAllocationSize.QuadPart != 0)
                throw formatted_error("StreamAllocationSize was {}, expected 0", fsi.StreamAllocationSize.QuadPart);

            auto name = u16string_view((char16_t*)fsi.StreamName, fsi.StreamNameLength / sizeof(char16_t));

            if (name != u"::$DATA")
                throw formatted_error("StreamName was {}, expected ::$DATA", u16string_to_string(name));
        });

        test("Check FILE_STANDARD_INFORMATION_EX", [&]() {
            auto fsix = query_information<FILE_STANDARD_INFORMATION_EX>(h.get());

            if (fsix.AlternateStream)
                throw runtime_error("AlternateStream was true, expected false");
        });

        h.reset();
    }

    test("Create stream", [&]() {
        h = create_file(dir + u"\\stream1:stream", FILE_READ_ATTRIBUTES, 0, 0, FILE_CREATE,
                        FILE_NON_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Get file ID", [&]() {
            auto fii = query_information<FILE_INTERNAL_INFORMATION>(h.get());

            if (fii.IndexNumber.QuadPart != fileid)
                throw runtime_error("File IDs did not match.");
        });

        test("Check FILE_STANDARD_INFORMATION_EX", [&]() {
            auto fsix = query_information<FILE_STANDARD_INFORMATION_EX>(h.get());

            if (!fsix.AlternateStream)
                throw runtime_error("AlternateStream was false, expected true");
        });

        h.reset();
    }

    test("Open file", [&]() {
        h = create_file(dir + u"\\stream1", FILE_READ_ATTRIBUTES, 0, 0, FILE_OPEN,
                        FILE_NON_DIRECTORY_FILE, FILE_OPENED);
    });

    if (h) {
        test("Query streams", [&]() {
            auto items = query_streams(h.get());

            if (items.size() != 2)
                throw formatted_error("{} entries returned, expected 2", items.size());

            auto& fsi1 = *static_cast<FILE_STREAM_INFORMATION*>(items[0]);

            if (fsi1.StreamSize.QuadPart != 0)
                throw formatted_error("StreamSize was {}, expected 0", fsi1.StreamSize.QuadPart);

            if (fsi1.StreamAllocationSize.QuadPart != 0)
                throw formatted_error("StreamAllocationSize was {}, expected 0", fsi1.StreamAllocationSize.QuadPart);

            auto name1 = u16string_view((char16_t*)fsi1.StreamName, fsi1.StreamNameLength / sizeof(char16_t));

            if (name1 != u"::$DATA")
                throw formatted_error("StreamName was {}, expected ::$DATA", u16string_to_string(name1));

            auto& fsi2 = *static_cast<FILE_STREAM_INFORMATION*>(items[1]);

            if (fsi2.StreamSize.QuadPart != 0)
                throw formatted_error("StreamSize was {}, expected 0", fsi2.StreamSize.QuadPart);

            if (fsi2.StreamAllocationSize.QuadPart != 0)
                throw formatted_error("StreamAllocationSize was {}, expected 0", fsi2.StreamAllocationSize.QuadPart);

            auto name2 = u16string_view((char16_t*)fsi2.StreamName, fsi2.StreamNameLength / sizeof(char16_t));

            if (name2 != u":stream:$DATA")
                throw formatted_error("StreamName was {}, expected :stream:$DATA", u16string_to_string(name2));
        });

        h.reset();
    }

    test("Create stream on non-existent file", [&]() {
        h = create_file(dir + u"\\stream2:stream", FILE_READ_ATTRIBUTES, 0, 0, FILE_CREATE,
                        FILE_NON_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Query streams", [&]() {
            auto items = query_streams(h.get());

            if (items.size() != 2)
                throw formatted_error("{} entries returned, expected 2", items.size());

            auto& fsi1 = *static_cast<FILE_STREAM_INFORMATION*>(items[0]);

            if (fsi1.StreamSize.QuadPart != 0)
                throw formatted_error("StreamSize was {}, expected 0", fsi1.StreamSize.QuadPart);

            if (fsi1.StreamAllocationSize.QuadPart != 0)
                throw formatted_error("StreamAllocationSize was {}, expected 0", fsi1.StreamAllocationSize.QuadPart);

            auto name1 = u16string_view((char16_t*)fsi1.StreamName, fsi1.StreamNameLength / sizeof(char16_t));

            if (name1 != u"::$DATA")
                throw formatted_error("StreamName was {}, expected ::$DATA", u16string_to_string(name1));

            auto& fsi2 = *static_cast<FILE_STREAM_INFORMATION*>(items[1]);

            if (fsi2.StreamSize.QuadPart != 0)
                throw formatted_error("StreamSize was {}, expected 0", fsi2.StreamSize.QuadPart);

            if (fsi2.StreamAllocationSize.QuadPart != 0)
                throw formatted_error("StreamAllocationSize was {}, expected 0", fsi2.StreamAllocationSize.QuadPart);

            auto name2 = u16string_view((char16_t*)fsi2.StreamName, fsi2.StreamNameLength / sizeof(char16_t));

            if (name2 != u":stream:$DATA")
                throw formatted_error("StreamName was {}, expected :stream:$DATA", u16string_to_string(name2));
        });

        h.reset();
    }

    test("Check file created for stream", [&]() {
        create_file(dir + u"\\stream2", FILE_READ_ATTRIBUTES, 0, 0, FILE_OPEN,
                    FILE_NON_DIRECTORY_FILE, FILE_OPENED);
    });

    test("Try to create stream with FILE_DIRECTORY_FILE", [&]() {
        exp_status([&]() {
            create_file(dir + u"\\stream2:stream", FILE_READ_ATTRIBUTES, 0, 0, FILE_CREATE,
                        FILE_DIRECTORY_FILE, FILE_CREATED);
        }, STATUS_NOT_A_DIRECTORY);
    });

    test("Create directory", [&]() {
        h = create_file(dir + u"\\stream3", FILE_READ_ATTRIBUTES, 0, 0, FILE_CREATE,
                        FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Query streams", [&]() {
            auto items = query_streams(h.get());

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1", items.size());

            auto& fsi = *static_cast<FILE_STREAM_INFORMATION*>(items.front());

            if (fsi.StreamSize.QuadPart != 0)
                throw formatted_error("StreamSize was {}, expected 0", fsi.StreamSize.QuadPart);

            if (fsi.StreamAllocationSize.QuadPart != 0)
                throw formatted_error("StreamAllocationSize was {}, expected 0", fsi.StreamAllocationSize.QuadPart);

            auto name = u16string_view((char16_t*)fsi.StreamName, fsi.StreamNameLength / sizeof(char16_t));

            if (name != u"")
                throw formatted_error("StreamName was {}, expected empty string", u16string_to_string(name));
        });

        test("Check FILE_STANDARD_INFORMATION_EX", [&]() {
            auto fsix = query_information<FILE_STANDARD_INFORMATION_EX>(h.get());

            if (fsix.AlternateStream)
                throw runtime_error("AlternateStream was true, expected false");
        });

        h.reset();
    }

    test("Try to create stream with FILE_DIRECTORY_FILE", [&]() {
        exp_status([&]() {
            create_file(dir + u"\\stream3:stream", FILE_READ_ATTRIBUTES, 0, 0, FILE_CREATE,
                        FILE_DIRECTORY_FILE, FILE_CREATED);
        }, STATUS_NOT_A_DIRECTORY);
    });

    test("Create stream on directory", [&]() {
        h = create_file(dir + u"\\stream3:stream", FILE_READ_ATTRIBUTES, 0, 0, FILE_CREATE,
                        FILE_NON_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Query streams", [&]() {
            auto items = query_streams(h.get());

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1", items.size());

            auto& fsi = *static_cast<FILE_STREAM_INFORMATION*>(items.front());

            if (fsi.StreamSize.QuadPart != 0)
                throw formatted_error("StreamSize was {}, expected 0", fsi.StreamSize.QuadPart);

            if (fsi.StreamAllocationSize.QuadPart != 0)
                throw formatted_error("StreamAllocationSize was {}, expected 0", fsi.StreamAllocationSize.QuadPart);

            auto name = u16string_view((char16_t*)fsi.StreamName, fsi.StreamNameLength / sizeof(char16_t));

            if (name != u":stream:$DATA")
                throw formatted_error("StreamName was {}, expected :stream:$DATA", u16string_to_string(name));
        });

        test("Check FILE_STANDARD_INFORMATION_EX", [&]() {
            auto fsix = query_information<FILE_STANDARD_INFORMATION_EX>(h.get());

            if (!fsix.AlternateStream)
                throw runtime_error("AlternateStream was false, expected true");
        });

        h.reset();
    }

    test("Try to create ::$DATA stream on directory", [&]() {
        exp_status([&]() {
            create_file(dir + u"\\stream3::$DATA", FILE_READ_ATTRIBUTES, 0, 0, FILE_CREATE,
                        0, FILE_CREATED);
        }, STATUS_FILE_IS_A_DIRECTORY);
    });

    test("Create stream", [&]() {
        h = create_file(dir + u"\\stream4:stream", SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA, 0, 0, FILE_CREATE,
                        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATED);
    });

    if (h) {
        static const string_view data = "hello";

        test("Write to stream", [&]() {
            write_file(h.get(), span((uint8_t*)data.data(), data.size()));
        });

        test("Read from stream", [&]() {
            auto buf = read_file(h.get(), data.size(), 0);

            if (buf.size() != data.size() || memcmp(buf.data(), data.data(), data.size()))
                throw runtime_error("Data read did not match data written");
        });

        test("Query streams", [&]() {
            auto items = query_streams(h.get());

            if (items.size() != 2)
                throw formatted_error("{} entries returned, expected 2", items.size());

            auto& fsi1 = *static_cast<FILE_STREAM_INFORMATION*>(items[0]);

            if (fsi1.StreamSize.QuadPart != 0)
                throw formatted_error("StreamSize was {}, expected 0", fsi1.StreamSize.QuadPart);

            if (fsi1.StreamAllocationSize.QuadPart != 0)
                throw formatted_error("StreamAllocationSize was {}, expected 0", fsi1.StreamAllocationSize.QuadPart);

            auto name1 = u16string_view((char16_t*)fsi1.StreamName, fsi1.StreamNameLength / sizeof(char16_t));

            if (name1 != u"::$DATA")
                throw formatted_error("StreamName was {}, expected ::$DATA", u16string_to_string(name1));

            auto& fsi2 = *static_cast<FILE_STREAM_INFORMATION*>(items[1]);

            if ((size_t)fsi2.StreamSize.QuadPart != data.size())
                throw formatted_error("StreamSize was {}, expected {}", fsi2.StreamSize.QuadPart, data.size());

            if (fsi2.StreamAllocationSize.QuadPart < fsi2.StreamSize.QuadPart) {
                throw formatted_error("StreamAllocationSize was less than StreamSize ({} < {})",
                                      fsi2.StreamAllocationSize.QuadPart,
                                      fsi2.StreamSize.QuadPart);
            }

            auto name2 = u16string_view((char16_t*)fsi2.StreamName, fsi2.StreamNameLength / sizeof(char16_t));

            if (name2 != u":stream:$DATA")
                throw formatted_error("StreamName was {}, expected :stream:$DATA", u16string_to_string(name2));
        });

        test("Set zero data", [&]() {
            set_zero_data(h.get(), 2, 4);
        });

        test("Read from stream", [&]() {
            static const string_view exp("he\0\0o", 5);

            auto buf = read_file(h.get(), data.size(), 0);

            if (buf.size() != exp.size() || memcmp(buf.data(), exp.data(), exp.size()))
                throw runtime_error("Data read was not as expected");
        });

        test("Query streams", [&]() {
            auto items = query_streams(h.get());

            if (items.size() != 2)
                throw formatted_error("{} entries returned, expected 2", items.size());

            auto& fsi1 = *static_cast<FILE_STREAM_INFORMATION*>(items[0]);

            if (fsi1.StreamSize.QuadPart != 0)
                throw formatted_error("StreamSize was {}, expected 0", fsi1.StreamSize.QuadPart);

            if (fsi1.StreamAllocationSize.QuadPart != 0)
                throw formatted_error("StreamAllocationSize was {}, expected 0", fsi1.StreamAllocationSize.QuadPart);

            auto name1 = u16string_view((char16_t*)fsi1.StreamName, fsi1.StreamNameLength / sizeof(char16_t));

            if (name1 != u"::$DATA")
                throw formatted_error("StreamName was {}, expected ::$DATA", u16string_to_string(name1));

            auto& fsi2 = *static_cast<FILE_STREAM_INFORMATION*>(items[1]);

            if ((size_t)fsi2.StreamSize.QuadPart != data.size())
                throw formatted_error("StreamSize was {}, expected {}", fsi2.StreamSize.QuadPart, data.size());

            if (fsi2.StreamAllocationSize.QuadPart < fsi2.StreamSize.QuadPart) {
                throw formatted_error("StreamAllocationSize was less than StreamSize ({} < {})",
                                      fsi2.StreamAllocationSize.QuadPart,
                                      fsi2.StreamSize.QuadPart);
            }

            auto name2 = u16string_view((char16_t*)fsi2.StreamName, fsi2.StreamNameLength / sizeof(char16_t));

            if (name2 != u":stream:$DATA")
                throw formatted_error("StreamName was {}, expected :stream:$DATA", u16string_to_string(name2));
        });

        test("Truncate stream", [&]() {
            set_end_of_file(h.get(), 3);
        });

        test("Read from stream", [&]() {
            static const string_view exp("he\0", 3);

            auto buf = read_file(h.get(), data.size(), 0);

            if (buf.size() != exp.size() || memcmp(buf.data(), exp.data(), exp.size()))
                throw runtime_error("Data read was not as expected");
        });

        test("Query streams", [&]() {
            auto items = query_streams(h.get());

            if (items.size() != 2)
                throw formatted_error("{} entries returned, expected 2", items.size());

            auto& fsi1 = *static_cast<FILE_STREAM_INFORMATION*>(items[0]);

            if (fsi1.StreamSize.QuadPart != 0)
                throw formatted_error("StreamSize was {}, expected 0", fsi1.StreamSize.QuadPart);

            if (fsi1.StreamAllocationSize.QuadPart != 0)
                throw formatted_error("StreamAllocationSize was {}, expected 0", fsi1.StreamAllocationSize.QuadPart);

            auto name1 = u16string_view((char16_t*)fsi1.StreamName, fsi1.StreamNameLength / sizeof(char16_t));

            if (name1 != u"::$DATA")
                throw formatted_error("StreamName was {}, expected ::$DATA", u16string_to_string(name1));

            auto& fsi2 = *static_cast<FILE_STREAM_INFORMATION*>(items[1]);

            if (fsi2.StreamSize.QuadPart != 3)
                throw formatted_error("StreamSize was {}, expected 3", fsi2.StreamSize.QuadPart);

            if (fsi2.StreamAllocationSize.QuadPart < fsi2.StreamSize.QuadPart) {
                throw formatted_error("StreamAllocationSize was less than StreamSize ({} < {})",
                                      fsi2.StreamAllocationSize.QuadPart,
                                      fsi2.StreamSize.QuadPart);
            }

            auto name2 = u16string_view((char16_t*)fsi2.StreamName, fsi2.StreamNameLength / sizeof(char16_t));

            if (name2 != u":stream:$DATA")
                throw formatted_error("StreamName was {}, expected :stream:$DATA", u16string_to_string(name2));
        });

        h.reset();
    }

    test("Create stream", [&]() {
        create_file(dir + u"\\stream5:stream", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE,
                    FILE_NON_DIRECTORY_FILE, FILE_CREATED);
    });

    test("Open stream (FILE_OPEN)", [&]() {
        create_file(dir + u"\\stream5:stream", MAXIMUM_ALLOWED, 0, 0, FILE_OPEN,
                    FILE_NON_DIRECTORY_FILE, FILE_OPENED);
    });

    test("Open stream (FILE_OPEN_IF)", [&]() {
        create_file(dir + u"\\stream5:stream", MAXIMUM_ALLOWED, 0, 0, FILE_OPEN_IF,
                    FILE_NON_DIRECTORY_FILE, FILE_OPENED);
    });

    test("Overwrite stream (FILE_OVERWRITE)", [&]() {
        create_file(dir + u"\\stream5:stream", MAXIMUM_ALLOWED, 0, 0, FILE_OVERWRITE,
                    FILE_NON_DIRECTORY_FILE, FILE_OVERWRITTEN);
    });

    test("Overwrite stream (FILE_OVERWRITE_IF)", [&]() {
        create_file(dir + u"\\stream5:stream", MAXIMUM_ALLOWED, 0, 0, FILE_OVERWRITE_IF,
                    FILE_NON_DIRECTORY_FILE, FILE_OVERWRITTEN);
    });

    test("Supersede stream", [&]() {
        create_file(dir + u"\\stream5:stream", MAXIMUM_ALLOWED, 0, 0, FILE_SUPERSEDE,
                    FILE_NON_DIRECTORY_FILE, FILE_SUPERSEDED);
    });

    test("Create stream", [&]() {
        h = create_file(dir + u"\\stream6:stream", DELETE, 0, 0, FILE_CREATE,
                        FILE_NON_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Delete stream", [&]() {
            set_disposition_information(h.get(), true);
        });

        h.reset();

        test("Check directory entry for file", [&]() {
            u16string_view name = u"stream6";

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

    test("Create stream", [&]() {
        create_file(dir + u"\\stream7:stream", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE,
                    FILE_NON_DIRECTORY_FILE, FILE_CREATED);
    });

    test("Open file", [&]() {
        h = create_file(dir + u"\\stream7", DELETE, 0, 0, FILE_OPEN,
                        FILE_NON_DIRECTORY_FILE, FILE_OPENED);
    });

    if (h) {
        test("Delete file", [&]() {
            set_disposition_information(h.get(), true);
        });

        h.reset();

        test("Check directory entry for file gone", [&]() {
            exp_status([&]() {
                u16string_view name = u"stream7";

                query_dir<FILE_DIRECTORY_INFORMATION>(dir, name);
            }, STATUS_NO_SUCH_FILE);
        });
    }

    test("Create stream", [&]() {
        h = create_file(dir + u"\\stream8:stream", FILE_WRITE_DATA | DELETE, 0, 0, FILE_CREATE,
                        FILE_NON_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Write to stream", [&]() {
            static const string_view data = "hello";

            write_file_wait(h.get(), span((uint8_t*)data.data(), data.size()), 0);
        });

        test("Check FILE_STANDARD_INFORMATION_EX", [&]() {
            auto fsix = query_information<FILE_STANDARD_INFORMATION_EX>(h.get());

            if (!fsix.AlternateStream)
                throw runtime_error("AlternateStream was false, expected true");
        });

        test("Try to rename stream using full path", [&]() {
            exp_status([&]() {
                set_rename_information(h.get(), false, nullptr, dir + u"\\stream8:stream2");
            }, STATUS_INVALID_PARAMETER);
        });

        test("Rename stream", [&]() {
            set_rename_information(h.get(), false, nullptr, u":stream2");
        });

        test("Check FILE_STANDARD_INFORMATION_EX", [&]() {
            auto fsix = query_information<FILE_STANDARD_INFORMATION_EX>(h.get());

            if (!fsix.AlternateStream)
                throw runtime_error("AlternateStream was false, expected true");
        });

        h.reset();
    }

    test("Open stream", [&]() {
        h = create_file(dir + u"\\stream8:stream2", FILE_READ_DATA, 0, 0, FILE_OPEN,
                        FILE_NON_DIRECTORY_FILE, FILE_OPENED);
    });

    if (h) {
        static const string_view data = "hello";

        test("Read from stream", [&]() {
            auto buf = read_file_wait(h.get(), data.size(), 0);

            if (buf.size() != data.size() || memcmp(buf.data(), data.data(), data.size()))
                throw runtime_error("Data read did not match data written");
        });

        test("Query streams", [&]() {
            auto items = query_streams(h.get());

            if (items.size() != 2)
                throw formatted_error("{} entries returned, expected 2", items.size());

            auto& fsi1 = *static_cast<FILE_STREAM_INFORMATION*>(items[0]);

            if (fsi1.StreamSize.QuadPart != 0)
                throw formatted_error("StreamSize was {}, expected 0", fsi1.StreamSize.QuadPart);

            if (fsi1.StreamAllocationSize.QuadPart != 0)
                throw formatted_error("StreamAllocationSize was {}, expected 0", fsi1.StreamAllocationSize.QuadPart);

            auto name1 = u16string_view((char16_t*)fsi1.StreamName, fsi1.StreamNameLength / sizeof(char16_t));

            if (name1 != u"::$DATA")
                throw formatted_error("StreamName was {}, expected ::$DATA", u16string_to_string(name1));

            auto& fsi2 = *static_cast<FILE_STREAM_INFORMATION*>(items[1]);

            if ((size_t)fsi2.StreamSize.QuadPart != data.size())
                throw formatted_error("StreamSize was {}, expected {}", fsi2.StreamSize.QuadPart, data.size());

            if (fsi2.StreamAllocationSize.QuadPart < fsi2.StreamSize.QuadPart) {
                throw formatted_error("StreamAllocationSize was less than StreamSize ({} < {})",
                                      fsi2.StreamAllocationSize.QuadPart,
                                      fsi2.StreamSize.QuadPart);
            }

            auto name2 = u16string_view((char16_t*)fsi2.StreamName, fsi2.StreamNameLength / sizeof(char16_t));

            if (name2 != u":stream2:$DATA")
                throw formatted_error("StreamName was {}, expected :stream2:$DATA", u16string_to_string(name2));
        });

        h.reset();
    }

    test("Create stream", [&]() {
        h = create_file(dir + u"\\stream9:stream", FILE_WRITE_DATA | DELETE, 0, 0, FILE_CREATE,
                        FILE_NON_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        static const string_view data = "hello";

        test("Write to stream", [&]() {
            write_file_wait(h.get(), span((uint8_t*)data.data(), data.size()), 0);
        });

        test("Check FILE_STANDARD_INFORMATION_EX", [&]() {
            auto fsix = query_information<FILE_STANDARD_INFORMATION_EX>(h.get());

            if (!fsix.AlternateStream)
                throw runtime_error("AlternateStream was false, expected true");
        });

        test("Rename stream to ::$DATA without ReplaceIfExists", [&]() {
            exp_status([&]() {
                set_rename_information(h.get(), false, nullptr, u"::$DATA");
            }, STATUS_OBJECT_NAME_COLLISION);
        });

        test("Rename stream to ::$DATA with ReplaceIfExists", [&]() {
            set_rename_information(h.get(), true, nullptr, u"::$DATA");
        });

        test("Check FILE_STANDARD_INFORMATION_EX", [&]() {
            auto fsix = query_information<FILE_STANDARD_INFORMATION_EX>(h.get());

            if (fsix.AlternateStream)
                throw runtime_error("AlternateStream was true, expected false");
        });

        test("Query streams", [&]() {
            auto items = query_streams(h.get());

            if (items.size() != 1)
                throw formatted_error("{} entries returned, expected 1", items.size());

            auto& fsi = *static_cast<FILE_STREAM_INFORMATION*>(items.front());

            if ((size_t)fsi.StreamSize.QuadPart != data.size())
                throw formatted_error("StreamSize was {}, expected {}", fsi.StreamSize.QuadPart, data.size());

            if (fsi.StreamAllocationSize.QuadPart < fsi.StreamSize.QuadPart) {
                throw formatted_error("StreamAllocationSize was less than StreamSize ({} < {})",
                                      fsi.StreamAllocationSize.QuadPart,
                                      fsi.StreamSize.QuadPart);
            }

            auto name = u16string_view((char16_t*)fsi.StreamName, fsi.StreamNameLength / sizeof(char16_t));

            if (name != u"::$DATA")
                throw formatted_error("StreamName was {}, expected ::$DATA", u16string_to_string(name));
        });

        h.reset();
    }

    test("Open file", [&]() {
        h = create_file(dir + u"\\stream9", FILE_READ_DATA, 0, 0, FILE_OPEN,
                        FILE_NON_DIRECTORY_FILE, FILE_OPENED);
    });

    if (h) {
        test("Read from file", [&]() {
            static const string_view data = "hello";

            auto buf = read_file_wait(h.get(), data.size(), 0);

            if (buf.size() != data.size() || memcmp(buf.data(), data.data(), data.size()))
                throw runtime_error("Data read did not match data written");
        });

        h.reset();
    }

    test("Create directory", [&]() {
        create_file(dir + u"\\stream10", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE,
                    FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    test("Create stream", [&]() {
        h = create_file(dir + u"\\stream10:stream", FILE_WRITE_DATA | DELETE, 0, 0, FILE_CREATE,
                        FILE_NON_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Try to rename stream on directory to ::$DATA", [&]() {
            exp_status([&]() {
                set_rename_information(h.get(), true, nullptr, u"::$DATA");
            }, STATUS_INVALID_PARAMETER);
        });

        h.reset();
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\stream11", FILE_WRITE_DATA | DELETE, 0, 0, FILE_CREATE,
                        FILE_NON_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        static const string_view data = "hello";

        test("Write to file", [&]() {
            write_file_wait(h.get(), span((uint8_t*)data.data(), data.size()), 0);
        });

        test("Check FILE_STANDARD_INFORMATION_EX", [&]() {
            auto fsix = query_information<FILE_STANDARD_INFORMATION_EX>(h.get());

            if (fsix.AlternateStream)
                throw runtime_error("AlternateStream was true, expected false");
        });

        test("Rename file to :stream", [&]() {
            set_rename_information(h.get(), false, nullptr, u":stream");
        });

        test("Query streams", [&]() {
            auto items = query_streams(h.get());

            if (items.size() != 2)
                throw formatted_error("{} entries returned, expected 2", items.size());

            auto& fsi1 = *static_cast<FILE_STREAM_INFORMATION*>(items[0]);

            if (fsi1.StreamSize.QuadPart != 0)
                throw formatted_error("StreamSize was {}, expected 0", fsi1.StreamSize.QuadPart);

            if (fsi1.StreamAllocationSize.QuadPart != 0)
                throw formatted_error("StreamAllocationSize was {}, expected 0", fsi1.StreamAllocationSize.QuadPart);

            auto name1 = u16string_view((char16_t*)fsi1.StreamName, fsi1.StreamNameLength / sizeof(char16_t));

            if (name1 != u"::$DATA")
                throw formatted_error("StreamName was {}, expected ::$DATA", u16string_to_string(name1));

            auto& fsi2 = *static_cast<FILE_STREAM_INFORMATION*>(items[1]);

            if ((size_t)fsi2.StreamSize.QuadPart != data.size())
                throw formatted_error("StreamSize was {}, expected {}", fsi2.StreamSize.QuadPart, data.size());

            if (fsi2.StreamAllocationSize.QuadPart < fsi2.StreamSize.QuadPart) {
                throw formatted_error("StreamAllocationSize was less than StreamSize ({} < {})",
                                      fsi2.StreamAllocationSize.QuadPart,
                                      fsi2.StreamSize.QuadPart);
            }

            auto name2 = u16string_view((char16_t*)fsi2.StreamName, fsi2.StreamNameLength / sizeof(char16_t));

            if (name2 != u":stream:$DATA")
                throw formatted_error("StreamName was {}, expected :stream:$DATA", u16string_to_string(name2));
        });

        test("Check FILE_STANDARD_INFORMATION_EX", [&]() {
            auto fsix = query_information<FILE_STANDARD_INFORMATION_EX>(h.get());

            if (!fsix.AlternateStream)
                throw runtime_error("AlternateStream was false, expected true");
        });

        h.reset();
    }

    test("Open stream", [&]() {
        h = create_file(dir + u"\\stream11:stream", FILE_READ_DATA, 0, 0, FILE_OPEN,
                        FILE_NON_DIRECTORY_FILE, FILE_OPENED);
    });

    if (h) {
        test("Read from file", [&]() {
            static const string_view data = "hello";

            auto buf = read_file_wait(h.get(), data.size(), 0);

            if (buf.size() != data.size() || memcmp(buf.data(), data.data(), data.size()))
                throw runtime_error("Data read did not match data written");
        });

        h.reset();
    }

    test("Create directory", [&]() {
        h = create_file(dir + u"\\stream12", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE,
                        FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Try to rename directory to :stream", [&]() {
            exp_status([&]() {
                set_rename_information(h.get(), true, nullptr, u":stream");
            }, STATUS_INVALID_PARAMETER);
        });

        h.reset();
    }

    test("Create file", [&]() {
        create_file(dir + u"\\stream13", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE,
                    FILE_NON_DIRECTORY_FILE, FILE_CREATED);
    });

    test("Open file with ::$DATA suffix", [&]() {
        create_file(dir + u"\\stream13::$DATA", MAXIMUM_ALLOWED, 0, 0, FILE_OPEN,
                    FILE_NON_DIRECTORY_FILE, FILE_OPENED);
    });

    test("Open file with ::$data suffix", [&]() {
        create_file(dir + u"\\stream13::$data", MAXIMUM_ALLOWED, 0, 0, FILE_OPEN,
                    FILE_NON_DIRECTORY_FILE, FILE_OPENED);
    });

    test("Create stream", [&]() {
        create_file(dir + u"\\stream13:stream", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE,
                    FILE_NON_DIRECTORY_FILE, FILE_CREATED);
    });

    test("Open stream with ::$DATA suffix", [&]() {
        create_file(dir + u"\\stream13:stream:$DATA", MAXIMUM_ALLOWED, 0, 0, FILE_OPEN,
                    FILE_NON_DIRECTORY_FILE, FILE_OPENED);
    });

    test("Open stream with ::$data suffix", [&]() {
        create_file(dir + u"\\stream13:stream:$data", MAXIMUM_ALLOWED, 0, 0, FILE_OPEN,
                    FILE_NON_DIRECTORY_FILE, FILE_OPENED);
    });

    test("Create file", [&]() {
        create_file(dir + u"\\stream14", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE,
                    FILE_NON_DIRECTORY_FILE, FILE_CREATED);
    });

    test("Create stream with long name", [&]() {
        u16string longname(256, u'x');

        exp_status([&]() {
            create_file(dir + u"\\stream14:" + longname, MAXIMUM_ALLOWED, 0, 0,
                        FILE_CREATE, 0, FILE_CREATED);
        }, STATUS_OBJECT_NAME_INVALID);
    });

    test("Create stream with emoji", [&]() {
        create_file(dir + u"\\stream14:\U0001f525", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
    });

    bool is_ntfs = fstype == fs_type::ntfs;

    test("Create stream with more than 255 UTF-8 characters", [&]() {
        auto fn = dir + u"\\stream14:";

        for (unsigned int i = 0; i < 64; i++) {
            fn += u"\U0001f525";
        }

        exp_status([&]() {
            create_file(fn, MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
        }, is_ntfs ? STATUS_SUCCESS : STATUS_OBJECT_NAME_INVALID);
    });

    test("Create stream with WTF-16 (1)", [&]() {
        auto fn = dir + u"\\stream14:";

        fn += (char16_t)0xd83d;

        exp_status([&]() {
            create_file(fn, MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
        }, is_ntfs ? STATUS_SUCCESS : STATUS_OBJECT_NAME_INVALID);
    });

    test("Create stream with WTF-16 (2)", [&]() {
        auto fn = dir + u"\\stream14:";

        fn += (char16_t)0xdd25;

        exp_status([&]() {
            create_file(fn, MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
        }, is_ntfs ? STATUS_SUCCESS : STATUS_OBJECT_NAME_INVALID);
    });

    test("Create stream with WTF-16 (3)", [&]() {
        auto fn = dir + u"\\stream14:";

        fn += (char16_t)0xdd25;
        fn += (char16_t)0xd83d;

        exp_status([&]() {
            create_file(fn, MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
        }, is_ntfs ? STATUS_SUCCESS : STATUS_OBJECT_NAME_INVALID);
    });

    struct {
        u16string name;
        string desc;
        bool valid;
    } unusual_names[] = {
        { u"/", "slash", false },
        { u":", "colon", false },
        { u"<", "less than", true },
        { u">", "greater than", true },
        { u"\"", "quote", true },
        { u"|", "pipe", true },
        { u"?", "question mark", true },
        { u"*", "asterisk", true }
    };

    for (const auto& n : unusual_names) {
        test("Create stream with unusual name (" + n.desc + ")", [&]() {
            auto fn = dir + u"\\stream14:" + n.name;

            exp_status([&]() {
                create_file(fn, MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
            }, n.valid ? STATUS_SUCCESS : STATUS_OBJECT_NAME_INVALID);
        });
    }

    struct {
        u16string name;
        string desc;
    } btrfs_reserved[] = {
        { u"DOSATTRIB", "DOSATTRIB" },
        { u"reparse", "reparse" },
        { u"EA", "EA" },
        { u"casesensitive", "casesensitive" }
    };

    for (const auto& n : btrfs_reserved) {
        test("Create stream with reserved name (" + n.desc + ")", [&]() {
            auto fn = dir + u"\\stream14:" + n.name;

            exp_status([&]() {
                create_file(fn, MAXIMUM_ALLOWED, 0, 0, FILE_CREATE, 0, FILE_CREATED);
            }, is_ntfs ? STATUS_SUCCESS : STATUS_OBJECT_NAME_INVALID);
        });
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\stream15", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE,
                        FILE_NON_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Rename to stream with long name", [&]() {
            u16string longname(256, u'x');

            exp_status([&]() {
                set_rename_information(h.get(), false, nullptr, u":" + longname);
            }, STATUS_INVALID_PARAMETER);
        });

        test("Rename to stream with emoji", [&]() {
            set_rename_information(h.get(), false, nullptr, u":\U0001f525");
        });

        test("Rename to stream with more than 255 UTF-8 characters", [&]() {
            u16string fn = u":";

            for (unsigned int i = 0; i < 64; i++) {
                fn += u"\U0001f525";
            }

            exp_status([&]() {
                set_rename_information(h.get(), false, nullptr, fn);
            }, is_ntfs ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER);
        });

        test("Rename to stream with WTF-16 (1)", [&]() {
            u16string fn = u":";

            fn += (char16_t)0xd83d;

            exp_status([&]() {
                set_rename_information(h.get(), false, nullptr, fn);
            }, is_ntfs ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER);
        });

        test("Rename to stream with WTF-16 (2)", [&]() {
            u16string fn = u":";

            fn += (char16_t)0xdd25;

            exp_status([&]() {
                set_rename_information(h.get(), false, nullptr, fn);
            }, is_ntfs ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER);
        });

        test("Rename to stream with WTF-16 (3)", [&]() {
            u16string fn = u":";

            fn += (char16_t)0xdd25;
            fn += (char16_t)0xd83d;

            exp_status([&]() {
                set_rename_information(h.get(), false, nullptr, fn);
            }, is_ntfs ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER);
        });

        for (const auto& n : unusual_names) {
            test("Rename to stream with unusual name (" + n.desc + ")", [&]() {
                auto fn = u":" + n.name;

                exp_status([&]() {
                    set_rename_information(h.get(), false, nullptr, fn);
                }, n.valid ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER);
            });
        }

        for (const auto& n : btrfs_reserved) {
            test("Rename to stream with reserved name (" + n.desc + ")", [&]() {
                auto fn = u":" + n.name;

                exp_status([&]() {
                    set_rename_information(h.get(), false, nullptr, fn);
                }, is_ntfs ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER);
            });
        }

        h.reset();
    }

    test("Create stream", [&]() {
        create_file(dir + u"\\stream16:stream", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE,
                    FILE_NON_DIRECTORY_FILE, FILE_CREATED);
    });

    test("Open stream using wrong case", [&]() {
        create_file(dir + u"\\STREAM16:STREAM", MAXIMUM_ALLOWED, 0, 0, FILE_OPEN,
                    FILE_NON_DIRECTORY_FILE, FILE_OPENED);
    });
}
