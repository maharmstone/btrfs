#include "test.h"

using namespace std;

void set_basic_information(HANDLE h, int64_t creation_time, int64_t last_access_time,
                           int64_t last_write_time, int64_t change_time, uint32_t attributes) {
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;
    FILE_BASIC_INFORMATION fbi;

    fbi.CreationTime.QuadPart = creation_time;
    fbi.LastAccessTime.QuadPart = last_access_time;
    fbi.LastWriteTime.QuadPart = last_write_time;
    fbi.ChangeTime.QuadPart = change_time;
    fbi.FileAttributes = attributes;

    Status = NtSetInformationFile(h, &iosb, &fbi, sizeof(fbi), FileBasicInformation);

    if (Status != STATUS_SUCCESS)
        throw ntstatus_error(Status);

    if (iosb.Information != 0)
        throw formatted_error("iosb.Information was {}, expected 0", iosb.Information);
                                  }

void test_fileinfo(const u16string& dir) {
    unique_handle h;
    LARGE_INTEGER delay;

    // ignoring LastAccessTime for the most part here, as the NtfsDisableLastAccessUpdate option means it's unpredictable

    delay.QuadPart = -1000000; // 100ms - should be 2 seconds for FAT?

    test("Create file", [&]() {
        h = create_file(dir + u"\\fileinfo1", SYNCHRONIZE | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | FILE_WRITE_DATA,
                        0, 0, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATED);
    });

    if (h) {
        static const vector<uint8_t> data = {'a','b','c','d','e','f'};
        FILE_BASIC_INFORMATION fbi;

        test("Query basic information", [&]() {
            fbi = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi.FileAttributes != FILE_ATTRIBUTE_ARCHIVE)
                throw formatted_error("FileAttributes was {:x}, expected FILE_ATTRIBUTE_ARCHIVE", fbi.FileAttributes);
        });

        test("Set times and attributes to 0", [&]() {
            set_basic_information(h.get(), 0, 0, 0, 0, 0);
        });

        test("Check times and attributes unchanged", [&]() {
            auto fbi2 = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi2.CreationTime.QuadPart != fbi.CreationTime.QuadPart)
                throw formatted_error("CreationTime was {}, expected {}", fbi2.CreationTime.QuadPart, fbi.CreationTime.QuadPart);

            if (fbi2.LastAccessTime.QuadPart != fbi.LastAccessTime.QuadPart)
                throw formatted_error("LastAccessTime was {}, expected {}", fbi2.LastAccessTime.QuadPart, fbi.LastAccessTime.QuadPart);

            if (fbi2.LastWriteTime.QuadPart != fbi.LastWriteTime.QuadPart)
                throw formatted_error("LastWriteTime was {}, expected {}", fbi2.LastWriteTime.QuadPart, fbi.LastWriteTime.QuadPart);

            if (fbi2.ChangeTime.QuadPart != fbi.ChangeTime.QuadPart)
                throw formatted_error("ChangeTime was {}, expected {}", fbi2.ChangeTime.QuadPart, fbi.ChangeTime.QuadPart);

            if (fbi2.FileAttributes != fbi.FileAttributes)
                throw formatted_error("FileAttributes was {:x}, expected {:x}", fbi2.FileAttributes, fbi.FileAttributes);
        });

        NtDelayExecution(false, &delay);

        test("Write to file", [&]() {
            write_file(h.get(), data);
        });

        test("Query basic information", [&]() {
            auto fbi2 = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi2.CreationTime.QuadPart != fbi.CreationTime.QuadPart)
                throw formatted_error("CreationTime was {}, expected {}", fbi2.CreationTime.QuadPart, fbi.CreationTime.QuadPart);

            if (fbi2.LastWriteTime.QuadPart == fbi.LastWriteTime.QuadPart)
                throw runtime_error("LastWriteTime was unchanged");

            if (fbi2.ChangeTime.QuadPart == fbi.ChangeTime.QuadPart)
                throw runtime_error("ChangeTime was unchanged");

            if (fbi2.FileAttributes != fbi.FileAttributes)
                throw formatted_error("FileAttributes was {:x}, expected {:x}", fbi2.FileAttributes, fbi.FileAttributes);

            fbi = fbi2;
        });

        test("Set LastWriteTime to -1", [&]() {
            set_basic_information(h.get(), 0, 0, -1, 0, 0);
        });

        NtDelayExecution(false, &delay);

        test("Write to file", [&]() {
            write_file(h.get(), data);
        });

        test("Query basic information", [&]() {
            auto fbi2 = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi2.CreationTime.QuadPart != fbi.CreationTime.QuadPart)
                throw formatted_error("CreationTime was {}, expected {}", fbi2.CreationTime.QuadPart, fbi.CreationTime.QuadPart);

            if (fbi2.LastWriteTime.QuadPart != fbi.LastWriteTime.QuadPart)
                throw formatted_error("LastWriteTime was {}, expected {}", fbi2.LastWriteTime.QuadPart, fbi.LastWriteTime.QuadPart);

            if (fbi2.ChangeTime.QuadPart == fbi.ChangeTime.QuadPart)
                throw runtime_error("ChangeTime was unchanged");

            if (fbi2.FileAttributes != fbi.FileAttributes)
                throw formatted_error("FileAttributes was {:x}, expected {:x}", fbi2.FileAttributes, fbi.FileAttributes);

            fbi = fbi2;
        });

        test("Set ChangeTime to -1", [&]() {
            set_basic_information(h.get(), 0, 0, 0, -1, 0);
        });

        NtDelayExecution(false, &delay);

        test("Write to file", [&]() {
            write_file(h.get(), data);
        });

        test("Query basic information", [&]() {
            auto fbi2 = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi2.CreationTime.QuadPart != fbi.CreationTime.QuadPart)
                throw formatted_error("CreationTime was {}, expected {}", fbi2.CreationTime.QuadPart, fbi.CreationTime.QuadPart);

            if (fbi2.LastWriteTime.QuadPart != fbi.LastWriteTime.QuadPart)
                throw formatted_error("LastWriteTime was {}, expected {}", fbi2.LastWriteTime.QuadPart, fbi.LastWriteTime.QuadPart);

            if (fbi2.ChangeTime.QuadPart != fbi.ChangeTime.QuadPart)
                throw formatted_error("ChangeTime was {}, expected {}", fbi2.ChangeTime.QuadPart, fbi.ChangeTime.QuadPart);

            if (fbi2.FileAttributes != fbi.FileAttributes)
                throw formatted_error("FileAttributes was {:x}, expected {:x}", fbi2.FileAttributes, fbi.FileAttributes);

            fbi = fbi2;
        });

        test("Set LastWriteTime to -2", [&]() {
            set_basic_information(h.get(), 0, 0, -2, 0, 0);
        });

        NtDelayExecution(false, &delay);

        test("Write to file", [&]() {
            write_file(h.get(), data);
        });

        test("Query basic information", [&]() {
            auto fbi2 = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi2.CreationTime.QuadPart != fbi.CreationTime.QuadPart)
                throw formatted_error("CreationTime was {}, expected {}", fbi2.CreationTime.QuadPart, fbi.CreationTime.QuadPart);

            if (fbi2.LastWriteTime.QuadPart == fbi.LastWriteTime.QuadPart)
                throw runtime_error("LastWriteTime was unchanged");

            if (fbi2.ChangeTime.QuadPart != fbi.ChangeTime.QuadPart)
                throw formatted_error("ChangeTime was {}, expected {}", fbi2.ChangeTime.QuadPart, fbi.ChangeTime.QuadPart);

            if (fbi2.FileAttributes != fbi.FileAttributes)
                throw formatted_error("FileAttributes was {:x}, expected {:x}", fbi2.FileAttributes, fbi.FileAttributes);

            fbi = fbi2;
        });

        test("Set ChangeTime to -2", [&]() {
            set_basic_information(h.get(), 0, 0, 0, -2, 0);
        });

        NtDelayExecution(false, &delay);

        test("Write to file", [&]() {
            write_file(h.get(), data);
        });

        test("Query basic information", [&]() {
            auto fbi2 = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi2.CreationTime.QuadPart != fbi.CreationTime.QuadPart)
                throw formatted_error("CreationTime was {}, expected {}", fbi2.CreationTime.QuadPart, fbi.CreationTime.QuadPart);

            if (fbi2.LastWriteTime.QuadPart == fbi.LastWriteTime.QuadPart)
                throw runtime_error("LastWriteTime was unchanged");

            if (fbi2.ChangeTime.QuadPart == fbi.ChangeTime.QuadPart)
                throw runtime_error("ChangeTime was unchanged");

            if (fbi2.FileAttributes != fbi.FileAttributes)
                throw formatted_error("FileAttributes was {:x}, expected {:x}", fbi2.FileAttributes, fbi.FileAttributes);

            fbi = fbi2;
        });

        int64_t date_val = 128790414900000000; // 2009-02-13T23:31:30

        NtDelayExecution(false, &delay);

        test("Set CreationTime", [&]() {
            set_basic_information(h.get(), date_val, 0, 0, 0, 0);
        });

        test("Query basic information", [&]() {
            auto fbi2 = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi2.CreationTime.QuadPart != date_val)
                throw formatted_error("CreationTime was {}, expected {}", fbi2.CreationTime.QuadPart, date_val);

            if (fbi2.LastWriteTime.QuadPart != fbi.LastWriteTime.QuadPart)
                throw formatted_error("LastWriteTime was {}, expected {}", fbi2.LastWriteTime.QuadPart, fbi.LastWriteTime.QuadPart);

            if (fbi2.ChangeTime.QuadPart == fbi.ChangeTime.QuadPart)
                throw runtime_error("ChangeTime was unchanged");

            if (fbi2.FileAttributes != fbi.FileAttributes)
                throw formatted_error("FileAttributes was {:x}, expected {:x}", fbi2.FileAttributes, fbi.FileAttributes);

            fbi = fbi2;
        });

        NtDelayExecution(false, &delay);

        test("Set LastWriteTime", [&]() {
            set_basic_information(h.get(), 0, 0, date_val, 0, 0);
        });

        test("Query basic information", [&]() {
            auto fbi2 = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi2.CreationTime.QuadPart != date_val)
                throw formatted_error("CreationTime was {}, expected {}", fbi2.CreationTime.QuadPart, date_val);

            if (fbi2.LastWriteTime.QuadPart != date_val)
                throw formatted_error("LastWriteTime was {}, expected {}", fbi2.LastWriteTime.QuadPart, date_val);

            if (fbi2.ChangeTime.QuadPart == fbi.ChangeTime.QuadPart)
                throw runtime_error("ChangeTime was unchanged");

            if (fbi2.FileAttributes != fbi.FileAttributes)
                throw formatted_error("FileAttributes was {:x}, expected {:x}", fbi2.FileAttributes, fbi.FileAttributes);

            fbi = fbi2;
        });

        NtDelayExecution(false, &delay);

        test("Set ChangeTime", [&]() {
            set_basic_information(h.get(), 0, 0, 0, date_val, 0);
        });

        test("Query basic information", [&]() {
            auto fbi2 = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi2.CreationTime.QuadPart != date_val)
                throw formatted_error("CreationTime was {}, expected {}", fbi2.CreationTime.QuadPart, date_val);

            if (fbi2.LastWriteTime.QuadPart != date_val)
                throw formatted_error("LastWriteTime was {}, expected {}", fbi2.LastWriteTime.QuadPart, date_val);

            if (fbi2.ChangeTime.QuadPart != date_val)
                throw formatted_error("ChangeTime was {}, expected {}", fbi2.ChangeTime.QuadPart, date_val);

            if (fbi2.FileAttributes != fbi.FileAttributes)
                throw formatted_error("FileAttributes was {:x}, expected {:x}", fbi2.FileAttributes, fbi.FileAttributes);

            fbi = fbi2;
        });

        h.reset();
    }

    test("Open file without FILE_READ_ATTRIBUTES", [&]() {
        h = create_file(dir + u"\\fileinfo1", FILE_WRITE_ATTRIBUTES,
                        0, 0, FILE_OPEN, 0, FILE_OPENED);
    });

    if (h) {
        test("Try to query basic information", [&]() {
            exp_status([&]() {
                query_information<FILE_BASIC_INFORMATION>(h.get());
            }, STATUS_ACCESS_DENIED);
        });

        h.reset();
    }

    test("Open file without FILE_WRITE_ATTRIBUTES", [&]() {
        h = create_file(dir + u"\\fileinfo1", FILE_READ_ATTRIBUTES,
                        0, 0, FILE_OPEN, 0, FILE_OPENED);
    });

    if (h) {
        test("Try to set basic information", [&]() {
            exp_status([&]() {
                set_basic_information(h.get(), 0, 0, 0, 0, 0);
            }, STATUS_ACCESS_DENIED);
        });

        h.reset();
    }

    test("Open file", [&]() {
        h = create_file(dir + u"\\fileinfo1", FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
                        0, 0, FILE_OPEN, 0, FILE_OPENED);
    });

    if (h) {
        test("Set hidden flag", [&]() {
            set_basic_information(h.get(), 0, 0, 0, 0, FILE_ATTRIBUTE_HIDDEN);
        });

        test("Query basic information", [&]() {
            auto fbi = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi.FileAttributes != FILE_ATTRIBUTE_HIDDEN)
                throw formatted_error("FileAttributes was {:x}, expected FILE_ATTRIBUTE_HIDDEN", fbi.FileAttributes);
        });

        test("Set attributes to FILE_ATTRIBUTE_NORMAL", [&]() {
            set_basic_information(h.get(), 0, 0, 0, 0, FILE_ATTRIBUTE_NORMAL);
        });

        test("Query basic information", [&]() {
            auto fbi = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi.FileAttributes != FILE_ATTRIBUTE_NORMAL)
                throw formatted_error("FileAttributes was {:x}, expected FILE_ATTRIBUTE_NORMAL", fbi.FileAttributes);
        });

        test("Set attributes to FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_READONLY", [&]() {
            set_basic_information(h.get(), 0, 0, 0, 0, FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_READONLY);
        });

        test("Query basic information", [&]() {
            auto fbi = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi.FileAttributes != FILE_ATTRIBUTE_READONLY)
                throw formatted_error("FileAttributes was {:x}, expected FILE_ATTRIBUTE_READONLY", fbi.FileAttributes);
        });

        test("Try to set attributes to FILE_ATTRIBUTE_DIRECTORY", [&]() { // fails
            exp_status([&]() {
                set_basic_information(h.get(), 0, 0, 0, 0, FILE_ATTRIBUTE_DIRECTORY);
            }, STATUS_INVALID_PARAMETER);
        });

        test("Set attributes to FILE_ATTRIBUTE_REPARSE_POINT", [&]() { // gets ignored
            set_basic_information(h.get(), 0, 0, 0, 0, FILE_ATTRIBUTE_REPARSE_POINT);
        });

        test("Query basic information", [&]() {
            auto fbi = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi.FileAttributes != FILE_ATTRIBUTE_NORMAL)
                throw formatted_error("FileAttributes was {:x}, expected FILE_ATTRIBUTE_NORMAL", fbi.FileAttributes);
        });

        test("Set attributes to FILE_ATTRIBUTE_SPARSE_FILE", [&]() { // gets ignored
            set_basic_information(h.get(), 0, 0, 0, 0, FILE_ATTRIBUTE_SPARSE_FILE);
        });

        test("Query basic information", [&]() {
            auto fbi = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi.FileAttributes != FILE_ATTRIBUTE_NORMAL)
                throw formatted_error("FileAttributes was {:x}, expected FILE_ATTRIBUTE_NORMAL", fbi.FileAttributes);
        });

        h.reset();
    }

    test("Create directory", [&]() {
        h = create_file(dir + u"\\fileinfo2", FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
                        0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        test("Set hidden flag", [&]() {
            set_basic_information(h.get(), 0, 0, 0, 0, FILE_ATTRIBUTE_HIDDEN);
        });

        test("Query basic information", [&]() {
            auto fbi = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi.FileAttributes != (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_HIDDEN))
                throw formatted_error("FileAttributes was {:x}, expected FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_HIDDEN", fbi.FileAttributes);
        });

        test("Set attributes to FILE_ATTRIBUTE_NORMAL", [&]() {
            set_basic_information(h.get(), 0, 0, 0, 0, FILE_ATTRIBUTE_NORMAL);
        });

        test("Query basic information", [&]() {
            auto fbi = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi.FileAttributes != FILE_ATTRIBUTE_DIRECTORY)
                throw formatted_error("FileAttributes was {:x}, expected FILE_ATTRIBUTE_DIRECTORY", fbi.FileAttributes);
        });

        test("Set attributes to FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_READONLY", [&]() {
            set_basic_information(h.get(), 0, 0, 0, 0, FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_READONLY);
        });

        test("Query basic information", [&]() {
            auto fbi = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi.FileAttributes != (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_READONLY))
                throw formatted_error("FileAttributes was {:x}, expected FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_READONLY", fbi.FileAttributes);
        });

        test("Set attributes to FILE_ATTRIBUTE_DIRECTORY", [&]() {
            set_basic_information(h.get(), 0, 0, 0, 0, FILE_ATTRIBUTE_DIRECTORY);
        });

        test("Query basic information", [&]() {
            auto fbi = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi.FileAttributes != FILE_ATTRIBUTE_DIRECTORY)
                throw formatted_error("FileAttributes was {:x}, expected FILE_ATTRIBUTE_DIRECTORY", fbi.FileAttributes);
        });

        test("Set attributes to FILE_ATTRIBUTE_REPARSE_POINT", [&]() { // gets ignored
            set_basic_information(h.get(), 0, 0, 0, 0, FILE_ATTRIBUTE_REPARSE_POINT);
        });

        test("Query basic information", [&]() {
            auto fbi = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi.FileAttributes != FILE_ATTRIBUTE_DIRECTORY)
                throw formatted_error("FileAttributes was {:x}, expected FILE_ATTRIBUTE_DIRECTORY", fbi.FileAttributes);
        });

        test("Set attributes to FILE_ATTRIBUTE_SPARSE_FILE", [&]() { // gets ignored
            set_basic_information(h.get(), 0, 0, 0, 0, FILE_ATTRIBUTE_SPARSE_FILE);
        });

        test("Query basic information", [&]() {
            auto fbi = query_information<FILE_BASIC_INFORMATION>(h.get());

            if (fbi.FileAttributes != FILE_ATTRIBUTE_DIRECTORY)
                throw formatted_error("FileAttributes was {:x}, expected FILE_ATTRIBUTE_DIRECTORY", fbi.FileAttributes);
        });

        h.reset();
    }
}
