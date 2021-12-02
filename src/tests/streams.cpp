#include "test.h"

using namespace std;

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

    // FIXME - data streams on directories (can we have ::$DATA?)
    // FIXME - overwriting and superseding streams
    // FIXME - deleting streams (inc. ::$DATA)
    // FIXME - stream I/O (check file sizes)
    // FIXME - renaming streams
    // FIXME - promoting ADS to main stream by rename, and vice versa
    // FIXME - name validity (inc. DOSATTRIB etc.) (test UTF-16 issues)
    // FIXME - make sure ::$DATA suffix ignored
}
