#include "test.h"

using namespace std;

void test_overwrite(const u16string& dir) {
    unique_handle h;

    test("Try overwriting non-existent file", [&]() {
        exp_status([&]() {
            create_file(dir + u"\\nonsuch", MAXIMUM_ALLOWED, 0, 0, FILE_OVERWRITE,
                        0, FILE_OVERWRITTEN);
        }, STATUS_OBJECT_NAME_NOT_FOUND);
    });

    test("Create readonly file", [&]() {
        h = create_file(dir + u"\\overwritero", MAXIMUM_ALLOWED, FILE_ATTRIBUTE_READONLY, 0, FILE_CREATE,
                        0, FILE_CREATED);
    });

    if (h) {
        h.reset();

        test("Try overwriting readonly file", [&]() {
            exp_status([&]() {
                create_file(dir + u"\\overwritero", MAXIMUM_ALLOWED, 0, 0, FILE_OVERWRITE,
                            0, FILE_OVERWRITTEN);
            }, STATUS_ACCESS_DENIED);
        });
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\overwrite", MAXIMUM_ALLOWED, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_CREATE, 0, FILE_CREATED);
    });

    if (h) {
        test("Try overwriting open file", [&]() {
            create_file(dir + u"\\overwrite", MAXIMUM_ALLOWED, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_OVERWRITE, 0, FILE_OVERWRITTEN);
        });

        h.reset();

        test("Overwrite file", [&]() {
            h = create_file(dir + u"\\overwrite", MAXIMUM_ALLOWED, 0, 0, FILE_OVERWRITE,
                            0, FILE_OVERWRITTEN);
        });
    }

    if (h) {
        h.reset();

        test("Overwrite file adding readonly flag", [&]() {
            create_file(dir + u"\\overwrite", MAXIMUM_ALLOWED, FILE_ATTRIBUTE_READONLY, 0, FILE_OVERWRITE,
                        0, FILE_OVERWRITTEN);
        });
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\overwrite2", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE,
                        0, FILE_CREATED);
    });

    if (h) {
        h.reset();

        test("Try overwriting file, changing to directory", [&]() {
            exp_status([&]() {
                create_file(dir + u"\\overwrite2", MAXIMUM_ALLOWED, 0, 0, FILE_OVERWRITE,
                            FILE_DIRECTORY_FILE, FILE_OVERWRITTEN);
            }, STATUS_INVALID_PARAMETER);
        });

        test("Overwrite file adding hidden flag", [&]() {
            h = create_file(dir + u"\\overwrite2", MAXIMUM_ALLOWED, FILE_ATTRIBUTE_HIDDEN, 0, FILE_OVERWRITE,
                            0, FILE_OVERWRITTEN);
        });
    }

    if (h) {
        h.reset();

        test("Try overwriting file clearing hidden flag", [&]() {
            exp_status([&]() {
                create_file(dir + u"\\overwrite2", MAXIMUM_ALLOWED, 0, 0, FILE_OVERWRITE,
                            0, FILE_OVERWRITTEN);
            }, STATUS_ACCESS_DENIED);
        });
    }

    test("Overwrite file adding system flag", [&]() {
        h = create_file(dir + u"\\overwrite2", MAXIMUM_ALLOWED, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, 0,
                        FILE_OVERWRITE, 0, FILE_OVERWRITTEN);
    });

    if (h) {
        h.reset();

        test("Try overwriting file clearing system flag", [&]() {
            exp_status([&]() {
                create_file(dir + u"\\overwrite2", MAXIMUM_ALLOWED, FILE_ATTRIBUTE_HIDDEN, 0, FILE_OVERWRITE,
                            0, FILE_OVERWRITTEN);
            }, STATUS_ACCESS_DENIED);
        });
    }

    test("Create directory", [&]() {
        h = create_file(dir + u"\\overwritedir", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE,
                        FILE_DIRECTORY_FILE, FILE_CREATED);
    });

    if (h) {
        h.reset();

        test("Try overwriting directory", [&]() {
            exp_status([&]() {
                create_file(dir + u"\\overwritedir", MAXIMUM_ALLOWED, 0, 0, FILE_OVERWRITE,
                            FILE_DIRECTORY_FILE, FILE_OVERWRITTEN);
            }, STATUS_INVALID_PARAMETER);
        });

        test("Try overwriting directory, changing to file", [&]() {
            exp_status([&]() {
                create_file(dir + u"\\overwritedir", MAXIMUM_ALLOWED, 0, 0, FILE_OVERWRITE,
                            FILE_NON_DIRECTORY_FILE, FILE_OVERWRITTEN);
            }, STATUS_FILE_IS_A_DIRECTORY);
        });
    }

    test("Create file", [&]() {
        h = create_file(dir + u"\\overwrite3", MAXIMUM_ALLOWED, 0, 0, FILE_CREATE,
                        0, FILE_CREATED);
    });

    if (h) {
        h.reset();

        test("Overwrite file with different case", [&]() {
            h = create_file(dir + u"\\OVERWRITE3", MAXIMUM_ALLOWED, 0, 0, FILE_OVERWRITE,
                            0, FILE_OVERWRITTEN);
        });

        if (h) {
            test("Check name", [&]() {
                auto fn = query_file_name_information(h.get());

                static const u16string_view ends_with = u"\\overwrite3";

                if (fn.size() < ends_with.size() || fn.substr(fn.size() - ends_with.size()) != ends_with)
                    throw runtime_error("Name did not end with \"\\overwrite3\".");
            });
        }
    }

    test("Create file with FILE_OPEN_IF", [&]() {
        h = create_file(dir + u"\\overwriteif", MAXIMUM_ALLOWED, 0, 0, FILE_OVERWRITE_IF, 0, FILE_CREATED);
    });

    if (h) {
        h.reset();

        test("Open file with FILE_OVERWRITE_IF", [&]() {
            create_file(dir + u"\\overwriteif", MAXIMUM_ALLOWED, 0, 0, FILE_OVERWRITE_IF, 0, FILE_OVERWRITTEN);
        });
    }
}
