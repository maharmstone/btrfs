/* btrfs.h
 * Generic btrfs header file. Thanks to whoever it was who wrote
 * https://btrfs.wiki.kernel.org/index.php/On-disk_Format - you saved me a lot of time!
 *
 * I release this file, and this file only, into the public domain - do whatever
 * you want with it. You don't have to, but I'd appreciate if you let me know if you
 * use it anything cool - mark@harmstone.com. */

#pragma once

#include <stdint.h>
#include <assert.h>

static const uint64_t superblock_addrs[] = { 0x10000, 0x4000000, 0x4000000000, 0x4000000000000, 0 };

#define BTRFS_MAGIC         0x4d5f53665248425f
#define MAX_LABEL_SIZE      0x100
#define SUBVOL_ROOT_INODE   0x100
#define BTRFS_LAST_FREE_OBJECTID    0xffffffffffffff00

#define TYPE_INODE_ITEM        0x01
#define TYPE_INODE_REF         0x0C
#define TYPE_INODE_EXTREF      0x0D
#define TYPE_XATTR_ITEM        0x18
#define TYPE_ORPHAN_INODE      0x30
#define TYPE_DIR_ITEM          0x54
#define TYPE_DIR_INDEX         0x60
#define TYPE_EXTENT_DATA       0x6C
#define TYPE_EXTENT_CSUM       0x80
#define TYPE_ROOT_ITEM         0x84
#define TYPE_ROOT_BACKREF      0x90
#define TYPE_ROOT_REF          0x9C
#define TYPE_EXTENT_ITEM       0xA8
#define TYPE_METADATA_ITEM     0xA9
#define TYPE_TREE_BLOCK_REF    0xB0
#define TYPE_EXTENT_DATA_REF   0xB2
#define TYPE_EXTENT_REF_V0     0xB4
#define TYPE_SHARED_BLOCK_REF  0xB6
#define TYPE_SHARED_DATA_REF   0xB8
#define TYPE_BLOCK_GROUP_ITEM  0xC0
#define TYPE_FREE_SPACE_INFO   0xC6
#define TYPE_FREE_SPACE_EXTENT 0xC7
#define TYPE_FREE_SPACE_BITMAP 0xC8
#define TYPE_DEV_EXTENT        0xCC
#define TYPE_DEV_ITEM          0xD8
#define TYPE_CHUNK_ITEM        0xE4
#define TYPE_TEMP_ITEM         0xF8
#define TYPE_DEV_STATS         0xF9
#define TYPE_SUBVOL_UUID       0xFB
#define TYPE_SUBVOL_REC_UUID   0xFC

#define BTRFS_ROOT_ROOT         1
#define BTRFS_ROOT_EXTENT       2
#define BTRFS_ROOT_CHUNK        3
#define BTRFS_ROOT_DEVTREE      4
#define BTRFS_ROOT_FSTREE       5
#define BTRFS_ROOT_TREEDIR      6
#define BTRFS_ROOT_CHECKSUM     7
#define BTRFS_ROOT_UUID         9
#define BTRFS_ROOT_FREE_SPACE   0xa
#define BTRFS_ROOT_BLOCK_GROUP  0xb
#define BTRFS_ROOT_RAID_STRIPE  0xc
#define BTRFS_ROOT_DATA_RELOC   0xFFFFFFFFFFFFFFF7

#define BTRFS_COMPRESSION_NONE  0
#define BTRFS_COMPRESSION_ZLIB  1
#define BTRFS_COMPRESSION_LZO   2
#define BTRFS_COMPRESSION_ZSTD  3

#define BTRFS_ENCRYPTION_NONE   0

#define BTRFS_ENCODING_NONE     0

#define EXTENT_TYPE_INLINE      0
#define EXTENT_TYPE_REGULAR     1
#define EXTENT_TYPE_PREALLOC    2

#define BLOCK_FLAG_DATA         0x001
#define BLOCK_FLAG_SYSTEM       0x002
#define BLOCK_FLAG_METADATA     0x004
#define BLOCK_FLAG_RAID0        0x008
#define BLOCK_FLAG_RAID1        0x010
#define BLOCK_FLAG_DUPLICATE    0x020
#define BLOCK_FLAG_RAID10       0x040
#define BLOCK_FLAG_RAID5        0x080
#define BLOCK_FLAG_RAID6        0x100
#define BLOCK_FLAG_RAID1C3      0x200
#define BLOCK_FLAG_RAID1C4      0x400

#define FREE_SPACE_CACHE_ID     0xFFFFFFFFFFFFFFF5
#define EXTENT_CSUM_ID          0xFFFFFFFFFFFFFFF6
#define BALANCE_ITEM_ID         0xFFFFFFFFFFFFFFFC

#define BTRFS_INODE_NODATASUM   0x001
#define BTRFS_INODE_NODATACOW   0x002
#define BTRFS_INODE_READONLY    0x004
#define BTRFS_INODE_NOCOMPRESS  0x008
#define BTRFS_INODE_PREALLOC    0x010
#define BTRFS_INODE_SYNC        0x020
#define BTRFS_INODE_IMMUTABLE   0x040
#define BTRFS_INODE_APPEND      0x080
#define BTRFS_INODE_NODUMP      0x100
#define BTRFS_INODE_NOATIME     0x200
#define BTRFS_INODE_DIRSYNC     0x400
#define BTRFS_INODE_COMPRESS    0x800

#define BTRFS_INODE_RO_VERITY   0x1

#define BTRFS_INODE_ROOT_ITEM_INIT (1U << 31)

#define BTRFS_SUBVOL_READONLY   0x1

#define BTRFS_COMPAT_RO_FLAGS_FREE_SPACE_CACHE          0x1
#define BTRFS_COMPAT_RO_FLAGS_FREE_SPACE_CACHE_VALID    0x2
#define BTRFS_COMPAT_RO_FLAGS_VERITY                    0x4
#define BTRFS_COMPAT_RO_FLAGS_BLOCK_GROUP_TREE          0x8

#define BTRFS_INCOMPAT_FLAGS_MIXED_BACKREF      0x0001
#define BTRFS_INCOMPAT_FLAGS_DEFAULT_SUBVOL     0x0002
#define BTRFS_INCOMPAT_FLAGS_MIXED_GROUPS       0x0004
#define BTRFS_INCOMPAT_FLAGS_COMPRESS_LZO       0x0008
#define BTRFS_INCOMPAT_FLAGS_COMPRESS_ZSTD      0x0010
#define BTRFS_INCOMPAT_FLAGS_BIG_METADATA       0x0020
#define BTRFS_INCOMPAT_FLAGS_EXTENDED_IREF      0x0040
#define BTRFS_INCOMPAT_FLAGS_RAID56             0x0080
#define BTRFS_INCOMPAT_FLAGS_SKINNY_METADATA    0x0100
#define BTRFS_INCOMPAT_FLAGS_NO_HOLES           0x0200
#define BTRFS_INCOMPAT_FLAGS_METADATA_UUID      0x0400
#define BTRFS_INCOMPAT_FLAGS_RAID1C34           0x0800
#define BTRFS_INCOMPAT_FLAGS_ZONED              0x1000
#define BTRFS_INCOMPAT_FLAGS_EXTENT_TREE_V2     0x2000
#define BTRFS_INCOMPAT_FLAGS_RAID_STRIPE_TREE   0x4000
#define BTRFS_INCOMPAT_FLAGS_SIMPLE_QUOTA       0x10000

#define BTRFS_SUPERBLOCK_FLAGS_SEEDING   0x100000000

#define BTRFS_ORPHAN_INODE_OBJID         0xFFFFFFFFFFFFFFFB

#define CSUM_TYPE_CRC32C        0
#define CSUM_TYPE_XXHASH        1
#define CSUM_TYPE_SHA256        2
#define CSUM_TYPE_BLAKE2        3

#pragma pack(push, 1)

typedef struct {
    uint8_t uuid[16];
} BTRFS_UUID;

struct btrfs_key {
    uint64_t objectid;
    uint8_t type;
    uint64_t offset;
};

#define HEADER_FLAG_WRITTEN         0x000000000000001
#define HEADER_FLAG_SHARED_BACKREF  0x000000000000002
#define HEADER_FLAG_MIXED_BACKREF   0x100000000000000

struct btrfs_header {
    uint8_t csum[32];
    BTRFS_UUID fsid;
    uint64_t bytenr;
    uint64_t flags;
    BTRFS_UUID chunk_tree_uuid;
    uint64_t generation;
    uint64_t owner;
    uint32_t nritems;
    uint8_t level;
};

struct btrfs_item {
    struct btrfs_key key;
    uint32_t offset;
    uint32_t size;
};

struct btrfs_key_ptr {
    struct btrfs_key key;
    uint64_t blockptr;
    uint64_t generation;
};

struct btrfs_dev_item {
    uint64_t devid;
    uint64_t total_bytes;
    uint64_t bytes_used;
    uint32_t io_align;
    uint32_t io_width;
    uint32_t sector_size;
    uint64_t type;
    uint64_t generation;
    uint64_t start_offset;
    uint32_t dev_group;
    uint8_t seek_speed;
    uint8_t bandwidth;
    BTRFS_UUID uuid;
    BTRFS_UUID fsid;
};

#define SYS_CHUNK_ARRAY_SIZE 0x800
#define BTRFS_NUM_BACKUP_ROOTS 4

struct btrfs_root_backup {
    uint64_t tree_root;
    uint64_t tree_root_gen;
    uint64_t chunk_root;
    uint64_t chunk_root_gen;
    uint64_t extent_root;
    uint64_t extent_root_gen;
    uint64_t fs_root;
    uint64_t fs_root_gen;
    uint64_t dev_root;
    uint64_t dev_root_gen;
    uint64_t csum_root;
    uint64_t csum_root_gen;
    uint64_t total_bytes;
    uint64_t bytes_used;
    uint64_t num_devices;
    uint64_t unused_64[4];
    uint8_t tree_root_level;
    uint8_t chunk_root_level;
    uint8_t extent_root_level;
    uint8_t fs_root_level;
    uint8_t dev_root_level;
    uint8_t csum_root_level;
    uint8_t unused_8[10];
};

struct btrfs_super_block {
    uint8_t csum[32];
    BTRFS_UUID fsid;
    uint64_t bytenr;
    uint64_t flags;
    uint64_t magic;
    uint64_t generation;
    uint64_t root;
    uint64_t chunk_root;
    uint64_t log_root;
    uint64_t __unused_log_root_transid;
    uint64_t total_bytes;
    uint64_t bytes_used;
    uint64_t root_dir_objectid;
    uint64_t num_devices;
    uint32_t sectorsize;
    uint32_t nodesize;
    uint32_t __unused_leafsize;
    uint32_t stripesize;
    uint32_t sys_chunk_array_size;
    uint64_t chunk_root_generation;
    uint64_t compat_flags;
    uint64_t compat_ro_flags;
    uint64_t incompat_flags;
    uint16_t csum_type;
    uint8_t root_level;
    uint8_t chunk_root_level;
    uint8_t log_root_level;
    struct btrfs_dev_item dev_item;
    char label[MAX_LABEL_SIZE];
    uint64_t cache_generation;
    uint64_t uuid_tree_generation;
    BTRFS_UUID metadata_uuid;
    uint64_t nr_global_roots;
    uint64_t remap_root;
    uint64_t remap_root_generation;
    uint8_t remap_root_level;
    uint8_t reserved[199];
    uint8_t sys_chunk_array[SYS_CHUNK_ARRAY_SIZE];
    struct btrfs_root_backup super_roots[BTRFS_NUM_BACKUP_ROOTS];
    uint8_t padding[565];
};

#define BTRFS_TYPE_UNKNOWN   0
#define BTRFS_TYPE_FILE      1
#define BTRFS_TYPE_DIRECTORY 2
#define BTRFS_TYPE_CHARDEV   3
#define BTRFS_TYPE_BLOCKDEV  4
#define BTRFS_TYPE_FIFO      5
#define BTRFS_TYPE_SOCKET    6
#define BTRFS_TYPE_SYMLINK   7
#define BTRFS_TYPE_EA        8

struct btrfs_dir_item {
    struct btrfs_key location;
    uint64_t transid;
    uint16_t data_len;
    uint16_t name_len;
    uint8_t type;
};

struct btrfs_timespec {
    uint64_t sec;
    uint32_t nsec;
};

struct btrfs_inode_item {
    uint64_t generation;
    uint64_t transid;
    uint64_t size;
    uint64_t nbytes;
    uint64_t block_group;
    uint32_t nlink;
    uint32_t uid;
    uint32_t gid;
    uint32_t mode;
    uint64_t rdev;
    uint64_t flags;
    uint64_t sequence;
    uint64_t reserved[4];
    struct btrfs_timespec atime;
    struct btrfs_timespec ctime;
    struct btrfs_timespec mtime;
    struct btrfs_timespec otime;
};

static_assert(sizeof(struct btrfs_inode_item) == 0xa0, "btrfs_inode_item has wrong size");

struct btrfs_root_item {
    struct btrfs_inode_item inode;
    uint64_t generation;
    uint64_t root_dirid;
    uint64_t bytenr;
    uint64_t byte_limit;
    uint64_t bytes_used;
    uint64_t last_snapshot;
    uint64_t flags;
    uint32_t refs;
    struct btrfs_key drop_progress;
    uint8_t drop_level;
    uint8_t level;
    uint64_t generation_v2;
    BTRFS_UUID uuid;
    BTRFS_UUID parent_uuid;
    BTRFS_UUID received_uuid;
    uint64_t ctransid;
    uint64_t otransid;
    uint64_t stransid;
    uint64_t rtransid;
    struct btrfs_timespec ctime;
    struct btrfs_timespec otime;
    struct btrfs_timespec stime;
    struct btrfs_timespec rtime;
    uint64_t reserved[8];
};

struct btrfs_stripe {
    uint64_t devid;
    uint64_t offset;
    BTRFS_UUID dev_uuid;
};

struct btrfs_chunk {
    uint64_t length;
    uint64_t owner;
    uint64_t stripe_len;
    uint64_t type;
    uint32_t io_align;
    uint32_t io_width;
    uint32_t sector_size;
    uint16_t num_stripes;
    uint16_t sub_stripes;
    struct btrfs_stripe stripe[1];
};

struct btrfs_file_extent_item {
    uint64_t generation;
    uint64_t ram_bytes;
    uint8_t compression;
    uint8_t encryption;
    uint16_t other_encoding;
    uint8_t type;
    uint64_t disk_bytenr;
    uint64_t disk_num_bytes;
    uint64_t offset;
    uint64_t num_bytes;
};

struct btrfs_inode_ref {
    uint64_t index;
    uint16_t name_len;
};

struct btrfs_inode_extref {
    uint64_t parent_objectid;
    uint64_t index;
    uint16_t name_len;
    uint8_t name[];
};

#define EXTENT_ITEM_DATA            0x001
#define EXTENT_ITEM_TREE_BLOCK      0x002
#define EXTENT_ITEM_SHARED_BACKREFS 0x100

struct btrfs_extent_item {
    uint64_t refs;
    uint64_t generation;
    uint64_t flags;
};

typedef struct {
    struct btrfs_key firstitem;
    uint8_t level;
} EXTENT_ITEM2;

typedef struct {
    uint32_t refcount;
} EXTENT_ITEM_V0;

typedef struct {
    struct btrfs_extent_item extent_item;
    struct btrfs_key firstitem;
    uint8_t level;
} EXTENT_ITEM_TREE;

typedef struct {
    uint64_t offset;
} TREE_BLOCK_REF;

struct btrfs_extent_data_ref {
    uint64_t root;
    uint64_t objectid;
    uint64_t offset;
    uint32_t count;
};

struct btrfs_block_group_item {
    uint64_t used;
    uint64_t chunk_objectid;
    uint64_t flags;
};

typedef struct {
    uint64_t root;
    uint64_t gen;
    uint64_t objid;
    uint32_t count;
} EXTENT_REF_V0;

typedef struct {
    uint64_t offset;
} SHARED_BLOCK_REF;

typedef struct {
    uint64_t offset;
    uint32_t count;
} SHARED_DATA_REF;

#define FREE_SPACE_EXTENT 1
#define FREE_SPACE_BITMAP 2

struct btrfs_free_space_entry {
    uint64_t offset;
    uint64_t bytes;
    uint8_t type;
};

struct btrfs_free_space_header {
    struct btrfs_key location;
    uint64_t generation;
    uint64_t num_entries;
    uint64_t num_bitmaps;
};

struct btrfs_root_ref {
    uint64_t dirid;
    uint64_t sequence;
    uint16_t name_len;
};

struct btrfs_dev_extent {
    uint64_t chunk_tree;
    uint64_t chunk_objectid;
    uint64_t chunk_offset;
    uint64_t length;
    BTRFS_UUID chunk_tree_uuid;
};

#define BALANCE_FLAGS_DATA          0x1
#define BALANCE_FLAGS_SYSTEM        0x2
#define BALANCE_FLAGS_METADATA      0x4

#define BALANCE_ARGS_FLAGS_PROFILES         0x001
#define BALANCE_ARGS_FLAGS_USAGE            0x002
#define BALANCE_ARGS_FLAGS_DEVID            0x004
#define BALANCE_ARGS_FLAGS_DRANGE           0x008
#define BALANCE_ARGS_FLAGS_VRANGE           0x010
#define BALANCE_ARGS_FLAGS_LIMIT            0x020
#define BALANCE_ARGS_FLAGS_LIMIT_RANGE      0x040
#define BALANCE_ARGS_FLAGS_STRIPES_RANGE    0x080
#define BALANCE_ARGS_FLAGS_CONVERT          0x100
#define BALANCE_ARGS_FLAGS_SOFT             0x200
#define BALANCE_ARGS_FLAGS_USAGE_RANGE      0x400

typedef struct {
    uint64_t profiles;

    union {
            uint64_t usage;
            struct {
                    uint32_t usage_start;
                    uint32_t usage_end;
            };
    };

    uint64_t devid;
    uint64_t drange_start;
    uint64_t drange_end;
    uint64_t vrange_start;
    uint64_t vrange_end;
    uint64_t convert;
    uint64_t flags;

    union {
            uint64_t limit;
            struct {
                    uint32_t limit_start;
                    uint32_t limit_end;
            };
    };

    uint32_t stripes_start;
    uint32_t stripes_end;
    uint8_t reserved[48];
} BALANCE_ARGS;

typedef struct {
    uint64_t flags;
    BALANCE_ARGS data;
    BALANCE_ARGS metadata;
    BALANCE_ARGS system;
    uint8_t reserved[32];
} BALANCE_ITEM;

#define BTRFS_FREE_SPACE_USING_BITMAPS      1

struct btrfs_free_space_info {
    uint32_t extent_count;
    uint32_t flags;
};

#define BTRFS_DEV_STAT_WRITE_ERRORS          0
#define BTRFS_DEV_STAT_READ_ERRORS           1
#define BTRFS_DEV_STAT_FLUSH_ERRORS          2
#define BTRFS_DEV_STAT_CORRUPTION_ERRORS     3
#define BTRFS_DEV_STAT_GENERATION_ERRORS     4

#define BTRFS_SEND_CMD_SUBVOL          1
#define BTRFS_SEND_CMD_SNAPSHOT        2
#define BTRFS_SEND_CMD_MKFILE          3
#define BTRFS_SEND_CMD_MKDIR           4
#define BTRFS_SEND_CMD_MKNOD           5
#define BTRFS_SEND_CMD_MKFIFO          6
#define BTRFS_SEND_CMD_MKSOCK          7
#define BTRFS_SEND_CMD_SYMLINK         8
#define BTRFS_SEND_CMD_RENAME          9
#define BTRFS_SEND_CMD_LINK           10
#define BTRFS_SEND_CMD_UNLINK         11
#define BTRFS_SEND_CMD_RMDIR          12
#define BTRFS_SEND_CMD_SET_XATTR      13
#define BTRFS_SEND_CMD_REMOVE_XATTR   14
#define BTRFS_SEND_CMD_WRITE          15
#define BTRFS_SEND_CMD_CLONE          16
#define BTRFS_SEND_CMD_TRUNCATE       17
#define BTRFS_SEND_CMD_CHMOD          18
#define BTRFS_SEND_CMD_CHOWN          19
#define BTRFS_SEND_CMD_UTIMES         20
#define BTRFS_SEND_CMD_END            21
#define BTRFS_SEND_CMD_UPDATE_EXTENT  22

#define BTRFS_SEND_TLV_UUID             1
#define BTRFS_SEND_TLV_TRANSID          2
#define BTRFS_SEND_TLV_INODE            3
#define BTRFS_SEND_TLV_SIZE             4
#define BTRFS_SEND_TLV_MODE             5
#define BTRFS_SEND_TLV_UID              6
#define BTRFS_SEND_TLV_GID              7
#define BTRFS_SEND_TLV_RDEV             8
#define BTRFS_SEND_TLV_CTIME            9
#define BTRFS_SEND_TLV_MTIME           10
#define BTRFS_SEND_TLV_ATIME           11
#define BTRFS_SEND_TLV_OTIME           12
#define BTRFS_SEND_TLV_XATTR_NAME      13
#define BTRFS_SEND_TLV_XATTR_DATA      14
#define BTRFS_SEND_TLV_PATH            15
#define BTRFS_SEND_TLV_PATH_TO         16
#define BTRFS_SEND_TLV_PATH_LINK       17
#define BTRFS_SEND_TLV_OFFSET          18
#define BTRFS_SEND_TLV_DATA            19
#define BTRFS_SEND_TLV_CLONE_UUID      20
#define BTRFS_SEND_TLV_CLONE_CTRANSID  21
#define BTRFS_SEND_TLV_CLONE_PATH      22
#define BTRFS_SEND_TLV_CLONE_OFFSET    23
#define BTRFS_SEND_TLV_CLONE_LENGTH    24

#define BTRFS_SEND_MAGIC "btrfs-stream"

typedef struct {
    uint8_t magic[13];
    uint32_t version;
} btrfs_send_header;

typedef struct {
    uint32_t length;
    uint16_t cmd;
    uint32_t csum;
} btrfs_send_command;

typedef struct {
    uint16_t type;
    uint16_t length;
} btrfs_send_tlv;

#pragma pack(pop)
