// Portion of the LZO code here were cribbed from code in libavcodec,
// also under the LGPL. Thank you, Reimar Doeffinger.

#include "btrfs_drv.h"

#define Z_SOLO
#define ZLIB_INTERNAL

#include "zlib/zlib.h"
#include "zlib/inftrees.h"
#include "zlib/inflate.h"

#define LINUX_PAGE_SIZE 4096

typedef struct {
    UINT8* in;
    UINT32 inlen;
    UINT32 inpos;
    UINT8* out;
    UINT32 outlen;
    UINT32 outpos;
    BOOL error;
} lzo_stream;

static UINT8 lzo_nextbyte(lzo_stream* stream) {
    UINT8 c;
    
    if (stream->inpos >= stream->inlen) {
        stream->error = TRUE;
        return 0;
    }
    
    c = stream->in[stream->inpos];
    stream->inpos++;
    
    return c;
}

static int lzo_len(lzo_stream* stream, int byte, int mask) {
    int len = byte & mask;
    
    if (len == 0) {
        while (!(byte = lzo_nextbyte(stream))) {
            if (stream->error) return 0;
            
            len += 255;
        }
        
        len += mask + byte;
    }
    
    return len;
}

static void lzo_copy(lzo_stream* stream, int len) {
    if (stream->inpos + len > stream->inlen) {
        stream->error = TRUE;
        return;
    }
    
    if (stream->outpos + len > stream->outlen) {
        stream->error = TRUE;
        return;
    }
    
    do {
        stream->out[stream->outpos] = stream->in[stream->inpos];
        stream->inpos++;
        stream->outpos++;
        len--;
    } while (len > 0);
}

static void lzo_copyback(lzo_stream* stream, int back, int len) {
    if (stream->outpos < back) {
        stream->error = TRUE;
        return;
    }
    
    if (stream->outpos + len > stream->outlen) {
        stream->error = TRUE;
        return;
    }
    
    do {
        stream->out[stream->outpos] = stream->out[stream->outpos - back];
        stream->outpos++;
        len--;
    } while (len > 0);
}

static NTSTATUS do_lzo_decompress(lzo_stream* stream) {
    UINT8 byte;
    UINT32 len, back;
    BOOL backcopy = FALSE;
    
    stream->error = FALSE;
    
    byte = lzo_nextbyte(stream);
    if (stream->error) return STATUS_INTERNAL_ERROR;
    
    if (byte > 17) {
        lzo_copy(stream, byte - 17);
        if (stream->error) return STATUS_INTERNAL_ERROR;
        
        byte = lzo_nextbyte(stream);
        if (stream->error) return STATUS_INTERNAL_ERROR;
        
        if (byte < 16) return STATUS_INTERNAL_ERROR;
    }
    
    while (1) {
        if (byte >> 4) {
            backcopy = TRUE;
            if (byte >> 6) {
                len = (byte >> 5) - 1;
                back = (lzo_nextbyte(stream) << 3) + ((byte >> 2) & 7) + 1;
                if (stream->error) return STATUS_INTERNAL_ERROR;
            } else if (byte >> 5) {
                len = lzo_len(stream, byte, 31);
                if (stream->error) return STATUS_INTERNAL_ERROR;
                
                byte = lzo_nextbyte(stream);
                if (stream->error) return STATUS_INTERNAL_ERROR;
                
                back = (lzo_nextbyte(stream) << 6) + (byte >> 2) + 1;
                if (stream->error) return STATUS_INTERNAL_ERROR;
            } else {
                len = lzo_len(stream, byte, 7);
                if (stream->error) return STATUS_INTERNAL_ERROR;
                
                back = (1 << 14) + ((byte & 8) << 11);
                
                byte = lzo_nextbyte(stream);
                if (stream->error) return STATUS_INTERNAL_ERROR;
                
                back += (lzo_nextbyte(stream) << 6) + (byte >> 2);
                if (stream->error) return STATUS_INTERNAL_ERROR;
                
                if (back == (1 << 14)) {
                    if (len != 1)
                        return STATUS_INTERNAL_ERROR;
                    break;
                }
            }
        } else if (backcopy) {
            len = 0;
            back = (lzo_nextbyte(stream) << 2) + (byte >> 2) + 1;
            if (stream->error) return STATUS_INTERNAL_ERROR;
        } else {
            len = lzo_len(stream, byte, 15);
            if (stream->error) return STATUS_INTERNAL_ERROR;
            
            lzo_copy(stream, len + 3);
            if (stream->error) return STATUS_INTERNAL_ERROR;
            
            byte = lzo_nextbyte(stream);
            if (stream->error) return STATUS_INTERNAL_ERROR;
            
            if (byte >> 4)
                continue;
            
            len = 1;
            back = (1 << 11) + (lzo_nextbyte(stream) << 2) + (byte >> 2) + 1;
            if (stream->error) return STATUS_INTERNAL_ERROR;
            
            break;
        }
        
        lzo_copyback(stream, back, len + 2);
        if (stream->error) return STATUS_INTERNAL_ERROR;
        
        len = byte & 3;
        
        if (len) {
            lzo_copy(stream, len);
            if (stream->error) return STATUS_INTERNAL_ERROR;
        } else
            backcopy = !backcopy;
        
        byte = lzo_nextbyte(stream);
        if (stream->error) return STATUS_INTERNAL_ERROR;
    }
    
    return STATUS_SUCCESS;
}

static NTSTATUS lzo_decompress(UINT8* inbuf, UINT64 inlen, UINT8* outbuf, UINT64 outlen) {
    NTSTATUS Status;
    UINT32 extlen, partlen, inoff, outoff;
    lzo_stream stream;
    
    extlen = *((UINT32*)inbuf);
    if (inlen < extlen) {
        ERR("compressed extent was %llx, should have been at least %x\n", inlen, extlen);
        return STATUS_INTERNAL_ERROR;
    }
    
    inoff = sizeof(UINT32);
    outoff = 0;
    
    do {
        partlen = *(UINT32*)&inbuf[inoff];
        
        if (partlen + inoff > inlen) {
            ERR("overflow: %x + %x > %llx\n", partlen, inoff, inlen);
            return STATUS_INTERNAL_ERROR;
        }
        
        inoff += sizeof(UINT32);
    
        stream.in = &inbuf[inoff];
        stream.inlen = partlen;
        stream.inpos = 0;
        stream.out = &outbuf[outoff];
        stream.outlen = LINUX_PAGE_SIZE;
        stream.outpos = 0;
        
        Status = do_lzo_decompress(&stream);
        if (!NT_SUCCESS(Status)) {
            ERR("do_lzo_decompress returned %08x\n", Status);
            return Status;
        }
        
        if (stream.outpos < stream.outlen)
            RtlZeroMemory(&stream.out[stream.outpos], stream.outlen - stream.outpos);
        
        inoff += partlen;
        outoff += stream.outlen;
        
        if (LINUX_PAGE_SIZE - (inoff % LINUX_PAGE_SIZE) < sizeof(UINT32))
            inoff = ((inoff / LINUX_PAGE_SIZE) + 1) * LINUX_PAGE_SIZE;
    } while (inoff < extlen);
    
    return STATUS_SUCCESS;
}

static void* zlib_alloc(void* opaque, unsigned int items, unsigned int size) {
    return ExAllocatePoolWithTag(PagedPool, items * size, ALLOC_TAG_ZLIB);
}

static void zlib_free(void* opaque, void* ptr) {
    ExFreePool(ptr);
}

static NTSTATUS zlib_decompress(UINT8* inbuf, UINT64 inlen, UINT8* outbuf, UINT64 outlen) {
    z_stream c_stream;
    int ret;

    c_stream.zalloc = zlib_alloc;
    c_stream.zfree = zlib_free;
    c_stream.opaque = (voidpf)0;

    ret = inflateInit(&c_stream);
    
    if (ret != Z_OK) {
        ERR("inflateInit returned %08x\n", ret);
        return STATUS_INTERNAL_ERROR;
    }

    c_stream.next_in = inbuf;
    c_stream.avail_in = inlen;
    
    c_stream.next_out = outbuf;
    c_stream.avail_out = outlen;
    
    do {
        ret = inflate(&c_stream, Z_NO_FLUSH);
        
        if (ret != Z_OK && ret != Z_STREAM_END) {
            ERR("inflate returned %08x\n", ret);
            inflateEnd(&c_stream);
            return STATUS_INTERNAL_ERROR;
        }
    } while (ret != Z_STREAM_END);

    ret = inflateEnd(&c_stream);
    
    if (ret != Z_OK) {
        ERR("inflateEnd returned %08x\n", ret);
        return STATUS_INTERNAL_ERROR;
    }
    
    // FIXME - if we're short, should we zero the end of outbuf so we don't leak information into userspace?
    
    return STATUS_SUCCESS;
}

NTSTATUS decompress(UINT8 type, UINT8* inbuf, UINT64 inlen, UINT8* outbuf, UINT64 outlen) {
    if (type == BTRFS_COMPRESSION_ZLIB)
        return zlib_decompress(inbuf, inlen, outbuf, outlen);
    else if (type == BTRFS_COMPRESSION_LZO)
        return lzo_decompress(inbuf, inlen, outbuf, outlen);
    else {
        ERR("unsupported compression type %x\n", type);
        return STATUS_NOT_SUPPORTED;
    }
}

NTSTATUS write_compressed_bit(fcb* fcb, UINT64 start_data, UINT64 end_data, void* data, LIST_ENTRY* changed_sector_list, PIRP Irp, LIST_ENTRY* rollback) {
    NTSTATUS Status;
    UINT8 compression;
    UINT64 comp_length;
    UINT8* comp_data;
    UINT32 out_left;
    LIST_ENTRY* le;
    chunk* c;
    z_stream c_stream;
    int ret;
    
    comp_data = ExAllocatePoolWithTag(PagedPool, end_data - start_data, ALLOC_TAG);
    if (!comp_data) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    Status = excise_extents(fcb->Vcb, fcb, start_data, end_data, rollback);
    if (!NT_SUCCESS(Status)) {
        ERR("excise_extents returned %08x\n", Status);
        ExFreePool(comp_data);
        return Status;
    }
    
    c_stream.zalloc = zlib_alloc;
    c_stream.zfree = zlib_free;
    c_stream.opaque = (voidpf)0;

    ret = deflateInit(&c_stream, 3);
    
    if (ret != Z_OK) {
        ERR("deflateInit returned %08x\n", ret);
        ExFreePool(comp_data);
        return STATUS_INTERNAL_ERROR;
    }
    
    c_stream.avail_in = end_data - start_data;
    c_stream.next_in = data;
    c_stream.avail_out = end_data - start_data;
    c_stream.next_out = comp_data;
    
    do {
        ret = deflate(&c_stream, Z_FINISH);
        
        if (ret == Z_STREAM_ERROR) {
            ERR("deflate returned %x\n", ret);
            ExFreePool(comp_data);
            return STATUS_INTERNAL_ERROR;
        }
    } while (c_stream.avail_in > 0 && c_stream.avail_out > 0);
    
    out_left = c_stream.avail_out;
    
    ret = deflateEnd(&c_stream);
    
    if (ret != Z_OK) {
        ERR("deflateEnd returned %08x\n", ret);
        ExFreePool(comp_data);
        return STATUS_INTERNAL_ERROR;
    }
    
    if (out_left < fcb->Vcb->superblock.sector_size) { // compressed extent would be larger than or same size as uncompressed extent
        ExFreePool(comp_data);
        
        comp_length = end_data - start_data;
        comp_data = data;
        compression = BTRFS_COMPRESSION_NONE;
    } else {
        UINT32 cl;
        
        compression = BTRFS_COMPRESSION_ZLIB;
        cl = end_data - start_data - out_left;
        comp_length = sector_align(cl, fcb->Vcb->superblock.sector_size);
        
        RtlZeroMemory(comp_data + cl, comp_length - cl);
    }
    
    ExAcquireResourceExclusiveLite(&fcb->Vcb->chunk_lock, TRUE);
    
    le = fcb->Vcb->chunks.Flink;
    while (le != &fcb->Vcb->chunks) {
        c = CONTAINING_RECORD(le, chunk, list_entry);
        
        ExAcquireResourceExclusiveLite(&c->nonpaged->lock, TRUE);
        
        if (c->chunk_item->type == fcb->Vcb->data_flags && (c->chunk_item->size - c->used) >= comp_length) {
            if (insert_extent_chunk(fcb->Vcb, fcb, c, start_data, comp_length, FALSE, comp_data, changed_sector_list, Irp, rollback, compression, end_data - start_data)) {
                ExReleaseResourceLite(&c->nonpaged->lock);
                ExReleaseResourceLite(&fcb->Vcb->chunk_lock);
                
                if (compression != BTRFS_COMPRESSION_NONE)
                    ExFreePool(comp_data);
                
                return STATUS_SUCCESS;
            }
        }
        
        ExReleaseResourceLite(&c->nonpaged->lock);

        le = le->Flink;
    }
    
    if ((c = alloc_chunk(fcb->Vcb, fcb->Vcb->data_flags, rollback))) {
        ExAcquireResourceExclusiveLite(&c->nonpaged->lock, TRUE);
        
        if (c->chunk_item->type == fcb->Vcb->data_flags && (c->chunk_item->size - c->used) >= comp_length) {
            if (insert_extent_chunk(fcb->Vcb, fcb, c, start_data, comp_length, FALSE, comp_data, changed_sector_list, Irp, rollback, compression, end_data - start_data)) {
                ExReleaseResourceLite(&c->nonpaged->lock);
                ExReleaseResourceLite(&fcb->Vcb->chunk_lock);
                
                if (compression != BTRFS_COMPRESSION_NONE)
                    ExFreePool(comp_data);
                
                return STATUS_SUCCESS;
            }
        }
        
        ExReleaseResourceLite(&c->nonpaged->lock);
    }
    
    ExReleaseResourceLite(&fcb->Vcb->chunk_lock);
    
    WARN("couldn't find any data chunks with %llx bytes free\n", comp_length);

    return STATUS_DISK_FULL;
}
