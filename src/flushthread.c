/* Copyright (c) Mark Harmstone 2016-17
 *
 * This file is part of WinBtrfs.
 *
 * WinBtrfs is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public Licence as published by
 * the Free Software Foundation, either version 3 of the Licence, or
 * (at your option) any later version.
 *
 * WinBtrfs is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public Licence for more details.
 *
 * You should have received a copy of the GNU Lesser General Public Licence
 * along with WinBtrfs.  If not, see <http://www.gnu.org/licenses/>. */

#include "btrfs_drv.h"
#include "zstd/lib/common/xxhash.h"
#include "crc32c.h"
#include <ata.h>
#include <ntddscsi.h>
#include <ntddstor.h>

/* cf. __MAX_CSUM_ITEMS in Linux - it needs sizeof(struct btrfs_item) bytes free
 * so it can do a split. Linux tries to get it so a run will fit in a
 * sector, but the MAX_CSUM_ITEMS logic is wrong... */
#define MAX_CSUM_SIZE (4096 - sizeof(struct btrfs_header) - (2 * sizeof(struct btrfs_item)))

// #define DEBUG_WRITE_LOOPS

#define BATCH_ITEM_LIMIT 1000

typedef struct {
    KEVENT Event;
    IO_STATUS_BLOCK iosb;
} write_context;

typedef struct {
    struct btrfs_extent_item extent_item;
    struct btrfs_tree_block_info tbi;
    struct btrfs_extent_inline_ref eir;
} EXTENT_ITEM_TREE2;

static_assert(sizeof(EXTENT_ITEM_TREE2) == 51, "EXTENT_ITEM_TREE2 has wrong size");

typedef struct {
    struct btrfs_extent_item ei;
    struct btrfs_extent_inline_ref eir;
} EXTENT_ITEM_SKINNY_METADATA;

static_assert(sizeof(EXTENT_ITEM_SKINNY_METADATA) == 33, "EXTENT_ITEM_SKINNY_METADATA has wrong size");

static NTSTATUS create_chunk(device_extension* Vcb, chunk* c, PIRP Irp);
static NTSTATUS update_tree_extents(device_extension* Vcb, tree* t, PIRP Irp, LIST_ENTRY* rollback);

static NTSTATUS insert_tree_item_batch(LIST_ENTRY* batchlist, device_extension* Vcb, root* r, uint64_t objid,
                                       uint8_t objtype, uint64_t offset, _In_opt_ _When_(return >= 0, __drv_aliasesMem) void* data,
                                       uint16_t datalen, enum batch_operation operation);

_Function_class_(IO_COMPLETION_ROUTINE)
static NTSTATUS __stdcall write_completion(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID conptr) {
    write_context* context = conptr;

    UNUSED(DeviceObject);

    context->iosb = Irp->IoStatus;
    KeSetEvent(&context->Event, 0, false);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS write_data_phys(_In_ PDEVICE_OBJECT device, _In_ PFILE_OBJECT fileobj, _In_ uint64_t address,
                         _In_reads_bytes_(length) void* data, _In_ uint32_t length) {
    NTSTATUS Status;
    LARGE_INTEGER offset;
    PIRP Irp;
    PIO_STACK_LOCATION IrpSp;
    write_context context;

    TRACE("(%p, %I64x, %p, %x)\n", device, address, data, length);

    RtlZeroMemory(&context, sizeof(write_context));

    KeInitializeEvent(&context.Event, NotificationEvent, false);

    offset.QuadPart = address;

    Irp = IoAllocateIrp(device->StackSize, false);

    if (!Irp) {
        ERR("IoAllocateIrp failed\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    IrpSp = IoGetNextIrpStackLocation(Irp);
    IrpSp->MajorFunction = IRP_MJ_WRITE;
    IrpSp->FileObject = fileobj;

    if (device->Flags & DO_BUFFERED_IO) {
        Irp->AssociatedIrp.SystemBuffer = data;

        Irp->Flags = IRP_BUFFERED_IO;
    } else if (device->Flags & DO_DIRECT_IO) {
        Irp->MdlAddress = IoAllocateMdl(data, length, false, false, NULL);
        if (!Irp->MdlAddress) {
            DbgPrint("IoAllocateMdl failed\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto exit;
        }

        Status = STATUS_SUCCESS;

        try {
            MmProbeAndLockPages(Irp->MdlAddress, KernelMode, IoReadAccess);
        } except (EXCEPTION_EXECUTE_HANDLER) {
            Status = GetExceptionCode();
        }

        if (!NT_SUCCESS(Status)) {
            ERR("MmProbeAndLockPages threw exception %08lx\n", Status);
            IoFreeMdl(Irp->MdlAddress);
            goto exit;
        }
    } else {
        Irp->UserBuffer = data;
    }

    IrpSp->Parameters.Write.Length = length;
    IrpSp->Parameters.Write.ByteOffset = offset;

    Irp->UserIosb = &context.iosb;

    Irp->UserEvent = &context.Event;

    IoSetCompletionRoutine(Irp, write_completion, &context, true, true, true);

    Status = IoCallDriver(device, Irp);

    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject(&context.Event, Executive, KernelMode, false, NULL);
        Status = context.iosb.Status;
    }

    if (!NT_SUCCESS(Status)) {
        ERR("IoCallDriver returned %08lx\n", Status);
    }

    if (device->Flags & DO_DIRECT_IO) {
        MmUnlockPages(Irp->MdlAddress);
        IoFreeMdl(Irp->MdlAddress);
    }

exit:
    IoFreeIrp(Irp);

    return Status;
}

static void add_trim_entry(device* dev, uint64_t address, uint64_t size) {
    space* s = ExAllocatePoolWithTag(PagedPool, sizeof(space), ALLOC_TAG);
    if (!s) {
        ERR("out of memory\n");
        return;
    }

    s->address = address;
    s->size = size;
    dev->num_trim_entries++;

    InsertTailList(&dev->trim_list, &s->list_entry);
}

static void clean_space_cache_chunk(device_extension* Vcb, chunk* c) {
    LIST_ENTRY* le;
    ULONG type;

    if (c->chunk_item->type & BLOCK_FLAG_DUPLICATE)
        type = BLOCK_FLAG_DUPLICATE;
    else if (c->chunk_item->type & BLOCK_FLAG_RAID0)
        type = BLOCK_FLAG_RAID0;
    else if (c->chunk_item->type & BLOCK_FLAG_RAID1)
        type = BLOCK_FLAG_DUPLICATE;
    else if (c->chunk_item->type & BLOCK_FLAG_RAID10)
        type = BLOCK_FLAG_RAID10;
    else if (c->chunk_item->type & BLOCK_FLAG_RAID5)
        type = BLOCK_FLAG_RAID5;
    else if (c->chunk_item->type & BLOCK_FLAG_RAID6)
        type = BLOCK_FLAG_RAID6;
    else if (c->chunk_item->type & BLOCK_FLAG_RAID1C3)
        type = BLOCK_FLAG_DUPLICATE;
    else if (c->chunk_item->type & BLOCK_FLAG_RAID1C4)
        type = BLOCK_FLAG_DUPLICATE;
    else // SINGLE
        type = BLOCK_FLAG_DUPLICATE;

    le = c->deleting.Flink;
    while (le != &c->deleting) {
        space* s = CONTAINING_RECORD(le, space, list_entry);

        if (!Vcb->options.no_barrier || !(c->chunk_item->type & BLOCK_FLAG_METADATA)) {
            if (type == BLOCK_FLAG_DUPLICATE) {
                uint16_t i;

                for (i = 0; i < c->chunk_item->num_stripes; i++) {
                    if (c->devices[i] && c->devices[i]->devobj && !c->devices[i]->readonly && c->devices[i]->trim)
                        add_trim_entry(c->devices[i], s->address - c->offset + c->chunk_item->stripe[i].offset, s->size);
                }
            } else if (type == BLOCK_FLAG_RAID0) {
                uint64_t startoff, endoff;
                uint16_t startoffstripe, endoffstripe, i;

                get_raid0_offset(s->address - c->offset, c->chunk_item->stripe_len, c->chunk_item->num_stripes, &startoff, &startoffstripe);
                get_raid0_offset(s->address - c->offset + s->size - 1, c->chunk_item->stripe_len, c->chunk_item->num_stripes, &endoff, &endoffstripe);

                for (i = 0; i < c->chunk_item->num_stripes; i++) {
                    if (c->devices[i] && c->devices[i]->devobj && !c->devices[i]->readonly && c->devices[i]->trim) {
                        uint64_t stripestart, stripeend;

                        if (startoffstripe > i)
                            stripestart = startoff - (startoff % c->chunk_item->stripe_len) + c->chunk_item->stripe_len;
                        else if (startoffstripe == i)
                            stripestart = startoff;
                        else
                            stripestart = startoff - (startoff % c->chunk_item->stripe_len);

                        if (endoffstripe > i)
                            stripeend = endoff - (endoff % c->chunk_item->stripe_len) + c->chunk_item->stripe_len;
                        else if (endoffstripe == i)
                            stripeend = endoff + 1;
                        else
                            stripeend = endoff - (endoff % c->chunk_item->stripe_len);

                        if (stripestart != stripeend)
                            add_trim_entry(c->devices[i], stripestart + c->chunk_item->stripe[i].offset, stripeend - stripestart);
                    }
                }
            } else if (type == BLOCK_FLAG_RAID10) {
                uint64_t startoff, endoff;
                uint16_t sub_stripes, startoffstripe, endoffstripe, i;

                sub_stripes = max(1, c->chunk_item->sub_stripes);

                get_raid0_offset(s->address - c->offset, c->chunk_item->stripe_len, c->chunk_item->num_stripes / sub_stripes, &startoff, &startoffstripe);
                get_raid0_offset(s->address - c->offset + s->size - 1, c->chunk_item->stripe_len, c->chunk_item->num_stripes / sub_stripes, &endoff, &endoffstripe);

                startoffstripe *= sub_stripes;
                endoffstripe *= sub_stripes;

                for (i = 0; i < c->chunk_item->num_stripes; i += sub_stripes) {
                    ULONG j;
                    uint64_t stripestart, stripeend;

                    if (startoffstripe > i)
                        stripestart = startoff - (startoff % c->chunk_item->stripe_len) + c->chunk_item->stripe_len;
                    else if (startoffstripe == i)
                        stripestart = startoff;
                    else
                        stripestart = startoff - (startoff % c->chunk_item->stripe_len);

                    if (endoffstripe > i)
                        stripeend = endoff - (endoff % c->chunk_item->stripe_len) + c->chunk_item->stripe_len;
                    else if (endoffstripe == i)
                        stripeend = endoff + 1;
                    else
                        stripeend = endoff - (endoff % c->chunk_item->stripe_len);

                    if (stripestart != stripeend) {
                        for (j = 0; j < sub_stripes; j++) {
                            if (c->devices[i+j] && c->devices[i+j]->devobj && !c->devices[i+j]->readonly && c->devices[i+j]->trim)
                                add_trim_entry(c->devices[i+j], stripestart + c->chunk_item->stripe[i+j].offset, stripeend - stripestart);
                        }
                    }
                }
            }
            // FIXME - RAID5(?), RAID6(?)
        }

        le = le->Flink;
    }
}

typedef struct {
    DEVICE_MANAGE_DATA_SET_ATTRIBUTES* dmdsa;
    ATA_PASS_THROUGH_EX apte;
    PIRP Irp;
    IO_STATUS_BLOCK iosb;
#ifdef DEBUG_TRIM_EMULATION
    PMDL mdl;
    void* buf;
#endif
} ioctl_context_stripe;

typedef struct {
    KEVENT Event;
    LONG left;
    ioctl_context_stripe* stripes;
} ioctl_context;

_Function_class_(IO_COMPLETION_ROUTINE)
static NTSTATUS __stdcall ioctl_completion(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID conptr) {
    ioctl_context* context = (ioctl_context*)conptr;
    LONG left2 = InterlockedDecrement(&context->left);

    UNUSED(DeviceObject);
    UNUSED(Irp);

    if (left2 == 0)
        KeSetEvent(&context->Event, 0, false);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

#ifdef DEBUG_TRIM_EMULATION
static void trim_emulation(device* dev) {
    LIST_ENTRY* le;
    ioctl_context context;
    unsigned int i = 0, count = 0;

    le = dev->trim_list.Flink;
    while (le != &dev->trim_list) {
        count++;
        le = le->Flink;
    }

    context.left = count;

    KeInitializeEvent(&context.Event, NotificationEvent, false);

    context.stripes = ExAllocatePoolWithTag(NonPagedPool, sizeof(ioctl_context_stripe) * context.left, ALLOC_TAG);
    if (!context.stripes) {
        ERR("out of memory\n");
        return;
    }

    RtlZeroMemory(context.stripes, sizeof(ioctl_context_stripe) * context.left);

    i = 0;
    le = dev->trim_list.Flink;
    while (le != &dev->trim_list) {
        ioctl_context_stripe* stripe = &context.stripes[i];
        space* s = CONTAINING_RECORD(le, space, list_entry);

        WARN("(%I64x, %I64x)\n", s->address, s->size);

        stripe->Irp = IoAllocateIrp(dev->devobj->StackSize, false);

        if (!stripe->Irp) {
            ERR("IoAllocateIrp failed\n");
        } else {
            PIO_STACK_LOCATION IrpSp = IoGetNextIrpStackLocation(stripe->Irp);
            IrpSp->MajorFunction = IRP_MJ_WRITE;
            IrpSp->FileObject = dev->fileobj;

            stripe->buf = ExAllocatePoolWithTag(NonPagedPool, (uint32_t)s->size, ALLOC_TAG);

            if (!stripe->buf) {
                ERR("out of memory\n");
            } else {
                RtlZeroMemory(stripe->buf, (uint32_t)s->size); // FIXME - randomize instead?

                stripe->mdl = IoAllocateMdl(stripe->buf, (uint32_t)s->size, false, false, NULL);

                if (!stripe->mdl) {
                    ERR("IoAllocateMdl failed\n");
                } else {
                    MmBuildMdlForNonPagedPool(stripe->mdl);

                    stripe->Irp->MdlAddress = stripe->mdl;

                    IrpSp->Parameters.Write.ByteOffset.QuadPart = s->address;
                    IrpSp->Parameters.Write.Length = s->size;

                    stripe->Irp->UserIosb = &stripe->iosb;

                    IoSetCompletionRoutine(stripe->Irp, ioctl_completion, &context, true, true, true);

                    IoCallDriver(dev->devobj, stripe->Irp);
                }
            }
        }

        i++;

        le = le->Flink;
    }

    KeWaitForSingleObject(&context.Event, Executive, KernelMode, false, NULL);

    for (i = 0; i < count; i++) {
        ioctl_context_stripe* stripe = &context.stripes[i];

        if (stripe->mdl)
            IoFreeMdl(stripe->mdl);

        if (stripe->buf)
            ExFreePool(stripe->buf);
    }

    ExFreePool(context.stripes);
}
#endif

static void clean_space_cache(device_extension* Vcb) {
    LIST_ENTRY* le;
    chunk* c;
#ifndef DEBUG_TRIM_EMULATION
    ULONG num;
#endif

    TRACE("(%p)\n", Vcb);

    ExAcquireResourceSharedLite(&Vcb->chunk_lock, true);

    le = Vcb->chunks.Flink;
    while (le != &Vcb->chunks) {
        c = CONTAINING_RECORD(le, chunk, list_entry);

        if (c->space_changed) {
            acquire_chunk_lock(c, Vcb);

            if (c->space_changed) {
                if (Vcb->trim && !Vcb->options.no_trim)
                    clean_space_cache_chunk(Vcb, c);

                space_list_merge(&c->space, &c->space_size, &c->deleting);

                while (!IsListEmpty(&c->deleting)) {
                    space* s = CONTAINING_RECORD(RemoveHeadList(&c->deleting), space, list_entry);

                    ExFreePool(s);
                }
            }

            c->space_changed = false;

            release_chunk_lock(c, Vcb);
        }

        le = le->Flink;
    }

    ExReleaseResourceLite(&Vcb->chunk_lock);

    if (Vcb->trim && !Vcb->options.no_trim) {
#ifndef DEBUG_TRIM_EMULATION
        ioctl_context context;
        ULONG total_num;

        context.left = 0;

        le = Vcb->devices.Flink;
        while (le != &Vcb->devices) {
            device* dev = CONTAINING_RECORD(le, device, list_entry);

            if (dev->devobj && !dev->readonly && dev->trim && dev->num_trim_entries > 0)
                context.left++;

            le = le->Flink;
        }

        if (context.left == 0)
            return;

        total_num = context.left;
        num = 0;

        KeInitializeEvent(&context.Event, NotificationEvent, false);

        context.stripes = ExAllocatePoolWithTag(NonPagedPool, sizeof(ioctl_context_stripe) * context.left, ALLOC_TAG);
        if (!context.stripes) {
            ERR("out of memory\n");
            return;
        }

        RtlZeroMemory(context.stripes, sizeof(ioctl_context_stripe) * context.left);
#endif

        le = Vcb->devices.Flink;
        while (le != &Vcb->devices) {
            device* dev = CONTAINING_RECORD(le, device, list_entry);

            if (dev->devobj && !dev->readonly && dev->trim && dev->num_trim_entries > 0) {
#ifdef DEBUG_TRIM_EMULATION
                trim_emulation(dev);
#else
                LIST_ENTRY* le2;
                ioctl_context_stripe* stripe = &context.stripes[num];
                DEVICE_DATA_SET_RANGE* ranges;
                ULONG datalen = (ULONG)sector_align(sizeof(DEVICE_MANAGE_DATA_SET_ATTRIBUTES), sizeof(uint64_t)) + (dev->num_trim_entries * sizeof(DEVICE_DATA_SET_RANGE)), i;
                PIO_STACK_LOCATION IrpSp;

                stripe->dmdsa = ExAllocatePoolWithTag(PagedPool, datalen, ALLOC_TAG);
                if (!stripe->dmdsa) {
                    ERR("out of memory\n");
                    goto nextdev;
                }

                stripe->dmdsa->Size = sizeof(DEVICE_MANAGE_DATA_SET_ATTRIBUTES);
                stripe->dmdsa->Action = DeviceDsmAction_Trim;
                stripe->dmdsa->Flags = DEVICE_DSM_FLAG_TRIM_NOT_FS_ALLOCATED;
                stripe->dmdsa->ParameterBlockOffset = 0;
                stripe->dmdsa->ParameterBlockLength = 0;
                stripe->dmdsa->DataSetRangesOffset = (ULONG)sector_align(sizeof(DEVICE_MANAGE_DATA_SET_ATTRIBUTES), sizeof(uint64_t));
                stripe->dmdsa->DataSetRangesLength = dev->num_trim_entries * sizeof(DEVICE_DATA_SET_RANGE);

                ranges = (DEVICE_DATA_SET_RANGE*)((uint8_t*)stripe->dmdsa + stripe->dmdsa->DataSetRangesOffset);

                i = 0;

                le2 = dev->trim_list.Flink;
                while (le2 != &dev->trim_list) {
                    space* s = CONTAINING_RECORD(le2, space, list_entry);

                    ranges[i].StartingOffset = s->address;
                    ranges[i].LengthInBytes = s->size;
                    i++;

                    le2 = le2->Flink;
                }

                stripe->Irp = IoAllocateIrp(dev->devobj->StackSize, false);

                if (!stripe->Irp) {
                    ERR("IoAllocateIrp failed\n");
                    goto nextdev;
                }

                IrpSp = IoGetNextIrpStackLocation(stripe->Irp);
                IrpSp->MajorFunction = IRP_MJ_DEVICE_CONTROL;
                IrpSp->FileObject = dev->fileobj;

                IrpSp->Parameters.DeviceIoControl.IoControlCode = IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES;
                IrpSp->Parameters.DeviceIoControl.InputBufferLength = datalen;
                IrpSp->Parameters.DeviceIoControl.OutputBufferLength = 0;

                stripe->Irp->AssociatedIrp.SystemBuffer = stripe->dmdsa;
                stripe->Irp->Flags |= IRP_BUFFERED_IO;
                stripe->Irp->UserBuffer = NULL;
                stripe->Irp->UserIosb = &stripe->iosb;

                IoSetCompletionRoutine(stripe->Irp, ioctl_completion, &context, true, true, true);

                IoCallDriver(dev->devobj, stripe->Irp);

nextdev:
#endif
                while (!IsListEmpty(&dev->trim_list)) {
                    space* s = CONTAINING_RECORD(RemoveHeadList(&dev->trim_list), space, list_entry);
                    ExFreePool(s);
                }

                dev->num_trim_entries = 0;

#ifndef DEBUG_TRIM_EMULATION
                num++;
#endif
            }

            le = le->Flink;
        }

#ifndef DEBUG_TRIM_EMULATION
        KeWaitForSingleObject(&context.Event, Executive, KernelMode, false, NULL);

        for (num = 0; num < total_num; num++) {
            if (context.stripes[num].dmdsa)
                ExFreePool(context.stripes[num].dmdsa);

            if (context.stripes[num].Irp)
                IoFreeIrp(context.stripes[num].Irp);
        }

        ExFreePool(context.stripes);
#endif
    }
}

static bool trees_consistent(device_extension* Vcb) {
    ULONG maxsize = Vcb->superblock.nodesize - sizeof(struct btrfs_header);
    LIST_ENTRY* le;

    le = Vcb->trees.Flink;
    while (le != &Vcb->trees) {
        tree* t = CONTAINING_RECORD(le, tree, list_entry);

        if (t->write) {
            if (t->header.nritems == 0 && t->parent) {
#ifdef DEBUG_WRITE_LOOPS
                ERR("empty tree found, looping again\n");
#endif
                return false;
            }

            if (t->size > maxsize) {
#ifdef DEBUG_WRITE_LOOPS
                ERR("overlarge tree found (%u > %u), looping again\n", t->size, maxsize);
#endif
                return false;
            }

            if (!t->has_new_address) {
#ifdef DEBUG_WRITE_LOOPS
                ERR("tree found without new address, looping again\n");
#endif
                return false;
            }
        }

        le = le->Flink;
    }

    return true;
}

static NTSTATUS add_parents(device_extension* Vcb, PIRP Irp) {
    ULONG level;
    LIST_ENTRY* le;

    for (level = 0; level <= 255; level++) {
        bool nothing_found = true;

        TRACE("level = %lu\n", level);

        le = Vcb->trees.Flink;
        while (le != &Vcb->trees) {
            tree* t = CONTAINING_RECORD(le, tree, list_entry);

            if (t->write && t->header.level == level) {
                TRACE("tree %p: root = %I64x, level = %x, parent = %p\n", t, t->header.owner, t->header.level, t->parent);

                nothing_found = false;

                if (t->parent) {
                    if (!t->parent->write)
                        TRACE("adding tree %p (level %x)\n", t->parent, t->header.level);

                    t->parent->write = true;
                } else if (t->root != Vcb->root_root && t->root != Vcb->chunk_root) {
                    struct btrfs_key searchkey;
                    traverse_ptr tp;
                    NTSTATUS Status;

                    searchkey.objectid = t->root->id;
                    searchkey.type = TYPE_ROOT_ITEM;
                    searchkey.offset = 0xffffffffffffffff;

                    Status = find_item(Vcb, Vcb->root_root, &tp, &searchkey, false, Irp);
                    if (!NT_SUCCESS(Status)) {
                        ERR("error - find_item returned %08lx\n", Status);
                        return Status;
                    }

                    if (tp.item->key.objectid != searchkey.objectid || tp.item->key.type != searchkey.type) {
                        ERR("could not find ROOT_ITEM for tree %I64x\n", searchkey.objectid);
                        return STATUS_INTERNAL_ERROR;
                    }

                    if (tp.item->size < sizeof(struct btrfs_root_item)) { // if not full length, delete and create new entry
                        struct btrfs_root_item* ri = ExAllocatePoolWithTag(PagedPool, sizeof(struct btrfs_root_item), ALLOC_TAG);

                        if (!ri) {
                            ERR("out of memory\n");
                            return STATUS_INSUFFICIENT_RESOURCES;
                        }

                        RtlCopyMemory(ri, &t->root->root_item, sizeof(struct btrfs_root_item));

                        Status = delete_tree_item(Vcb, &tp);
                        if (!NT_SUCCESS(Status)) {
                            ERR("delete_tree_item returned %08lx\n", Status);
                            ExFreePool(ri);
                            return Status;
                        }

                        Status = insert_tree_item(Vcb, Vcb->root_root, tp.item->key.objectid, tp.item->key.type, tp.item->key.offset, ri, sizeof(struct btrfs_root_item), NULL, Irp);
                        if (!NT_SUCCESS(Status)) {
                            ERR("insert_tree_item returned %08lx\n", Status);
                            ExFreePool(ri);
                            return Status;
                        }
                    }

                    tree* t2 = tp.tree;
                    while (t2) {
                        t2->write = true;

                        t2 = t2->parent;
                    }
                }
            }

            le = le->Flink;
        }

        if (nothing_found)
            break;
    }

    return STATUS_SUCCESS;
}

static void add_parents_to_cache(tree* t) {
    while (t->parent) {
        t = t->parent;
        t->write = true;
    }
}

static bool insert_tree_extent_skinny(device_extension* Vcb, uint8_t level, uint64_t root_id, chunk* c, uint64_t address, PIRP Irp, LIST_ENTRY* rollback) {
    NTSTATUS Status;
    EXTENT_ITEM_SKINNY_METADATA* eism;
    traverse_ptr insert_tp;

    eism = ExAllocatePoolWithTag(PagedPool, sizeof(EXTENT_ITEM_SKINNY_METADATA), ALLOC_TAG);
    if (!eism) {
        ERR("out of memory\n");
        return false;
    }

    eism->ei.refs = 1;
    eism->ei.generation = Vcb->superblock.generation;
    eism->ei.flags = EXTENT_ITEM_TREE_BLOCK;
    eism->eir.type = TYPE_TREE_BLOCK_REF;
    eism->eir.offset = root_id;

    Status = insert_tree_item(Vcb, Vcb->extent_root, address, TYPE_METADATA_ITEM, level, eism, sizeof(EXTENT_ITEM_SKINNY_METADATA), &insert_tp, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("insert_tree_item returned %08lx\n", Status);
        ExFreePool(eism);
        return false;
    }

    acquire_chunk_lock(c, Vcb);

    space_list_subtract(c, address, Vcb->superblock.nodesize, rollback);

    release_chunk_lock(c, Vcb);

    add_parents_to_cache(insert_tp.tree);

    return true;
}

bool find_metadata_address_in_chunk(device_extension* Vcb, chunk* c, uint64_t* address) {
    LIST_ENTRY* le;
    space* s;

    TRACE("(%p, %I64x, %p)\n", Vcb, c->offset, address);

    if (Vcb->superblock.nodesize > c->chunk_item->length - c->used)
        return false;

    if (!c->cache_loaded) {
        NTSTATUS Status = load_cache_chunk(Vcb, c, NULL);

        if (!NT_SUCCESS(Status)) {
            ERR("load_cache_chunk returned %08lx\n", Status);
            return false;
        }
    }

    if (IsListEmpty(&c->space_size))
        return false;

    if (!c->last_alloc_set) {
        s = CONTAINING_RECORD(c->space.Blink, space, list_entry);

        c->last_alloc = s->address;
        c->last_alloc_set = true;

        if (s->size >= Vcb->superblock.nodesize) {
            *address = s->address;
            c->last_alloc += Vcb->superblock.nodesize;
            return true;
        }
    }

    le = c->space.Flink;
    while (le != &c->space) {
        s = CONTAINING_RECORD(le, space, list_entry);

        if (s->address <= c->last_alloc && s->address + s->size >= c->last_alloc + Vcb->superblock.nodesize) {
            *address = c->last_alloc;
            c->last_alloc += Vcb->superblock.nodesize;
            return true;
        }

        le = le->Flink;
    }

    le = c->space_size.Flink;
    while (le != &c->space_size) {
        s = CONTAINING_RECORD(le, space, list_entry_size);

        if (s->size == Vcb->superblock.nodesize) {
            *address = s->address;
            c->last_alloc = s->address + Vcb->superblock.nodesize;
            return true;
        } else if (s->size < Vcb->superblock.nodesize) {
            if (le == c->space_size.Flink)
                return false;

            s = CONTAINING_RECORD(le->Blink, space, list_entry_size);

            *address = s->address;
            c->last_alloc = s->address + Vcb->superblock.nodesize;

            return true;
        }

        le = le->Flink;
    }

    s = CONTAINING_RECORD(c->space_size.Blink, space, list_entry_size);

    if (s->size > Vcb->superblock.nodesize) {
        *address = s->address;
        c->last_alloc = s->address + Vcb->superblock.nodesize;
        return true;
    }

    return false;
}

static bool insert_tree_extent(device_extension* Vcb, uint8_t level, uint64_t root_id, chunk* c, uint64_t* new_address, PIRP Irp, LIST_ENTRY* rollback) {
    NTSTATUS Status;
    uint64_t address;
    EXTENT_ITEM_TREE2* eit2;
    traverse_ptr insert_tp;

    TRACE("(%p, %x, %I64x, %p, %p, %p, %p)\n", Vcb, level, root_id, c, new_address, Irp, rollback);

    if (!find_metadata_address_in_chunk(Vcb, c, &address))
        return false;

    if (Vcb->superblock.incompat_flags & BTRFS_INCOMPAT_FLAGS_SKINNY_METADATA) {
        bool b = insert_tree_extent_skinny(Vcb, level, root_id, c, address, Irp, rollback);

        if (b)
            *new_address = address;

        return b;
    }

    eit2 = ExAllocatePoolWithTag(PagedPool, sizeof(EXTENT_ITEM_TREE2), ALLOC_TAG);
    if (!eit2) {
        ERR("out of memory\n");
        return false;
    }

    eit2->extent_item.refs = 1;
    eit2->extent_item.generation = Vcb->superblock.generation;
    eit2->extent_item.flags = EXTENT_ITEM_TREE_BLOCK;
    eit2->tbi.level = level;
    eit2->eir.type = TYPE_TREE_BLOCK_REF;
    eit2->eir.offset = root_id;

    Status = insert_tree_item(Vcb, Vcb->extent_root, address, TYPE_EXTENT_ITEM, Vcb->superblock.nodesize, eit2, sizeof(EXTENT_ITEM_TREE2), &insert_tp, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("insert_tree_item returned %08lx\n", Status);
        ExFreePool(eit2);
        return false;
    }

    acquire_chunk_lock(c, Vcb);

    space_list_subtract(c, address, Vcb->superblock.nodesize, rollback);

    release_chunk_lock(c, Vcb);

    add_parents_to_cache(insert_tp.tree);

    *new_address = address;

    return true;
}

NTSTATUS get_tree_new_address(device_extension* Vcb, tree* t, PIRP Irp, LIST_ENTRY* rollback) {
    NTSTATUS Status;
    chunk *origchunk = NULL, *c;
    LIST_ENTRY* le;
    uint64_t flags, addr;

    if (t->root->id == BTRFS_ROOT_CHUNK)
        flags = Vcb->system_flags;
    else
        flags = Vcb->metadata_flags;

    if (t->has_address) {
        origchunk = get_chunk_from_address(Vcb, t->header.bytenr);

        if (origchunk && !origchunk->readonly && !origchunk->reloc && origchunk->chunk_item->type == flags &&
            insert_tree_extent(Vcb, t->header.level, t->root->id, origchunk, &addr, Irp, rollback)) {
            t->new_address = addr;
            t->has_new_address = true;
            return STATUS_SUCCESS;
        }
    }

    ExAcquireResourceExclusiveLite(&Vcb->chunk_lock, true);

    le = Vcb->chunks.Flink;
    while (le != &Vcb->chunks) {
        c = CONTAINING_RECORD(le, chunk, list_entry);

        if (!c->readonly && !c->reloc) {
            acquire_chunk_lock(c, Vcb);

            if (c != origchunk && c->chunk_item->type == flags && (c->chunk_item->length - c->used) >= Vcb->superblock.nodesize) {
                if (insert_tree_extent(Vcb, t->header.level, t->root->id, c, &addr, Irp, rollback)) {
                    release_chunk_lock(c, Vcb);
                    ExReleaseResourceLite(&Vcb->chunk_lock);
                    t->new_address = addr;
                    t->has_new_address = true;
                    return STATUS_SUCCESS;
                }
            }

            release_chunk_lock(c, Vcb);
        }

        le = le->Flink;
    }

    // allocate new chunk if necessary

    Status = alloc_chunk(Vcb, flags, &c, false);

    if (!NT_SUCCESS(Status)) {
        ERR("alloc_chunk returned %08lx\n", Status);
        ExReleaseResourceLite(&Vcb->chunk_lock);
        return Status;
    }

    acquire_chunk_lock(c, Vcb);

    if ((c->chunk_item->length - c->used) >= Vcb->superblock.nodesize) {
        if (insert_tree_extent(Vcb, t->header.level, t->root->id, c, &addr, Irp, rollback)) {
            release_chunk_lock(c, Vcb);
            ExReleaseResourceLite(&Vcb->chunk_lock);
            t->new_address = addr;
            t->has_new_address = true;
            return STATUS_SUCCESS;
        }
    }

    release_chunk_lock(c, Vcb);

    ExReleaseResourceLite(&Vcb->chunk_lock);

    ERR("couldn't find any metadata chunks with %x bytes free\n", Vcb->superblock.nodesize);

    return STATUS_DISK_FULL;
}

static NTSTATUS reduce_tree_extent(device_extension* Vcb, uint64_t address, tree* t, uint64_t parent_root, uint8_t level, PIRP Irp, LIST_ENTRY* rollback) {
    NTSTATUS Status;
    uint64_t rc, root;

    TRACE("(%p, %I64x, %p)\n", Vcb, address, t);

    rc = get_extent_refcount(Vcb, address, Vcb->superblock.nodesize, Irp);
    if (rc == 0) {
        ERR("error - refcount for extent %I64x was 0\n", address);
        return STATUS_INTERNAL_ERROR;
    }

    if (!t || t->parent)
        root = parent_root;
    else
        root = t->header.owner;

    Status = decrease_extent_refcount_tree(Vcb, address, Vcb->superblock.nodesize, root, level, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("decrease_extent_refcount_tree returned %08lx\n", Status);
        return Status;
    }

    if (rc == 1) {
        chunk* c = get_chunk_from_address(Vcb, address);

        if (c) {
            acquire_chunk_lock(c, Vcb);

            if (!c->cache_loaded) {
                Status = load_cache_chunk(Vcb, c, NULL);

                if (!NT_SUCCESS(Status)) {
                    ERR("load_cache_chunk returned %08lx\n", Status);
                    release_chunk_lock(c, Vcb);
                    return Status;
                }
            }

            c->used -= Vcb->superblock.nodesize;

            space_list_add(c, address, Vcb->superblock.nodesize, rollback);

            release_chunk_lock(c, Vcb);
        } else
            ERR("could not find chunk for address %I64x\n", address);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS add_changed_extent_ref_edr(changed_extent* ce, struct btrfs_extent_data_ref* edr, bool old) {
    LIST_ENTRY *le2, *list;
    changed_extent_ref* cer;

    list = old ? &ce->old_refs : &ce->refs;

    le2 = list->Flink;
    while (le2 != list) {
        cer = CONTAINING_RECORD(le2, changed_extent_ref, list_entry);

        if (cer->type == TYPE_EXTENT_DATA_REF && cer->edr.root == edr->root && cer->edr.objectid == edr->objectid && cer->edr.offset == edr->offset) {
            cer->edr.count += edr->count;
            goto end;
        }

        le2 = le2->Flink;
    }

    cer = ExAllocatePoolWithTag(PagedPool, sizeof(changed_extent_ref), ALLOC_TAG);
    if (!cer) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    cer->type = TYPE_EXTENT_DATA_REF;
    RtlCopyMemory(&cer->edr, edr, sizeof(struct btrfs_extent_data_ref));
    InsertTailList(list, &cer->list_entry);

end:
    if (old)
        ce->old_count += edr->count;
    else
        ce->count += edr->count;

    return STATUS_SUCCESS;
}

static NTSTATUS add_changed_extent_ref_sdr(changed_extent* ce, SHARED_DATA_REF* sdr, bool old) {
    LIST_ENTRY *le2, *list;
    changed_extent_ref* cer;

    list = old ? &ce->old_refs : &ce->refs;

    le2 = list->Flink;
    while (le2 != list) {
        cer = CONTAINING_RECORD(le2, changed_extent_ref, list_entry);

        if (cer->type == TYPE_SHARED_DATA_REF && cer->sdr.offset == sdr->offset) {
            cer->sdr.count += sdr->count;
            goto end;
        }

        le2 = le2->Flink;
    }

    cer = ExAllocatePoolWithTag(PagedPool, sizeof(changed_extent_ref), ALLOC_TAG);
    if (!cer) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    cer->type = TYPE_SHARED_DATA_REF;
    RtlCopyMemory(&cer->sdr, sdr, sizeof(SHARED_DATA_REF));
    InsertTailList(list, &cer->list_entry);

end:
    if (old)
        ce->old_count += sdr->count;
    else
        ce->count += sdr->count;

    return STATUS_SUCCESS;
}

static bool shared_tree_is_unique(device_extension* Vcb, tree* t, PIRP Irp, LIST_ENTRY* rollback) {
    struct btrfs_key searchkey;
    traverse_ptr tp;
    NTSTATUS Status;

    if (!t->updated_extents && t->has_address) {
        Status = update_tree_extents(Vcb, t, Irp, rollback);
        if (!NT_SUCCESS(Status)) {
            ERR("update_tree_extents returned %08lx\n", Status);
            return false;
        }
    }

    searchkey.objectid = t->header.bytenr;
    searchkey.type = Vcb->superblock.incompat_flags & BTRFS_INCOMPAT_FLAGS_SKINNY_METADATA ? TYPE_METADATA_ITEM : TYPE_EXTENT_ITEM;
    searchkey.offset = 0xffffffffffffffff;

    Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, false, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08lx\n", Status);
        return false;
    }

    if (tp.item->key.objectid == t->header.bytenr && (tp.item->key.type == TYPE_METADATA_ITEM || tp.item->key.type == TYPE_EXTENT_ITEM))
        return false;
    else
        return true;
}

static NTSTATUS update_tree_extents(device_extension* Vcb, tree* t, PIRP Irp, LIST_ENTRY* rollback) {
    NTSTATUS Status;
    uint64_t rc = get_extent_refcount(Vcb, t->header.bytenr, Vcb->superblock.nodesize, Irp);
    uint64_t flags = get_extent_flags(Vcb, t->header.bytenr, Irp);

    if (rc == 0) {
        ERR("refcount for extent %I64x was 0\n", t->header.bytenr);
        return STATUS_INTERNAL_ERROR;
    }

    if (flags & EXTENT_ITEM_SHARED_BACKREFS || t->header.flags & HEADER_FLAG_SHARED_BACKREF || !(t->header.flags & HEADER_FLAG_MIXED_BACKREF)) {
        bool unique = rc > 1 ? false : (t->parent ? shared_tree_is_unique(Vcb, t->parent, Irp, rollback) : false);
        uint64_t offset;

        if (t->header.level == 0) {
            LIST_ENTRY* le;

            le = t->itemlist.Flink;
            while (le != &t->itemlist) {
                tree_data* td = CONTAINING_RECORD(le, tree_data, list_entry);

                if (!td->inserted && td->key.type == TYPE_EXTENT_DATA && td->size >= sizeof(struct btrfs_file_extent_item)) {
                    struct btrfs_file_extent_item* ed = (struct btrfs_file_extent_item*)td->data;

                    if (ed->type == EXTENT_TYPE_REGULAR || ed->type == EXTENT_TYPE_PREALLOC) {
                        if (ed->disk_num_bytes > 0) {
                            struct btrfs_extent_data_ref edr;
                            changed_extent* ce = NULL;
                            chunk* c = get_chunk_from_address(Vcb, ed->disk_bytenr);

                            if (c) {
                                LIST_ENTRY* le2;

                                le2 = c->changed_extents.Flink;
                                while (le2 != &c->changed_extents) {
                                    changed_extent* ce2 = CONTAINING_RECORD(le2, changed_extent, list_entry);

                                    if (ce2->address == ed->disk_bytenr) {
                                        ce = ce2;
                                        break;
                                    }

                                    le2 = le2->Flink;
                                }
                            }

                            edr.root = t->root->id;
                            edr.objectid = td->key.objectid;
                            edr.offset = td->key.offset - ed->offset;
                            edr.count = 1;

                            if (ce) {
                                Status = add_changed_extent_ref_edr(ce, &edr, true);
                                if (!NT_SUCCESS(Status)) {
                                    ERR("add_changed_extent_ref_edr returned %08lx\n", Status);
                                    return Status;
                                }

                                Status = add_changed_extent_ref_edr(ce, &edr, false);
                                if (!NT_SUCCESS(Status)) {
                                    ERR("add_changed_extent_ref_edr returned %08lx\n", Status);
                                    return Status;
                                }
                            }

                            Status = increase_extent_refcount(Vcb, ed->disk_bytenr, ed->disk_num_bytes, TYPE_EXTENT_DATA_REF, &edr, NULL, 0, Irp);
                            if (!NT_SUCCESS(Status)) {
                                ERR("increase_extent_refcount returned %08lx\n", Status);
                                return Status;
                            }

                            if ((flags & EXTENT_ITEM_SHARED_BACKREFS && unique) || !(t->header.flags & HEADER_FLAG_MIXED_BACKREF)) {
                                uint64_t sdrrc = find_extent_shared_data_refcount(Vcb, ed->disk_bytenr, t->header.bytenr, Irp);

                                if (sdrrc > 0) {
                                    SHARED_DATA_REF sdr;

                                    sdr.offset = t->header.bytenr;
                                    sdr.count = 1;

                                    Status = decrease_extent_refcount(Vcb, ed->disk_bytenr, ed->disk_num_bytes, TYPE_SHARED_DATA_REF, &sdr, NULL, 0,
                                                                      t->header.bytenr, ce ? ce->superseded : false, Irp);
                                    if (!NT_SUCCESS(Status)) {
                                        ERR("decrease_extent_refcount returned %08lx\n", Status);
                                        return Status;
                                    }

                                    if (ce) {
                                        LIST_ENTRY* le2;

                                        le2 = ce->refs.Flink;
                                        while (le2 != &ce->refs) {
                                            changed_extent_ref* cer = CONTAINING_RECORD(le2, changed_extent_ref, list_entry);

                                            if (cer->type == TYPE_SHARED_DATA_REF && cer->sdr.offset == sdr.offset) {
                                                ce->count--;
                                                cer->sdr.count--;
                                                break;
                                            }

                                            le2 = le2->Flink;
                                        }

                                        le2 = ce->old_refs.Flink;
                                        while (le2 != &ce->old_refs) {
                                            changed_extent_ref* cer = CONTAINING_RECORD(le2, changed_extent_ref, list_entry);

                                            if (cer->type == TYPE_SHARED_DATA_REF && cer->sdr.offset == sdr.offset) {
                                                ce->old_count--;

                                                if (cer->sdr.count > 1)
                                                    cer->sdr.count--;
                                                else {
                                                    RemoveEntryList(&cer->list_entry);
                                                    ExFreePool(cer);
                                                }

                                                break;
                                            }

                                            le2 = le2->Flink;
                                        }
                                    }
                                }
                            }

                            // FIXME - clear shared flag if unique?
                        }
                    }
                }

                le = le->Flink;
            }
        } else {
            LIST_ENTRY* le;

            le = t->itemlist.Flink;
            while (le != &t->itemlist) {
                tree_data* td = CONTAINING_RECORD(le, tree_data, list_entry);

                if (!td->inserted) {
                    Status = increase_extent_refcount_tree(Vcb, td->treeholder.address,
                                                           t->root->id, &td->key,
                                                           t->header.level - 1, Irp);
                    if (!NT_SUCCESS(Status)) {
                        ERR("increase_extent_refcount_tree returned %08lx\n", Status);
                        return Status;
                    }

                    if (unique || !(t->header.flags & HEADER_FLAG_MIXED_BACKREF)) {
                        uint64_t sbrrc = find_extent_shared_tree_refcount(Vcb, td->treeholder.address, t->header.bytenr, Irp);

                        if (sbrrc > 0) {
                            SHARED_BLOCK_REF sbr;

                            sbr.offset = t->header.bytenr;

                            Status = decrease_extent_refcount(Vcb, td->treeholder.address, Vcb->superblock.nodesize, TYPE_SHARED_BLOCK_REF, &sbr, NULL, 0,
                                                              t->header.bytenr, false, Irp);
                            if (!NT_SUCCESS(Status)) {
                                ERR("decrease_extent_refcount returned %08lx\n", Status);
                                return Status;
                            }
                        }
                    }

                    // FIXME - clear shared flag if unique?
                }

                le = le->Flink;
            }
        }

        if (unique) {
            uint64_t sbrrc = find_extent_shared_tree_refcount(Vcb, t->header.bytenr, t->parent->header.bytenr, Irp);

            if (sbrrc == 1) {
                SHARED_BLOCK_REF sbr;

                sbr.offset = t->parent->header.bytenr;

                Status = decrease_extent_refcount(Vcb, t->header.bytenr, Vcb->superblock.nodesize, TYPE_SHARED_BLOCK_REF, &sbr, NULL, 0,
                                                  t->parent->header.bytenr, false, Irp);
                if (!NT_SUCCESS(Status)) {
                    ERR("decrease_extent_refcount returned %08lx\n", Status);
                    return Status;
                }
            }
        }

        if (t->parent)
            offset = t->parent->header.owner;
        else
            offset = t->header.owner;

        Status = increase_extent_refcount_tree(Vcb, t->header.bytenr, offset,
                                               t->parent ? &t->paritem->key : NULL, t->header.level, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("increase_extent_refcount returned %08lx\n", Status);
            return Status;
        }

        // FIXME - clear shared flag if unique?

        t->header.flags &= ~HEADER_FLAG_SHARED_BACKREF;
    }

    if (rc > 1 || t->header.owner == t->root->id) {
        Status = reduce_tree_extent(Vcb, t->header.bytenr, t, t->parent ? t->parent->header.owner : t->header.owner, t->header.level, Irp, rollback);

        if (!NT_SUCCESS(Status)) {
            ERR("reduce_tree_extent returned %08lx\n", Status);
            return Status;
        }
    }

    t->has_address = false;

    if ((rc > 1 || t->header.owner != t->root->id) && !(flags & EXTENT_ITEM_SHARED_BACKREFS)) {
        if (t->header.owner == t->root->id) {
            flags |= EXTENT_ITEM_SHARED_BACKREFS;
            update_extent_flags(Vcb, t->header.bytenr, flags, Irp);
        }

        if (t->header.level > 0) {
            LIST_ENTRY* le;

            le = t->itemlist.Flink;
            while (le != &t->itemlist) {
                tree_data* td = CONTAINING_RECORD(le, tree_data, list_entry);

                if (!td->inserted) {
                    if (t->header.owner == t->root->id) {
                        SHARED_BLOCK_REF sbr;

                        sbr.offset = t->header.bytenr;

                        Status = increase_extent_refcount(Vcb, td->treeholder.address, Vcb->superblock.nodesize, TYPE_SHARED_BLOCK_REF, &sbr, &td->key, t->header.level - 1, Irp);
                    } else {
                        Status = increase_extent_refcount_tree(Vcb, td->treeholder.address,
                                                               t->root->id, &td->key,
                                                               t->header.level - 1, Irp);
                    }

                    if (!NT_SUCCESS(Status)) {
                        ERR("increase_extent_refcount returned %08lx\n", Status);
                        return Status;
                    }
                }

                le = le->Flink;
            }
        } else {
            LIST_ENTRY* le;

            le = t->itemlist.Flink;
            while (le != &t->itemlist) {
                tree_data* td = CONTAINING_RECORD(le, tree_data, list_entry);

                if (!td->inserted && td->key.type == TYPE_EXTENT_DATA && td->size >= sizeof(struct btrfs_file_extent_item)) {
                    struct btrfs_file_extent_item* ed = (struct btrfs_file_extent_item*)td->data;

                    if (ed->type == EXTENT_TYPE_REGULAR || ed->type == EXTENT_TYPE_PREALLOC) {
                        if (ed->disk_num_bytes > 0) {
                            changed_extent* ce = NULL;
                            chunk* c = get_chunk_from_address(Vcb, ed->disk_bytenr);

                            if (c) {
                                LIST_ENTRY* le2;

                                le2 = c->changed_extents.Flink;
                                while (le2 != &c->changed_extents) {
                                    changed_extent* ce2 = CONTAINING_RECORD(le2, changed_extent, list_entry);

                                    if (ce2->address == ed->disk_bytenr) {
                                        ce = ce2;
                                        break;
                                    }

                                    le2 = le2->Flink;
                                }
                            }

                            if (t->header.owner == t->root->id) {
                                SHARED_DATA_REF sdr;

                                sdr.offset = t->header.bytenr;
                                sdr.count = 1;

                                if (ce) {
                                    Status = add_changed_extent_ref_sdr(ce, &sdr, true);
                                    if (!NT_SUCCESS(Status)) {
                                        ERR("add_changed_extent_ref_edr returned %08lx\n", Status);
                                        return Status;
                                    }

                                    Status = add_changed_extent_ref_sdr(ce, &sdr, false);
                                    if (!NT_SUCCESS(Status)) {
                                        ERR("add_changed_extent_ref_edr returned %08lx\n", Status);
                                        return Status;
                                    }
                                }

                                Status = increase_extent_refcount(Vcb, ed->disk_bytenr, ed->disk_num_bytes, TYPE_SHARED_DATA_REF, &sdr, NULL, 0, Irp);
                            } else {
                                struct btrfs_extent_data_ref edr;

                                edr.root = t->root->id;
                                edr.objectid = td->key.objectid;
                                edr.offset = td->key.offset - ed->offset;
                                edr.count = 1;

                                if (ce) {
                                    Status = add_changed_extent_ref_edr(ce, &edr, true);
                                    if (!NT_SUCCESS(Status)) {
                                        ERR("add_changed_extent_ref_edr returned %08lx\n", Status);
                                        return Status;
                                    }

                                    Status = add_changed_extent_ref_edr(ce, &edr, false);
                                    if (!NT_SUCCESS(Status)) {
                                        ERR("add_changed_extent_ref_edr returned %08lx\n", Status);
                                        return Status;
                                    }
                                }

                                Status = increase_extent_refcount(Vcb, ed->disk_bytenr, ed->disk_num_bytes, TYPE_EXTENT_DATA_REF, &edr, NULL, 0, Irp);
                            }

                            if (!NT_SUCCESS(Status)) {
                                ERR("increase_extent_refcount returned %08lx\n", Status);
                                return Status;
                            }
                        }
                    }
                }

                le = le->Flink;
            }
        }
    }

    t->updated_extents = true;
    t->header.owner = t->root->id;

    return STATUS_SUCCESS;
}

static NTSTATUS allocate_tree_extents(device_extension* Vcb, PIRP Irp, LIST_ENTRY* rollback) {
    LIST_ENTRY* le;
    NTSTATUS Status;
    bool changed = false;
    uint8_t max_level = 0, level;

    TRACE("(%p)\n", Vcb);

    le = Vcb->trees.Flink;
    while (le != &Vcb->trees) {
        tree* t = CONTAINING_RECORD(le, tree, list_entry);

        if (t->write && !t->has_new_address) {
            chunk* c;

            if (t->has_address) {
                c = get_chunk_from_address(Vcb, t->header.bytenr);

                if (c) {
                    if (!c->cache_loaded) {
                        acquire_chunk_lock(c, Vcb);

                        if (!c->cache_loaded) {
                            Status = load_cache_chunk(Vcb, c, NULL);

                            if (!NT_SUCCESS(Status)) {
                                ERR("load_cache_chunk returned %08lx\n", Status);
                                release_chunk_lock(c, Vcb);
                                return Status;
                            }
                        }

                        release_chunk_lock(c, Vcb);
                    }
                }
            }

            Status = get_tree_new_address(Vcb, t, Irp, rollback);
            if (!NT_SUCCESS(Status)) {
                ERR("get_tree_new_address returned %08lx\n", Status);
                return Status;
            }

            TRACE("allocated extent %I64x\n", t->new_address);

            c = get_chunk_from_address(Vcb, t->new_address);

            if (c)
                c->used += Vcb->superblock.nodesize;
            else {
                ERR("could not find chunk for address %I64x\n", t->new_address);
                return STATUS_INTERNAL_ERROR;
            }

            changed = true;

            if (t->header.level > max_level)
                max_level = t->header.level;
        }

        le = le->Flink;
    }

    if (!changed)
        return STATUS_SUCCESS;

    level = max_level;
    do {
        le = Vcb->trees.Flink;
        while (le != &Vcb->trees) {
            tree* t = CONTAINING_RECORD(le, tree, list_entry);

            if (t->write && !t->updated_extents && t->has_address && t->header.level == level) {
                Status = update_tree_extents(Vcb, t, Irp, rollback);
                if (!NT_SUCCESS(Status)) {
                    ERR("update_tree_extents returned %08lx\n", Status);
                    return Status;
                }
            }

            le = le->Flink;
        }

        if (level == 0)
            break;

        level--;
    } while (true);

    return STATUS_SUCCESS;
}

static NTSTATUS update_root_root(device_extension* Vcb, bool no_cache, PIRP Irp, LIST_ENTRY* rollback) {
    LIST_ENTRY* le;
    NTSTATUS Status;

    TRACE("(%p)\n", Vcb);

    le = Vcb->trees.Flink;
    while (le != &Vcb->trees) {
        tree* t = CONTAINING_RECORD(le, tree, list_entry);

        if (t->write && !t->parent) {
            if (t->root != Vcb->root_root && t->root != Vcb->chunk_root) {
                struct btrfs_key searchkey;
                traverse_ptr tp;

                searchkey.objectid = t->root->id;
                searchkey.type = TYPE_ROOT_ITEM;
                searchkey.offset = 0xffffffffffffffff;

                Status = find_item(Vcb, Vcb->root_root, &tp, &searchkey, false, Irp);
                if (!NT_SUCCESS(Status)) {
                    ERR("error - find_item returned %08lx\n", Status);
                    return Status;
                }

                if (tp.item->key.objectid != searchkey.objectid || tp.item->key.type != searchkey.type) {
                    ERR("could not find ROOT_ITEM for tree %I64x\n", searchkey.objectid);
                    return STATUS_INTERNAL_ERROR;
                }

                TRACE("updating the address for root %I64x to %I64x\n", searchkey.objectid, t->new_address);

                t->root->root_item.bytenr = t->new_address;
                t->root->root_item.level = t->header.level;
                t->root->root_item.generation = Vcb->superblock.generation;
                t->root->root_item.generation_v2 = Vcb->superblock.generation;

                // item is guaranteed to be at least sizeof(struct btrfs_root_item), due to add_parents

                RtlCopyMemory(tp.item->data, &t->root->root_item, sizeof(struct btrfs_root_item));
            }

            t->root->treeholder.address = t->new_address;
            t->root->treeholder.generation = Vcb->superblock.generation;
        }

        le = le->Flink;
    }

    if (!no_cache && !(Vcb->superblock.compat_ro_flags & BTRFS_COMPAT_RO_FLAGS_FREE_SPACE_CACHE)) {
        ExAcquireResourceSharedLite(&Vcb->chunk_lock, true);
        Status = update_chunk_caches(Vcb, Irp, rollback);
        ExReleaseResourceLite(&Vcb->chunk_lock);

        if (!NT_SUCCESS(Status)) {
            ERR("update_chunk_caches returned %08lx\n", Status);
            return Status;
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS do_tree_writes(device_extension* Vcb, LIST_ENTRY* tree_writes, bool no_free) {
    chunk* c;
    LIST_ENTRY* le;
    tree_write* tw;
    NTSTATUS Status;
    ULONG i, num_bits;
    write_data_context* wtc;
    ULONG bit_num = 0;
    bool raid56 = false;

    // merge together runs
    c = NULL;
    le = tree_writes->Flink;
    while (le != tree_writes) {
        tw = CONTAINING_RECORD(le, tree_write, list_entry);

        if (!c || tw->address < c->offset || tw->address >= c->offset + c->chunk_item->length)
            c = get_chunk_from_address(Vcb, tw->address);
        else {
            tree_write* tw2 = CONTAINING_RECORD(le->Blink, tree_write, list_entry);

            if (tw->address == tw2->address + tw2->length) {
                uint8_t* data = ExAllocatePoolWithTag(NonPagedPool, tw2->length + tw->length, ALLOC_TAG);

                if (!data) {
                    ERR("out of memory\n");
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                RtlCopyMemory(data, tw2->data, tw2->length);
                RtlCopyMemory(&data[tw2->length], tw->data, tw->length);

                if (!no_free || tw2->allocated)
                    ExFreePool(tw2->data);

                tw2->data = data;
                tw2->length += tw->length;
                tw2->allocated = true;

                if (!no_free || tw->allocated)
                    ExFreePool(tw->data);

                RemoveEntryList(&tw->list_entry);
                ExFreePool(tw);

                le = tw2->list_entry.Flink;
                continue;
            }
        }

        tw->c = c;

        if (c->chunk_item->type & (BLOCK_FLAG_RAID5 | BLOCK_FLAG_RAID6))
            raid56 = true;

        le = le->Flink;
    }

    num_bits = 0;

    le = tree_writes->Flink;
    while (le != tree_writes) {
        tw = CONTAINING_RECORD(le, tree_write, list_entry);

        num_bits++;

        le = le->Flink;
    }

    wtc = ExAllocatePoolWithTag(NonPagedPool, sizeof(write_data_context) * num_bits, ALLOC_TAG);
    if (!wtc) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    le = tree_writes->Flink;

    while (le != tree_writes) {
        tw = CONTAINING_RECORD(le, tree_write, list_entry);

        TRACE("address: %I64x, size: %x\n", tw->address, tw->length);

        KeInitializeEvent(&wtc[bit_num].Event, NotificationEvent, false);
        InitializeListHead(&wtc[bit_num].stripes);
        wtc[bit_num].need_wait = false;
        wtc[bit_num].stripes_left = 0;
        wtc[bit_num].parity1 = wtc[bit_num].parity2 = wtc[bit_num].scratch = NULL;
        wtc[bit_num].mdl = wtc[bit_num].parity1_mdl = wtc[bit_num].parity2_mdl = NULL;

        Status = write_data(Vcb, tw->address, tw->data, tw->length, &wtc[bit_num], NULL, NULL, false, 0, HighPagePriority);
        if (!NT_SUCCESS(Status)) {
            ERR("write_data returned %08lx\n", Status);

            for (i = 0; i < num_bits; i++) {
                free_write_data_stripes(&wtc[i]);
            }
            ExFreePool(wtc);

            return Status;
        }

        bit_num++;

        le = le->Flink;
    }

    for (i = 0; i < num_bits; i++) {
        if (wtc[i].stripes.Flink != &wtc[i].stripes) {
            // launch writes and wait
            le = wtc[i].stripes.Flink;
            while (le != &wtc[i].stripes) {
                write_data_stripe* stripe = CONTAINING_RECORD(le, write_data_stripe, list_entry);

                if (stripe->status != WriteDataStatus_Ignore) {
                    wtc[i].need_wait = true;
                    IoCallDriver(stripe->device->devobj, stripe->Irp);
                }

                le = le->Flink;
            }
        }
    }

    for (i = 0; i < num_bits; i++) {
        if (wtc[i].need_wait)
            KeWaitForSingleObject(&wtc[i].Event, Executive, KernelMode, false, NULL);
    }

    for (i = 0; i < num_bits; i++) {
        le = wtc[i].stripes.Flink;
        while (le != &wtc[i].stripes) {
            write_data_stripe* stripe = CONTAINING_RECORD(le, write_data_stripe, list_entry);

            if (stripe->status != WriteDataStatus_Ignore && !NT_SUCCESS(stripe->iosb.Status)) {
                Status = stripe->iosb.Status;
                log_device_error(Vcb, stripe->device, BTRFS_DEV_STAT_WRITE_ERRORS);
                break;
            }

            le = le->Flink;
        }

        free_write_data_stripes(&wtc[i]);
    }

    ExFreePool(wtc);

    if (raid56) {
        c = NULL;

        le = tree_writes->Flink;
        while (le != tree_writes) {
            tw = CONTAINING_RECORD(le, tree_write, list_entry);

            if (tw->c != c) {
                c = tw->c;

                ExAcquireResourceExclusiveLite(&c->partial_stripes_lock, true);

                while (!IsListEmpty(&c->partial_stripes)) {
                    partial_stripe* ps = CONTAINING_RECORD(RemoveHeadList(&c->partial_stripes), partial_stripe, list_entry);

                    Status = flush_partial_stripe(Vcb, c, ps);

                    if (ps->bmparr)
                        ExFreePool(ps->bmparr);

                    ExFreePool(ps);

                    if (!NT_SUCCESS(Status)) {
                        ERR("flush_partial_stripe returned %08lx\n", Status);
                        ExReleaseResourceLite(&c->partial_stripes_lock);
                        return Status;
                    }
                }

                ExReleaseResourceLite(&c->partial_stripes_lock);
            }

            le = le->Flink;
        }
    }

    return STATUS_SUCCESS;
}

void calc_tree_checksum(device_extension* Vcb, struct btrfs_header* th) {
    switch (Vcb->superblock.csum_type) {
        case CSUM_TYPE_CRC32C:
            *((uint32_t*)th) = ~calc_crc32c(0xffffffff, (uint8_t*)&th->fsid, Vcb->superblock.nodesize - sizeof(th->csum));
        break;

        case CSUM_TYPE_XXHASH:
            *((uint64_t*)th) = XXH64((uint8_t*)&th->fsid, Vcb->superblock.nodesize - sizeof(th->csum), 0);
        break;

        case CSUM_TYPE_SHA256:
            calc_sha256((uint8_t*)th, &th->fsid, Vcb->superblock.nodesize - sizeof(th->csum));
        break;

        case CSUM_TYPE_BLAKE2:
            blake2b((uint8_t*)th, BLAKE2_HASH_SIZE, &th->fsid, Vcb->superblock.nodesize - sizeof(th->csum));
        break;
    }
}

static NTSTATUS write_trees(device_extension* Vcb, PIRP Irp) {
    ULONG level;
    uint8_t *data, *body;
    NTSTATUS Status;
    LIST_ENTRY* le;
    LIST_ENTRY tree_writes;
    tree_write* tw;

    TRACE("(%p)\n", Vcb);

    InitializeListHead(&tree_writes);

    for (level = 0; level <= 255; level++) {
        bool nothing_found = true;

        TRACE("level = %lu\n", level);

        le = Vcb->trees.Flink;
        while (le != &Vcb->trees) {
            tree* t = CONTAINING_RECORD(le, tree, list_entry);

            if (t->write && t->header.level == level) {
                struct btrfs_key firstitem, searchkey;
                LIST_ENTRY* le2;
                traverse_ptr tp;

                if (!t->has_new_address) {
                    ERR("error - tried to write tree with no new address\n");
                    return STATUS_INTERNAL_ERROR;
                }

                le2 = t->itemlist.Flink;
                while (le2 != &t->itemlist) {
                    tree_data* td = CONTAINING_RECORD(le2, tree_data, list_entry);
                    if (!td->ignore) {
                        firstitem = td->key;
                        break;
                    }
                    le2 = le2->Flink;
                }

                if (t->parent) {
                    t->paritem->key = firstitem;
                    t->paritem->treeholder.address = t->new_address;
                    t->paritem->treeholder.generation = Vcb->superblock.generation;
                }

                if (!(Vcb->superblock.incompat_flags & BTRFS_INCOMPAT_FLAGS_SKINNY_METADATA)) {
                    struct btrfs_extent_item* ei;
                    struct btrfs_tree_block_info* tbi;

                    searchkey.objectid = t->new_address;
                    searchkey.type = TYPE_EXTENT_ITEM;
                    searchkey.offset = Vcb->superblock.nodesize;

                    Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, false, Irp);
                    if (!NT_SUCCESS(Status)) {
                        ERR("error - find_item returned %08lx\n", Status);
                        return Status;
                    }

                    if (keycmp(searchkey, tp.item->key)) {
                        ERR("could not find %I64x,%x,%I64x in extent_root (found %I64x,%x,%I64x instead)\n", searchkey.objectid, searchkey.type, searchkey.offset, tp.item->key.objectid, tp.item->key.type, tp.item->key.offset);
                        return STATUS_INTERNAL_ERROR;
                    }

                    if (tp.item->size < sizeof(struct btrfs_extent_item) + sizeof(struct btrfs_tree_block_info)) {
                        ERR("(%I64x,%x,%I64x) was %u bytes, expected at least %Iu\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset, tp.item->size, sizeof(struct btrfs_extent_item) + sizeof(struct btrfs_tree_block_info));
                        return STATUS_INTERNAL_ERROR;
                    }

                    ei = (struct btrfs_extent_item*)tp.item->data;
                    tbi = (struct btrfs_tree_block_info*)&ei[1];

                    tbi->key = firstitem;
                }

                nothing_found = false;
            }

            le = le->Flink;
        }

        if (nothing_found)
            break;
    }

    TRACE("allocated tree extents\n");

    le = Vcb->trees.Flink;
    while (le != &Vcb->trees) {
        tree* t = CONTAINING_RECORD(le, tree, list_entry);
        LIST_ENTRY* le2;
#ifdef DEBUG_PARANOID
        uint32_t num_items = 0, size = 0;
        bool crash = false;
#endif

        if (t->write) {
#ifdef DEBUG_PARANOID
            bool first = true;
            struct btrfs_key lastkey;

            le2 = t->itemlist.Flink;
            while (le2 != &t->itemlist) {
                tree_data* td = CONTAINING_RECORD(le2, tree_data, list_entry);
                if (!td->ignore) {
                    num_items++;

                    if (!first) {
                        if (keycmp(td->key, lastkey) == 0) {
                            ERR("(%I64x,%x,%I64x): duplicate key\n", td->key.objectid, td->key.type, td->key.offset);
                            crash = true;
                        } else if (keycmp(td->key, lastkey) == -1) {
                            ERR("(%I64x,%x,%I64x): key out of order\n", td->key.objectid, td->key.type, td->key.offset);
                            crash = true;
                        }
                    } else
                        first = false;

                    lastkey = td->key;

                    if (t->header.level == 0)
                        size += td->size;
                }
                le2 = le2->Flink;
            }

            if (t->header.level == 0)
                size += num_items * sizeof(struct btrfs_item);
            else
                size += num_items * sizeof(struct btrfs_key_ptr);

            if (num_items != t->header.nritems) {
                ERR("tree %I64x, level %x: num_items was %x, expected %x\n", t->root->id, t->header.level, num_items, t->header.nritems);
                crash = true;
            }

            if (size != t->size) {
                ERR("tree %I64x, level %x: size was %x, expected %x\n", t->root->id, t->header.level, size, t->size);
                crash = true;
            }

            if (t->header.nritems == 0 && t->parent) {
                ERR("tree %I64x, level %x: tried to write empty tree with parent\n", t->root->id, t->header.level);
                crash = true;
            }

            if (t->size > Vcb->superblock.nodesize - sizeof(struct btrfs_header)) {
                ERR("tree %I64x, level %x: tried to write overlarge tree (%x > %Ix)\n", t->root->id, t->header.level, t->size, Vcb->superblock.nodesize - sizeof(struct btrfs_header));
                crash = true;
            }

            if (crash) {
                ERR("tree %p\n", t);
                le2 = t->itemlist.Flink;
                while (le2 != &t->itemlist) {
                    tree_data* td = CONTAINING_RECORD(le2, tree_data, list_entry);
                    if (!td->ignore) {
                        ERR("%I64x,%x,%I64x inserted=%u\n", td->key.objectid, td->key.type, td->key.offset, td->inserted);
                    }
                    le2 = le2->Flink;
                }
                int3;
            }
#endif
            t->header.bytenr = t->new_address;
            t->header.generation = Vcb->superblock.generation;
            t->header.owner = t->root->id;
            t->header.flags |= HEADER_FLAG_MIXED_BACKREF;
            t->header.fsid = Vcb->superblock.metadata_uuid;
            t->has_address = true;

            data = ExAllocatePoolWithTag(NonPagedPool, Vcb->superblock.nodesize, ALLOC_TAG);
            if (!data) {
                ERR("out of memory\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto end;
            }

            body = data + sizeof(struct btrfs_header);

            RtlCopyMemory(data, &t->header, sizeof(struct btrfs_header));
            RtlZeroMemory(body, Vcb->superblock.nodesize - sizeof(struct btrfs_header));

            if (t->header.level == 0) {
                struct btrfs_item* itemptr = (struct btrfs_item*)body;
                int i = 0;
                uint8_t* dataptr = data + Vcb->superblock.nodesize;

                le2 = t->itemlist.Flink;
                while (le2 != &t->itemlist) {
                    tree_data* td = CONTAINING_RECORD(le2, tree_data, list_entry);
                    if (!td->ignore) {
                        dataptr = dataptr - td->size;

                        itemptr[i].key = td->key;
                        itemptr[i].offset = (uint32_t)((uint8_t*)dataptr - (uint8_t*)body);
                        itemptr[i].size = td->size;
                        i++;

                        if (td->size > 0)
                            RtlCopyMemory(dataptr, td->data, td->size);
                    }

                    le2 = le2->Flink;
                }
            } else {
                struct btrfs_key_ptr* itemptr = (struct btrfs_key_ptr*)body;
                int i = 0;

                le2 = t->itemlist.Flink;
                while (le2 != &t->itemlist) {
                    tree_data* td = CONTAINING_RECORD(le2, tree_data, list_entry);
                    if (!td->ignore) {
                        itemptr[i].key = td->key;
                        itemptr[i].blockptr = td->treeholder.address;
                        itemptr[i].generation = td->treeholder.generation;
                        i++;
                    }

                    le2 = le2->Flink;
                }
            }

            calc_tree_checksum(Vcb, (struct btrfs_header*)data);

            tw = ExAllocatePoolWithTag(PagedPool, sizeof(tree_write), ALLOC_TAG);
            if (!tw) {
                ERR("out of memory\n");
                ExFreePool(data);
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto end;
            }

            tw->address = t->new_address;
            tw->length = Vcb->superblock.nodesize;
            tw->data = data;
            tw->allocated = false;

            if (IsListEmpty(&tree_writes))
                InsertTailList(&tree_writes, &tw->list_entry);
            else {
                bool inserted = false;

                le2 = tree_writes.Flink;
                while (le2 != &tree_writes) {
                    tree_write* tw2 = CONTAINING_RECORD(le2, tree_write, list_entry);

                    if (tw2->address > tw->address) {
                        InsertHeadList(le2->Blink, &tw->list_entry);
                        inserted = true;
                        break;
                    }

                    le2 = le2->Flink;
                }

                if (!inserted)
                    InsertTailList(&tree_writes, &tw->list_entry);
            }
        }

        le = le->Flink;
    }

    Status = do_tree_writes(Vcb, &tree_writes, false);
    if (!NT_SUCCESS(Status)) {
        ERR("do_tree_writes returned %08lx\n", Status);
        goto end;
    }

    Status = STATUS_SUCCESS;

end:
    while (!IsListEmpty(&tree_writes)) {
        le = RemoveHeadList(&tree_writes);
        tw = CONTAINING_RECORD(le, tree_write, list_entry);

        if (tw->data)
            ExFreePool(tw->data);

        ExFreePool(tw);
    }

    return Status;
}

static void update_backup_superblock(device_extension* Vcb, struct btrfs_root_backup* sb, PIRP Irp) {
    struct btrfs_key searchkey;
    traverse_ptr tp;

    RtlZeroMemory(sb, sizeof(struct btrfs_root_backup));

    sb->tree_root = Vcb->superblock.root;
    sb->tree_root_gen = Vcb->superblock.generation;
    sb->tree_root_level = Vcb->superblock.root_level;

    sb->chunk_root = Vcb->superblock.chunk_root;
    sb->chunk_root_gen = Vcb->superblock.chunk_root_generation;
    sb->chunk_root_level = Vcb->superblock.chunk_root_level;

    searchkey.objectid = BTRFS_ROOT_EXTENT;
    searchkey.type = TYPE_ROOT_ITEM;
    searchkey.offset = 0xffffffffffffffff;

    if (NT_SUCCESS(find_item(Vcb, Vcb->root_root, &tp, &searchkey, false, Irp))) {
        if (tp.item->key.objectid == searchkey.objectid && tp.item->key.type == searchkey.type && tp.item->size >= sizeof(struct btrfs_root_item)) {
            struct btrfs_root_item* ri = (struct btrfs_root_item*)tp.item->data;

            sb->extent_root = ri->bytenr;
            sb->extent_root_gen = ri->generation;
            sb->extent_root_level = ri->level;
        }
    }

    searchkey.objectid = BTRFS_ROOT_FSTREE;

    if (NT_SUCCESS(find_item(Vcb, Vcb->root_root, &tp, &searchkey, false, Irp))) {
        if (tp.item->key.objectid == searchkey.objectid && tp.item->key.type == searchkey.type && tp.item->size >= sizeof(struct btrfs_root_item)) {
            struct btrfs_root_item* ri = (struct btrfs_root_item*)tp.item->data;

            sb->fs_root = ri->bytenr;
            sb->fs_root_gen = ri->generation;
            sb->fs_root_level = ri->level;
        }
    }

    searchkey.objectid = BTRFS_ROOT_DEVTREE;

    if (NT_SUCCESS(find_item(Vcb, Vcb->root_root, &tp, &searchkey, false, Irp))) {
        if (tp.item->key.objectid == searchkey.objectid && tp.item->key.type == searchkey.type && tp.item->size >= sizeof(struct btrfs_root_item)) {
            struct btrfs_root_item* ri = (struct btrfs_root_item*)tp.item->data;

            sb->dev_root = ri->bytenr;
            sb->dev_root_gen = ri->generation;
            sb->dev_root_level = ri->level;
        }
    }

    searchkey.objectid = BTRFS_ROOT_CHECKSUM;

    if (NT_SUCCESS(find_item(Vcb, Vcb->root_root, &tp, &searchkey, false, Irp))) {
        if (tp.item->key.objectid == searchkey.objectid && tp.item->key.type == searchkey.type && tp.item->size >= sizeof(struct btrfs_root_item)) {
            struct btrfs_root_item* ri = (struct btrfs_root_item*)tp.item->data;

            sb->csum_root = ri->bytenr;
            sb->csum_root_gen = ri->generation;
            sb->csum_root_level = ri->level;
        }
    }

    sb->total_bytes = Vcb->superblock.total_bytes;
    sb->bytes_used = Vcb->superblock.bytes_used;
    sb->num_devices = Vcb->superblock.num_devices;
}

typedef struct {
    void* context;
    uint8_t* buf;
    PMDL mdl;
    device* device;
    NTSTATUS Status;
    PIRP Irp;
    LIST_ENTRY list_entry;
} write_superblocks_stripe;

typedef struct _write_superblocks_context {
    KEVENT Event;
    LIST_ENTRY stripes;
    LONG left;
} write_superblocks_context;

_Function_class_(IO_COMPLETION_ROUTINE)
static NTSTATUS __stdcall write_superblock_completion(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID conptr) {
    write_superblocks_stripe* stripe = conptr;
    write_superblocks_context* context = stripe->context;

    UNUSED(DeviceObject);

    stripe->Status = Irp->IoStatus.Status;

    if (InterlockedDecrement(&context->left) == 0)
        KeSetEvent(&context->Event, 0, false);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

static void calc_superblock_checksum(struct btrfs_super_block* sb) {
    switch (sb->csum_type) {
        case CSUM_TYPE_CRC32C:
            *(uint32_t*)sb = ~calc_crc32c(0xffffffff, (uint8_t*)&sb->fsid, (ULONG)sizeof(struct btrfs_super_block) - sizeof(sb->csum));
        break;

        case CSUM_TYPE_XXHASH:
            *(uint64_t*)sb = XXH64(&sb->fsid, sizeof(struct btrfs_super_block) - sizeof(sb->csum), 0);
        break;

        case CSUM_TYPE_SHA256:
            calc_sha256((uint8_t*)sb, &sb->fsid, sizeof(struct btrfs_super_block) - sizeof(sb->csum));
        break;

        case CSUM_TYPE_BLAKE2:
            blake2b((uint8_t*)sb, BLAKE2_HASH_SIZE, &sb->fsid, sizeof(struct btrfs_super_block) - sizeof(sb->csum));
        break;
    }
}

static NTSTATUS write_superblock(device_extension* Vcb, device* device, write_superblocks_context* context) {
    unsigned int i = 0;

    // All the documentation says that the Linux driver only writes one superblock
    // if it thinks a disk is an SSD, but this doesn't seem to be the case!

    while (superblock_addrs[i] > 0 && device->devitem.total_bytes >= superblock_addrs[i] + sizeof(struct btrfs_super_block)) {
        ULONG sblen = (ULONG)sector_align(sizeof(struct btrfs_super_block), Vcb->superblock.sectorsize);
        struct btrfs_super_block* sb;
        write_superblocks_stripe* stripe;
        PIO_STACK_LOCATION IrpSp;

        sb = ExAllocatePoolWithTag(NonPagedPool, sblen, ALLOC_TAG);
        if (!sb) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlCopyMemory(sb, &Vcb->superblock, sizeof(struct btrfs_super_block));

        if (sblen > sizeof(struct btrfs_super_block))
            RtlZeroMemory((uint8_t*)sb + sizeof(struct btrfs_super_block), sblen - sizeof(struct btrfs_super_block));

        RtlCopyMemory(&sb->dev_item, &device->devitem, sizeof(struct btrfs_dev_item));
        sb->bytenr = superblock_addrs[i];

        calc_superblock_checksum(sb);

        stripe = ExAllocatePoolWithTag(NonPagedPool, sizeof(write_superblocks_stripe), ALLOC_TAG);
        if (!stripe) {
            ERR("out of memory\n");
            ExFreePool(sb);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        stripe->buf = (uint8_t*)sb;

        stripe->Irp = IoAllocateIrp(device->devobj->StackSize, false);
        if (!stripe->Irp) {
            ERR("IoAllocateIrp failed\n");
            ExFreePool(stripe);
            ExFreePool(sb);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        IrpSp = IoGetNextIrpStackLocation(stripe->Irp);
        IrpSp->MajorFunction = IRP_MJ_WRITE;
        IrpSp->FileObject = device->fileobj;

        if (i == 0)
            IrpSp->Flags |= SL_WRITE_THROUGH;

        if (device->devobj->Flags & DO_BUFFERED_IO) {
            stripe->Irp->AssociatedIrp.SystemBuffer = sb;
            stripe->mdl = NULL;

            stripe->Irp->Flags = IRP_BUFFERED_IO;
        } else if (device->devobj->Flags & DO_DIRECT_IO) {
            stripe->mdl = IoAllocateMdl(sb, sblen, false, false, NULL);
            if (!stripe->mdl) {
                ERR("IoAllocateMdl failed\n");
                IoFreeIrp(stripe->Irp);
                ExFreePool(stripe);
                ExFreePool(sb);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            stripe->Irp->MdlAddress = stripe->mdl;

            MmBuildMdlForNonPagedPool(stripe->mdl);
        } else {
            stripe->Irp->UserBuffer = sb;
            stripe->mdl = NULL;
        }

        IrpSp->Parameters.Write.Length = sblen;
        IrpSp->Parameters.Write.ByteOffset.QuadPart = superblock_addrs[i];

        IoSetCompletionRoutine(stripe->Irp, write_superblock_completion, stripe, true, true, true);

        stripe->context = context;
        stripe->device = device;
        InsertTailList(&context->stripes, &stripe->list_entry);

        context->left++;

        i++;
    }

    if (i == 0)
        ERR("no superblocks written!\n");

    return STATUS_SUCCESS;
}

static NTSTATUS write_superblocks(device_extension* Vcb, PIRP Irp) {
    uint64_t i;
    NTSTATUS Status;
    LIST_ENTRY* le;
    write_superblocks_context context;

    TRACE("(%p)\n", Vcb);

    le = Vcb->trees.Flink;
    while (le != &Vcb->trees) {
        tree* t = CONTAINING_RECORD(le, tree, list_entry);

        if (t->write && !t->parent) {
            if (t->root == Vcb->root_root) {
                Vcb->superblock.root = t->new_address;
                Vcb->superblock.root_level = t->header.level;
            } else if (t->root == Vcb->chunk_root) {
                Vcb->superblock.chunk_root = t->new_address;
                Vcb->superblock.chunk_root_generation = t->header.generation;
                Vcb->superblock.chunk_root_level = t->header.level;
            }
        }

        le = le->Flink;
    }

    for (i = 0; i < BTRFS_NUM_BACKUP_ROOTS - 1; i++) {
        RtlCopyMemory(&Vcb->superblock.super_roots[i], &Vcb->superblock.super_roots[i+1], sizeof(struct btrfs_root_backup));
    }

    update_backup_superblock(Vcb, &Vcb->superblock.super_roots[BTRFS_NUM_BACKUP_ROOTS - 1], Irp);

    KeInitializeEvent(&context.Event, NotificationEvent, false);
    InitializeListHead(&context.stripes);
    context.left = 0;

    le = Vcb->devices.Flink;
    while (le != &Vcb->devices) {
        device* dev = CONTAINING_RECORD(le, device, list_entry);

        if (dev->devobj && !dev->readonly) {
            Status = write_superblock(Vcb, dev, &context);
            if (!NT_SUCCESS(Status)) {
                ERR("write_superblock returned %08lx\n", Status);
                goto end;
            }
        }

        le = le->Flink;
    }

    if (IsListEmpty(&context.stripes)) {
        ERR("error - not writing any superblocks\n");
        Status = STATUS_INTERNAL_ERROR;
        goto end;
    }

    le = context.stripes.Flink;
    while (le != &context.stripes) {
        write_superblocks_stripe* stripe = CONTAINING_RECORD(le, write_superblocks_stripe, list_entry);

        IoCallDriver(stripe->device->devobj, stripe->Irp);

        le = le->Flink;
    }

    KeWaitForSingleObject(&context.Event, Executive, KernelMode, false, NULL);

    le = context.stripes.Flink;
    while (le != &context.stripes) {
        write_superblocks_stripe* stripe = CONTAINING_RECORD(le, write_superblocks_stripe, list_entry);

        if (!NT_SUCCESS(stripe->Status)) {
            ERR("device %I64x returned %08lx\n", stripe->device->devitem.devid, stripe->Status);
            log_device_error(Vcb, stripe->device, BTRFS_DEV_STAT_WRITE_ERRORS);
            Status = stripe->Status;
            goto end;
        }

        le = le->Flink;
    }

    Status = STATUS_SUCCESS;

end:
    while (!IsListEmpty(&context.stripes)) {
        write_superblocks_stripe* stripe = CONTAINING_RECORD(RemoveHeadList(&context.stripes), write_superblocks_stripe, list_entry);

        if (stripe->mdl) {
            if (stripe->mdl->MdlFlags & MDL_PAGES_LOCKED)
                MmUnlockPages(stripe->mdl);

            IoFreeMdl(stripe->mdl);
        }

        if (stripe->Irp)
            IoFreeIrp(stripe->Irp);

        if (stripe->buf)
            ExFreePool(stripe->buf);

        ExFreePool(stripe);
    }

    return Status;
}

static NTSTATUS flush_changed_extent(device_extension* Vcb, chunk* c, changed_extent* ce, PIRP Irp, LIST_ENTRY* rollback) {
    LIST_ENTRY *le, *le2;
    NTSTATUS Status;
    uint64_t old_size;

    if (ce->count == 0 && ce->old_count == 0) {
        while (!IsListEmpty(&ce->refs)) {
            changed_extent_ref* cer = CONTAINING_RECORD(RemoveHeadList(&ce->refs), changed_extent_ref, list_entry);
            ExFreePool(cer);
        }

        while (!IsListEmpty(&ce->old_refs)) {
            changed_extent_ref* cer = CONTAINING_RECORD(RemoveHeadList(&ce->old_refs), changed_extent_ref, list_entry);
            ExFreePool(cer);
        }

        goto end;
    }

    le = ce->refs.Flink;
    while (le != &ce->refs) {
        changed_extent_ref* cer = CONTAINING_RECORD(le, changed_extent_ref, list_entry);
        uint32_t old_count = 0;

        if (cer->type == TYPE_EXTENT_DATA_REF) {
            le2 = ce->old_refs.Flink;
            while (le2 != &ce->old_refs) {
                changed_extent_ref* cer2 = CONTAINING_RECORD(le2, changed_extent_ref, list_entry);

                if (cer2->type == TYPE_EXTENT_DATA_REF && cer2->edr.root == cer->edr.root && cer2->edr.objectid == cer->edr.objectid && cer2->edr.offset == cer->edr.offset) {
                    old_count = cer2->edr.count;
                    break;
                }

                le2 = le2->Flink;
            }

            old_size = ce->old_count > 0 ? ce->old_size : ce->size;

            if (cer->edr.count > old_count) {
                Status = increase_extent_refcount_data(Vcb, ce->address, old_size, cer->edr.root, cer->edr.objectid, cer->edr.offset, cer->edr.count - old_count, Irp);

                if (!NT_SUCCESS(Status)) {
                    ERR("increase_extent_refcount_data returned %08lx\n", Status);
                    return Status;
                }
            }
        } else if (cer->type == TYPE_SHARED_DATA_REF) {
            le2 = ce->old_refs.Flink;
            while (le2 != &ce->old_refs) {
                changed_extent_ref* cer2 = CONTAINING_RECORD(le2, changed_extent_ref, list_entry);

                if (cer2->type == TYPE_SHARED_DATA_REF && cer2->sdr.offset == cer->sdr.offset) {
                    RemoveEntryList(&cer2->list_entry);
                    ExFreePool(cer2);
                    break;
                }

                le2 = le2->Flink;
            }
        }

        le = le->Flink;
    }

    le = ce->refs.Flink;
    while (le != &ce->refs) {
        changed_extent_ref* cer = CONTAINING_RECORD(le, changed_extent_ref, list_entry);
        LIST_ENTRY* le3 = le->Flink;
        uint32_t old_count = 0;

        if (cer->type == TYPE_EXTENT_DATA_REF) {
            le2 = ce->old_refs.Flink;
            while (le2 != &ce->old_refs) {
                changed_extent_ref* cer2 = CONTAINING_RECORD(le2, changed_extent_ref, list_entry);

                if (cer2->type == TYPE_EXTENT_DATA_REF && cer2->edr.root == cer->edr.root && cer2->edr.objectid == cer->edr.objectid && cer2->edr.offset == cer->edr.offset) {
                    old_count = cer2->edr.count;

                    RemoveEntryList(&cer2->list_entry);
                    ExFreePool(cer2);
                    break;
                }

                le2 = le2->Flink;
            }

            old_size = ce->old_count > 0 ? ce->old_size : ce->size;

            if (cer->edr.count < old_count) {
                Status = decrease_extent_refcount_data(Vcb, ce->address, old_size, cer->edr.root, cer->edr.objectid, cer->edr.offset,
                                                       old_count - cer->edr.count, ce->superseded, Irp);

                if (!NT_SUCCESS(Status)) {
                    ERR("decrease_extent_refcount_data returned %08lx\n", Status);
                    return Status;
                }
            }

            if (ce->size != ce->old_size && ce->old_count > 0) {
                struct btrfs_key searchkey;
                traverse_ptr tp;
                void* data;

                searchkey.objectid = ce->address;
                searchkey.type = TYPE_EXTENT_ITEM;
                searchkey.offset = ce->old_size;

                Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, false, Irp);
                if (!NT_SUCCESS(Status)) {
                    ERR("error - find_item returned %08lx\n", Status);
                    return Status;
                }

                if (keycmp(searchkey, tp.item->key)) {
                    ERR("could not find (%I64x,%x,%I64x) in extent tree\n", searchkey.objectid, searchkey.type, searchkey.offset);
                    return STATUS_INTERNAL_ERROR;
                }

                if (tp.item->size > 0) {
                    data = ExAllocatePoolWithTag(PagedPool, tp.item->size, ALLOC_TAG);

                    if (!data) {
                        ERR("out of memory\n");
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }

                    RtlCopyMemory(data, tp.item->data, tp.item->size);
                } else
                    data = NULL;

                Status = insert_tree_item(Vcb, Vcb->extent_root, ce->address, TYPE_EXTENT_ITEM, ce->size, data, tp.item->size, NULL, Irp);
                if (!NT_SUCCESS(Status)) {
                    ERR("insert_tree_item returned %08lx\n", Status);
                    if (data) ExFreePool(data);
                    return Status;
                }

                Status = delete_tree_item(Vcb, &tp);
                if (!NT_SUCCESS(Status)) {
                    ERR("delete_tree_item returned %08lx\n", Status);
                    return Status;
                }
            }
        }

        RemoveEntryList(&cer->list_entry);
        ExFreePool(cer);

        le = le3;
    }

#ifdef DEBUG_PARANOID
    if (!IsListEmpty(&ce->old_refs))
        WARN("old_refs not empty\n");
#endif

end:
    if (ce->count == 0 && !ce->superseded) {
        c->used -= ce->size;
        space_list_add(c, ce->address, ce->size, rollback);
    }

    RemoveEntryList(&ce->list_entry);
    ExFreePool(ce);

    return STATUS_SUCCESS;
}

void add_checksum_entry(device_extension* Vcb, uint64_t address, ULONG length, void* csum, PIRP Irp) {
    struct btrfs_key searchkey;
    traverse_ptr tp, next_tp;
    NTSTATUS Status;
    uint64_t startaddr, endaddr;
    ULONG len;
    RTL_BITMAP bmp;
    ULONG* bmparr;
    ULONG runlength, index;

    TRACE("(%p, %I64x, %lx, %p, %p)\n", Vcb, address, length, csum, Irp);

    searchkey.objectid = EXTENT_CSUM_ID;
    searchkey.type = TYPE_EXTENT_CSUM;
    searchkey.offset = address;

    // FIXME - create checksum_root if it doesn't exist at all

    Status = find_item(Vcb, Vcb->checksum_root, &tp, &searchkey, false, Irp);
    if (Status == STATUS_NOT_FOUND) { // tree is completely empty
        if (csum) { // not deleted
            ULONG length2 = length;
            uint64_t off = address;
            void* data = csum;

            do {
                uint16_t il = (uint16_t)min(length2, MAX_CSUM_SIZE / Vcb->csum_size);

                void* checksums = ExAllocatePoolWithTag(PagedPool, il * Vcb->csum_size, ALLOC_TAG);
                if (!checksums) {
                    ERR("out of memory\n");
                    return;
                }

                RtlCopyMemory(checksums, data, il * Vcb->csum_size);

                Status = insert_tree_item(Vcb, Vcb->checksum_root, EXTENT_CSUM_ID, TYPE_EXTENT_CSUM, off, checksums,
                                          il * Vcb->csum_size, NULL, Irp);
                if (!NT_SUCCESS(Status)) {
                    ERR("insert_tree_item returned %08lx\n", Status);
                    ExFreePool(checksums);
                    return;
                }

                length2 -= il;

                if (length2 > 0) {
                    off += (uint64_t)il << Vcb->sector_shift;
                    data = (uint8_t*)data + (il * Vcb->csum_size);
                }
            } while (length2 > 0);
        }
    } else if (!NT_SUCCESS(Status)) {
        ERR("find_item returned %08lx\n", Status);
        return;
    } else {
        uint32_t tplen;
        void* checksums;

        // FIXME - check entry is TYPE_EXTENT_CSUM?

        if (tp.item->key.offset < address && tp.item->key.offset + (((uint64_t)tp.item->size << Vcb->sector_shift) / Vcb->csum_size) >= address)
            startaddr = tp.item->key.offset;
        else
            startaddr = address;

        searchkey.objectid = EXTENT_CSUM_ID;
        searchkey.type = TYPE_EXTENT_CSUM;
        searchkey.offset = address + (length << Vcb->sector_shift);

        Status = find_item(Vcb, Vcb->checksum_root, &tp, &searchkey, false, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("find_item returned %08lx\n", Status);
            return;
        }

        tplen = tp.item->size / Vcb->csum_size;

        if (tp.item->key.offset + (tplen << Vcb->sector_shift) >= address + (length << Vcb->sector_shift))
            endaddr = tp.item->key.offset + (tplen << Vcb->sector_shift);
        else
            endaddr = address + (length << Vcb->sector_shift);

        TRACE("cs starts at %I64x (%lx sectors)\n", address, length);
        TRACE("startaddr = %I64x\n", startaddr);
        TRACE("endaddr = %I64x\n", endaddr);

        len = (ULONG)((endaddr - startaddr) >> Vcb->sector_shift);

        checksums = ExAllocatePoolWithTag(PagedPool, Vcb->csum_size * len, ALLOC_TAG);
        if (!checksums) {
            ERR("out of memory\n");
            return;
        }

        bmparr = ExAllocatePoolWithTag(PagedPool, sizeof(ULONG) * ((len/8)+1), ALLOC_TAG);
        if (!bmparr) {
            ERR("out of memory\n");
            ExFreePool(checksums);
            return;
        }

        RtlInitializeBitMap(&bmp, bmparr, len);
        RtlSetAllBits(&bmp);

        searchkey.objectid = EXTENT_CSUM_ID;
        searchkey.type = TYPE_EXTENT_CSUM;
        searchkey.offset = address;

        Status = find_item(Vcb, Vcb->checksum_root, &tp, &searchkey, false, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("find_item returned %08lx\n", Status);
            ExFreePool(checksums);
            ExFreePool(bmparr);
            return;
        }

        // set bit = free space, cleared bit = allocated sector

        while (tp.item->key.offset < endaddr) {
            if (tp.item->key.offset >= startaddr) {
                if (tp.item->size > 0) {
                    ULONG itemlen = (ULONG)min((len - ((tp.item->key.offset - startaddr) >> Vcb->sector_shift)) * Vcb->csum_size, tp.item->size);

                    RtlCopyMemory((uint8_t*)checksums + (((tp.item->key.offset - startaddr) * Vcb->csum_size) >> Vcb->sector_shift),
                                  tp.item->data, itemlen);
                    RtlClearBits(&bmp, (ULONG)((tp.item->key.offset - startaddr) >> Vcb->sector_shift), itemlen / Vcb->csum_size);
                }

                Status = delete_tree_item(Vcb, &tp);
                if (!NT_SUCCESS(Status)) {
                    ERR("delete_tree_item returned %08lx\n", Status);
                    ExFreePool(checksums);
                    ExFreePool(bmparr);
                    return;
                }
            }

            if (find_next_item(Vcb, &tp, &next_tp, false, Irp)) {
                tp = next_tp;
            } else
                break;
        }

        if (!csum) { // deleted
            RtlSetBits(&bmp, (ULONG)((address - startaddr) >> Vcb->sector_shift), length);
        } else {
            RtlCopyMemory((uint8_t*)checksums + (((address - startaddr) * Vcb->csum_size) >> Vcb->sector_shift),
                          csum, length * Vcb->csum_size);
            RtlClearBits(&bmp, (ULONG)((address - startaddr) >> Vcb->sector_shift), length);
        }

        runlength = RtlFindFirstRunClear(&bmp, &index);

        while (runlength != 0) {
            if (index >= len)
                break;

            if (index + runlength >= len) {
                runlength = len - index;

                if (runlength == 0)
                    break;
            }

            do {
                uint16_t rl;
                uint64_t off;
                void* data;

                if (runlength * Vcb->csum_size > MAX_CSUM_SIZE)
                    rl = (uint16_t)(MAX_CSUM_SIZE / Vcb->csum_size);
                else
                    rl = (uint16_t)runlength;

                data = ExAllocatePoolWithTag(PagedPool, Vcb->csum_size * rl, ALLOC_TAG);
                if (!data) {
                    ERR("out of memory\n");
                    ExFreePool(bmparr);
                    ExFreePool(checksums);
                    return;
                }

                RtlCopyMemory(data, (uint8_t*)checksums + (Vcb->csum_size * index), Vcb->csum_size * rl);

                off = startaddr + ((uint64_t)index << Vcb->sector_shift);

                Status = insert_tree_item(Vcb, Vcb->checksum_root, EXTENT_CSUM_ID, TYPE_EXTENT_CSUM, off, data, Vcb->csum_size * rl, NULL, Irp);
                if (!NT_SUCCESS(Status)) {
                    ERR("insert_tree_item returned %08lx\n", Status);
                    ExFreePool(data);
                    ExFreePool(bmparr);
                    ExFreePool(checksums);
                    return;
                }

                runlength -= rl;
                index += rl;
            } while (runlength > 0);

            runlength = RtlFindNextForwardRunClear(&bmp, index, &index);
        }

        ExFreePool(bmparr);
        ExFreePool(checksums);
    }
}

static NTSTATUS update_chunk_usage(device_extension* Vcb, PIRP Irp, LIST_ENTRY* rollback) {
    LIST_ENTRY *le = Vcb->chunks.Flink, *le2;
    chunk* c;
    struct btrfs_key searchkey;
    traverse_ptr tp;
    struct btrfs_block_group_item* bgi;
    NTSTATUS Status;

    TRACE("(%p)\n", Vcb);

    ExAcquireResourceSharedLite(&Vcb->chunk_lock, true);

    while (le != &Vcb->chunks) {
        c = CONTAINING_RECORD(le, chunk, list_entry);

        acquire_chunk_lock(c, Vcb);

        if (!c->cache_loaded && (!IsListEmpty(&c->changed_extents) || c->used != c->oldused)) {
            Status = load_cache_chunk(Vcb, c, NULL);

            if (!NT_SUCCESS(Status)) {
                ERR("load_cache_chunk returned %08lx\n", Status);
                release_chunk_lock(c, Vcb);
                goto end;
            }
        }

        le2 = c->changed_extents.Flink;
        while (le2 != &c->changed_extents) {
            LIST_ENTRY* le3 = le2->Flink;
            changed_extent* ce = CONTAINING_RECORD(le2, changed_extent, list_entry);

            Status = flush_changed_extent(Vcb, c, ce, Irp, rollback);
            if (!NT_SUCCESS(Status)) {
                ERR("flush_changed_extent returned %08lx\n", Status);
                release_chunk_lock(c, Vcb);
                goto end;
            }

            le2 = le3;
        }

        // This is usually done by update_chunks, but we have to check again in case any new chunks
        // have been allocated since.
        if (c->created) {
            Status = create_chunk(Vcb, c, Irp);
            if (!NT_SUCCESS(Status)) {
                ERR("create_chunk returned %08lx\n", Status);
                release_chunk_lock(c, Vcb);
                goto end;
            }
        }

        if (c->old_cache) {
            if (c->old_cache->dirty) {
                LIST_ENTRY batchlist;

                InitializeListHead(&batchlist);

                Status = flush_fcb(c->old_cache, false, &batchlist, Irp);
                if (!NT_SUCCESS(Status)) {
                    ERR("flush_fcb returned %08lx\n", Status);
                    release_chunk_lock(c, Vcb);
                    clear_batch_list(Vcb, &batchlist);
                    goto end;
                }

                Status = commit_batch_list(Vcb, &batchlist, Irp);
                if (!NT_SUCCESS(Status)) {
                    ERR("commit_batch_list returned %08lx\n", Status);
                    release_chunk_lock(c, Vcb);
                    goto end;
                }
            }

            free_fcb(c->old_cache);

            if (c->old_cache->refcount == 0)
                reap_fcb(c->old_cache);

            c->old_cache = NULL;
        }

        if (c->used != c->oldused) {
            root* r = Vcb->block_group_root ? Vcb->block_group_root : Vcb->extent_root;

            searchkey.objectid = c->offset;
            searchkey.type = TYPE_BLOCK_GROUP_ITEM;
            searchkey.offset = c->chunk_item->length;

            Status = find_item(Vcb, r, &tp, &searchkey, false, Irp);
            if (!NT_SUCCESS(Status)) {
                ERR("error - find_item returned %08lx\n", Status);
                release_chunk_lock(c, Vcb);
                goto end;
            }

            if (keycmp(searchkey, tp.item->key)) {
                ERR("could not find (%I64x;%I64x,%x,%I64x)\n", r->id, searchkey.objectid, searchkey.type, searchkey.offset);
                Status = STATUS_INTERNAL_ERROR;
                release_chunk_lock(c, Vcb);
                goto end;
            }

            if (tp.item->size < sizeof(struct btrfs_block_group_item)) {
                ERR("(%I64x,%x,%I64x) was %u bytes, expected %Iu\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset, tp.item->size, sizeof(struct btrfs_block_group_item));
                Status = STATUS_INTERNAL_ERROR;
                release_chunk_lock(c, Vcb);
                goto end;
            }

            bgi = ExAllocatePoolWithTag(PagedPool, tp.item->size, ALLOC_TAG);
            if (!bgi) {
                ERR("out of memory\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                release_chunk_lock(c, Vcb);
                goto end;
            }

            RtlCopyMemory(bgi, tp.item->data, tp.item->size);
            bgi->used = c->used;

#ifdef DEBUG_PARANOID
            if (bgi->used & 0x8000000000000000) {
                ERR("refusing to write BLOCK_GROUP_ITEM with negative usage value (%I64x)\n", bgi->used);
                int3;
            }
#endif

            TRACE("adjusting usage of chunk %I64x to %I64x\n", c->offset, c->used);

            Status = delete_tree_item(Vcb, &tp);
            if (!NT_SUCCESS(Status)) {
                ERR("delete_tree_item returned %08lx\n", Status);
                ExFreePool(bgi);
                release_chunk_lock(c, Vcb);
                goto end;
            }

            Status = insert_tree_item(Vcb, r, searchkey.objectid, searchkey.type, searchkey.offset, bgi, tp.item->size, NULL, Irp);
            if (!NT_SUCCESS(Status)) {
                ERR("insert_tree_item returned %08lx\n", Status);
                ExFreePool(bgi);
                release_chunk_lock(c, Vcb);
                goto end;
            }

            Vcb->superblock.bytes_used += c->used - c->oldused;
            c->oldused = c->used;
        }

        release_chunk_lock(c, Vcb);

        le = le->Flink;
    }

    Status = STATUS_SUCCESS;

end:
    ExReleaseResourceLite(&Vcb->chunk_lock);

    return Status;
}

static void get_first_item(tree* t, struct btrfs_key* key) {
    LIST_ENTRY* le;

    le = t->itemlist.Flink;
    while (le != &t->itemlist) {
        tree_data* td = CONTAINING_RECORD(le, tree_data, list_entry);

        *key = td->key;
        return;
    }
}

static NTSTATUS split_tree_at(device_extension* Vcb, tree* t, tree_data* newfirstitem, uint32_t numitems, uint32_t size) {
    tree *nt, *pt;
    tree_data* td;
    tree_data* oldlastitem;

    TRACE("splitting tree in %I64x at (%I64x,%x,%I64x)\n", t->root->id, newfirstitem->key.objectid, newfirstitem->key.type, newfirstitem->key.offset);

    nt = ExAllocatePoolWithTag(PagedPool, sizeof(tree), ALLOC_TAG);
    if (!nt) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (t->header.level > 0) {
        nt->nonpaged = ExAllocatePoolWithTag(NonPagedPool, sizeof(tree_nonpaged), ALLOC_TAG);
        if (!nt->nonpaged) {
            ERR("out of memory\n");
            ExFreePool(nt);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        ExInitializeFastMutex(&nt->nonpaged->mutex);
    } else
        nt->nonpaged = NULL;

    RtlCopyMemory(&nt->header, &t->header, sizeof(struct btrfs_header));
    nt->header.bytenr = 0;
    nt->header.generation = Vcb->superblock.generation;
    nt->header.nritems = t->header.nritems - numitems;
    nt->header.flags = HEADER_FLAG_MIXED_BACKREF | HEADER_FLAG_WRITTEN;

    nt->has_address = false;
    nt->Vcb = Vcb;
    nt->parent = t->parent;

#ifdef DEBUG_PARANOID
    if (nt->parent && nt->parent->header.level <= nt->header.level) int3;
#endif

    nt->root = t->root;
    nt->new_address = 0;
    nt->has_new_address = false;
    nt->updated_extents = false;
    nt->uniqueness_determined = true;
    nt->is_unique = true;
    nt->list_entry_hash.Flink = NULL;
    nt->buf = NULL;
    InitializeListHead(&nt->itemlist);

    oldlastitem = CONTAINING_RECORD(newfirstitem->list_entry.Blink, tree_data, list_entry);

    nt->itemlist.Flink = &newfirstitem->list_entry;
    nt->itemlist.Blink = t->itemlist.Blink;
    nt->itemlist.Flink->Blink = &nt->itemlist;
    nt->itemlist.Blink->Flink = &nt->itemlist;

    t->itemlist.Blink = &oldlastitem->list_entry;
    t->itemlist.Blink->Flink = &t->itemlist;

    nt->size = t->size - size;
    t->size = size;
    t->header.nritems = numitems;
    nt->write = true;

    InsertTailList(&Vcb->trees, &nt->list_entry);

    if (nt->header.level > 0) {
        LIST_ENTRY* le = nt->itemlist.Flink;

        while (le != &nt->itemlist) {
            tree_data* td2 = CONTAINING_RECORD(le, tree_data, list_entry);

            if (td2->treeholder.tree) {
                td2->treeholder.tree->parent = nt;
#ifdef DEBUG_PARANOID
                if (td2->treeholder.tree->parent && td2->treeholder.tree->parent->header.level <= td2->treeholder.tree->header.level) int3;
#endif
            }

            le = le->Flink;
        }
    } else {
        LIST_ENTRY* le = nt->itemlist.Flink;

        while (le != &nt->itemlist) {
            tree_data* td2 = CONTAINING_RECORD(le, tree_data, list_entry);

            if (!td2->inserted && td2->data) {
                uint8_t* data = ExAllocatePoolWithTag(PagedPool, td2->size, ALLOC_TAG);

                if (!data) {
                    ERR("out of memory\n");
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                RtlCopyMemory(data, td2->data, td2->size);
                td2->data = data;
                td2->inserted = true;
            }

            le = le->Flink;
        }
    }

    if (nt->parent) {
        td = ExAllocateFromPagedLookasideList(&Vcb->tree_data_lookaside);
        if (!td) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        td->key = newfirstitem->key;

        InsertHeadList(&t->paritem->list_entry, &td->list_entry);

        td->ignore = false;
        td->inserted = true;
        td->treeholder.tree = nt;
        nt->paritem = td;

        nt->parent->header.nritems++;
        nt->parent->size += sizeof(struct btrfs_key_ptr);

        goto end;
    }

    TRACE("adding new tree parent\n");

    if (nt->header.level == 255) {
        ERR("cannot add parent to tree at level 255\n");
        return STATUS_INTERNAL_ERROR;
    }

    pt = ExAllocatePoolWithTag(PagedPool, sizeof(tree), ALLOC_TAG);
    if (!pt) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    pt->nonpaged = ExAllocatePoolWithTag(NonPagedPool, sizeof(tree_nonpaged), ALLOC_TAG);
    if (!pt->nonpaged) {
        ERR("out of memory\n");
        ExFreePool(pt);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ExInitializeFastMutex(&pt->nonpaged->mutex);

    RtlCopyMemory(&pt->header, &nt->header, sizeof(struct btrfs_header));
    pt->header.bytenr = 0;
    pt->header.nritems = 2;
    pt->header.level = nt->header.level + 1;
    pt->header.flags = HEADER_FLAG_MIXED_BACKREF | HEADER_FLAG_WRITTEN;

    pt->has_address = false;
    pt->Vcb = Vcb;
    pt->parent = NULL;
    pt->paritem = NULL;
    pt->root = t->root;
    pt->new_address = 0;
    pt->has_new_address = false;
    pt->updated_extents = false;
    pt->size = pt->header.nritems * sizeof(struct btrfs_key_ptr);
    pt->uniqueness_determined = true;
    pt->is_unique = true;
    pt->list_entry_hash.Flink = NULL;
    pt->buf = NULL;
    InitializeListHead(&pt->itemlist);

    InsertTailList(&Vcb->trees, &pt->list_entry);

    td = ExAllocateFromPagedLookasideList(&Vcb->tree_data_lookaside);
    if (!td) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    get_first_item(t, &td->key);
    td->ignore = false;
    td->inserted = false;
    td->treeholder.address = 0;
    td->treeholder.generation = Vcb->superblock.generation;
    td->treeholder.tree = t;
    InsertTailList(&pt->itemlist, &td->list_entry);
    t->paritem = td;

    td = ExAllocateFromPagedLookasideList(&Vcb->tree_data_lookaside);
    if (!td) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    td->key = newfirstitem->key;
    td->ignore = false;
    td->inserted = false;
    td->treeholder.address = 0;
    td->treeholder.generation = Vcb->superblock.generation;
    td->treeholder.tree = nt;
    InsertTailList(&pt->itemlist, &td->list_entry);
    nt->paritem = td;

    pt->write = true;

    t->root->treeholder.tree = pt;

    t->parent = pt;
    nt->parent = pt;

#ifdef DEBUG_PARANOID
    if (t->parent && t->parent->header.level <= t->header.level) int3;
    if (nt->parent && nt->parent->header.level <= nt->header.level) int3;
#endif

end:
    t->root->root_item.bytes_used += Vcb->superblock.nodesize;

    return STATUS_SUCCESS;
}

static NTSTATUS split_tree(device_extension* Vcb, tree* t) {
    LIST_ENTRY* le;
    uint32_t size, ds, numitems;

    size = 0;
    numitems = 0;

    // FIXME - naïve implementation: maximizes number of filled trees

    le = t->itemlist.Flink;
    while (le != &t->itemlist) {
        tree_data* td = CONTAINING_RECORD(le, tree_data, list_entry);

        if (!td->ignore) {
            if (t->header.level == 0)
                ds = sizeof(struct btrfs_item) + td->size;
            else
                ds = sizeof(struct btrfs_key_ptr);

            if (numitems == 0 && ds > Vcb->superblock.nodesize - sizeof(struct btrfs_header)) {
                ERR("(%I64x,%x,%I64x) in tree %I64x is too large (%x > %Ix)\n",
                    td->key.objectid, td->key.type, td->key.offset, t->root->id,
                    ds, Vcb->superblock.nodesize - sizeof(struct btrfs_header));
                return STATUS_INTERNAL_ERROR;
            }

            // FIXME - move back if previous item was deleted item with same key
            if (size + ds > Vcb->superblock.nodesize - sizeof(struct btrfs_header))
                return split_tree_at(Vcb, t, td, numitems, size);

            size += ds;
            numitems++;
        }

        le = le->Flink;
    }

    return STATUS_SUCCESS;
}

bool is_tree_unique(device_extension* Vcb, tree* t, PIRP Irp) {
    struct btrfs_key searchkey;
    traverse_ptr tp;
    NTSTATUS Status;
    bool ret = false;
    struct btrfs_extent_item* ei;
    uint8_t* type;

    if (t->uniqueness_determined)
        return t->is_unique;

    if (t->parent && !is_tree_unique(Vcb, t->parent, Irp))
        goto end;

    if (t->has_address) {
        searchkey.objectid = t->header.bytenr;
        searchkey.type = Vcb->superblock.incompat_flags & BTRFS_INCOMPAT_FLAGS_SKINNY_METADATA ? TYPE_METADATA_ITEM : TYPE_EXTENT_ITEM;
        searchkey.offset = 0xffffffffffffffff;

        Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, false, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("error - find_item returned %08lx\n", Status);
            goto end;
        }

        if (tp.item->key.objectid != t->header.bytenr || (tp.item->key.type != TYPE_METADATA_ITEM && tp.item->key.type != TYPE_EXTENT_ITEM))
            goto end;

        if (tp.item->key.type == TYPE_EXTENT_ITEM && tp.item->size == sizeof(struct btrfs_extent_item_v0))
            goto end;

        if (tp.item->size < sizeof(struct btrfs_extent_item))
            goto end;

        ei = (struct btrfs_extent_item*)tp.item->data;

        if (ei->refs > 1)
            goto end;

        if (tp.item->key.type == TYPE_EXTENT_ITEM && ei->flags & EXTENT_ITEM_TREE_BLOCK) {
            struct btrfs_tree_block_info* ei2;

            if (tp.item->size < sizeof(struct btrfs_extent_item) + sizeof(struct btrfs_tree_block_info))
                goto end;

            ei2 = (struct btrfs_tree_block_info*)&ei[1];
            type = (uint8_t*)&ei2[1];
        } else
            type = (uint8_t*)&ei[1];

        if (type >= tp.item->data + tp.item->size || *type != TYPE_TREE_BLOCK_REF)
            goto end;
    }

    ret = true;

end:
    t->is_unique = ret;
    t->uniqueness_determined = true;

    return ret;
}

static NTSTATUS try_tree_amalgamate(device_extension* Vcb, tree* t, bool* done, bool* done_deletions, PIRP Irp, LIST_ENTRY* rollback) {
    LIST_ENTRY* le;
    tree_data* nextparitem = NULL;
    NTSTATUS Status;
    tree *next_tree, *par;

    *done = false;

    TRACE("trying to amalgamate tree in root %I64x, level %x (size %u)\n", t->root->id, t->header.level, t->size);

    // FIXME - doesn't capture everything, as it doesn't ascend
    le = t->paritem->list_entry.Flink;
    while (le != &t->parent->itemlist) {
        tree_data* td = CONTAINING_RECORD(le, tree_data, list_entry);

        if (!td->ignore) {
            nextparitem = td;
            break;
        }

        le = le->Flink;
    }

    if (!nextparitem)
        return STATUS_SUCCESS;

    TRACE("nextparitem: key = %I64x,%x,%I64x\n", nextparitem->key.objectid, nextparitem->key.type, nextparitem->key.offset);

    if (!nextparitem->treeholder.tree) {
        Status = do_load_tree(Vcb, &nextparitem->treeholder, t->root, t->parent, nextparitem, NULL);
        if (!NT_SUCCESS(Status)) {
            ERR("do_load_tree returned %08lx\n", Status);
            return Status;
        }
    }

    if (!is_tree_unique(Vcb, nextparitem->treeholder.tree, Irp))
        return STATUS_SUCCESS;

    next_tree = nextparitem->treeholder.tree;

    if (!next_tree->updated_extents && next_tree->has_address) {
        Status = update_tree_extents(Vcb, next_tree, Irp, rollback);
        if (!NT_SUCCESS(Status)) {
            ERR("update_tree_extents returned %08lx\n", Status);
            return Status;
        }
    }

    if (t->size + next_tree->size <= Vcb->superblock.nodesize - sizeof(struct btrfs_header)) {
        // merge two trees into one

        t->header.nritems += next_tree->header.nritems;
        t->size += next_tree->size;

        if (next_tree->header.level > 0) {
            le = next_tree->itemlist.Flink;

            while (le != &next_tree->itemlist) {
                tree_data* td2 = CONTAINING_RECORD(le, tree_data, list_entry);

                if (td2->treeholder.tree) {
                    td2->treeholder.tree->parent = t;
#ifdef DEBUG_PARANOID
                    if (td2->treeholder.tree->parent && td2->treeholder.tree->parent->header.level <= td2->treeholder.tree->header.level) int3;
#endif
                }

                td2->inserted = true;
                le = le->Flink;
            }
        } else {
            le = next_tree->itemlist.Flink;

            while (le != &next_tree->itemlist) {
                tree_data* td2 = CONTAINING_RECORD(le, tree_data, list_entry);

                if (!td2->inserted && td2->data) {
                    uint8_t* data = ExAllocatePoolWithTag(PagedPool, td2->size, ALLOC_TAG);

                    if (!data) {
                        ERR("out of memory\n");
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }

                    RtlCopyMemory(data, td2->data, td2->size);
                    td2->data = data;
                    td2->inserted = true;
                }

                le = le->Flink;
            }
        }

        t->itemlist.Blink->Flink = next_tree->itemlist.Flink;
        t->itemlist.Blink->Flink->Blink = t->itemlist.Blink;
        t->itemlist.Blink = next_tree->itemlist.Blink;
        t->itemlist.Blink->Flink = &t->itemlist;

        next_tree->itemlist.Flink = next_tree->itemlist.Blink = &next_tree->itemlist;

        next_tree->header.nritems = 0;
        next_tree->size = 0;

        if (next_tree->has_new_address) { // delete associated EXTENT_ITEM
            Status = reduce_tree_extent(Vcb, next_tree->new_address, next_tree, next_tree->parent->header.owner, next_tree->header.level, Irp, rollback);

            if (!NT_SUCCESS(Status)) {
                ERR("reduce_tree_extent returned %08lx\n", Status);
                return Status;
            }
        } else if (next_tree->has_address) {
            Status = reduce_tree_extent(Vcb, next_tree->header.bytenr, next_tree, next_tree->parent->header.owner, next_tree->header.level, Irp, rollback);

            if (!NT_SUCCESS(Status)) {
                ERR("reduce_tree_extent returned %08lx\n", Status);
                return Status;
            }
        }

        if (!nextparitem->ignore) {
            nextparitem->ignore = true;
            next_tree->parent->header.nritems--;
            next_tree->parent->size -= sizeof(struct btrfs_key_ptr);

            *done_deletions = true;
        }

        par = next_tree->parent;
        while (par) {
            par->write = true;
            par = par->parent;
        }

        RemoveEntryList(&nextparitem->list_entry);
        ExFreePool(next_tree->paritem);
        next_tree->paritem = NULL;

        next_tree->root->root_item.bytes_used -= Vcb->superblock.nodesize;

        free_tree(next_tree);

        *done = true;
    } else {
        // rebalance by moving items from second tree into first
        ULONG avg_size = (t->size + next_tree->size) / 2;
        struct btrfs_key firstitem = {0, 0, 0};
        bool changed = false;

        TRACE("attempting rebalance\n");

        le = next_tree->itemlist.Flink;
        while (le != &next_tree->itemlist && t->size < avg_size && next_tree->header.nritems > 1) {
            tree_data* td = CONTAINING_RECORD(le, tree_data, list_entry);
            ULONG size;

            if (!td->ignore) {
                if (next_tree->header.level == 0)
                    size = sizeof(struct btrfs_item) + td->size;
                else
                    size = sizeof(struct btrfs_key_ptr);
            } else
                size = 0;

            if (t->size + size < Vcb->superblock.nodesize - sizeof(struct btrfs_header)) {
                RemoveEntryList(&td->list_entry);
                InsertTailList(&t->itemlist, &td->list_entry);

                if (next_tree->header.level > 0 && td->treeholder.tree) {
                    td->treeholder.tree->parent = t;
#ifdef DEBUG_PARANOID
                    if (td->treeholder.tree->parent && td->treeholder.tree->parent->header.level <= td->treeholder.tree->header.level) int3;
#endif
                } else if (next_tree->header.level == 0 && !td->inserted && td->size > 0) {
                    uint8_t* data = ExAllocatePoolWithTag(PagedPool, td->size, ALLOC_TAG);

                    if (!data) {
                        ERR("out of memory\n");
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }

                    RtlCopyMemory(data, td->data, td->size);
                    td->data = data;
                }

                td->inserted = true;

                if (!td->ignore) {
                    next_tree->size -= size;
                    t->size += size;
                    next_tree->header.nritems--;
                    t->header.nritems++;
                }

                changed = true;
            } else
                break;

            le = next_tree->itemlist.Flink;
        }

        le = next_tree->itemlist.Flink;
        while (le != &next_tree->itemlist) {
            tree_data* td = CONTAINING_RECORD(le, tree_data, list_entry);

            if (!td->ignore) {
                firstitem = td->key;
                break;
            }

            le = le->Flink;
        }

        // FIXME - once ascension is working, make this work with parent's parent, etc.
        if (next_tree->paritem)
            next_tree->paritem->key = firstitem;

        par = next_tree;
        while (par) {
            par->write = true;
            par = par->parent;
        }

        if (changed)
            *done = true;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS update_extent_level(device_extension* Vcb, uint64_t address, tree* t, uint8_t level, PIRP Irp) {
    struct btrfs_key searchkey;
    traverse_ptr tp;
    NTSTATUS Status;

    if (Vcb->superblock.incompat_flags & BTRFS_INCOMPAT_FLAGS_SKINNY_METADATA) {
        searchkey.objectid = address;
        searchkey.type = TYPE_METADATA_ITEM;
        searchkey.offset = t->header.level;

        Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, false, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("error - find_item returned %08lx\n", Status);
            return Status;
        }

        if (!keycmp(tp.item->key, searchkey)) {
            EXTENT_ITEM_SKINNY_METADATA* eism;

            if (tp.item->size > 0) {
                eism = ExAllocatePoolWithTag(PagedPool, tp.item->size, ALLOC_TAG);

                if (!eism) {
                    ERR("out of memory\n");
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                RtlCopyMemory(eism, tp.item->data, tp.item->size);
            } else
                eism = NULL;

            Status = delete_tree_item(Vcb, &tp);
            if (!NT_SUCCESS(Status)) {
                ERR("delete_tree_item returned %08lx\n", Status);
                if (eism) ExFreePool(eism);
                return Status;
            }

            Status = insert_tree_item(Vcb, Vcb->extent_root, address, TYPE_METADATA_ITEM, level, eism, tp.item->size, NULL, Irp);
            if (!NT_SUCCESS(Status)) {
                ERR("insert_tree_item returned %08lx\n", Status);
                if (eism) ExFreePool(eism);
                return Status;
            }

            return STATUS_SUCCESS;
        }
    }

    searchkey.objectid = address;
    searchkey.type = TYPE_EXTENT_ITEM;
    searchkey.offset = 0xffffffffffffffff;

    Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, false, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08lx\n", Status);
        return Status;
    }

    if (tp.item->key.objectid == searchkey.objectid && tp.item->key.type == searchkey.type) {
        struct btrfs_extent_item* ei;
        struct btrfs_tree_block_info* tbi;

        if (tp.item->size < sizeof(struct btrfs_extent_item) + sizeof(struct btrfs_tree_block_info)) {
            ERR("(%I64x,%x,%I64x) was %u bytes, expected at least %Iu\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset, tp.item->size, sizeof(struct btrfs_extent_item) + sizeof(struct btrfs_tree_block_info));
            return STATUS_INTERNAL_ERROR;
        }

        ei = ExAllocatePoolWithTag(PagedPool, tp.item->size, ALLOC_TAG);

        if (!ei) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlCopyMemory(ei, tp.item->data, tp.item->size);

        Status = delete_tree_item(Vcb, &tp);
        if (!NT_SUCCESS(Status)) {
            ERR("delete_tree_item returned %08lx\n", Status);
            ExFreePool(ei);
            return Status;
        }

        tbi = (struct btrfs_tree_block_info*)&ei[1];

        tbi->level = level;

        Status = insert_tree_item(Vcb, Vcb->extent_root, tp.item->key.objectid, tp.item->key.type, tp.item->key.offset, ei, tp.item->size, NULL, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("insert_tree_item returned %08lx\n", Status);
            ExFreePool(ei);
            return Status;
        }

        return STATUS_SUCCESS;
    }

    ERR("could not find EXTENT_ITEM for address %I64x\n", address);

    return STATUS_INTERNAL_ERROR;
}

static NTSTATUS update_tree_extents_recursive(device_extension* Vcb, tree* t, PIRP Irp, LIST_ENTRY* rollback) {
    NTSTATUS Status;

    if (t->parent && !t->parent->updated_extents && t->parent->has_address) {
        Status = update_tree_extents_recursive(Vcb, t->parent, Irp, rollback);
        if (!NT_SUCCESS(Status))
            return Status;
    }

    Status = update_tree_extents(Vcb, t, Irp, rollback);
    if (!NT_SUCCESS(Status)) {
        ERR("update_tree_extents returned %08lx\n", Status);
        return Status;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS do_splits(device_extension* Vcb, PIRP Irp, LIST_ENTRY* rollback) {
    ULONG level, max_level;
    uint32_t min_size, min_size_fst;
    bool empty, done_deletions = false;
    NTSTATUS Status;
    tree* t;

    TRACE("(%p)\n", Vcb);

    max_level = 0;

    for (level = 0; level <= 255; level++) {
        LIST_ENTRY *le, *nextle;

        empty = true;

        TRACE("doing level %lu\n", level);

        le = Vcb->trees.Flink;

        while (le != &Vcb->trees) {
            t = CONTAINING_RECORD(le, tree, list_entry);

            nextle = le->Flink;

            if (t->write && t->header.level == level) {
                empty = false;

                if (t->header.nritems == 0) {
                    if (t->parent) {
                        done_deletions = true;

                        TRACE("deleting tree in root %I64x\n", t->root->id);

                        t->root->root_item.bytes_used -= Vcb->superblock.nodesize;

                        if (t->has_new_address) { // delete associated EXTENT_ITEM
                            Status = reduce_tree_extent(Vcb, t->new_address, t, t->parent->header.owner, t->header.level, Irp, rollback);

                            if (!NT_SUCCESS(Status)) {
                                ERR("reduce_tree_extent returned %08lx\n", Status);
                                return Status;
                            }

                            t->has_new_address = false;
                        } else if (t->has_address) {
                            Status = reduce_tree_extent(Vcb,t->header.bytenr, t, t->parent->header.owner, t->header.level, Irp, rollback);

                            if (!NT_SUCCESS(Status)) {
                                ERR("reduce_tree_extent returned %08lx\n", Status);
                                return Status;
                            }

                            t->has_address = false;
                        }

                        if (!t->paritem->ignore) {
                            t->paritem->ignore = true;
                            t->parent->header.nritems--;
                            t->parent->size -= sizeof(struct btrfs_key_ptr);
                        }

                        RemoveEntryList(&t->paritem->list_entry);
                        ExFreePool(t->paritem);
                        t->paritem = NULL;

                        free_tree(t);
                    } else if (t->header.level != 0) {
                        if (t->has_new_address) {
                            Status = update_extent_level(Vcb, t->new_address, t, 0, Irp);

                            if (!NT_SUCCESS(Status)) {
                                ERR("update_extent_level returned %08lx\n", Status);
                                return Status;
                            }
                        }

                        t->header.level = 0;
                    }
                } else if (t->size > Vcb->superblock.nodesize - sizeof(struct btrfs_header)) {
                    TRACE("splitting overlarge tree (%x > %Ix)\n", t->size, Vcb->superblock.nodesize - sizeof(struct btrfs_header));

                    if (!t->updated_extents && t->has_address) {
                        Status = update_tree_extents_recursive(Vcb, t, Irp, rollback);
                        if (!NT_SUCCESS(Status)) {
                            ERR("update_tree_extents_recursive returned %08lx\n", Status);
                            return Status;
                        }
                    }

                    Status = split_tree(Vcb, t);

                    if (!NT_SUCCESS(Status)) {
                        ERR("split_tree returned %08lx\n", Status);
                        return Status;
                    }
                }
            }

            le = nextle;
        }

        if (!empty) {
            max_level = level;
        } else {
            TRACE("nothing found for level %lu\n", level);
            break;
        }
    }

    min_size = (Vcb->superblock.nodesize - sizeof(struct btrfs_header)) / 2;
    min_size_fst = (Vcb->superblock.nodesize - sizeof(struct btrfs_header)) / 4;

    for (level = 0; level <= max_level; level++) {
        LIST_ENTRY* le;

        le = Vcb->trees.Flink;

        while (le != &Vcb->trees) {
            t = CONTAINING_RECORD(le, tree, list_entry);

            if (t->write && t->header.level == level && t->header.nritems > 0 && t->parent &&
                ((t->size < min_size && t->root->id != BTRFS_ROOT_FREE_SPACE) || (t->size < min_size_fst && t->root->id == BTRFS_ROOT_FREE_SPACE)) &&
                is_tree_unique(Vcb, t, Irp)) {
                bool done;

                do {
                    Status = try_tree_amalgamate(Vcb, t, &done, &done_deletions, Irp, rollback);
                    if (!NT_SUCCESS(Status)) {
                        ERR("try_tree_amalgamate returned %08lx\n", Status);
                        return Status;
                    }
                } while (done && t->size < min_size);
            }

            le = le->Flink;
        }
    }

    // simplify trees if top tree only has one entry

    if (done_deletions) {
        for (level = max_level; level > 0; level--) {
            LIST_ENTRY *le, *nextle;

            le = Vcb->trees.Flink;
            while (le != &Vcb->trees) {
                nextle = le->Flink;
                t = CONTAINING_RECORD(le, tree, list_entry);

                if (t->write && t->header.level == level) {
                    if (!t->parent && t->header.nritems == 1) {
                        LIST_ENTRY* le2 = t->itemlist.Flink;
                        tree_data* td = NULL;
                        tree* child_tree = NULL;

                        while (le2 != &t->itemlist) {
                            td = CONTAINING_RECORD(le2, tree_data, list_entry);
                            if (!td->ignore)
                                break;
                            le2 = le2->Flink;
                        }

                        TRACE("deleting top-level tree in root %I64x with one item\n", t->root->id);

                        if (t->has_new_address) { // delete associated EXTENT_ITEM
                            Status = reduce_tree_extent(Vcb, t->new_address, t, t->header.owner, t->header.level, Irp, rollback);

                            if (!NT_SUCCESS(Status)) {
                                ERR("reduce_tree_extent returned %08lx\n", Status);
                                return Status;
                            }

                            t->has_new_address = false;
                        } else if (t->has_address) {
                            Status = reduce_tree_extent(Vcb,t->header.bytenr, t, t->header.owner, t->header.level, Irp, rollback);

                            if (!NT_SUCCESS(Status)) {
                                ERR("reduce_tree_extent returned %08lx\n", Status);
                                return Status;
                            }

                            t->has_address = false;
                        }

                        if (!td->treeholder.tree) { // load first item if not already loaded
                            struct btrfs_key searchkey = {0,0,0};
                            traverse_ptr tp;

                            Status = find_item(Vcb, t->root, &tp, &searchkey, false, Irp);
                            if (!NT_SUCCESS(Status)) {
                                ERR("error - find_item returned %08lx\n", Status);
                                return Status;
                            }
                        }

                        child_tree = td->treeholder.tree;

                        if (child_tree) {
                            child_tree->parent = NULL;
                            child_tree->paritem = NULL;
                        }

                        t->root->root_item.bytes_used -= Vcb->superblock.nodesize;

                        free_tree(t);

                        if (child_tree)
                            child_tree->root->treeholder.tree = child_tree;
                    }
                }

                le = nextle;
            }
        }
    }

    return STATUS_SUCCESS;
}

static NTSTATUS remove_root_extents(device_extension* Vcb, root* r, tree_holder* th, uint8_t level, tree* parent, PIRP Irp, LIST_ENTRY* rollback) {
    NTSTATUS Status;

    if (!th->tree) {
        uint8_t* buf;
        chunk* c;

        buf = ExAllocatePoolWithTag(PagedPool, Vcb->superblock.nodesize, ALLOC_TAG);
        if (!buf) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        Status = read_data(Vcb, th->address, Vcb->superblock.nodesize, NULL, true, buf, NULL,
                           &c, Irp, th->generation, false, NormalPagePriority);
        if (!NT_SUCCESS(Status)) {
            ERR("read_data returned 0x%08lx\n", Status);
            ExFreePool(buf);
            return Status;
        }

        Status = load_tree(Vcb, th->address, buf, r, &th->tree);

        if (!th->tree || th->tree->buf != buf)
            ExFreePool(buf);

        if (!NT_SUCCESS(Status)) {
            ERR("load_tree(%I64x) returned %08lx\n", th->address, Status);
            return Status;
        }
    }

    if (level > 0) {
        LIST_ENTRY* le = th->tree->itemlist.Flink;

        while (le != &th->tree->itemlist) {
            tree_data* td = CONTAINING_RECORD(le, tree_data, list_entry);

            if (!td->ignore) {
                Status = remove_root_extents(Vcb, r, &td->treeholder, th->tree->header.level - 1, th->tree, Irp, rollback);

                if (!NT_SUCCESS(Status)) {
                    ERR("remove_root_extents returned %08lx\n", Status);
                    return Status;
                }
            }

            le = le->Flink;
        }
    }

    if (th->tree && !th->tree->updated_extents && th->tree->has_address) {
        Status = update_tree_extents(Vcb, th->tree, Irp, rollback);
        if (!NT_SUCCESS(Status)) {
            ERR("update_tree_extents returned %08lx\n", Status);
            return Status;
        }
    }

    if (!th->tree || th->tree->has_address) {
        Status = reduce_tree_extent(Vcb, th->address, NULL, parent ? parent->header.owner : r->id, level, Irp, rollback);

        if (!NT_SUCCESS(Status)) {
            ERR("reduce_tree_extent(%I64x) returned %08lx\n", th->address, Status);
            return Status;
        }
    }

    return STATUS_SUCCESS;
}

static NTSTATUS drop_root(device_extension* Vcb, root* r, PIRP Irp, LIST_ENTRY* rollback) {
    NTSTATUS Status;
    struct btrfs_key searchkey;
    traverse_ptr tp;

    Status = remove_root_extents(Vcb, r, &r->treeholder, r->root_item.level, NULL, Irp, rollback);
    if (!NT_SUCCESS(Status)) {
        ERR("remove_root_extents returned %08lx\n", Status);
        return Status;
    }

    // remove entries in uuid root (tree 9)
    if (Vcb->uuid_root) {
        RtlCopyMemory(&searchkey.objectid, &r->root_item.uuid.uuid[0], sizeof(uint64_t));
        searchkey.type = TYPE_SUBVOL_UUID;
        RtlCopyMemory(&searchkey.offset, &r->root_item.uuid.uuid[sizeof(uint64_t)], sizeof(uint64_t));

        if (searchkey.objectid != 0 || searchkey.offset != 0) {
            Status = find_item(Vcb, Vcb->uuid_root, &tp, &searchkey, false, Irp);
            if (!NT_SUCCESS(Status)) {
                WARN("find_item returned %08lx\n", Status);
            } else {
                if (!keycmp(tp.item->key, searchkey)) {
                    Status = delete_tree_item(Vcb, &tp);
                    if (!NT_SUCCESS(Status)) {
                        ERR("delete_tree_item returned %08lx\n", Status);
                        return Status;
                    }
                } else
                    WARN("could not find (%I64x,%x,%I64x) in uuid tree\n", searchkey.objectid, searchkey.type, searchkey.offset);
            }
        }

        if (r->root_item.rtransid > 0) {
            RtlCopyMemory(&searchkey.objectid, &r->root_item.received_uuid.uuid[0], sizeof(uint64_t));
            searchkey.type = TYPE_SUBVOL_REC_UUID;
            RtlCopyMemory(&searchkey.offset, &r->root_item.received_uuid.uuid[sizeof(uint64_t)], sizeof(uint64_t));

            Status = find_item(Vcb, Vcb->uuid_root, &tp, &searchkey, false, Irp);
            if (!NT_SUCCESS(Status))
                WARN("find_item returned %08lx\n", Status);
            else {
                if (!keycmp(tp.item->key, searchkey)) {
                    if (tp.item->size == sizeof(uint64_t)) {
                        uint64_t* id = (uint64_t*)tp.item->data;

                        if (*id == r->id) {
                            Status = delete_tree_item(Vcb, &tp);
                            if (!NT_SUCCESS(Status)) {
                                ERR("delete_tree_item returned %08lx\n", Status);
                                return Status;
                            }
                        }
                    } else if (tp.item->size > sizeof(uint64_t)) {
                        ULONG i;
                        uint64_t* ids = (uint64_t*)tp.item->data;

                        for (i = 0; i < tp.item->size / sizeof(uint64_t); i++) {
                            if (ids[i] == r->id) {
                                uint64_t* ne;

                                ne = ExAllocatePoolWithTag(PagedPool, tp.item->size - sizeof(uint64_t), ALLOC_TAG);
                                if (!ne) {
                                    ERR("out of memory\n");
                                    return STATUS_INSUFFICIENT_RESOURCES;
                                }

                                if (i > 0)
                                    RtlCopyMemory(ne, ids, sizeof(uint64_t) * i);

                                if ((i + 1) * sizeof(uint64_t) < tp.item->size)
                                    RtlCopyMemory(&ne[i], &ids[i + 1], tp.item->size - ((i + 1) * sizeof(uint64_t)));

                                Status = delete_tree_item(Vcb, &tp);
                                if (!NT_SUCCESS(Status)) {
                                    ERR("delete_tree_item returned %08lx\n", Status);
                                    ExFreePool(ne);
                                    return Status;
                                }

                                Status = insert_tree_item(Vcb, Vcb->uuid_root, tp.item->key.objectid, tp.item->key.type, tp.item->key.offset,
                                                          ne, tp.item->size - sizeof(uint64_t), NULL, Irp);
                                if (!NT_SUCCESS(Status)) {
                                    ERR("insert_tree_item returned %08lx\n", Status);
                                    ExFreePool(ne);
                                    return Status;
                                }

                                break;
                            }
                        }
                    }
                } else
                    WARN("could not find (%I64x,%x,%I64x) in uuid tree\n", searchkey.objectid, searchkey.type, searchkey.offset);
            }
        }
    }

    // delete ROOT_ITEM

    searchkey.objectid = r->id;
    searchkey.type = TYPE_ROOT_ITEM;
    searchkey.offset = 0xffffffffffffffff;

    Status = find_item(Vcb, Vcb->root_root, &tp, &searchkey, false, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("find_item returned %08lx\n", Status);
        return Status;
    }

    if (tp.item->key.objectid == searchkey.objectid && tp.item->key.type == searchkey.type) {
        Status = delete_tree_item(Vcb, &tp);

        if (!NT_SUCCESS(Status)) {
            ERR("delete_tree_item returned %08lx\n", Status);
            return Status;
        }
    } else
        WARN("could not find (%I64x,%x,%I64x) in root_root\n", searchkey.objectid, searchkey.type, searchkey.offset);

    // delete items in tree cache

    free_trees_root(Vcb, r);

    return STATUS_SUCCESS;
}

static NTSTATUS drop_roots(device_extension* Vcb, PIRP Irp, LIST_ENTRY* rollback) {
    LIST_ENTRY *le = Vcb->drop_roots.Flink, *le2;
    NTSTATUS Status;

    while (le != &Vcb->drop_roots) {
        root* r = CONTAINING_RECORD(le, root, list_entry);

        le2 = le->Flink;

        Status = drop_root(Vcb, r, Irp, rollback);
        if (!NT_SUCCESS(Status)) {
            ERR("drop_root(%I64x) returned %08lx\n", r->id, Status);
            return Status;
        }

        le = le2;
    }

    return STATUS_SUCCESS;
}

NTSTATUS update_dev_item(device_extension* Vcb, device* device, PIRP Irp) {
    struct btrfs_key searchkey;
    traverse_ptr tp;
    struct btrfs_dev_item* di;
    NTSTATUS Status;

    searchkey.objectid = 1;
    searchkey.type = TYPE_DEV_ITEM;
    searchkey.offset = device->devitem.devid;

    Status = find_item(Vcb, Vcb->chunk_root, &tp, &searchkey, false, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08lx\n", Status);
        return Status;
    }

    if (keycmp(tp.item->key, searchkey)) {
        ERR("error - could not find btrfs_dev_item for device %I64x\n", device->devitem.devid);
        return STATUS_INTERNAL_ERROR;
    }

    Status = delete_tree_item(Vcb, &tp);
    if (!NT_SUCCESS(Status)) {
        ERR("delete_tree_item returned %08lx\n", Status);
        return Status;
    }

    di = ExAllocatePoolWithTag(PagedPool, sizeof(struct btrfs_dev_item), ALLOC_TAG);
    if (!di) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(di, &device->devitem, sizeof(struct btrfs_dev_item));

    Status = insert_tree_item(Vcb, Vcb->chunk_root, 1, TYPE_DEV_ITEM, device->devitem.devid, di, sizeof(struct btrfs_dev_item), NULL, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("insert_tree_item returned %08lx\n", Status);
        ExFreePool(di);
        return Status;
    }

    return STATUS_SUCCESS;
}

static void regen_bootstrap(device_extension* Vcb) {
    sys_chunk* sc2;
    USHORT i = 0;
    LIST_ENTRY* le;

    i = 0;
    le = Vcb->sys_chunks.Flink;
    while (le != &Vcb->sys_chunks) {
        sc2 = CONTAINING_RECORD(le, sys_chunk, list_entry);

        TRACE("%I64x,%x,%I64x\n", sc2->key.objectid, sc2->key.type, sc2->key.offset);

        RtlCopyMemory(&Vcb->superblock.sys_chunk_array[i], &sc2->key, sizeof(struct btrfs_key));
        i += sizeof(struct btrfs_key);

        RtlCopyMemory(&Vcb->superblock.sys_chunk_array[i], sc2->data, sc2->size);
        i += sc2->size;

        le = le->Flink;
    }
}

static NTSTATUS add_to_bootstrap(device_extension* Vcb, uint64_t objectid, uint8_t type, uint64_t offset, void* data, uint16_t size) {
    sys_chunk* sc;
    LIST_ENTRY* le;

    if (Vcb->superblock.sys_chunk_array_size + sizeof(struct btrfs_key) + size > SYS_CHUNK_ARRAY_SIZE) {
        ERR("error - bootstrap is full\n");
        return STATUS_INTERNAL_ERROR;
    }

    sc = ExAllocatePoolWithTag(PagedPool, sizeof(sys_chunk), ALLOC_TAG);
    if (!sc) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    sc->key.objectid = objectid;
    sc->key.type = type;
    sc->key.offset = offset;
    sc->size = size;
    sc->data = ExAllocatePoolWithTag(PagedPool, sc->size, ALLOC_TAG);
    if (!sc->data) {
        ERR("out of memory\n");
        ExFreePool(sc);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(sc->data, data, sc->size);

    le = Vcb->sys_chunks.Flink;
    while (le != &Vcb->sys_chunks) {
        sys_chunk* sc2 = CONTAINING_RECORD(le, sys_chunk, list_entry);

        if (keycmp(sc2->key, sc->key) == 1)
            break;

        le = le->Flink;
    }
    InsertTailList(le, &sc->list_entry);

    Vcb->superblock.sys_chunk_array_size += sizeof(struct btrfs_key) + size;

    regen_bootstrap(Vcb);

    return STATUS_SUCCESS;
}

static NTSTATUS create_chunk(device_extension* Vcb, chunk* c, PIRP Irp) {
    struct btrfs_chunk* ci;
    struct btrfs_block_group_item* bgi;
    uint16_t i, factor;
    NTSTATUS Status;

    ci = ExAllocatePoolWithTag(PagedPool, c->size, ALLOC_TAG);
    if (!ci) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(ci, c->chunk_item, c->size);

    Status = insert_tree_item(Vcb, Vcb->chunk_root, 0x100, TYPE_CHUNK_ITEM, c->offset, ci, c->size, NULL, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("insert_tree_item failed\n");
        ExFreePool(ci);
        return Status;
    }

    if (c->chunk_item->type & BLOCK_FLAG_SYSTEM) {
        Status = add_to_bootstrap(Vcb, 0x100, TYPE_CHUNK_ITEM, c->offset, ci, c->size);
        if (!NT_SUCCESS(Status)) {
            ERR("add_to_bootstrap returned %08lx\n", Status);
            return Status;
        }
    }

    // add BLOCK_GROUP_ITEM to tree 2

    bgi = ExAllocatePoolWithTag(PagedPool, sizeof(struct btrfs_block_group_item), ALLOC_TAG);
    if (!bgi) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    bgi->used = c->used;
    bgi->chunk_objectid = 0x100;
    bgi->flags = c->chunk_item->type;

    Status = insert_tree_item(Vcb, Vcb->block_group_root ? Vcb->block_group_root : Vcb->extent_root, c->offset,
                              TYPE_BLOCK_GROUP_ITEM, c->chunk_item->length, bgi, sizeof(struct btrfs_block_group_item), NULL, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("insert_tree_item failed\n");
        ExFreePool(bgi);
        return Status;
    }

    if (c->chunk_item->type & BLOCK_FLAG_RAID0)
        factor = c->chunk_item->num_stripes;
    else if (c->chunk_item->type & BLOCK_FLAG_RAID10)
        factor = c->chunk_item->num_stripes / c->chunk_item->sub_stripes;
    else if (c->chunk_item->type & BLOCK_FLAG_RAID5)
        factor = c->chunk_item->num_stripes - 1;
    else if (c->chunk_item->type & BLOCK_FLAG_RAID6)
        factor = c->chunk_item->num_stripes - 2;
    else // SINGLE, DUPLICATE, RAID1, RAID1C3, RAID1C4
        factor = 1;

    // add DEV_EXTENTs to tree 4

    for (i = 0; i < c->chunk_item->num_stripes; i++) {
        struct btrfs_dev_extent* de;

        de = ExAllocatePoolWithTag(PagedPool, sizeof(struct btrfs_dev_extent), ALLOC_TAG);
        if (!de) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        de->chunk_tree = Vcb->chunk_root->id;
        de->chunk_objectid = 0x100;
        de->chunk_offset = c->offset;
        de->length = c->chunk_item->length / factor;
        de->chunk_tree_uuid = Vcb->chunk_root->treeholder.tree->header.chunk_tree_uuid;

        Status = insert_tree_item(Vcb, Vcb->dev_root, c->devices[i]->devitem.devid, TYPE_DEV_EXTENT, c->chunk_item->stripe[i].offset, de, sizeof(struct btrfs_dev_extent), NULL, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("insert_tree_item returned %08lx\n", Status);
            ExFreePool(de);
            return Status;
        }

        // FIXME - no point in calling this twice for the same device
        Status = update_dev_item(Vcb, c->devices[i], Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("update_dev_item returned %08lx\n", Status);
            return Status;
        }
    }

    c->created = false;
    c->oldused = c->used;

    Vcb->superblock.bytes_used += c->used;

    return STATUS_SUCCESS;
}

static void remove_from_bootstrap(device_extension* Vcb, uint64_t objectid, uint8_t type, uint64_t offset) {
    sys_chunk* sc2;
    LIST_ENTRY* le;

    le = Vcb->sys_chunks.Flink;
    while (le != &Vcb->sys_chunks) {
        sc2 = CONTAINING_RECORD(le, sys_chunk, list_entry);

        if (sc2->key.objectid == objectid && sc2->key.type == type && sc2->key.offset == offset) {
            RemoveEntryList(&sc2->list_entry);

            Vcb->superblock.sys_chunk_array_size -= sizeof(struct btrfs_key) + sc2->size;

            ExFreePool(sc2->data);
            ExFreePool(sc2);
            regen_bootstrap(Vcb);
            return;
        }

        le = le->Flink;
    }
}

static NTSTATUS set_xattr(device_extension* Vcb, LIST_ENTRY* batchlist, root* subvol, uint64_t inode, char* name, uint16_t namelen,
                          uint32_t crc32, uint8_t* data, uint16_t datalen) {
    NTSTATUS Status;
    uint16_t xasize;
    struct btrfs_dir_item* xa;

    TRACE("(%p, %I64x, %I64x, %.*s, %08x, %p, %u)\n", Vcb, subvol->id, inode, namelen, name, crc32, data, datalen);

    xasize = (uint16_t)sizeof(struct btrfs_dir_item) + namelen + datalen;

    xa = ExAllocatePoolWithTag(PagedPool, xasize, ALLOC_TAG);
    if (!xa) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    xa->location.objectid = 0;
    xa->location.type = 0;
    xa->location.offset = 0;
    xa->transid = Vcb->superblock.generation;
    xa->data_len = datalen;
    xa->name_len = namelen;
    xa->type = BTRFS_TYPE_EA;
    RtlCopyMemory(&xa[1], name, namelen);
    RtlCopyMemory((uint8_t*)&xa[1] + namelen, data, datalen);

    Status = insert_tree_item_batch(batchlist, Vcb, subvol, inode, TYPE_XATTR_ITEM, crc32, xa, xasize, Batch_SetXattr);
    if (!NT_SUCCESS(Status)) {
        ERR("insert_tree_item_batch returned %08lx\n", Status);
        ExFreePool(xa);
        return Status;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS delete_xattr(device_extension* Vcb, LIST_ENTRY* batchlist, root* subvol, uint64_t inode, char* name,
                             uint16_t namelen, uint32_t crc32) {
    NTSTATUS Status;
    uint16_t xasize;
    struct btrfs_dir_item* xa;

    TRACE("(%p, %I64x, %I64x, %.*s, %08x)\n", Vcb, subvol->id, inode, namelen, name, crc32);

    xasize = (uint16_t)sizeof(struct btrfs_dir_item) + namelen;

    xa = ExAllocatePoolWithTag(PagedPool, xasize, ALLOC_TAG);
    if (!xa) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    xa->location.objectid = 0;
    xa->location.type = 0;
    xa->location.offset = 0;
    xa->transid = Vcb->superblock.generation;
    xa->data_len = 0;
    xa->name_len = namelen;
    xa->type = BTRFS_TYPE_EA;
    RtlCopyMemory(&xa[1], name, namelen);

    Status = insert_tree_item_batch(batchlist, Vcb, subvol, inode, TYPE_XATTR_ITEM, crc32, xa, xasize, Batch_DeleteXattr);
    if (!NT_SUCCESS(Status)) {
        ERR("insert_tree_item_batch returned %08lx\n", Status);
        ExFreePool(xa);
        return Status;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS insert_sparse_extent(fcb* fcb, LIST_ENTRY* batchlist, uint64_t start, uint64_t length) {
    NTSTATUS Status;
    struct btrfs_file_extent_item* ed;

    TRACE("((%I64x, %I64x), %I64x, %I64x)\n", fcb->subvol->id, fcb->inode, start, length);

    ed = ExAllocatePoolWithTag(PagedPool, sizeof(struct btrfs_file_extent_item), ALLOC_TAG);
    if (!ed) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ed->generation = fcb->Vcb->superblock.generation;
    ed->ram_bytes = length;
    ed->compression = BTRFS_COMPRESSION_NONE;
    ed->encryption = BTRFS_ENCRYPTION_NONE;
    ed->other_encoding = BTRFS_ENCODING_NONE;
    ed->type = EXTENT_TYPE_REGULAR;
    ed->disk_bytenr = 0;
    ed->disk_num_bytes = 0;
    ed->offset = 0;
    ed->num_bytes = length;

    Status = insert_tree_item_batch(batchlist, fcb->Vcb, fcb->subvol, fcb->inode, TYPE_EXTENT_DATA, start, ed, sizeof(struct btrfs_file_extent_item), Batch_Insert);
    if (!NT_SUCCESS(Status)) {
        ERR("insert_tree_item_batch returned %08lx\n", Status);
        ExFreePool(ed);
        return Status;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS split_batch_item_list(batch_item_ind* bii) {
    LIST_ENTRY* le;
    unsigned int i = 0;
    LIST_ENTRY* midpoint = NULL;
    batch_item_ind* bii2;
    batch_item* midpoint_item;
    LIST_ENTRY* before_midpoint;

    le = bii->items.Flink;
    while (le != &bii->items) {
        if (i >= bii->num_items / 2) {
            midpoint = le;
            break;
        }

        i++;

        le = le->Flink;
    }

    if (!midpoint)
        return STATUS_SUCCESS;

    // make sure items on either side of split don't have same key

    while (midpoint->Blink != &bii->items) {
        batch_item* item = CONTAINING_RECORD(midpoint, batch_item, list_entry);
        batch_item* prev = CONTAINING_RECORD(midpoint->Blink, batch_item, list_entry);

        if (item->key.objectid != prev->key.objectid)
            break;

        if (item->key.type != prev->key.type)
            break;

        if (item->key.offset != prev->key.offset)
            break;

        midpoint = midpoint->Blink;
        i--;
    }

    if (midpoint->Blink == &bii->items)
        return STATUS_SUCCESS;

    bii2 = ExAllocatePoolWithTag(PagedPool, sizeof(batch_item_ind), ALLOC_TAG);
    if (!bii2) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    midpoint_item = CONTAINING_RECORD(midpoint, batch_item, list_entry);

    bii2->key.objectid = midpoint_item->key.objectid;
    bii2->key.type = midpoint_item->key.type;
    bii2->key.offset = midpoint_item->key.offset;

    bii2->num_items = bii->num_items - i;
    bii->num_items = i;

    before_midpoint = midpoint->Blink;

    bii2->items.Flink = midpoint;
    midpoint->Blink = &bii2->items;
    bii2->items.Blink = bii->items.Blink;
    bii->items.Blink->Flink = &bii2->items;

    bii->items.Blink = before_midpoint;
    before_midpoint->Flink = &bii->items;

    InsertHeadList(&bii->list_entry, &bii2->list_entry);

    return STATUS_SUCCESS;
}

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(suppress: 28194)
#endif
static NTSTATUS insert_tree_item_batch(LIST_ENTRY* batchlist, device_extension* Vcb, root* r, uint64_t objid,
                                       uint8_t objtype, uint64_t offset, _In_opt_ _When_(return >= 0, __drv_aliasesMem) void* data,
                                       uint16_t datalen, enum batch_operation operation) {
    LIST_ENTRY* le;
    batch_root* br = NULL;
    batch_item* bi;

    le = batchlist->Flink;
    while (le != batchlist) {
        batch_root* br2 = CONTAINING_RECORD(le, batch_root, list_entry);

        if (br2->r == r) {
            br = br2;
            break;
        }

        le = le->Flink;
    }

    if (!br) {
        br = ExAllocatePoolWithTag(PagedPool, sizeof(batch_root), ALLOC_TAG);
        if (!br) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        br->r = r;
        InitializeListHead(&br->items_ind);
        InsertTailList(batchlist, &br->list_entry);
    }

    if (IsListEmpty(&br->items_ind)) {
        batch_item_ind* bii;

        bii = ExAllocatePoolWithTag(PagedPool, sizeof(batch_item_ind), ALLOC_TAG);
        if (!bii) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        bii->key.objectid = 0;
        bii->key.type = 0;
        bii->key.offset = 0;
        InitializeListHead(&bii->items);
        bii->num_items = 0;
        InsertTailList(&br->items_ind, &bii->list_entry);
    }

    bi = ExAllocateFromPagedLookasideList(&Vcb->batch_item_lookaside);
    if (!bi) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    bi->key.objectid = objid;
    bi->key.type = objtype;
    bi->key.offset = offset;
    bi->data = data;
    bi->datalen = datalen;
    bi->operation = operation;

    le = br->items_ind.Blink;
    while (le != &br->items_ind) {
        LIST_ENTRY* le2;
        batch_item_ind* bii = CONTAINING_RECORD(le, batch_item_ind, list_entry);

        if (keycmp(bii->key, bi->key) == 1) {
            le = le->Blink;
            continue;
        }

        le2 = bii->items.Blink;
        while (le2 != &bii->items) {
            batch_item* bi2 = CONTAINING_RECORD(le2, batch_item, list_entry);
            int cmp = keycmp(bi2->key, bi->key);

            if (cmp == -1 || (cmp == 0 && bi->operation >= bi2->operation)) {
                InsertHeadList(&bi2->list_entry, &bi->list_entry);
                bii->num_items++;
                goto end;
            }

            le2 = le2->Blink;
        }

        InsertHeadList(&bii->items, &bi->list_entry);
        bii->num_items++;

end:
        if (bii->num_items > BATCH_ITEM_LIMIT)
            return split_batch_item_list(bii);

        return STATUS_SUCCESS;
    }

    return STATUS_INTERNAL_ERROR;
}
#ifdef _MSC_VER
#pragma warning(pop)
#endif

typedef struct {
    uint64_t address;
    uint64_t length;
    uint64_t offset;
    bool changed;
    chunk* chunk;
    uint64_t skip_start;
    uint64_t skip_end;
    LIST_ENTRY list_entry;
} extent_range;

static void rationalize_extents(fcb* fcb, PIRP Irp) {
    LIST_ENTRY* le;
    LIST_ENTRY extent_ranges;
    extent_range* er;
    bool changed = false, truncating = false;
    uint32_t num_extents = 0;

    InitializeListHead(&extent_ranges);

    le = fcb->extents.Flink;
    while (le != &fcb->extents) {
        extent* ext = CONTAINING_RECORD(le, extent, list_entry);

        if ((ext->extent_data.type == EXTENT_TYPE_REGULAR || ext->extent_data.type == EXTENT_TYPE_PREALLOC) && ext->extent_data.compression == BTRFS_COMPRESSION_NONE && ext->unique) {
            if (ext->extent_data.disk_num_bytes != 0) {
                LIST_ENTRY* le2;

                le2 = extent_ranges.Flink;
                while (le2 != &extent_ranges) {
                    extent_range* er2 = CONTAINING_RECORD(le2, extent_range, list_entry);

                    if (er2->address == ext->extent_data.disk_bytenr) {
                        er2->skip_start = min(er2->skip_start, ext->extent_data.offset);
                        er2->skip_end = min(er2->skip_end, ext->extent_data.disk_num_bytes - ext->extent_data.offset - ext->extent_data.num_bytes);
                        goto cont;
                    } else if (er2->address > ext->extent_data.disk_bytenr)
                        break;

                    le2 = le2->Flink;
                }

                er = ExAllocatePoolWithTag(PagedPool, sizeof(extent_range), ALLOC_TAG); // FIXME - should be from lookaside?
                if (!er) {
                    ERR("out of memory\n");
                    goto end;
                }

                er->address = ext->extent_data.disk_bytenr;
                er->length = ext->extent_data.disk_num_bytes;
                er->offset = ext->offset - ext->extent_data.offset;
                er->changed = false;
                er->chunk = NULL;
                er->skip_start = ext->extent_data.offset;
                er->skip_end = ext->extent_data.disk_num_bytes - ext->extent_data.offset - ext->extent_data.num_bytes;

                if (er->skip_start != 0 || er->skip_end != 0)
                    truncating = true;

                InsertHeadList(le2->Blink, &er->list_entry);
                num_extents++;
            }
        }

cont:
        le = le->Flink;
    }

    if (num_extents == 0 || (num_extents == 1 && !truncating))
        goto end;

    le = extent_ranges.Flink;
    while (le != &extent_ranges) {
        er = CONTAINING_RECORD(le, extent_range, list_entry);

        if (!er->chunk) {
            LIST_ENTRY* le2;

            er->chunk = get_chunk_from_address(fcb->Vcb, er->address);

            if (!er->chunk) {
                ERR("get_chunk_from_address(%I64x) failed\n", er->address);
                goto end;
            }

            le2 = le->Flink;
            while (le2 != &extent_ranges) {
                extent_range* er2 = CONTAINING_RECORD(le2, extent_range, list_entry);

                if (!er2->chunk && er2->address >= er->chunk->offset && er2->address < er->chunk->offset + er->chunk->chunk_item->length)
                    er2->chunk = er->chunk;

                le2 = le2->Flink;
            }
        }

        le = le->Flink;
    }

    if (truncating) {
        // truncate beginning or end of extent if unused

        le = extent_ranges.Flink;
        while (le != &extent_ranges) {
            er = CONTAINING_RECORD(le, extent_range, list_entry);

            if (er->skip_start > 0) {
                LIST_ENTRY* le2 = fcb->extents.Flink;
                while (le2 != &fcb->extents) {
                    extent* ext = CONTAINING_RECORD(le2, extent, list_entry);

                    if ((ext->extent_data.type == EXTENT_TYPE_REGULAR || ext->extent_data.type == EXTENT_TYPE_PREALLOC) && ext->extent_data.compression == BTRFS_COMPRESSION_NONE && ext->unique) {
                        if (ext->extent_data.disk_num_bytes != 0 && ext->extent_data.disk_bytenr == er->address) {
                            NTSTATUS Status;

                            Status = update_changed_extent_ref(fcb->Vcb, er->chunk, ext->extent_data.disk_bytenr, ext->extent_data.disk_num_bytes, fcb->subvol->id,
                                                               fcb->inode, ext->offset - ext->extent_data.offset, -1, fcb->inode_item.flags & BTRFS_INODE_NODATASUM,
                                                               true, Irp);
                            if (!NT_SUCCESS(Status)) {
                                ERR("update_changed_extent_ref returned %08lx\n", Status);
                                goto end;
                            }

                            ext->extent_data.ram_bytes -= er->skip_start;
                            ext->extent_data.disk_num_bytes -= er->skip_start;
                            ext->extent_data.disk_bytenr += er->skip_start;
                            ext->extent_data.offset -= er->skip_start;

                            add_changed_extent_ref(er->chunk, ext->extent_data.disk_bytenr, ext->extent_data.disk_num_bytes, fcb->subvol->id, fcb->inode, ext->offset - ext->extent_data.offset,
                                                   1, fcb->inode_item.flags & BTRFS_INODE_NODATASUM);
                        }
                    }

                    le2 = le2->Flink;
                }

                if (!(fcb->inode_item.flags & BTRFS_INODE_NODATASUM))
                    add_checksum_entry(fcb->Vcb, er->address, (ULONG)(er->skip_start >> fcb->Vcb->sector_shift), NULL, NULL);

                acquire_chunk_lock(er->chunk, fcb->Vcb);

                if (!er->chunk->cache_loaded) {
                    NTSTATUS Status = load_cache_chunk(fcb->Vcb, er->chunk, NULL);

                    if (!NT_SUCCESS(Status)) {
                        ERR("load_cache_chunk returned %08lx\n", Status);
                        release_chunk_lock(er->chunk, fcb->Vcb);
                        goto end;
                    }
                }

                er->chunk->used -= er->skip_start;

                space_list_add(er->chunk, er->address, er->skip_start, NULL);

                release_chunk_lock(er->chunk, fcb->Vcb);

                er->address += er->skip_start;
                er->length -= er->skip_start;
            }

            if (er->skip_end > 0) {
                LIST_ENTRY* le2 = fcb->extents.Flink;
                while (le2 != &fcb->extents) {
                    extent* ext = CONTAINING_RECORD(le2, extent, list_entry);

                    if ((ext->extent_data.type == EXTENT_TYPE_REGULAR || ext->extent_data.type == EXTENT_TYPE_PREALLOC) && ext->extent_data.compression == BTRFS_COMPRESSION_NONE && ext->unique) {
                        if (ext->extent_data.disk_num_bytes != 0 && ext->extent_data.disk_bytenr == er->address) {
                            NTSTATUS Status;

                            Status = update_changed_extent_ref(fcb->Vcb, er->chunk, ext->extent_data.disk_bytenr, ext->extent_data.disk_num_bytes, fcb->subvol->id, fcb->inode,
                                                               ext->offset - ext->extent_data.offset, -1, fcb->inode_item.flags & BTRFS_INODE_NODATASUM, true, Irp);
                            if (!NT_SUCCESS(Status)) {
                                ERR("update_changed_extent_ref returned %08lx\n", Status);
                                goto end;
                            }

                            ext->extent_data.ram_bytes -= er->skip_end;
                            ext->extent_data.disk_num_bytes -= er->skip_end;

                            add_changed_extent_ref(er->chunk, ext->extent_data.disk_bytenr, ext->extent_data.disk_num_bytes, fcb->subvol->id, fcb->inode,
                                                   ext->offset - ext->extent_data.offset, 1, fcb->inode_item.flags & BTRFS_INODE_NODATASUM);
                        }
                    }

                    le2 = le2->Flink;
                }

                if (!(fcb->inode_item.flags & BTRFS_INODE_NODATASUM))
                    add_checksum_entry(fcb->Vcb, er->address + er->length - er->skip_end, (ULONG)(er->skip_end >> fcb->Vcb->sector_shift), NULL, NULL);

                acquire_chunk_lock(er->chunk, fcb->Vcb);

                if (!er->chunk->cache_loaded) {
                    NTSTATUS Status = load_cache_chunk(fcb->Vcb, er->chunk, NULL);

                    if (!NT_SUCCESS(Status)) {
                        ERR("load_cache_chunk returned %08lx\n", Status);
                        release_chunk_lock(er->chunk, fcb->Vcb);
                        goto end;
                    }
                }

                er->chunk->used -= er->skip_end;

                space_list_add(er->chunk, er->address + er->length - er->skip_end, er->skip_end, NULL);

                release_chunk_lock(er->chunk, fcb->Vcb);

                er->length -= er->skip_end;
            }

            le = le->Flink;
        }
    }

    if (num_extents < 2)
        goto end;

    // merge together adjacent extents
    le = extent_ranges.Flink;
    while (le != &extent_ranges) {
        er = CONTAINING_RECORD(le, extent_range, list_entry);

        if (le->Flink != &extent_ranges && er->length < MAX_EXTENT_SIZE) {
            extent_range* er2 = CONTAINING_RECORD(le->Flink, extent_range, list_entry);

            if (er->chunk == er2->chunk) {
                if (er2->address == er->address + er->length && er2->offset >= er->offset + er->length) {
                    if (er->length + er2->length <= MAX_EXTENT_SIZE) {
                        er->length += er2->length;
                        er->changed = true;

                        RemoveEntryList(&er2->list_entry);
                        ExFreePool(er2);

                        changed = true;
                        continue;
                    }
                }
            }
        }

        le = le->Flink;
    }

    if (!changed)
        goto end;

    le = fcb->extents.Flink;
    while (le != &fcb->extents) {
        extent* ext = CONTAINING_RECORD(le, extent, list_entry);

        if ((ext->extent_data.type == EXTENT_TYPE_REGULAR || ext->extent_data.type == EXTENT_TYPE_PREALLOC) && ext->extent_data.compression == BTRFS_COMPRESSION_NONE && ext->unique) {
            if (ext->extent_data.disk_num_bytes != 0) {
                LIST_ENTRY* le2;

                le2 = extent_ranges.Flink;
                while (le2 != &extent_ranges) {
                    extent_range* er2 = CONTAINING_RECORD(le2, extent_range, list_entry);

                    if (ext->extent_data.disk_bytenr >= er2->address && ext->extent_data.disk_bytenr + ext->extent_data.disk_num_bytes <= er2->address + er2->length && er2->changed) {
                        NTSTATUS Status;

                        Status = update_changed_extent_ref(fcb->Vcb, er2->chunk, ext->extent_data.disk_bytenr, ext->extent_data.disk_num_bytes, fcb->subvol->id, fcb->inode,
                                                           ext->offset - ext->extent_data.offset, -1, fcb->inode_item.flags & BTRFS_INODE_NODATASUM, true, Irp);
                        if (!NT_SUCCESS(Status)) {
                            ERR("update_changed_extent_ref returned %08lx\n", Status);
                            goto end;
                        }

                        ext->extent_data.offset += ext->extent_data.disk_bytenr - er2->address;
                        ext->extent_data.disk_bytenr = er2->address;
                        ext->extent_data.disk_num_bytes = er2->length;
                        ext->extent_data.ram_bytes = ext->extent_data.disk_num_bytes;

                        add_changed_extent_ref(er2->chunk, ext->extent_data.disk_bytenr, ext->extent_data.disk_num_bytes, fcb->subvol->id, fcb->inode, ext->offset - ext->extent_data.offset,
                                               1, fcb->inode_item.flags & BTRFS_INODE_NODATASUM);

                        break;
                    }

                    le2 = le2->Flink;
                }
            }
        }

        le = le->Flink;
    }

end:
    while (!IsListEmpty(&extent_ranges)) {
        le = RemoveHeadList(&extent_ranges);
        er = CONTAINING_RECORD(le, extent_range, list_entry);

        ExFreePool(er);
    }
}

NTSTATUS flush_fcb(fcb* fcb, bool cache, LIST_ENTRY* batchlist, PIRP Irp) {
    traverse_ptr tp;
    struct btrfs_key searchkey;
    NTSTATUS Status;
    struct btrfs_inode_item* ii;
    uint64_t ii_offset;
#ifdef DEBUG_PARANOID
    uint64_t old_size = 0;
    bool extents_changed;
#endif

    if (fcb->ads) {
        if (fcb->deleted) {
            Status = delete_xattr(fcb->Vcb, batchlist, fcb->subvol, fcb->inode, fcb->adsxattr.Buffer, fcb->adsxattr.Length, fcb->adshash);
            if (!NT_SUCCESS(Status)) {
                ERR("delete_xattr returned %08lx\n", Status);
                goto end;
            }
        } else {
            Status = set_xattr(fcb->Vcb, batchlist, fcb->subvol, fcb->inode, fcb->adsxattr.Buffer, fcb->adsxattr.Length,
                               fcb->adshash, (uint8_t*)fcb->adsdata.Buffer, fcb->adsdata.Length);
            if (!NT_SUCCESS(Status)) {
                ERR("set_xattr returned %08lx\n", Status);
                goto end;
            }
        }

        Status = STATUS_SUCCESS;
        goto end;
    }

    if (fcb->deleted) {
        Status = insert_tree_item_batch(batchlist, fcb->Vcb, fcb->subvol, fcb->inode, TYPE_INODE_ITEM, 0xffffffffffffffff, NULL, 0, Batch_DeleteInode);
        if (!NT_SUCCESS(Status)) {
            ERR("insert_tree_item_batch returned %08lx\n", Status);
            goto end;
        }

        if (fcb->marked_as_orphan) {
            Status = insert_tree_item_batch(batchlist, fcb->Vcb, fcb->subvol, BTRFS_ORPHAN_INODE_OBJID, TYPE_ORPHAN_INODE,
                                            fcb->inode, NULL, 0, Batch_Delete);
            if (!NT_SUCCESS(Status)) {
                ERR("insert_tree_item_batch returned %08lx\n", Status);
                goto end;
            }
        }

        Status = STATUS_SUCCESS;
        goto end;
    }

#ifdef DEBUG_PARANOID
    extents_changed = fcb->extents_changed;
#endif

    if (fcb->extents_changed) {
        LIST_ENTRY* le;
        bool prealloc = false, extents_inline = false;
        uint64_t last_end;

        // delete ignored extent items
        le = fcb->extents.Flink;
        while (le != &fcb->extents) {
            LIST_ENTRY* le2 = le->Flink;
            extent* ext = CONTAINING_RECORD(le, extent, list_entry);

            if (ext->ignore) {
                RemoveEntryList(&ext->list_entry);

                if (ext->csum)
                    ExFreePool(ext->csum);

                ExFreePool(ext);
            }

            le = le2;
        }

        le = fcb->extents.Flink;
        while (le != &fcb->extents) {
            extent* ext = CONTAINING_RECORD(le, extent, list_entry);

            if (ext->inserted && ext->csum && ext->extent_data.type == EXTENT_TYPE_REGULAR) {
                if (ext->extent_data.disk_num_bytes > 0) { // not sparse
                    if (ext->extent_data.compression == BTRFS_COMPRESSION_NONE)
                        add_checksum_entry(fcb->Vcb, ext->extent_data.disk_bytenr + ext->extent_data.offset, (ULONG)(ext->extent_data.num_bytes >> fcb->Vcb->sector_shift), ext->csum, Irp);
                    else
                        add_checksum_entry(fcb->Vcb, ext->extent_data.disk_bytenr, (ULONG)(ext->extent_data.disk_num_bytes >> fcb->Vcb->sector_shift), ext->csum, Irp);
                }
            }

            le = le->Flink;
        }

        if (!IsListEmpty(&fcb->extents)) {
            rationalize_extents(fcb, Irp);

            // merge together adjacent EXTENT_DATAs pointing to same extent

            le = fcb->extents.Flink;
            while (le != &fcb->extents) {
                LIST_ENTRY* le2 = le->Flink;
                extent* ext = CONTAINING_RECORD(le, extent, list_entry);

                if ((ext->extent_data.type == EXTENT_TYPE_REGULAR || ext->extent_data.type == EXTENT_TYPE_PREALLOC) && le->Flink != &fcb->extents) {
                    extent* nextext = CONTAINING_RECORD(le->Flink, extent, list_entry);

                    if (ext->extent_data.type == nextext->extent_data.type) {
                        if (ext->extent_data.disk_num_bytes != 0 && ext->extent_data.disk_bytenr == nextext->extent_data.disk_bytenr && ext->extent_data.disk_num_bytes == nextext->extent_data.disk_num_bytes &&
                            nextext->offset == ext->offset + ext->extent_data.num_bytes && nextext->extent_data.offset == ext->extent_data.offset + ext->extent_data.num_bytes) {
                            chunk* c;

                            if (ext->extent_data.compression == BTRFS_COMPRESSION_NONE && ext->csum) {
                                ULONG len = (ULONG)((ext->extent_data.num_bytes + nextext->extent_data.num_bytes) >> fcb->Vcb->sector_shift);
                                void* csum;

                                csum = ExAllocatePoolWithTag(NonPagedPool, len * fcb->Vcb->csum_size, ALLOC_TAG);
                                if (!csum) {
                                    ERR("out of memory\n");
                                    Status = STATUS_INSUFFICIENT_RESOURCES;
                                    goto end;
                                }

                                RtlCopyMemory(csum, ext->csum, (ULONG)((ext->extent_data.num_bytes * fcb->Vcb->csum_size) >> fcb->Vcb->sector_shift));
                                RtlCopyMemory((uint8_t*)csum + ((ext->extent_data.num_bytes * fcb->Vcb->csum_size) >> fcb->Vcb->sector_shift), nextext->csum,
                                              (ULONG)((nextext->extent_data.num_bytes * fcb->Vcb->csum_size) >> fcb->Vcb->sector_shift));

                                ExFreePool(ext->csum);
                                ext->csum = csum;
                            }

                            ext->extent_data.generation = fcb->Vcb->superblock.generation;
                            ext->extent_data.num_bytes += nextext->extent_data.num_bytes;

                            RemoveEntryList(&nextext->list_entry);

                            if (nextext->csum)
                                ExFreePool(nextext->csum);

                            ExFreePool(nextext);

                            c = get_chunk_from_address(fcb->Vcb, ext->extent_data.disk_bytenr);

                            if (!c) {
                                ERR("get_chunk_from_address(%I64x) failed\n", ext->extent_data.disk_bytenr);
                            } else {
                                Status = update_changed_extent_ref(fcb->Vcb, c, ext->extent_data.disk_bytenr, ext->extent_data.disk_num_bytes, fcb->subvol->id, fcb->inode, ext->offset - ext->extent_data.offset, -1,
                                                                fcb->inode_item.flags & BTRFS_INODE_NODATASUM, false, Irp);
                                if (!NT_SUCCESS(Status)) {
                                    ERR("update_changed_extent_ref returned %08lx\n", Status);
                                    goto end;
                                }
                            }

                            le2 = le;
                        }
                    }
                }

                le = le2;
            }
        }

        if (!fcb->created) {
            // delete existing EXTENT_DATA items

            Status = insert_tree_item_batch(batchlist, fcb->Vcb, fcb->subvol, fcb->inode, TYPE_EXTENT_DATA, 0, NULL, 0, Batch_DeleteExtentData);
            if (!NT_SUCCESS(Status)) {
                ERR("insert_tree_item_batch returned %08lx\n", Status);
                goto end;
            }
        }

        // add new EXTENT_DATAs

        last_end = 0;

        le = fcb->extents.Flink;
        while (le != &fcb->extents) {
            extent* ext = CONTAINING_RECORD(le, extent, list_entry);
            struct btrfs_file_extent_item* ed;

            ext->inserted = false;

            if (!(fcb->Vcb->superblock.incompat_flags & BTRFS_INCOMPAT_FLAGS_NO_HOLES) && ext->offset > last_end) {
                Status = insert_sparse_extent(fcb, batchlist, last_end, ext->offset - last_end);
                if (!NT_SUCCESS(Status)) {
                    ERR("insert_sparse_extent returned %08lx\n", Status);
                    goto end;
                }
            }

            ed = ExAllocatePoolWithTag(PagedPool, ext->datalen, ALLOC_TAG);
            if (!ed) {
                ERR("out of memory\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto end;
            }

            RtlCopyMemory(ed, &ext->extent_data, ext->datalen);

            Status = insert_tree_item_batch(batchlist, fcb->Vcb, fcb->subvol, fcb->inode, TYPE_EXTENT_DATA, ext->offset,
                                            ed, ext->datalen, Batch_Insert);
            if (!NT_SUCCESS(Status)) {
                ERR("insert_tree_item_batch returned %08lx\n", Status);
                goto end;
            }

            if (ed->type == EXTENT_TYPE_PREALLOC)
                prealloc = true;

            if (ed->type == EXTENT_TYPE_INLINE)
                extents_inline = true;

            if (!(fcb->Vcb->superblock.incompat_flags & BTRFS_INCOMPAT_FLAGS_NO_HOLES)) {
                if (ed->type == EXTENT_TYPE_INLINE)
                    last_end = ext->offset + ed->ram_bytes;
                else
                    last_end = ext->offset + ed->num_bytes;
            }

            le = le->Flink;
        }

        if (!(fcb->Vcb->superblock.incompat_flags & BTRFS_INCOMPAT_FLAGS_NO_HOLES) && !extents_inline &&
            sector_align(fcb->inode_item.size, fcb->Vcb->superblock.sectorsize) > last_end) {
            Status = insert_sparse_extent(fcb, batchlist, last_end, sector_align(fcb->inode_item.size, fcb->Vcb->superblock.sectorsize) - last_end);
            if (!NT_SUCCESS(Status)) {
                ERR("insert_sparse_extent returned %08lx\n", Status);
                goto end;
            }
        }

        // update prealloc flag in INODE_ITEM

        if (!prealloc)
            fcb->inode_item.flags &= ~BTRFS_INODE_PREALLOC;
        else
            fcb->inode_item.flags |= BTRFS_INODE_PREALLOC;

        fcb->inode_item_changed = true;

        fcb->extents_changed = false;
    }

    if ((!fcb->created && fcb->inode_item_changed) || cache) {
        searchkey.objectid = fcb->inode;
        searchkey.type = TYPE_INODE_ITEM;
        searchkey.offset = 0xffffffffffffffff;

        Status = find_item(fcb->Vcb, fcb->subvol, &tp, &searchkey, false, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("error - find_item returned %08lx\n", Status);
            goto end;
        }

        if (tp.item->key.objectid != searchkey.objectid || tp.item->key.type != searchkey.type) {
            if (cache) {
                ii = ExAllocatePoolWithTag(PagedPool, sizeof(struct btrfs_inode_item), ALLOC_TAG);
                if (!ii) {
                    ERR("out of memory\n");
                    Status = STATUS_INSUFFICIENT_RESOURCES;
                    goto end;
                }

                RtlCopyMemory(ii, &fcb->inode_item, sizeof(struct btrfs_inode_item));

                Status = insert_tree_item(fcb->Vcb, fcb->subvol, fcb->inode, TYPE_INODE_ITEM, 0, ii, sizeof(struct btrfs_inode_item), NULL, Irp);
                if (!NT_SUCCESS(Status)) {
                    ERR("insert_tree_item returned %08lx\n", Status);
                    goto end;
                }

                ii_offset = 0;
            } else {
                ERR("could not find INODE_ITEM for inode %I64x in subvol %I64x\n", fcb->inode, fcb->subvol->id);
                Status = STATUS_INTERNAL_ERROR;
                goto end;
            }
        } else {
#ifdef DEBUG_PARANOID
            struct btrfs_inode_item* ii2 = (struct btrfs_inode_item*)tp.item->data;

            old_size = ii2->size;
#endif

            ii_offset = tp.item->key.offset;
        }

        if (!cache) {
            Status = delete_tree_item(fcb->Vcb, &tp);
            if (!NT_SUCCESS(Status)) {
                ERR("delete_tree_item returned %08lx\n", Status);
                goto end;
            }
        } else {
            searchkey.objectid = fcb->inode;
            searchkey.type = TYPE_INODE_ITEM;
            searchkey.offset = ii_offset;

            Status = find_item(fcb->Vcb, fcb->subvol, &tp, &searchkey, false, Irp);
            if (!NT_SUCCESS(Status)) {
                ERR("error - find_item returned %08lx\n", Status);
                goto end;
            }

            if (keycmp(tp.item->key, searchkey)) {
                ERR("could not find INODE_ITEM for inode %I64x in subvol %I64x\n", fcb->inode, fcb->subvol->id);
                Status = STATUS_INTERNAL_ERROR;
                goto end;
            } else
                RtlCopyMemory(tp.item->data, &fcb->inode_item, min(tp.item->size, sizeof(struct btrfs_inode_item)));
        }

#ifdef DEBUG_PARANOID
        if (!extents_changed && fcb->type != BTRFS_TYPE_DIRECTORY && old_size != fcb->inode_item.size) {
            ERR("error - size has changed but extents not marked as changed\n");
            int3;
        }
#endif
    } else
        ii_offset = 0;

    fcb->created = false;

    if (!cache && fcb->inode_item_changed) {
        ii = ExAllocatePoolWithTag(PagedPool, sizeof(struct btrfs_inode_item), ALLOC_TAG);
        if (!ii) {
            ERR("out of memory\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }

        RtlCopyMemory(ii, &fcb->inode_item, sizeof(struct btrfs_inode_item));

        Status = insert_tree_item_batch(batchlist, fcb->Vcb, fcb->subvol, fcb->inode, TYPE_INODE_ITEM, ii_offset, ii, sizeof(struct btrfs_inode_item),
                                        Batch_Insert);
        if (!NT_SUCCESS(Status)) {
            ERR("insert_tree_item_batch returned %08lx\n", Status);
            goto end;
        }

        fcb->inode_item_changed = false;
    }

    if (fcb->sd_dirty) {
        if (!fcb->sd_deleted) {
            Status = set_xattr(fcb->Vcb, batchlist, fcb->subvol, fcb->inode, EA_NTACL, sizeof(EA_NTACL) - 1,
                               EA_NTACL_HASH, (uint8_t*)fcb->sd, (uint16_t)RtlLengthSecurityDescriptor(fcb->sd));
            if (!NT_SUCCESS(Status)) {
                ERR("set_xattr returned %08lx\n", Status);
                goto end;
            }
        } else {
            Status = delete_xattr(fcb->Vcb, batchlist, fcb->subvol, fcb->inode, EA_NTACL, sizeof(EA_NTACL) - 1, EA_NTACL_HASH);
            if (!NT_SUCCESS(Status)) {
                ERR("delete_xattr returned %08lx\n", Status);
                goto end;
            }
        }

        fcb->sd_deleted = false;
        fcb->sd_dirty = false;
    }

    if (fcb->atts_changed) {
        if (!fcb->atts_deleted) {
            uint8_t val[16], *val2;
            ULONG atts = fcb->atts;

            TRACE("inserting new DOSATTRIB xattr\n");

            if (fcb->inode == SUBVOL_ROOT_INODE)
                atts &= ~FILE_ATTRIBUTE_READONLY;

            val2 = &val[sizeof(val) - 1];

            do {
                uint8_t c = atts % 16;
                *val2 = c <= 9 ? (c + '0') : (c - 0xa + 'a');

                val2--;
                atts >>= 4;
            } while (atts != 0);

            *val2 = 'x';
            val2--;
            *val2 = '0';

            Status = set_xattr(fcb->Vcb, batchlist, fcb->subvol, fcb->inode, EA_DOSATTRIB, sizeof(EA_DOSATTRIB) - 1,
                               EA_DOSATTRIB_HASH, val2, (uint16_t)(val + sizeof(val) - val2));
            if (!NT_SUCCESS(Status)) {
                ERR("set_xattr returned %08lx\n", Status);
                goto end;
            }
        } else {
            Status = delete_xattr(fcb->Vcb, batchlist, fcb->subvol, fcb->inode, EA_DOSATTRIB, sizeof(EA_DOSATTRIB) - 1, EA_DOSATTRIB_HASH);
            if (!NT_SUCCESS(Status)) {
                ERR("delete_xattr returned %08lx\n", Status);
                goto end;
            }
        }

        fcb->atts_changed = false;
        fcb->atts_deleted = false;
    }

    if (fcb->reparse_xattr_changed) {
        if (fcb->reparse_xattr.Buffer && fcb->reparse_xattr.Length > 0) {
            Status = set_xattr(fcb->Vcb, batchlist, fcb->subvol, fcb->inode, EA_REPARSE, sizeof(EA_REPARSE) - 1,
                               EA_REPARSE_HASH, (uint8_t*)fcb->reparse_xattr.Buffer, (uint16_t)fcb->reparse_xattr.Length);
            if (!NT_SUCCESS(Status)) {
                ERR("set_xattr returned %08lx\n", Status);
                goto end;
            }
        } else {
            Status = delete_xattr(fcb->Vcb, batchlist, fcb->subvol, fcb->inode, EA_REPARSE, sizeof(EA_REPARSE) - 1, EA_REPARSE_HASH);
            if (!NT_SUCCESS(Status)) {
                ERR("delete_xattr returned %08lx\n", Status);
                goto end;
            }
        }

        fcb->reparse_xattr_changed = false;
    }

    if (fcb->ea_changed) {
        if (fcb->ea_xattr.Buffer && fcb->ea_xattr.Length > 0) {
            Status = set_xattr(fcb->Vcb, batchlist, fcb->subvol, fcb->inode, EA_EA, sizeof(EA_EA) - 1,
                               EA_EA_HASH, (uint8_t*)fcb->ea_xattr.Buffer, (uint16_t)fcb->ea_xattr.Length);
            if (!NT_SUCCESS(Status)) {
                ERR("set_xattr returned %08lx\n", Status);
                goto end;
            }
        } else {
            Status = delete_xattr(fcb->Vcb, batchlist, fcb->subvol, fcb->inode, EA_EA, sizeof(EA_EA) - 1, EA_EA_HASH);
            if (!NT_SUCCESS(Status)) {
                ERR("delete_xattr returned %08lx\n", Status);
                goto end;
            }
        }

        fcb->ea_changed = false;
    }

    if (fcb->prop_compression_changed) {
        if (fcb->prop_compression == PropCompression_None) {
            Status = delete_xattr(fcb->Vcb, batchlist, fcb->subvol, fcb->inode, EA_PROP_COMPRESSION, sizeof(EA_PROP_COMPRESSION) - 1, EA_PROP_COMPRESSION_HASH);
            if (!NT_SUCCESS(Status)) {
                ERR("delete_xattr returned %08lx\n", Status);
                goto end;
            }
        } else if (fcb->prop_compression == PropCompression_Zlib) {
            static const char zlib[] = "zlib";

            Status = set_xattr(fcb->Vcb, batchlist, fcb->subvol, fcb->inode, EA_PROP_COMPRESSION, sizeof(EA_PROP_COMPRESSION) - 1,
                               EA_PROP_COMPRESSION_HASH, (uint8_t*)zlib, sizeof(zlib) - 1);
            if (!NT_SUCCESS(Status)) {
                ERR("set_xattr returned %08lx\n", Status);
                goto end;
            }
        } else if (fcb->prop_compression == PropCompression_LZO) {
            static const char lzo[] = "lzo";

            Status = set_xattr(fcb->Vcb, batchlist, fcb->subvol, fcb->inode, EA_PROP_COMPRESSION, sizeof(EA_PROP_COMPRESSION) - 1,
                               EA_PROP_COMPRESSION_HASH, (uint8_t*)lzo, sizeof(lzo) - 1);
            if (!NT_SUCCESS(Status)) {
                ERR("set_xattr returned %08lx\n", Status);
                goto end;
            }
        } else if (fcb->prop_compression == PropCompression_ZSTD) {
            static const char zstd[] = "zstd";

            Status = set_xattr(fcb->Vcb, batchlist, fcb->subvol, fcb->inode, EA_PROP_COMPRESSION, sizeof(EA_PROP_COMPRESSION) - 1,
                               EA_PROP_COMPRESSION_HASH, (uint8_t*)zstd, sizeof(zstd) - 1);
            if (!NT_SUCCESS(Status)) {
                ERR("set_xattr returned %08lx\n", Status);
                goto end;
            }
        }

        fcb->prop_compression_changed = false;
    }

    if (fcb->xattrs_changed) {
        LIST_ENTRY* le;

        le = fcb->xattrs.Flink;
        while (le != &fcb->xattrs) {
            xattr* xa = CONTAINING_RECORD(le, xattr, list_entry);
            LIST_ENTRY* le2 = le->Flink;

            if (xa->dirty) {
                uint32_t hash = calc_crc32c(0xfffffffe, (uint8_t*)xa->data, xa->namelen);

                if (xa->valuelen == 0) {
                    Status = delete_xattr(fcb->Vcb, batchlist, fcb->subvol, fcb->inode, xa->data, xa->namelen, hash);
                    if (!NT_SUCCESS(Status)) {
                        ERR("delete_xattr returned %08lx\n", Status);
                        goto end;
                    }

                    RemoveEntryList(&xa->list_entry);
                    ExFreePool(xa);
                } else {
                    Status = set_xattr(fcb->Vcb, batchlist, fcb->subvol, fcb->inode, xa->data, xa->namelen,
                                       hash, (uint8_t*)&xa->data[xa->namelen], xa->valuelen);
                    if (!NT_SUCCESS(Status)) {
                        ERR("set_xattr returned %08lx\n", Status);
                        goto end;
                    }

                    xa->dirty = false;
                }
            }

            le = le2;
        }

        fcb->xattrs_changed = false;
    }

    if ((fcb->case_sensitive_set && !fcb->case_sensitive)) {
        Status = delete_xattr(fcb->Vcb, batchlist, fcb->subvol, fcb->inode, EA_CASE_SENSITIVE,
                              sizeof(EA_CASE_SENSITIVE) - 1, EA_CASE_SENSITIVE_HASH);
        if (!NT_SUCCESS(Status)) {
            ERR("delete_xattr returned %08lx\n", Status);
            goto end;
        }

        fcb->case_sensitive_set = false;
    } else if ((!fcb->case_sensitive_set && fcb->case_sensitive)) {
        Status = set_xattr(fcb->Vcb, batchlist, fcb->subvol, fcb->inode, EA_CASE_SENSITIVE,
                           sizeof(EA_CASE_SENSITIVE) - 1, EA_CASE_SENSITIVE_HASH, (uint8_t*)"1", 1);
        if (!NT_SUCCESS(Status)) {
            ERR("set_xattr returned %08lx\n", Status);
            goto end;
        }

        fcb->case_sensitive_set = true;
    }

    if (fcb->inode_item.nlink == 0 && !fcb->marked_as_orphan) { // mark as orphan
        Status = insert_tree_item_batch(batchlist, fcb->Vcb, fcb->subvol, BTRFS_ORPHAN_INODE_OBJID, TYPE_ORPHAN_INODE,
                                        fcb->inode, NULL, 0, Batch_Insert);
        if (!NT_SUCCESS(Status)) {
            ERR("insert_tree_item_batch returned %08lx\n", Status);
            goto end;
        }

        fcb->marked_as_orphan = true;
    }

    Status = STATUS_SUCCESS;

end:
    if (fcb->dirty) {
        bool lock = false;

        fcb->dirty = false;

        if (!ExIsResourceAcquiredExclusiveLite(&fcb->Vcb->dirty_fcbs_lock)) {
            ExAcquireResourceExclusiveLite(&fcb->Vcb->dirty_fcbs_lock, true);
            lock = true;
        }

        RemoveEntryList(&fcb->list_entry_dirty);

        if (lock)
            ExReleaseResourceLite(&fcb->Vcb->dirty_fcbs_lock);
    }

    return Status;
}

void add_trim_entry_avoid_sb(device_extension* Vcb, device* dev, uint64_t address, uint64_t size) {
    int i;
    ULONG sblen = (ULONG)sector_align(sizeof(struct btrfs_super_block), Vcb->superblock.sectorsize);

    i = 0;
    while (superblock_addrs[i] != 0) {
        if (superblock_addrs[i] + sblen >= address && superblock_addrs[i] < address + size) {
            if (superblock_addrs[i] > address)
                add_trim_entry(dev, address, superblock_addrs[i] - address);

            if (size <= superblock_addrs[i] + sblen - address)
                return;

            size -= superblock_addrs[i] + sblen - address;
            address = superblock_addrs[i] + sblen;
        } else if (superblock_addrs[i] > address + size)
            break;

        i++;
    }

    add_trim_entry(dev, address, size);
}

static NTSTATUS drop_chunk(device_extension* Vcb, chunk* c, LIST_ENTRY* batchlist, PIRP Irp, LIST_ENTRY* rollback) {
    NTSTATUS Status;
    struct btrfs_key searchkey;
    traverse_ptr tp;
    uint64_t i, factor;

    TRACE("dropping chunk %I64x\n", c->offset);

    if (c->chunk_item->type & BLOCK_FLAG_RAID0)
        factor = c->chunk_item->num_stripes;
    else if (c->chunk_item->type & BLOCK_FLAG_RAID10)
        factor = c->chunk_item->num_stripes / c->chunk_item->sub_stripes;
    else if (c->chunk_item->type & BLOCK_FLAG_RAID5)
        factor = c->chunk_item->num_stripes - 1;
    else if (c->chunk_item->type & BLOCK_FLAG_RAID6)
        factor = c->chunk_item->num_stripes - 2;
    else // SINGLE, DUPLICATE, RAID1, RAID1C3, RAID1C4
        factor = 1;

    // do TRIM
    if (Vcb->trim && !Vcb->options.no_trim) {
        uint64_t len = c->chunk_item->length / factor;

        for (i = 0; i < c->chunk_item->num_stripes; i++) {
            if (c->devices[i] && c->devices[i]->devobj && !c->devices[i]->readonly && c->devices[i]->trim)
                add_trim_entry_avoid_sb(Vcb, c->devices[i], c->chunk_item->stripe[i].offset, len);
        }
    }

    if (!c->cache) {
        Status = load_stored_free_space_cache(Vcb, c, true, Irp);

        if (!NT_SUCCESS(Status) && Status != STATUS_NOT_FOUND)
            WARN("load_stored_free_space_cache returned %08lx\n", Status);
    }

    // remove free space cache
    if (c->cache) {
        c->cache->deleted = true;

        Status = excise_extents(Vcb, c->cache, 0, c->cache->inode_item.size, Irp, rollback);
        if (!NT_SUCCESS(Status)) {
            ERR("excise_extents returned %08lx\n", Status);
            return Status;
        }

        Status = flush_fcb(c->cache, true, batchlist, Irp);

        free_fcb(c->cache);

        if (c->cache->refcount == 0)
            reap_fcb(c->cache);

        if (!NT_SUCCESS(Status)) {
            ERR("flush_fcb returned %08lx\n", Status);
            return Status;
        }

        searchkey.objectid = FREE_SPACE_CACHE_ID;
        searchkey.type = 0;
        searchkey.offset = c->offset;

        Status = find_item(Vcb, Vcb->root_root, &tp, &searchkey, false, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("error - find_item returned %08lx\n", Status);
            return Status;
        }

        if (!keycmp(tp.item->key, searchkey)) {
            Status = delete_tree_item(Vcb, &tp);
            if (!NT_SUCCESS(Status)) {
                ERR("delete_tree_item returned %08lx\n", Status);
                return Status;
            }
        }
    }

    if (Vcb->space_root) {
        Status = insert_tree_item_batch(batchlist, Vcb, Vcb->space_root, c->offset, TYPE_FREE_SPACE_INFO, c->chunk_item->length,
                                        NULL, 0, Batch_DeleteFreeSpace);
        if (!NT_SUCCESS(Status)) {
            ERR("insert_tree_item_batch returned %08lx\n", Status);
            return Status;
        }
    }

    for (i = 0; i < c->chunk_item->num_stripes; i++) {
        if (!c->created) {
            // remove DEV_EXTENTs from tree 4
            searchkey.objectid = c->chunk_item->stripe[i].devid;
            searchkey.type = TYPE_DEV_EXTENT;
            searchkey.offset = c->chunk_item->stripe[i].offset;

            Status = find_item(Vcb, Vcb->dev_root, &tp, &searchkey, false, Irp);
            if (!NT_SUCCESS(Status)) {
                ERR("error - find_item returned %08lx\n", Status);
                return Status;
            }

            if (!keycmp(tp.item->key, searchkey)) {
                Status = delete_tree_item(Vcb, &tp);
                if (!NT_SUCCESS(Status)) {
                    ERR("delete_tree_item returned %08lx\n", Status);
                    return Status;
                }

                if (tp.item->size >= sizeof(struct btrfs_dev_extent)) {
                    struct btrfs_dev_extent* de = (struct btrfs_dev_extent*)tp.item->data;

                    c->devices[i]->devitem.bytes_used -= de->length;

                    if (Vcb->balance.thread && Vcb->balance.shrinking && Vcb->balance.opts[0].devid == c->devices[i]->devitem.devid) {
                        if (c->chunk_item->stripe[i].offset < Vcb->balance.opts[0].drange_start && c->chunk_item->stripe[i].offset + de->length > Vcb->balance.opts[0].drange_start)
                            space_list_add2(&c->devices[i]->space, NULL, c->chunk_item->stripe[i].offset, Vcb->balance.opts[0].drange_start - c->chunk_item->stripe[i].offset, NULL, rollback);
                    } else
                        space_list_add2(&c->devices[i]->space, NULL, c->chunk_item->stripe[i].offset, de->length, NULL, rollback);
                }
            } else
                WARN("could not find (%I64x,%x,%I64x) in dev tree\n", searchkey.objectid, searchkey.type, searchkey.offset);
        } else {
            uint64_t len = c->chunk_item->length / factor;

            c->devices[i]->devitem.bytes_used -= len;

            if (Vcb->balance.thread && Vcb->balance.shrinking && Vcb->balance.opts[0].devid == c->devices[i]->devitem.devid) {
                if (c->chunk_item->stripe[i].offset < Vcb->balance.opts[0].drange_start && c->chunk_item->stripe[i].offset + len > Vcb->balance.opts[0].drange_start)
                    space_list_add2(&c->devices[i]->space, NULL, c->chunk_item->stripe[i].offset, Vcb->balance.opts[0].drange_start - c->chunk_item->stripe[i].offset, NULL, rollback);
            } else
                space_list_add2(&c->devices[i]->space, NULL, c->chunk_item->stripe[i].offset, len, NULL, rollback);
        }
    }

    // modify btrfs_dev_items in chunk tree
    for (i = 0; i < c->chunk_item->num_stripes; i++) {
        if (c->devices[i]) {
            uint64_t j;
            struct btrfs_dev_item* di;

            searchkey.objectid = 1;
            searchkey.type = TYPE_DEV_ITEM;
            searchkey.offset = c->devices[i]->devitem.devid;

            Status = find_item(Vcb, Vcb->chunk_root, &tp, &searchkey, false, Irp);
            if (!NT_SUCCESS(Status)) {
                ERR("error - find_item returned %08lx\n", Status);
                return Status;
            }

            if (!keycmp(tp.item->key, searchkey)) {
                Status = delete_tree_item(Vcb, &tp);
                if (!NT_SUCCESS(Status)) {
                    ERR("delete_tree_item returned %08lx\n", Status);
                    return Status;
                }

                di = ExAllocatePoolWithTag(PagedPool, sizeof(struct btrfs_dev_item), ALLOC_TAG);
                if (!di) {
                    ERR("out of memory\n");
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                RtlCopyMemory(di, &c->devices[i]->devitem, sizeof(struct btrfs_dev_item));

                Status = insert_tree_item(Vcb, Vcb->chunk_root, 1, TYPE_DEV_ITEM, c->devices[i]->devitem.devid, di, sizeof(struct btrfs_dev_item), NULL, Irp);
                if (!NT_SUCCESS(Status)) {
                    ERR("insert_tree_item returned %08lx\n", Status);
                    return Status;
                }
            }

            for (j = i + 1; j < c->chunk_item->num_stripes; j++) {
                if (c->devices[j] == c->devices[i])
                    c->devices[j] = NULL;
            }
        }
    }

    if (!c->created) {
        // remove CHUNK_ITEM from chunk tree
        searchkey.objectid = 0x100;
        searchkey.type = TYPE_CHUNK_ITEM;
        searchkey.offset = c->offset;

        Status = find_item(Vcb, Vcb->chunk_root, &tp, &searchkey, false, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("error - find_item returned %08lx\n", Status);
            return Status;
        }

        if (!keycmp(tp.item->key, searchkey)) {
            Status = delete_tree_item(Vcb, &tp);

            if (!NT_SUCCESS(Status)) {
                ERR("delete_tree_item returned %08lx\n", Status);
                return Status;
            }
        } else
            WARN("could not find CHUNK_ITEM for chunk %I64x\n", c->offset);

        // remove BLOCK_GROUP_ITEM from extent tree
        searchkey.objectid = c->offset;
        searchkey.type = TYPE_BLOCK_GROUP_ITEM;
        searchkey.offset = 0xffffffffffffffff;

        Status = find_item(Vcb, Vcb->block_group_root ? Vcb->block_group_root : Vcb->extent_root,
                           &tp, &searchkey, false, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("error - find_item returned %08lx\n", Status);
            return Status;
        }

        if (tp.item->key.objectid == searchkey.objectid && tp.item->key.type == searchkey.type) {
            Status = delete_tree_item(Vcb, &tp);

            if (!NT_SUCCESS(Status)) {
                ERR("delete_tree_item returned %08lx\n", Status);
                return Status;
            }
        } else
            WARN("could not find BLOCK_GROUP_ITEM for chunk %I64x\n", c->offset);
    }

    if (c->chunk_item->type & BLOCK_FLAG_SYSTEM)
        remove_from_bootstrap(Vcb, 0x100, TYPE_CHUNK_ITEM, c->offset);

    RemoveEntryList(&c->list_entry);

    // clear raid56 incompat flag if dropping last RAID5/6 chunk

    if (c->chunk_item->type & BLOCK_FLAG_RAID5 || c->chunk_item->type & BLOCK_FLAG_RAID6) {
        LIST_ENTRY* le;
        bool clear_flag = true;

        le = Vcb->chunks.Flink;
        while (le != &Vcb->chunks) {
            chunk* c2 = CONTAINING_RECORD(le, chunk, list_entry);

            if (c2->chunk_item->type & BLOCK_FLAG_RAID5 || c2->chunk_item->type & BLOCK_FLAG_RAID6) {
                clear_flag = false;
                break;
            }

            le = le->Flink;
        }

        if (clear_flag)
            Vcb->superblock.incompat_flags &= ~BTRFS_INCOMPAT_FLAGS_RAID56;
    }

    // clear raid1c34 incompat flag if dropping last RAID5/6 chunk

    if (c->chunk_item->type & BLOCK_FLAG_RAID1C3 || c->chunk_item->type & BLOCK_FLAG_RAID1C4) {
        LIST_ENTRY* le;
        bool clear_flag = true;

        le = Vcb->chunks.Flink;
        while (le != &Vcb->chunks) {
            chunk* c2 = CONTAINING_RECORD(le, chunk, list_entry);

            if (c2->chunk_item->type & BLOCK_FLAG_RAID1C3 || c2->chunk_item->type & BLOCK_FLAG_RAID1C4) {
                clear_flag = false;
                break;
            }

            le = le->Flink;
        }

        if (clear_flag)
            Vcb->superblock.incompat_flags &= ~BTRFS_INCOMPAT_FLAGS_RAID1C34;
    }

    Vcb->superblock.bytes_used -= c->oldused;

    ExFreePool(c->chunk_item);
    ExFreePool(c->devices);

    while (!IsListEmpty(&c->space)) {
        space* s = CONTAINING_RECORD(c->space.Flink, space, list_entry);

        RemoveEntryList(&s->list_entry);
        ExFreePool(s);
    }

    while (!IsListEmpty(&c->deleting)) {
        space* s = CONTAINING_RECORD(c->deleting.Flink, space, list_entry);

        RemoveEntryList(&s->list_entry);
        ExFreePool(s);
    }

    release_chunk_lock(c, Vcb);

    ExDeleteResourceLite(&c->partial_stripes_lock);
    ExDeleteResourceLite(&c->range_locks_lock);
    ExDeleteResourceLite(&c->lock);
    ExDeleteResourceLite(&c->changed_extents_lock);

    ExFreePool(c);

    return STATUS_SUCCESS;
}

static NTSTATUS partial_stripe_read(device_extension* Vcb, chunk* c, partial_stripe* ps, uint64_t startoff, uint16_t parity, ULONG offset, ULONG len) {
    NTSTATUS Status;
    ULONG sl = (ULONG)(c->chunk_item->stripe_len >> Vcb->sector_shift);

    while (len > 0) {
        ULONG readlen = min(offset + len, offset + (sl - (offset % sl))) - offset;
        uint16_t stripe;

        stripe = (parity + (offset / sl) + 1) % c->chunk_item->num_stripes;

        if (c->devices[stripe]->devobj) {
            Status = sync_read_phys(c->devices[stripe]->devobj, c->devices[stripe]->fileobj, c->chunk_item->stripe[stripe].offset + startoff + ((offset % sl) << Vcb->sector_shift),
                                    readlen << Vcb->sector_shift, ps->data + (offset << Vcb->sector_shift), false);
            if (!NT_SUCCESS(Status)) {
                ERR("sync_read_phys returned %08lx\n", Status);
                return Status;
            }
        } else if (c->chunk_item->type & BLOCK_FLAG_RAID5) {
            uint16_t i;
            uint8_t* scratch;

            scratch = ExAllocatePoolWithTag(NonPagedPool, readlen << Vcb->sector_shift, ALLOC_TAG);
            if (!scratch) {
                ERR("out of memory\n");
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            for (i = 0; i < c->chunk_item->num_stripes; i++) {
                if (i != stripe) {
                    if (!c->devices[i]->devobj) {
                        ExFreePool(scratch);
                        return STATUS_UNEXPECTED_IO_ERROR;
                    }

                    if (i == 0 || (stripe == 0 && i == 1)) {
                        Status = sync_read_phys(c->devices[i]->devobj, c->devices[i]->fileobj, c->chunk_item->stripe[i].offset + startoff + ((offset % sl) << Vcb->sector_shift),
                                                readlen << Vcb->sector_shift, ps->data + (offset << Vcb->sector_shift), false);
                        if (!NT_SUCCESS(Status)) {
                            ERR("sync_read_phys returned %08lx\n", Status);
                            ExFreePool(scratch);
                            return Status;
                        }
                    } else {
                        Status = sync_read_phys(c->devices[i]->devobj, c->devices[i]->fileobj, c->chunk_item->stripe[i].offset + startoff + ((offset % sl) << Vcb->sector_shift),
                                                readlen << Vcb->sector_shift, scratch, false);
                        if (!NT_SUCCESS(Status)) {
                            ERR("sync_read_phys returned %08lx\n", Status);
                            ExFreePool(scratch);
                            return Status;
                        }

                        do_xor(ps->data + (offset << Vcb->sector_shift), scratch, readlen << Vcb->sector_shift);
                    }
                }
            }

            ExFreePool(scratch);
        } else {
            uint8_t* scratch;
            uint16_t k, i, logstripe, error_stripe, num_errors = 0;

            scratch = ExAllocatePoolWithTag(NonPagedPool, (c->chunk_item->num_stripes + 2) * readlen << Vcb->sector_shift, ALLOC_TAG);
            if (!scratch) {
                ERR("out of memory\n");
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            i = (parity + 1) % c->chunk_item->num_stripes;
            logstripe = (c->chunk_item->num_stripes + c->chunk_item->num_stripes - 1 - parity + stripe) % c->chunk_item->num_stripes;

            for (k = 0; k < c->chunk_item->num_stripes; k++) {
                if (i != stripe) {
                    if (c->devices[i]->devobj) {
                        Status = sync_read_phys(c->devices[i]->devobj, c->devices[i]->fileobj, c->chunk_item->stripe[i].offset + startoff + ((offset % sl) << Vcb->sector_shift),
                                                readlen << Vcb->sector_shift, scratch + (k * readlen << Vcb->sector_shift), false);
                        if (!NT_SUCCESS(Status)) {
                            ERR("sync_read_phys returned %08lx\n", Status);
                            num_errors++;
                            error_stripe = k;
                        }
                    } else {
                        num_errors++;
                        error_stripe = k;
                    }

                    if (num_errors > 1) {
                        ExFreePool(scratch);
                        return STATUS_UNEXPECTED_IO_ERROR;
                    }
                }

                i = (i + 1) % c->chunk_item->num_stripes;
            }

            if (num_errors == 0 || error_stripe == c->chunk_item->num_stripes - 1) {
                for (k = 0; k < c->chunk_item->num_stripes - 1; k++) {
                    if (k != logstripe) {
                        if (k == 0 || (k == 1 && logstripe == 0)) {
                            RtlCopyMemory(ps->data + (offset << Vcb->sector_shift), scratch + (k * readlen << Vcb->sector_shift),
                                          readlen << Vcb->sector_shift);
                        } else {
                            do_xor(ps->data + (offset << Vcb->sector_shift), scratch + (k * readlen << Vcb->sector_shift),
                                   readlen << Vcb->sector_shift);
                        }
                    }
                }
            } else {
                raid6_recover2(scratch, c->chunk_item->num_stripes, readlen << Vcb->sector_shift, logstripe,
                               error_stripe, scratch + (c->chunk_item->num_stripes * readlen << Vcb->sector_shift));

                RtlCopyMemory(ps->data + (offset << Vcb->sector_shift), scratch + (c->chunk_item->num_stripes * readlen << Vcb->sector_shift),
                              readlen << Vcb->sector_shift);
            }

            ExFreePool(scratch);
        }

        offset += readlen;
        len -= readlen;
    }

    return STATUS_SUCCESS;
}

NTSTATUS flush_partial_stripe(device_extension* Vcb, chunk* c, partial_stripe* ps) {
    NTSTATUS Status;
    uint16_t parity2, stripe, startoffstripe;
    uint8_t* data;
    uint64_t startoff;
    ULONG runlength, index, last1;
    LIST_ENTRY* le;
    uint16_t k, num_data_stripes = c->chunk_item->num_stripes - (c->chunk_item->type & BLOCK_FLAG_RAID5 ? 1 : 2);
    uint64_t ps_length = num_data_stripes * c->chunk_item->stripe_len;
    ULONG stripe_length = (ULONG)c->chunk_item->stripe_len;

    // FIXME - do writes asynchronously?

    get_raid0_offset(ps->address - c->offset, stripe_length, num_data_stripes, &startoff, &startoffstripe);

    parity2 = (((ps->address - c->offset) / ps_length) + c->chunk_item->num_stripes - 1) % c->chunk_item->num_stripes;

    // read data (or reconstruct if degraded)

    runlength = RtlFindFirstRunClear(&ps->bmp, &index);
    last1 = 0;

    while (runlength != 0) {
        if (index >= ps->bmplen)
            break;

        if (index + runlength >= ps->bmplen) {
            runlength = ps->bmplen - index;

            if (runlength == 0)
                break;
        }

        if (index > last1) {
            Status = partial_stripe_read(Vcb, c, ps, startoff, parity2, last1, index - last1);
            if (!NT_SUCCESS(Status)) {
                ERR("partial_stripe_read returned %08lx\n", Status);
                return Status;
            }
        }

        last1 = index + runlength;

        runlength = RtlFindNextForwardRunClear(&ps->bmp, index + runlength, &index);
    }

    if (last1 < ps_length >> Vcb->sector_shift) {
        Status = partial_stripe_read(Vcb, c, ps, startoff, parity2, last1, (ULONG)((ps_length >> Vcb->sector_shift) - last1));
        if (!NT_SUCCESS(Status)) {
            ERR("partial_stripe_read returned %08lx\n", Status);
            return Status;
        }
    }

    // set unallocated data to 0
    le = c->space.Flink;
    while (le != &c->space) {
        space* s = CONTAINING_RECORD(le, space, list_entry);

        if (s->address + s->size > ps->address && s->address < ps->address + ps_length) {
            uint64_t start = max(ps->address, s->address);
            uint64_t end = min(ps->address + ps_length, s->address + s->size);

            RtlZeroMemory(ps->data + start - ps->address, (ULONG)(end - start));
        } else if (s->address >= ps->address + ps_length)
            break;

        le = le->Flink;
    }

    le = c->deleting.Flink;
    while (le != &c->deleting) {
        space* s = CONTAINING_RECORD(le, space, list_entry);

        if (s->address + s->size > ps->address && s->address < ps->address + ps_length) {
            uint64_t start = max(ps->address, s->address);
            uint64_t end = min(ps->address + ps_length, s->address + s->size);

            RtlZeroMemory(ps->data + start - ps->address, (ULONG)(end - start));
        } else if (s->address >= ps->address + ps_length)
            break;

        le = le->Flink;
    }

    stripe = (parity2 + 1) % c->chunk_item->num_stripes;

    data = ps->data;
    for (k = 0; k < num_data_stripes; k++) {
        if (c->devices[stripe]->devobj) {
            Status = write_data_phys(c->devices[stripe]->devobj, c->devices[stripe]->fileobj, c->chunk_item->stripe[stripe].offset + startoff, data, stripe_length);
            if (!NT_SUCCESS(Status)) {
                ERR("write_data_phys returned %08lx\n", Status);
                return Status;
            }
        }

        data += stripe_length;
        stripe = (stripe + 1) % c->chunk_item->num_stripes;
    }

    // write parity
    if (c->chunk_item->type & BLOCK_FLAG_RAID5) {
        if (c->devices[parity2]->devobj) {
            uint16_t i;

            for (i = 1; i < c->chunk_item->num_stripes - 1; i++) {
                do_xor(ps->data, ps->data + (i * stripe_length), stripe_length);
            }

            Status = write_data_phys(c->devices[parity2]->devobj, c->devices[parity2]->fileobj, c->chunk_item->stripe[parity2].offset + startoff, ps->data, stripe_length);
            if (!NT_SUCCESS(Status)) {
                ERR("write_data_phys returned %08lx\n", Status);
                return Status;
            }
        }
    } else {
        uint16_t parity1 = (parity2 + c->chunk_item->num_stripes - 1) % c->chunk_item->num_stripes;

        if (c->devices[parity1]->devobj || c->devices[parity2]->devobj) {
            uint8_t* scratch;
            uint16_t i;

            scratch = ExAllocatePoolWithTag(NonPagedPool, stripe_length * 2, ALLOC_TAG);
            if (!scratch) {
                ERR("out of memory\n");
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            i = c->chunk_item->num_stripes - 3;

            while (true) {
                if (i == c->chunk_item->num_stripes - 3) {
                    RtlCopyMemory(scratch, ps->data + (i * stripe_length), stripe_length);
                    RtlCopyMemory(scratch + stripe_length, ps->data + (i * stripe_length), stripe_length);
                } else {
                    do_xor(scratch, ps->data + (i * stripe_length), stripe_length);

                    galois_double(scratch + stripe_length, stripe_length);
                    do_xor(scratch + stripe_length, ps->data + (i * stripe_length), stripe_length);
                }

                if (i == 0)
                    break;

                i--;
            }

            if (c->devices[parity1]->devobj) {
                Status = write_data_phys(c->devices[parity1]->devobj, c->devices[parity1]->fileobj, c->chunk_item->stripe[parity1].offset + startoff, scratch, stripe_length);
                if (!NT_SUCCESS(Status)) {
                    ERR("write_data_phys returned %08lx\n", Status);
                    ExFreePool(scratch);
                    return Status;
                }
            }

            if (c->devices[parity2]->devobj) {
                Status = write_data_phys(c->devices[parity2]->devobj, c->devices[parity2]->fileobj, c->chunk_item->stripe[parity2].offset + startoff,
                                         scratch + stripe_length, stripe_length);
                if (!NT_SUCCESS(Status)) {
                    ERR("write_data_phys returned %08lx\n", Status);
                    ExFreePool(scratch);
                    return Status;
                }
            }

            ExFreePool(scratch);
        }
    }

    return STATUS_SUCCESS;
}

static NTSTATUS update_chunks(device_extension* Vcb, LIST_ENTRY* batchlist, PIRP Irp, LIST_ENTRY* rollback) {
    LIST_ENTRY *le, *le2;
    NTSTATUS Status;
    uint64_t used_minus_cache;

    ExAcquireResourceExclusiveLite(&Vcb->chunk_lock, true);

    // FIXME - do tree chunks before data chunks

    le = Vcb->chunks.Flink;
    while (le != &Vcb->chunks) {
        chunk* c = CONTAINING_RECORD(le, chunk, list_entry);

        le2 = le->Flink;

        if (c->changed) {
            acquire_chunk_lock(c, Vcb);

            // flush partial stripes
            if (!Vcb->readonly && (c->chunk_item->type & BLOCK_FLAG_RAID5 || c->chunk_item->type & BLOCK_FLAG_RAID6)) {
                ExAcquireResourceExclusiveLite(&c->partial_stripes_lock, true);

                while (!IsListEmpty(&c->partial_stripes)) {
                    partial_stripe* ps = CONTAINING_RECORD(RemoveHeadList(&c->partial_stripes), partial_stripe, list_entry);

                    Status = flush_partial_stripe(Vcb, c, ps);

                    if (ps->bmparr)
                        ExFreePool(ps->bmparr);

                    ExFreePool(ps);

                    if (!NT_SUCCESS(Status)) {
                        ERR("flush_partial_stripe returned %08lx\n", Status);
                        ExReleaseResourceLite(&c->partial_stripes_lock);
                        release_chunk_lock(c, Vcb);
                        ExReleaseResourceLite(&Vcb->chunk_lock);
                        return Status;
                    }
                }

                ExReleaseResourceLite(&c->partial_stripes_lock);
            }

            if (c->list_entry_balance.Flink) {
                release_chunk_lock(c, Vcb);
                le = le2;
                continue;
            }

            if (c->space_changed || c->created) {
                bool created = c->created;

                used_minus_cache = c->used;

                // subtract self-hosted cache
                if (used_minus_cache > 0 && c->chunk_item->type & BLOCK_FLAG_DATA && c->cache && c->cache->inode_item.size == c->used) {
                    LIST_ENTRY* le3;

                    le3 = c->cache->extents.Flink;
                    while (le3 != &c->cache->extents) {
                        extent* ext = CONTAINING_RECORD(le3, extent, list_entry);
                        struct btrfs_file_extent_item* ed = &ext->extent_data;

                        if (!ext->ignore) {
                            if (ed->type == EXTENT_TYPE_REGULAR || ed->type == EXTENT_TYPE_PREALLOC) {
                                if (ed->disk_num_bytes != 0 && ed->disk_bytenr >= c->offset && ed->disk_bytenr + ed->disk_num_bytes <= c->offset + c->chunk_item->length)
                                    used_minus_cache -= ed->disk_num_bytes;
                            }
                        }

                        le3 = le3->Flink;
                    }
                }

                if (used_minus_cache == 0) {
                    Status = drop_chunk(Vcb, c, batchlist, Irp, rollback);
                    if (!NT_SUCCESS(Status)) {
                        ERR("drop_chunk returned %08lx\n", Status);
                        release_chunk_lock(c, Vcb);
                        ExReleaseResourceLite(&Vcb->chunk_lock);
                        return Status;
                    }

                    // c is now freed, so avoid releasing non-existent lock
                    le = le2;
                    continue;
                } else if (c->created) {
                    Status = create_chunk(Vcb, c, Irp);
                    if (!NT_SUCCESS(Status)) {
                        ERR("create_chunk returned %08lx\n", Status);
                        release_chunk_lock(c, Vcb);
                        ExReleaseResourceLite(&Vcb->chunk_lock);
                        return Status;
                    }
                }

                if (used_minus_cache > 0 || created)
                    release_chunk_lock(c, Vcb);
            } else
                release_chunk_lock(c, Vcb);
        }

        le = le2;
    }

    ExReleaseResourceLite(&Vcb->chunk_lock);

    return STATUS_SUCCESS;
}

static NTSTATUS delete_root_ref(device_extension* Vcb, uint64_t subvolid, uint64_t parsubvolid, uint64_t parinode, PANSI_STRING utf8, PIRP Irp) {
    struct btrfs_key searchkey;
    traverse_ptr tp;
    NTSTATUS Status;

    searchkey.objectid = parsubvolid;
    searchkey.type = TYPE_ROOT_REF;
    searchkey.offset = subvolid;

    Status = find_item(Vcb, Vcb->root_root, &tp, &searchkey, false, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08lx\n", Status);
        return Status;
    }

    if (!keycmp(searchkey, tp.item->key)) {
        if (tp.item->size < sizeof(struct btrfs_root_ref)) {
            ERR("(%I64x,%x,%I64x) was %u bytes, expected at least %Iu\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset, tp.item->size, sizeof(struct btrfs_root_ref));
            return STATUS_INTERNAL_ERROR;
        } else {
            struct btrfs_root_ref* rr;
            ULONG len;

            rr = (struct btrfs_root_ref*)tp.item->data;
            len = tp.item->size;

            do {
                uint16_t itemlen;

                if (len < sizeof(struct btrfs_root_ref) || len < sizeof(struct btrfs_root_ref) + rr->name_len) {
                    ERR("(%I64x,%x,%I64x) was truncated\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset);
                    break;
                }

                itemlen = (uint16_t)sizeof(struct btrfs_root_ref) + rr->name_len;

                if (rr->dirid == parinode && rr->name_len == utf8->Length && RtlCompareMemory(&rr[1], utf8->Buffer, rr->name_len) == rr->name_len) {
                    uint16_t newlen = tp.item->size - itemlen;

                    Status = delete_tree_item(Vcb, &tp);
                    if (!NT_SUCCESS(Status)) {
                        ERR("delete_tree_item returned %08lx\n", Status);
                        return Status;
                    }

                    if (newlen == 0) {
                        TRACE("deleting (%I64x,%x,%I64x)\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset);
                    } else {
                        uint8_t *newrr = ExAllocatePoolWithTag(PagedPool, newlen, ALLOC_TAG), *rroff;

                        if (!newrr) {
                            ERR("out of memory\n");
                            return STATUS_INSUFFICIENT_RESOURCES;
                        }

                        TRACE("modifying (%I64x,%x,%I64x)\n", tp.item->key.objectid, tp.item->key.type, tp.item->key.offset);

                        if ((uint8_t*)rr > tp.item->data) {
                            RtlCopyMemory(newrr, tp.item->data, (uint8_t*)rr - tp.item->data);
                            rroff = newrr + ((uint8_t*)rr - tp.item->data);
                        } else {
                            rroff = newrr;
                        }

                        if ((uint8_t*)&rr[1] + rr->name_len < tp.item->data + tp.item->size)
                            RtlCopyMemory(rroff, (uint8_t*)&rr[1] + rr->name_len, tp.item->size - (((uint8_t*)&rr[1] + rr->name_len) - tp.item->data));

                        Status = insert_tree_item(Vcb, Vcb->root_root, tp.item->key.objectid, tp.item->key.type, tp.item->key.offset, newrr, newlen, NULL, Irp);
                        if (!NT_SUCCESS(Status)) {
                            ERR("insert_tree_item returned %08lx\n", Status);
                            ExFreePool(newrr);
                            return Status;
                        }
                    }

                    break;
                }

                if (len > itemlen) {
                    len -= itemlen;
                    rr = (struct btrfs_root_ref*)((uint8_t*)&rr[1] + rr->name_len);
                } else
                    break;
            } while (len > 0);
        }
    } else {
        WARN("could not find ROOT_REF entry for subvol %I64x in %I64x\n", searchkey.offset, searchkey.objectid);
        return STATUS_NOT_FOUND;
    }

    return STATUS_SUCCESS;
}

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(suppress: 28194)
#endif
static NTSTATUS add_root_ref(_In_ device_extension* Vcb, _In_ uint64_t subvolid, _In_ uint64_t parsubvolid, _In_ __drv_aliasesMem struct btrfs_root_ref* rr, _In_opt_ PIRP Irp) {
    struct btrfs_key searchkey;
    traverse_ptr tp;
    NTSTATUS Status;

    searchkey.objectid = parsubvolid;
    searchkey.type = TYPE_ROOT_REF;
    searchkey.offset = subvolid;

    Status = find_item(Vcb, Vcb->root_root, &tp, &searchkey, false, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08lx\n", Status);
        return Status;
    }

    if (!keycmp(searchkey, tp.item->key)) {
        uint16_t rrsize = tp.item->size + (uint16_t)sizeof(struct btrfs_root_ref) + rr->name_len;
        uint8_t* rr2;

        rr2 = ExAllocatePoolWithTag(PagedPool, rrsize, ALLOC_TAG);
        if (!rr2) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        if (tp.item->size > 0)
            RtlCopyMemory(rr2, tp.item->data, tp.item->size);

        RtlCopyMemory(rr2 + tp.item->size, rr, sizeof(struct btrfs_root_ref) + rr->name_len);
        ExFreePool(rr);

        Status = delete_tree_item(Vcb, &tp);
        if (!NT_SUCCESS(Status)) {
            ERR("delete_tree_item returned %08lx\n", Status);
            ExFreePool(rr2);
            return Status;
        }

        Status = insert_tree_item(Vcb, Vcb->root_root, searchkey.objectid, searchkey.type, searchkey.offset, rr2, rrsize, NULL, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("insert_tree_item returned %08lx\n", Status);
            ExFreePool(rr2);
            return Status;
        }
    } else {
        Status = insert_tree_item(Vcb, Vcb->root_root, searchkey.objectid, searchkey.type, searchkey.offset, rr, (uint16_t)sizeof(struct btrfs_root_ref) + rr->name_len, NULL, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("insert_tree_item returned %08lx\n", Status);
            ExFreePool(rr);
            return Status;
        }
    }

    return STATUS_SUCCESS;
}
#ifdef _MSC_VER
#pragma warning(pop)
#endif

static NTSTATUS update_root_backref(device_extension* Vcb, uint64_t subvolid, uint64_t parsubvolid, PIRP Irp) {
    struct btrfs_key searchkey;
    traverse_ptr tp;
    uint8_t* data;
    uint16_t datalen;
    NTSTATUS Status;

    searchkey.objectid = parsubvolid;
    searchkey.type = TYPE_ROOT_REF;
    searchkey.offset = subvolid;

    Status = find_item(Vcb, Vcb->root_root, &tp, &searchkey, false, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08lx\n", Status);
        return Status;
    }

    if (!keycmp(tp.item->key, searchkey) && tp.item->size > 0) {
        datalen = tp.item->size;

        data = ExAllocatePoolWithTag(PagedPool, datalen, ALLOC_TAG);
        if (!data) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlCopyMemory(data, tp.item->data, datalen);
    } else {
        datalen = 0;
        data = NULL;
    }

    searchkey.objectid = subvolid;
    searchkey.type = TYPE_ROOT_BACKREF;
    searchkey.offset = parsubvolid;

    Status = find_item(Vcb, Vcb->root_root, &tp, &searchkey, false, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08lx\n", Status);

        if (datalen > 0)
            ExFreePool(data);

        return Status;
    }

    if (!keycmp(tp.item->key, searchkey)) {
        Status = delete_tree_item(Vcb, &tp);
        if (!NT_SUCCESS(Status)) {
            ERR("delete_tree_item returned %08lx\n", Status);

            if (datalen > 0)
                ExFreePool(data);

            return Status;
        }
    }

    if (datalen > 0) {
        Status = insert_tree_item(Vcb, Vcb->root_root, subvolid, TYPE_ROOT_BACKREF, parsubvolid, data, datalen, NULL, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("insert_tree_item returned %08lx\n", Status);
            ExFreePool(data);
            return Status;
        }
    }

    return STATUS_SUCCESS;
}

static NTSTATUS add_root_item_to_cache(device_extension* Vcb, uint64_t root, PIRP Irp) {
    struct btrfs_key searchkey;
    traverse_ptr tp;
    NTSTATUS Status;

    searchkey.objectid = root;
    searchkey.type = TYPE_ROOT_ITEM;
    searchkey.offset = 0xffffffffffffffff;

    Status = find_item(Vcb, Vcb->root_root, &tp, &searchkey, false, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("error - find_item returned %08lx\n", Status);
        return Status;
    }

    if (tp.item->key.objectid != searchkey.objectid || tp.item->key.type != searchkey.type) {
        ERR("could not find ROOT_ITEM for tree %I64x\n", searchkey.objectid);
        return STATUS_INTERNAL_ERROR;
    }

    if (tp.item->size < sizeof(struct btrfs_root_item)) { // if not full length, create new entry with new bits zeroed
        struct btrfs_root_item* ri = ExAllocatePoolWithTag(PagedPool, sizeof(struct btrfs_root_item), ALLOC_TAG);
        if (!ri) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        if (tp.item->size > 0)
            RtlCopyMemory(ri, tp.item->data, tp.item->size);

        RtlZeroMemory(((uint8_t*)ri) + tp.item->size, sizeof(struct btrfs_root_item) - tp.item->size);

        Status = delete_tree_item(Vcb, &tp);
        if (!NT_SUCCESS(Status)) {
            ERR("delete_tree_item returned %08lx\n", Status);
            ExFreePool(ri);
            return Status;
        }

        Status = insert_tree_item(Vcb, Vcb->root_root, searchkey.objectid, searchkey.type, tp.item->key.offset, ri, sizeof(struct btrfs_root_item), NULL, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("insert_tree_item returned %08lx\n", Status);
            ExFreePool(ri);
            return Status;
        }
    } else {
        tp.tree->write = true;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS flush_fileref(file_ref* fileref, LIST_ENTRY* batchlist, PIRP Irp) {
    NTSTATUS Status;

    // if fileref created and then immediately deleted, do nothing
    if (fileref->created && fileref->deleted) {
        fileref->dirty = false;
        return STATUS_SUCCESS;
    }

    if (fileref->fcb->ads) {
        fileref->dirty = false;
        return STATUS_SUCCESS;
    }

    if (fileref->created) {
        uint16_t disize;
        struct btrfs_dir_item *di, *di2;
        uint32_t crc32;

        crc32 = calc_crc32c(0xfffffffe, (uint8_t*)fileref->dc->utf8.Buffer, fileref->dc->utf8.Length);

        disize = (uint16_t)(sizeof(struct btrfs_dir_item) + fileref->dc->utf8.Length);
        di = ExAllocatePoolWithTag(PagedPool, disize, ALLOC_TAG);
        if (!di) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        if (fileref->parent->fcb->subvol == fileref->fcb->subvol) {
            di->location.objectid = fileref->fcb->inode;
            di->location.type = TYPE_INODE_ITEM;
            di->location.offset = 0;
        } else { // subvolume
            di->location.objectid = fileref->fcb->subvol->id;
            di->location.type = TYPE_ROOT_ITEM;
            di->location.offset = 0xffffffffffffffff;
        }

        di->transid = fileref->fcb->Vcb->superblock.generation;
        di->data_len = 0;
        di->name_len = (uint16_t)fileref->dc->utf8.Length;
        di->type = fileref->fcb->type;
        RtlCopyMemory(&di[1], fileref->dc->utf8.Buffer, fileref->dc->utf8.Length);

        di2 = ExAllocatePoolWithTag(PagedPool, disize, ALLOC_TAG);
        if (!di2) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlCopyMemory(di2, di, disize);

        Status = insert_tree_item_batch(batchlist, fileref->fcb->Vcb, fileref->parent->fcb->subvol, fileref->parent->fcb->inode, TYPE_DIR_INDEX,
                                        fileref->dc->index, di, disize, Batch_Insert);
        if (!NT_SUCCESS(Status)) {
            ERR("insert_tree_item_batch returned %08lx\n", Status);
            return Status;
        }

        Status = insert_tree_item_batch(batchlist, fileref->fcb->Vcb, fileref->parent->fcb->subvol, fileref->parent->fcb->inode, TYPE_DIR_ITEM, crc32,
                                        di2, disize, Batch_DirItem);
        if (!NT_SUCCESS(Status)) {
            ERR("insert_tree_item_batch returned %08lx\n", Status);
            return Status;
        }

        if (fileref->parent->fcb->subvol == fileref->fcb->subvol) {
            struct btrfs_inode_ref* ir;

            ir = ExAllocatePoolWithTag(PagedPool, sizeof(struct btrfs_inode_ref) + fileref->dc->utf8.Length, ALLOC_TAG);
            if (!ir) {
                ERR("out of memory\n");
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            ir->index = fileref->dc->index;
            ir->name_len = fileref->dc->utf8.Length;
            RtlCopyMemory(&ir[1], fileref->dc->utf8.Buffer, ir->name_len);

            Status = insert_tree_item_batch(batchlist, fileref->fcb->Vcb, fileref->fcb->subvol, fileref->fcb->inode, TYPE_INODE_REF, fileref->parent->fcb->inode,
                                            ir, sizeof(struct btrfs_inode_ref) + ir->name_len, Batch_InodeRef);
            if (!NT_SUCCESS(Status)) {
                ERR("insert_tree_item_batch returned %08lx\n", Status);
                return Status;
            }
        } else if (fileref->fcb != fileref->fcb->Vcb->dummy_fcb) {
            ULONG rrlen;
            struct btrfs_root_ref* rr;

            rrlen = sizeof(struct btrfs_root_ref) + fileref->dc->utf8.Length;

            rr = ExAllocatePoolWithTag(PagedPool, rrlen, ALLOC_TAG);
            if (!rr) {
                ERR("out of memory\n");
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            rr->dirid = fileref->parent->fcb->inode;
            rr->sequence = fileref->dc->index;
            rr->name_len = fileref->dc->utf8.Length;
            RtlCopyMemory(&rr[1], fileref->dc->utf8.Buffer, fileref->dc->utf8.Length);

            Status = add_root_ref(fileref->fcb->Vcb, fileref->fcb->subvol->id, fileref->parent->fcb->subvol->id, rr, Irp);
            if (!NT_SUCCESS(Status)) {
                ERR("add_root_ref returned %08lx\n", Status);
                return Status;
            }

            Status = update_root_backref(fileref->fcb->Vcb, fileref->fcb->subvol->id, fileref->parent->fcb->subvol->id, Irp);
            if (!NT_SUCCESS(Status)) {
                ERR("update_root_backref returned %08lx\n", Status);
                return Status;
            }
        }

        fileref->created = false;
    } else if (fileref->deleted) {
        uint32_t crc32;
        ANSI_STRING* name;
        struct btrfs_dir_item* di;

        name = &fileref->oldutf8;

        crc32 = calc_crc32c(0xfffffffe, (uint8_t*)name->Buffer, name->Length);

        di = ExAllocatePoolWithTag(PagedPool, sizeof(struct btrfs_dir_item) + name->Length, ALLOC_TAG);
        if (!di) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        di->data_len = 0;
        di->name_len = name->Length;
        RtlCopyMemory(&di[1], name->Buffer, name->Length);

        // delete DIR_ITEM (0x54)

        Status = insert_tree_item_batch(batchlist, fileref->fcb->Vcb, fileref->parent->fcb->subvol, fileref->parent->fcb->inode, TYPE_DIR_ITEM,
                                        crc32, di, sizeof(struct btrfs_dir_item) + name->Length, Batch_DeleteDirItem);
        if (!NT_SUCCESS(Status)) {
            ERR("insert_tree_item_batch returned %08lx\n", Status);
            return Status;
        }

        if (fileref->parent->fcb->subvol == fileref->fcb->subvol) {
            struct btrfs_inode_ref* ir;

            // delete INODE_REF (0xc)

            ir = ExAllocatePoolWithTag(PagedPool, sizeof(struct btrfs_inode_ref) + name->Length, ALLOC_TAG);
            if (!ir) {
                ERR("out of memory\n");
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            ir->index = fileref->oldindex;
            ir->name_len = name->Length;
            RtlCopyMemory(&ir[1], name->Buffer, name->Length);

            Status = insert_tree_item_batch(batchlist, fileref->fcb->Vcb, fileref->parent->fcb->subvol, fileref->fcb->inode, TYPE_INODE_REF,
                                            fileref->parent->fcb->inode, ir, sizeof(struct btrfs_inode_ref) + name->Length, Batch_DeleteInodeRef);
            if (!NT_SUCCESS(Status)) {
                ERR("insert_tree_item_batch returned %08lx\n", Status);
                return Status;
            }
        } else if (fileref->fcb != fileref->fcb->Vcb->dummy_fcb) { // subvolume
            Status = delete_root_ref(fileref->fcb->Vcb, fileref->fcb->subvol->id, fileref->parent->fcb->subvol->id, fileref->parent->fcb->inode, name, Irp);
            if (!NT_SUCCESS(Status)) {
                ERR("delete_root_ref returned %08lx\n", Status);
                return Status;
            }

            Status = update_root_backref(fileref->fcb->Vcb, fileref->fcb->subvol->id, fileref->parent->fcb->subvol->id, Irp);
            if (!NT_SUCCESS(Status)) {
                ERR("update_root_backref returned %08lx\n", Status);
                return Status;
            }
        }

        // delete DIR_INDEX (0x60)

        Status = insert_tree_item_batch(batchlist, fileref->fcb->Vcb, fileref->parent->fcb->subvol, fileref->parent->fcb->inode, TYPE_DIR_INDEX,
                                        fileref->oldindex, NULL, 0, Batch_Delete);
        if (!NT_SUCCESS(Status)) {
            ERR("insert_tree_item_batch returned %08lx\n", Status);
            return Status;
        }

        if (fileref->oldutf8.Buffer) {
            ExFreePool(fileref->oldutf8.Buffer);
            fileref->oldutf8.Buffer = NULL;
        }
    } else { // rename or change type
        PANSI_STRING oldutf8 = fileref->oldutf8.Buffer ? &fileref->oldutf8 : &fileref->dc->utf8;
        uint32_t crc32, oldcrc32;
        uint16_t disize;
        struct btrfs_dir_item *olddi, *di, *di2;

        crc32 = calc_crc32c(0xfffffffe, (uint8_t*)fileref->dc->utf8.Buffer, fileref->dc->utf8.Length);

        if (!fileref->oldutf8.Buffer)
            oldcrc32 = crc32;
        else
            oldcrc32 = calc_crc32c(0xfffffffe, (uint8_t*)fileref->oldutf8.Buffer, fileref->oldutf8.Length);

        olddi = ExAllocatePoolWithTag(PagedPool, sizeof(struct btrfs_dir_item) + oldutf8->Length, ALLOC_TAG);
        if (!olddi) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        olddi->data_len = 0;
        olddi->name_len = (uint16_t)oldutf8->Length;
        RtlCopyMemory(&olddi[1], oldutf8->Buffer, oldutf8->Length);

        // delete DIR_ITEM (0x54)

        Status = insert_tree_item_batch(batchlist, fileref->fcb->Vcb, fileref->parent->fcb->subvol, fileref->parent->fcb->inode, TYPE_DIR_ITEM,
                                        oldcrc32, olddi, sizeof(struct btrfs_dir_item) + oldutf8->Length, Batch_DeleteDirItem);
        if (!NT_SUCCESS(Status)) {
            ERR("insert_tree_item_batch returned %08lx\n", Status);
            ExFreePool(olddi);
            return Status;
        }

        // add DIR_ITEM (0x54)

        disize = (uint16_t)(sizeof(struct btrfs_dir_item) + fileref->dc->utf8.Length);
        di = ExAllocatePoolWithTag(PagedPool, disize, ALLOC_TAG);
        if (!di) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        di2 = ExAllocatePoolWithTag(PagedPool, disize, ALLOC_TAG);
        if (!di2) {
            ERR("out of memory\n");
            ExFreePool(di);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        if (fileref->dc)
            di->location = fileref->dc->key;
        else if (fileref->parent->fcb->subvol == fileref->fcb->subvol) {
            di->location.objectid = fileref->fcb->inode;
            di->location.type = TYPE_INODE_ITEM;
            di->location.offset = 0;
        } else { // subvolume
            di->location.objectid = fileref->fcb->subvol->id;
            di->location.type = TYPE_ROOT_ITEM;
            di->location.offset = 0xffffffffffffffff;
        }

        di->transid = fileref->fcb->Vcb->superblock.generation;
        di->data_len = 0;
        di->name_len = (uint16_t)fileref->dc->utf8.Length;
        di->type = fileref->fcb->type;
        RtlCopyMemory(&di[1], fileref->dc->utf8.Buffer, fileref->dc->utf8.Length);

        RtlCopyMemory(di2, di, disize);

        Status = insert_tree_item_batch(batchlist, fileref->fcb->Vcb, fileref->parent->fcb->subvol, fileref->parent->fcb->inode, TYPE_DIR_ITEM, crc32,
                                        di, disize, Batch_DirItem);
        if (!NT_SUCCESS(Status)) {
            ERR("insert_tree_item_batch returned %08lx\n", Status);
            ExFreePool(di2);
            ExFreePool(di);
            return Status;
        }

        if (fileref->parent->fcb->subvol == fileref->fcb->subvol) {
            struct btrfs_inode_ref *ir, *ir2;

            // delete INODE_REF (0xc)

            ir = ExAllocatePoolWithTag(PagedPool, sizeof(struct btrfs_inode_ref) + oldutf8->Length, ALLOC_TAG);
            if (!ir) {
                ERR("out of memory\n");
                ExFreePool(di2);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            ir->index = fileref->dc->index;
            ir->name_len = oldutf8->Length;
            RtlCopyMemory(&ir[1], oldutf8->Buffer, ir->name_len);

            Status = insert_tree_item_batch(batchlist, fileref->fcb->Vcb, fileref->fcb->subvol, fileref->fcb->inode, TYPE_INODE_REF, fileref->parent->fcb->inode,
                                            ir, sizeof(struct btrfs_inode_ref) + ir->name_len, Batch_DeleteInodeRef);
            if (!NT_SUCCESS(Status)) {
                ERR("insert_tree_item_batch returned %08lx\n", Status);
                ExFreePool(ir);
                ExFreePool(di2);
                return Status;
            }

            // add INODE_REF (0xc)

            ir2 = ExAllocatePoolWithTag(PagedPool, sizeof(struct btrfs_inode_ref) + fileref->dc->utf8.Length, ALLOC_TAG);
            if (!ir2) {
                ERR("out of memory\n");
                ExFreePool(di2);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            ir2->index = fileref->dc->index;
            ir2->name_len = fileref->dc->utf8.Length;
            RtlCopyMemory(&ir2[1], fileref->dc->utf8.Buffer, ir2->name_len);

            Status = insert_tree_item_batch(batchlist, fileref->fcb->Vcb, fileref->fcb->subvol, fileref->fcb->inode, TYPE_INODE_REF, fileref->parent->fcb->inode,
                                            ir2, sizeof(struct btrfs_inode_ref) + ir2->name_len, Batch_InodeRef);
            if (!NT_SUCCESS(Status)) {
                ERR("insert_tree_item_batch returned %08lx\n", Status);
                ExFreePool(ir2);
                ExFreePool(di2);
                return Status;
            }
        } else if (fileref->fcb != fileref->fcb->Vcb->dummy_fcb) { // subvolume
            ULONG rrlen;
            struct btrfs_root_ref* rr;

            Status = delete_root_ref(fileref->fcb->Vcb, fileref->fcb->subvol->id, fileref->parent->fcb->subvol->id, fileref->parent->fcb->inode, oldutf8, Irp);
            if (!NT_SUCCESS(Status)) {
                ERR("delete_root_ref returned %08lx\n", Status);
                ExFreePool(di2);
                return Status;
            }

            rrlen = sizeof(struct btrfs_root_ref) + fileref->dc->utf8.Length;

            rr = ExAllocatePoolWithTag(PagedPool, rrlen, ALLOC_TAG);
            if (!rr) {
                ERR("out of memory\n");
                ExFreePool(di2);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            rr->dirid = fileref->parent->fcb->inode;
            rr->sequence = fileref->dc->index;
            rr->name_len = fileref->dc->utf8.Length;
            RtlCopyMemory(&rr[1], fileref->dc->utf8.Buffer, fileref->dc->utf8.Length);

            Status = add_root_ref(fileref->fcb->Vcb, fileref->fcb->subvol->id, fileref->parent->fcb->subvol->id, rr, Irp);
            if (!NT_SUCCESS(Status)) {
                ERR("add_root_ref returned %08lx\n", Status);
                ExFreePool(di2);
                return Status;
            }

            Status = update_root_backref(fileref->fcb->Vcb, fileref->fcb->subvol->id, fileref->parent->fcb->subvol->id, Irp);
            if (!NT_SUCCESS(Status)) {
                ERR("update_root_backref returned %08lx\n", Status);
                ExFreePool(di2);
                return Status;
            }
        }

        // delete DIR_INDEX (0x60)

        Status = insert_tree_item_batch(batchlist, fileref->fcb->Vcb, fileref->parent->fcb->subvol, fileref->parent->fcb->inode, TYPE_DIR_INDEX,
                                        fileref->dc->index, NULL, 0, Batch_Delete);
        if (!NT_SUCCESS(Status)) {
            ERR("insert_tree_item_batch returned %08lx\n", Status);
            ExFreePool(di2);
            return Status;
        }

        // add DIR_INDEX (0x60)

       Status = insert_tree_item_batch(batchlist, fileref->fcb->Vcb, fileref->parent->fcb->subvol, fileref->parent->fcb->inode, TYPE_DIR_INDEX,
                                       fileref->dc->index, di2, disize, Batch_Insert);
       if (!NT_SUCCESS(Status)) {
            ERR("insert_tree_item_batch returned %08lx\n", Status);
            ExFreePool(di2);
            return Status;
        }

        if (fileref->oldutf8.Buffer) {
            ExFreePool(fileref->oldutf8.Buffer);
            fileref->oldutf8.Buffer = NULL;
        }
    }

    fileref->dirty = false;

    return STATUS_SUCCESS;
}

static void flush_disk_caches(device_extension* Vcb) {
    LIST_ENTRY* le;
    ioctl_context context;
    ULONG num;

    context.left = 0;

    le = Vcb->devices.Flink;

    while (le != &Vcb->devices) {
        device* dev = CONTAINING_RECORD(le, device, list_entry);

        if (dev->devobj && !dev->readonly && dev->can_flush)
            context.left++;

        le = le->Flink;
    }

    if (context.left == 0)
        return;

    num = 0;

    KeInitializeEvent(&context.Event, NotificationEvent, false);

    context.stripes = ExAllocatePoolWithTag(NonPagedPool, sizeof(ioctl_context_stripe) * context.left, ALLOC_TAG);
    if (!context.stripes) {
        ERR("out of memory\n");
        return;
    }

    RtlZeroMemory(context.stripes, sizeof(ioctl_context_stripe) * context.left);

    le = Vcb->devices.Flink;

    while (le != &Vcb->devices) {
        device* dev = CONTAINING_RECORD(le, device, list_entry);

        if (dev->devobj && !dev->readonly && dev->can_flush) {
            PIO_STACK_LOCATION IrpSp;
            ioctl_context_stripe* stripe = &context.stripes[num];

            RtlZeroMemory(&stripe->apte, sizeof(ATA_PASS_THROUGH_EX));

            stripe->apte.Length = sizeof(ATA_PASS_THROUGH_EX);
            stripe->apte.TimeOutValue = 5;
            stripe->apte.CurrentTaskFile[6] = IDE_COMMAND_FLUSH_CACHE;

            stripe->Irp = IoAllocateIrp(dev->devobj->StackSize, false);

            if (!stripe->Irp) {
                ERR("IoAllocateIrp failed\n");
                goto nextdev;
            }

            IrpSp = IoGetNextIrpStackLocation(stripe->Irp);
            IrpSp->MajorFunction = IRP_MJ_DEVICE_CONTROL;
            IrpSp->FileObject = dev->fileobj;

            IrpSp->Parameters.DeviceIoControl.IoControlCode = IOCTL_ATA_PASS_THROUGH;
            IrpSp->Parameters.DeviceIoControl.InputBufferLength = sizeof(ATA_PASS_THROUGH_EX);
            IrpSp->Parameters.DeviceIoControl.OutputBufferLength = sizeof(ATA_PASS_THROUGH_EX);

            stripe->Irp->AssociatedIrp.SystemBuffer = &stripe->apte;
            stripe->Irp->Flags |= IRP_BUFFERED_IO | IRP_INPUT_OPERATION;
            stripe->Irp->UserBuffer = &stripe->apte;
            stripe->Irp->UserIosb = &stripe->iosb;

            IoSetCompletionRoutine(stripe->Irp, ioctl_completion, &context, true, true, true);

            IoCallDriver(dev->devobj, stripe->Irp);

nextdev:
            num++;
        }

        le = le->Flink;
    }

    KeWaitForSingleObject(&context.Event, Executive, KernelMode, false, NULL);

    for (unsigned int i = 0; i < num; i++) {
        if (context.stripes[i].Irp)
            IoFreeIrp(context.stripes[i].Irp);
    }

    ExFreePool(context.stripes);
}

static NTSTATUS flush_changed_dev_stats(device_extension* Vcb, device* dev, PIRP Irp) {
    NTSTATUS Status;
    struct btrfs_key searchkey;
    traverse_ptr tp;
    uint16_t statslen;
    uint64_t* stats;

    searchkey.objectid = 0;
    searchkey.type = TYPE_DEV_STATS;
    searchkey.offset = dev->devitem.devid;

    Status = find_item(Vcb, Vcb->dev_root, &tp, &searchkey, false, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("find_item returned %08lx\n", Status);
        return Status;
    }

    if (!keycmp(tp.item->key, searchkey)) {
        Status = delete_tree_item(Vcb, &tp);
        if (!NT_SUCCESS(Status)) {
            ERR("delete_tree_item returned %08lx\n", Status);
            return Status;
        }
    }

    statslen = sizeof(uint64_t) * 5;
    stats = ExAllocatePoolWithTag(PagedPool, statslen, ALLOC_TAG);
    if (!stats) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(stats, dev->stats, statslen);

    Status = insert_tree_item(Vcb, Vcb->dev_root, 0, TYPE_DEV_STATS, dev->devitem.devid, stats, statslen, NULL, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("insert_tree_item returned %08lx\n", Status);
        ExFreePool(stats);
        return Status;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS flush_subvol(device_extension* Vcb, root* r, PIRP Irp) {
    NTSTATUS Status;

    if (r != Vcb->root_root && r != Vcb->chunk_root) {
        struct btrfs_key searchkey;
        traverse_ptr tp;
        struct btrfs_root_item* ri;

        searchkey.objectid = r->id;
        searchkey.type = TYPE_ROOT_ITEM;
        searchkey.offset = 0xffffffffffffffff;

        Status = find_item(Vcb, Vcb->root_root, &tp, &searchkey, false, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("error - find_item returned %08lx\n", Status);
            return Status;
        }

        if (tp.item->key.objectid != searchkey.objectid || tp.item->key.type != searchkey.type) {
            ERR("could not find ROOT_ITEM for tree %I64x\n", searchkey.objectid);
            return STATUS_INTERNAL_ERROR;
        }

        ri = ExAllocatePoolWithTag(PagedPool, sizeof(struct btrfs_root_item), ALLOC_TAG);
        if (!ri) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlCopyMemory(ri, &r->root_item, sizeof(struct btrfs_root_item));

        Status = delete_tree_item(Vcb, &tp);
        if (!NT_SUCCESS(Status)) {
            ERR("delete_tree_item returned %08lx\n", Status);
            return Status;
        }

        Status = insert_tree_item(Vcb, Vcb->root_root, tp.item->key.objectid, tp.item->key.type, tp.item->key.offset, ri, sizeof(struct btrfs_root_item), NULL, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("insert_tree_item returned %08lx\n", Status);
            return Status;
        }
    }

    if (r->received) {
        struct btrfs_key searchkey;
        traverse_ptr tp;

        if (!Vcb->uuid_root) {
            root* uuid_root;

            TRACE("uuid root doesn't exist, creating it\n");

            Status = create_root(Vcb, BTRFS_ROOT_UUID, &uuid_root, false, 0, Irp);

            if (!NT_SUCCESS(Status)) {
                ERR("create_root returned %08lx\n", Status);
                return Status;
            }

            Vcb->uuid_root = uuid_root;
        }

        RtlCopyMemory(&searchkey.objectid, &r->root_item.received_uuid, sizeof(uint64_t));
        searchkey.type = TYPE_SUBVOL_REC_UUID;
        RtlCopyMemory(&searchkey.offset, &r->root_item.received_uuid.uuid[sizeof(uint64_t)], sizeof(uint64_t));

        Status = find_item(Vcb, Vcb->uuid_root, &tp, &searchkey, false, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("find_item returned %08lx\n", Status);
            return Status;
        }

        if (!keycmp(tp.item->key, searchkey)) {
            if (tp.item->size + sizeof(uint64_t) <= Vcb->superblock.nodesize - sizeof(struct btrfs_header) - sizeof(struct btrfs_item)) {
                uint64_t* ids;

                ids = ExAllocatePoolWithTag(PagedPool, tp.item->size + sizeof(uint64_t), ALLOC_TAG);
                if (!ids) {
                    ERR("out of memory\n");
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                RtlCopyMemory(ids, tp.item->data, tp.item->size);
                RtlCopyMemory((uint8_t*)ids + tp.item->size, &r->id, sizeof(uint64_t));

                Status = delete_tree_item(Vcb, &tp);
                if (!NT_SUCCESS(Status)) {
                    ERR("delete_tree_item returned %08lx\n", Status);
                    ExFreePool(ids);
                    return Status;
                }

                Status = insert_tree_item(Vcb, Vcb->uuid_root, searchkey.objectid, searchkey.type, searchkey.offset, ids, tp.item->size + sizeof(uint64_t), NULL, Irp);
                if (!NT_SUCCESS(Status)) {
                    ERR("insert_tree_item returned %08lx\n", Status);
                    ExFreePool(ids);
                    return Status;
                }
            }
        } else {
            uint64_t* root_num;

            root_num = ExAllocatePoolWithTag(PagedPool, sizeof(uint64_t), ALLOC_TAG);
            if (!root_num) {
                ERR("out of memory\n");
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            *root_num = r->id;

            Status = insert_tree_item(Vcb, Vcb->uuid_root, searchkey.objectid, searchkey.type, searchkey.offset, root_num, sizeof(uint64_t), NULL, Irp);
            if (!NT_SUCCESS(Status)) {
                ERR("insert_tree_item returned %08lx\n", Status);
                ExFreePool(root_num);
                return Status;
            }
        }

        r->received = false;
    }

    r->dirty = false;

    return STATUS_SUCCESS;
}

static NTSTATUS test_not_full(device_extension* Vcb) {
    uint64_t reserve, could_alloc, free_space;
    LIST_ENTRY* le;

    // This function ensures we drop into readonly mode if we're about to leave very little
    // space for metadata - this is similar to the "global reserve" of the Linux driver.
    // Otherwise we might completely fill our space, at which point due to COW we can't
    // delete anything in order to fix this.

    reserve = Vcb->extent_root->root_item.bytes_used;
    reserve += Vcb->root_root->root_item.bytes_used;
    if (Vcb->checksum_root) reserve += Vcb->checksum_root->root_item.bytes_used;

    reserve = max(reserve, 0x1000000); // 16 M
    reserve = min(reserve, 0x20000000); // 512 M

    // Find out how much space would be available for new metadata chunks

    could_alloc = 0;

    if (Vcb->metadata_flags & BLOCK_FLAG_RAID5) {
        uint64_t s1 = 0, s2 = 0, s3 = 0;

        le = Vcb->devices.Flink;
        while (le != &Vcb->devices) {
            device* dev = CONTAINING_RECORD(le, device, list_entry);

            if (!dev->readonly) {
                uint64_t space = dev->devitem.total_bytes - dev->devitem.bytes_used;

                if (space >= s1) {
                    s3 = s2;
                    s2 = s1;
                    s1 = space;
                } else if (space >= s2) {
                    s3 = s2;
                    s2 = space;
                } else if (space >= s3)
                    s3 = space;
            }

            le = le->Flink;
        }

        could_alloc = s3 * 2;
    } else if (Vcb->metadata_flags & (BLOCK_FLAG_RAID10 | BLOCK_FLAG_RAID6)) {
        uint64_t s1 = 0, s2 = 0, s3 = 0, s4 = 0;

        le = Vcb->devices.Flink;
        while (le != &Vcb->devices) {
            device* dev = CONTAINING_RECORD(le, device, list_entry);

            if (!dev->readonly) {
                uint64_t space = dev->devitem.total_bytes - dev->devitem.bytes_used;

                if (space >= s1) {
                    s4 = s3;
                    s3 = s2;
                    s2 = s1;
                    s1 = space;
                } else if (space >= s2) {
                    s4 = s3;
                    s3 = s2;
                    s2 = space;
                } else if (space >= s3) {
                    s4 = s3;
                    s3 = space;
                } else if (space >= s4)
                    s4 = space;
            }

            le = le->Flink;
        }

        could_alloc = s4 * 2;
    } else if (Vcb->metadata_flags & (BLOCK_FLAG_RAID0 | BLOCK_FLAG_RAID1)) {
        uint64_t s1 = 0, s2 = 0;

        le = Vcb->devices.Flink;
        while (le != &Vcb->devices) {
            device* dev = CONTAINING_RECORD(le, device, list_entry);

            if (!dev->readonly) {
                uint64_t space = dev->devitem.total_bytes - dev->devitem.bytes_used;

                if (space >= s1) {
                    s2 = s1;
                    s1 = space;
                } else if (space >= s2)
                    s2 = space;
            }

            le = le->Flink;
        }

        if (Vcb->metadata_flags & BLOCK_FLAG_RAID1)
            could_alloc = s2;
        else // RAID0
            could_alloc = s2 * 2;
    } else if (Vcb->metadata_flags & BLOCK_FLAG_DUPLICATE) {
        le = Vcb->devices.Flink;
        while (le != &Vcb->devices) {
            device* dev = CONTAINING_RECORD(le, device, list_entry);

            if (!dev->readonly) {
                uint64_t space = (dev->devitem.total_bytes - dev->devitem.bytes_used) / 2;

                could_alloc = max(could_alloc, space);
            }

            le = le->Flink;
        }
    } else if (Vcb->metadata_flags & BLOCK_FLAG_RAID1C3) {
        uint64_t s1 = 0, s2 = 0, s3 = 0;

        le = Vcb->devices.Flink;
        while (le != &Vcb->devices) {
            device* dev = CONTAINING_RECORD(le, device, list_entry);

            if (!dev->readonly) {
                uint64_t space = dev->devitem.total_bytes - dev->devitem.bytes_used;

                if (space >= s1) {
                    s3 = s2;
                    s2 = s1;
                    s1 = space;
                } else if (space >= s2) {
                    s3 = s2;
                    s2 = space;
                } else if (space >= s3)
                    s3 = space;
            }

            le = le->Flink;
        }

        could_alloc = s3;
    } else if (Vcb->metadata_flags & BLOCK_FLAG_RAID1C4) {
        uint64_t s1 = 0, s2 = 0, s3 = 0, s4 = 0;

        le = Vcb->devices.Flink;
        while (le != &Vcb->devices) {
            device* dev = CONTAINING_RECORD(le, device, list_entry);

            if (!dev->readonly) {
                uint64_t space = dev->devitem.total_bytes - dev->devitem.bytes_used;

                if (space >= s1) {
                    s4 = s3;
                    s3 = s2;
                    s2 = s1;
                    s1 = space;
                } else if (space >= s2) {
                    s4 = s3;
                    s3 = s2;
                    s2 = space;
                } else if (space >= s3) {
                    s4 = s3;
                    s3 = space;
                } else if (space >= s4)
                    s4 = space;
            }

            le = le->Flink;
        }

        could_alloc = s4;
    } else { // SINGLE
        le = Vcb->devices.Flink;
        while (le != &Vcb->devices) {
            device* dev = CONTAINING_RECORD(le, device, list_entry);

            if (!dev->readonly) {
                uint64_t space = dev->devitem.total_bytes - dev->devitem.bytes_used;

                could_alloc = max(could_alloc, space);
            }

            le = le->Flink;
        }
    }

    if (could_alloc >= reserve)
        return STATUS_SUCCESS;

    free_space = 0;

    le = Vcb->chunks.Flink;
    while (le != &Vcb->chunks) {
        chunk* c = CONTAINING_RECORD(le, chunk, list_entry);

        if (!c->reloc && !c->readonly && c->chunk_item->type & BLOCK_FLAG_METADATA) {
            free_space += c->chunk_item->length - c->used;

            if (free_space + could_alloc >= reserve)
                return STATUS_SUCCESS;
        }

        le = le->Flink;
    }

    return STATUS_DISK_FULL;
}

static NTSTATUS check_for_orphans_root(device_extension* Vcb, root* r, PIRP Irp) {
    NTSTATUS Status;
    struct btrfs_key searchkey;
    traverse_ptr tp;
    LIST_ENTRY rollback;

    TRACE("(%p, %p)\n", Vcb, r);

    InitializeListHead(&rollback);

    searchkey.objectid = BTRFS_ORPHAN_INODE_OBJID;
    searchkey.type = TYPE_ORPHAN_INODE;
    searchkey.offset = 0;

    Status = find_item(Vcb, r, &tp, &searchkey, false, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("find_item returned %08lx\n", Status);
        return Status;
    }

    do {
        traverse_ptr next_tp;

        if (tp.item->key.objectid > searchkey.objectid || (tp.item->key.objectid == searchkey.objectid && tp.item->key.type > searchkey.type))
            break;

        if (tp.item->key.objectid == searchkey.objectid && tp.item->key.type == searchkey.type) {
            fcb* fcb;

            TRACE("removing orphaned inode %I64x\n", tp.item->key.offset);

            Status = open_fcb(Vcb, r, tp.item->key.offset, 0, NULL, false, NULL, &fcb, PagedPool, Irp);
            if (!NT_SUCCESS(Status))
                ERR("open_fcb returned %08lx\n", Status);
            else {
                if (fcb->inode_item.nlink == 0) {
                    if (fcb->type != BTRFS_TYPE_DIRECTORY && fcb->inode_item.size > 0) {
                        Status = excise_extents(Vcb, fcb, 0, sector_align(fcb->inode_item.size, Vcb->superblock.sectorsize), Irp, &rollback);
                        if (!NT_SUCCESS(Status)) {
                            ERR("excise_extents returned %08lx\n", Status);
                            goto end;
                        }
                    }

                    fcb->deleted = true;

                    mark_fcb_dirty(fcb);
                }

                free_fcb(fcb);

                Status = delete_tree_item(Vcb, &tp);
                if (!NT_SUCCESS(Status)) {
                    ERR("delete_tree_item returned %08lx\n", Status);
                    goto end;
                }
            }
        }

        if (find_next_item(Vcb, &tp, &next_tp, false, Irp))
            tp = next_tp;
        else
            break;
    } while (true);

    Status = STATUS_SUCCESS;

    clear_rollback(&rollback);

end:
    do_rollback(Vcb, &rollback);

    return Status;
}

static NTSTATUS check_for_orphans(device_extension* Vcb, PIRP Irp) {
    NTSTATUS Status;
    LIST_ENTRY* le;

    if (IsListEmpty(&Vcb->dirty_filerefs))
        return STATUS_SUCCESS;

    le = Vcb->dirty_filerefs.Flink;
    while (le != &Vcb->dirty_filerefs) {
        file_ref* fr = CONTAINING_RECORD(le, file_ref, list_entry_dirty);

        if (!fr->fcb->subvol->checked_for_orphans) {
            Status = check_for_orphans_root(Vcb, fr->fcb->subvol, Irp);
            if (!NT_SUCCESS(Status)) {
                ERR("check_for_orphans_root returned %08lx\n", Status);
                return Status;
            }

            fr->fcb->subvol->checked_for_orphans = true;
        }

        le = le->Flink;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS do_write2(device_extension* Vcb, PIRP Irp, LIST_ENTRY* rollback) {
    NTSTATUS Status;
    LIST_ENTRY *le, batchlist;
    bool cache_changed = false;
    volume_device_extension* vde;
    bool no_cache = false;
#ifdef DEBUG_FLUSH_TIMES
    uint64_t filerefs = 0, fcbs = 0;
    LARGE_INTEGER freq, time1, time2;
#endif
#ifdef DEBUG_WRITE_LOOPS
    UINT loops = 0;
#endif

    TRACE("(%p)\n", Vcb);

    InitializeListHead(&batchlist);

#ifdef DEBUG_FLUSH_TIMES
    time1 = KeQueryPerformanceCounter(&freq);
#endif

    Status = check_for_orphans(Vcb, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("check_for_orphans returned %08lx\n", Status);
        return Status;
    }

    ExAcquireResourceExclusiveLite(&Vcb->dirty_filerefs_lock, true);

    while (!IsListEmpty(&Vcb->dirty_filerefs)) {
        file_ref* fr = CONTAINING_RECORD(RemoveHeadList(&Vcb->dirty_filerefs), file_ref, list_entry_dirty);

        flush_fileref(fr, &batchlist, Irp);
        free_fileref(fr);

#ifdef DEBUG_FLUSH_TIMES
        filerefs++;
#endif
    }

    ExReleaseResourceLite(&Vcb->dirty_filerefs_lock);

    Status = commit_batch_list(Vcb, &batchlist, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("commit_batch_list returned %08lx\n", Status);
        return Status;
    }

#ifdef DEBUG_FLUSH_TIMES
    time2 = KeQueryPerformanceCounter(NULL);

    ERR("flushed %I64u filerefs in %I64u (freq = %I64u)\n", filerefs, time2.QuadPart - time1.QuadPart, freq.QuadPart);

    time1 = KeQueryPerformanceCounter(&freq);
#endif

    // We process deleted streams first, so we don't run over our xattr
    // limit unless we absolutely have to.
    // We also process deleted normal files, to avoid any problems
    // caused by inode collisions.

    ExAcquireResourceExclusiveLite(&Vcb->dirty_fcbs_lock, true);

    le = Vcb->dirty_fcbs.Flink;
    while (le != &Vcb->dirty_fcbs) {
        fcb* fcb = CONTAINING_RECORD(le, struct _fcb, list_entry_dirty);
        LIST_ENTRY* le2 = le->Flink;

        if (fcb->deleted) {
            ExAcquireResourceExclusiveLite(fcb->Header.Resource, true);
            Status = flush_fcb(fcb, false, &batchlist, Irp);
            ExReleaseResourceLite(fcb->Header.Resource);

            free_fcb(fcb);

            if (!NT_SUCCESS(Status)) {
                ERR("flush_fcb returned %08lx\n", Status);
                clear_batch_list(Vcb, &batchlist);
                ExReleaseResourceLite(&Vcb->dirty_fcbs_lock);
                return Status;
            }

#ifdef DEBUG_FLUSH_TIMES
            fcbs++;
#endif
        }

        le = le2;
    }

    Status = commit_batch_list(Vcb, &batchlist, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("commit_batch_list returned %08lx\n", Status);
        ExReleaseResourceLite(&Vcb->dirty_fcbs_lock);
        return Status;
    }

    le = Vcb->dirty_fcbs.Flink;
    while (le != &Vcb->dirty_fcbs) {
        fcb* fcb = CONTAINING_RECORD(le, struct _fcb, list_entry_dirty);
        LIST_ENTRY* le2 = le->Flink;

        if (fcb->subvol != Vcb->root_root) {
            ExAcquireResourceExclusiveLite(fcb->Header.Resource, true);
            Status = flush_fcb(fcb, false, &batchlist, Irp);
            ExReleaseResourceLite(fcb->Header.Resource);
            free_fcb(fcb);

            if (!NT_SUCCESS(Status)) {
                ERR("flush_fcb returned %08lx\n", Status);
                ExReleaseResourceLite(&Vcb->dirty_fcbs_lock);
                return Status;
            }

#ifdef DEBUG_FLUSH_TIMES
            fcbs++;
#endif
        }

        le = le2;
    }

    ExReleaseResourceLite(&Vcb->dirty_fcbs_lock);

    Status = commit_batch_list(Vcb, &batchlist, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("commit_batch_list returned %08lx\n", Status);
        return Status;
    }

#ifdef DEBUG_FLUSH_TIMES
    time2 = KeQueryPerformanceCounter(NULL);

    ERR("flushed %I64u fcbs in %I64u (freq = %I64u)\n", filerefs, time2.QuadPart - time1.QuadPart, freq.QuadPart);
#endif

    // no need to get dirty_subvols_lock here, as we have tree_lock exclusively
    while (!IsListEmpty(&Vcb->dirty_subvols)) {
        root* r = CONTAINING_RECORD(RemoveHeadList(&Vcb->dirty_subvols), root, list_entry_dirty);

        Status = flush_subvol(Vcb, r, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("flush_subvol returned %08lx\n", Status);
            return Status;
        }
    }

    if (!IsListEmpty(&Vcb->drop_roots)) {
        Status = drop_roots(Vcb, Irp, rollback);

        if (!NT_SUCCESS(Status)) {
            ERR("drop_roots returned %08lx\n", Status);
            return Status;
        }
    }

    Status = update_chunks(Vcb, &batchlist, Irp, rollback);

    if (!NT_SUCCESS(Status)) {
        ERR("update_chunks returned %08lx\n", Status);
        return Status;
    }

    Status = commit_batch_list(Vcb, &batchlist, Irp);

    // If only changing superblock, e.g. changing label, we still need to rewrite
    // the root tree so the generations match, otherwise you won't be able to mount on Linux.
    if (!Vcb->root_root->treeholder.tree || !Vcb->root_root->treeholder.tree->write) {
        struct btrfs_key searchkey;

        traverse_ptr tp;

        searchkey.objectid = 0;
        searchkey.type = 0;
        searchkey.offset = 0;

        Status = find_item(Vcb, Vcb->root_root, &tp, &searchkey, false, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("error - find_item returned %08lx\n", Status);
            return Status;
        }

        Vcb->root_root->treeholder.tree->write = true;
    }

    // make sure we always update the extent tree
    Status = add_root_item_to_cache(Vcb, BTRFS_ROOT_EXTENT, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("add_root_item_to_cache returned %08lx\n", Status);
        return Status;
    }

    if (Vcb->stats_changed) {
        le = Vcb->devices.Flink;
        while (le != &Vcb->devices) {
            device* dev = CONTAINING_RECORD(le, device, list_entry);

            if (dev->stats_changed) {
                Status = flush_changed_dev_stats(Vcb, dev, Irp);
                if (!NT_SUCCESS(Status)) {
                    ERR("flush_changed_dev_stats returned %08lx\n", Status);
                    return Status;
                }
                dev->stats_changed = false;
            }

            le = le->Flink;
        }

        Vcb->stats_changed = false;
    }

    do {
        Status = add_parents(Vcb, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("add_parents returned %08lx\n", Status);
            goto end;
        }

        Status = allocate_tree_extents(Vcb, Irp, rollback);
        if (!NT_SUCCESS(Status)) {
            ERR("allocate_tree_extents returned %08lx\n", Status);
            goto end;
        }

        Status = do_splits(Vcb, Irp, rollback);
        if (!NT_SUCCESS(Status)) {
            ERR("do_splits returned %08lx\n", Status);
            goto end;
        }

        Status = update_chunk_usage(Vcb, Irp, rollback);
        if (!NT_SUCCESS(Status)) {
            ERR("update_chunk_usage returned %08lx\n", Status);
            goto end;
        }

        if (!(Vcb->superblock.compat_ro_flags & BTRFS_COMPAT_RO_FLAGS_FREE_SPACE_CACHE)) {
            if (!no_cache) {
                Status = allocate_cache(Vcb, &cache_changed, Irp, rollback);
                if (!NT_SUCCESS(Status)) {
                    WARN("allocate_cache returned %08lx\n", Status);
                    no_cache = true;
                    cache_changed = false;
                }
            }
        } else {
            Status = update_chunk_caches_tree(Vcb, Irp);
            if (!NT_SUCCESS(Status)) {
                ERR("update_chunk_caches_tree returned %08lx\n", Status);
                goto end;
            }
        }

#ifdef DEBUG_WRITE_LOOPS
        loops++;

        if (cache_changed)
            ERR("cache has changed, looping again\n");
#endif
    } while (cache_changed || !trees_consistent(Vcb));

#ifdef DEBUG_WRITE_LOOPS
    ERR("%u loops\n", loops);
#endif

    TRACE("trees consistent\n");

    Status = update_root_root(Vcb, no_cache, Irp, rollback);
    if (!NT_SUCCESS(Status)) {
        ERR("update_root_root returned %08lx\n", Status);
        goto end;
    }

    Status = write_trees(Vcb, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("write_trees returned %08lx\n", Status);
        goto end;
    }

    Status = test_not_full(Vcb);
    if (!NT_SUCCESS(Status)) {
        ERR("test_not_full returned %08lx\n", Status);
        goto end;
    }

#ifdef DEBUG_PARANOID
    le = Vcb->trees.Flink;
    while (le != &Vcb->trees) {
        tree* t = CONTAINING_RECORD(le, tree, list_entry);
        struct btrfs_key searchkey;
        traverse_ptr tp;

        searchkey.objectid = t->header.bytenr;
        searchkey.type = TYPE_METADATA_ITEM;
        searchkey.offset = 0xffffffffffffffff;

        Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, false, Irp);
        if (!NT_SUCCESS(Status)) {
            ERR("error - find_item returned %08lx\n", Status);
            goto end;
        }

        if (tp.item->key.objectid != searchkey.objectid || tp.item->key.type != searchkey.type) {
            searchkey.objectid = t->header.bytenr;
            searchkey.type = TYPE_EXTENT_ITEM;
            searchkey.offset = 0xffffffffffffffff;

            Status = find_item(Vcb, Vcb->extent_root, &tp, &searchkey, false, Irp);
            if (!NT_SUCCESS(Status)) {
                ERR("error - find_item returned %08lx\n", Status);
                goto end;
            }

            if (tp.item->key.objectid != searchkey.objectid || tp.item->key.type != searchkey.type) {
                ERR("error - could not find entry in extent tree for tree at %I64x\n", t->header.bytenr);
                Status = STATUS_INTERNAL_ERROR;
                goto end;
            }
        }

        le = le->Flink;
    }
#endif

    Vcb->superblock.cache_generation = Vcb->superblock.generation;

    if (!Vcb->options.no_barrier)
        flush_disk_caches(Vcb);

    Status = write_superblocks(Vcb, Irp);
    if (!NT_SUCCESS(Status)) {
        ERR("write_superblocks returned %08lx\n", Status);
        goto end;
    }

    vde = Vcb->vde;

    if (vde) {
        pdo_device_extension* pdode = vde->pdode;

        ExAcquireResourceSharedLite(&pdode->child_lock, true);

        le = pdode->children.Flink;

        while (le != &pdode->children) {
            volume_child* vc = CONTAINING_RECORD(le, volume_child, list_entry);

            vc->generation = Vcb->superblock.generation;
            le = le->Flink;
        }

        ExReleaseResourceLite(&pdode->child_lock);
    }

    clean_space_cache(Vcb);

    le = Vcb->chunks.Flink;
    while (le != &Vcb->chunks) {
        chunk* c = CONTAINING_RECORD(le, chunk, list_entry);

        c->changed = false;
        c->space_changed = false;

        le = le->Flink;
    }

    Vcb->superblock.generation++;

    Status = STATUS_SUCCESS;

    le = Vcb->trees.Flink;
    while (le != &Vcb->trees) {
        tree* t = CONTAINING_RECORD(le, tree, list_entry);

        t->write = false;

        le = le->Flink;
    }

    Vcb->need_write = false;

    while (!IsListEmpty(&Vcb->drop_roots)) {
        root* r = CONTAINING_RECORD(RemoveHeadList(&Vcb->drop_roots), root, list_entry);

        if (IsListEmpty(&r->fcbs)) {
            ExDeleteResourceLite(&r->nonpaged->load_tree_lock);
            ExFreePool(r->nonpaged);
            ExFreePool(r);
        } else
            r->dropped = true;
    }

end:
    TRACE("do_write returning %08lx\n", Status);

    return Status;
}

NTSTATUS do_write(device_extension* Vcb, PIRP Irp) {
    LIST_ENTRY rollback;
    NTSTATUS Status;

    InitializeListHead(&rollback);

    Status = do_write2(Vcb, Irp, &rollback);

    if (!NT_SUCCESS(Status)) {
        ERR("do_write2 returned %08lx, dropping into readonly mode\n", Status);
        Vcb->readonly = true;
        FsRtlNotifyVolumeEvent(Vcb->root_file, FSRTL_VOLUME_FORCED_CLOSED);
        do_rollback(Vcb, &rollback);
    } else
        clear_rollback(&rollback);

    return Status;
}

static void do_flush(device_extension* Vcb) {
    NTSTATUS Status;

    ExAcquireResourceExclusiveLite(&Vcb->tree_lock, true);

    if (Vcb->need_write && !Vcb->readonly)
        Status = do_write(Vcb, NULL);
    else
        Status = STATUS_SUCCESS;

    free_trees(Vcb);

    if (!NT_SUCCESS(Status))
        ERR("do_write returned %08lx\n", Status);

    ExReleaseResourceLite(&Vcb->tree_lock);
}

_Function_class_(KSTART_ROUTINE)
void __stdcall flush_thread(void* context) {
    DEVICE_OBJECT* devobj = context;
    device_extension* Vcb = devobj->DeviceExtension;
    LARGE_INTEGER due_time;

    ObReferenceObject(devobj);

    KeInitializeTimer(&Vcb->flush_thread_timer);

    due_time.QuadPart = (uint64_t)Vcb->options.flush_interval * -10000000;

    KeSetTimer(&Vcb->flush_thread_timer, due_time, NULL);

    while (true) {
        KeWaitForSingleObject(&Vcb->flush_thread_timer, Executive, KernelMode, false, NULL);

        if (!(devobj->Vpb->Flags & VPB_MOUNTED) || Vcb->removing)
            break;

        if (!Vcb->locked)
            do_flush(Vcb);

        KeSetTimer(&Vcb->flush_thread_timer, due_time, NULL);
    }

    ObDereferenceObject(devobj);
    KeCancelTimer(&Vcb->flush_thread_timer);

    KeSetEvent(&Vcb->flush_thread_finished, 0, false);

    PsTerminateSystemThread(STATUS_SUCCESS);
}
