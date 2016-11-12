#include "btrfs_drv.h"

static void balance_thread(void* context) {
    device_extension* Vcb = (device_extension*)context;
    LIST_ENTRY* le;
    
    ExAcquireResourceSharedLite(&Vcb->chunk_lock, TRUE);
    
    le = Vcb->chunks.Flink;
    while (le != &Vcb->chunks) {
        chunk* c = CONTAINING_RECORD(le, chunk, list_entry);
        
        if (c->chunk_item->type & BLOCK_FLAG_METADATA) // FIXME
            c->reloc = TRUE;
        
        le = le->Flink;
    }
    
    ExReleaseResourceLite(&Vcb->chunk_lock);
    
    // FIXME
    
    Vcb->balance.thread = NULL;
}

NTSTATUS start_balance(device_extension* Vcb) {
    NTSTATUS Status;
    
    if (Vcb->balance.thread) {
        WARN("balance already running\n");
        return STATUS_DEVICE_NOT_READY;
    }
    
    if (Vcb->readonly)
        return STATUS_MEDIA_WRITE_PROTECTED;
    
    Status = PsCreateSystemThread(&Vcb->balance.thread, 0, NULL, NULL, NULL, balance_thread, Vcb);
    if (!NT_SUCCESS(Status)) {
        ERR("PsCreateSystemThread returned %08x\n", Status);
        return Status;
    }
    
    return STATUS_SUCCESS;
}
