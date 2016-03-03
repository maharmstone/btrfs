/* Copyright (c) Mark Harmstone 2016
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

typedef struct {
    UCHAR revision;
    UCHAR elements;
    UCHAR auth[6];
    UINT32 nums[8];
} sid_header;

static sid_header sid_BA = { 1, 2, SECURITY_NT_AUTHORITY, {32, 544}}; // BUILTIN\Administrators
static sid_header sid_SY = { 1, 1, SECURITY_NT_AUTHORITY, {18}};      // NT AUTHORITY\SYSTEM
static sid_header sid_BU = { 1, 2, SECURITY_NT_AUTHORITY, {32, 545}}; // BUILTIN\Users
static sid_header sid_AU = { 1, 1, SECURITY_NT_AUTHORITY, {11}};      // NT AUTHORITY\Authenticated Users

typedef struct {
    UCHAR flags;
    ACCESS_MASK mask;
    sid_header* sid;
} dacl;

static dacl def_dacls[] = {
    { 0, FILE_ALL_ACCESS, &sid_BA },
    { OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE, FILE_ALL_ACCESS, &sid_BA },
    { 0, FILE_ALL_ACCESS, &sid_SY },
    { OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE, FILE_ALL_ACCESS, &sid_SY },
    { OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE, &sid_BU },
    { OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE, FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE, &sid_AU },
    { 0, FILE_ADD_SUBDIRECTORY, &sid_AU },
    // FIXME - Mandatory Label\High Mandatory Level:(OI)(NP)(IO)(NW)
    { 0, 0, NULL }
};

extern LIST_ENTRY uid_map_list;

// UINT32 STDCALL get_uid() {
//     PACCESS_TOKEN at = PsReferencePrimaryToken(PsGetCurrentProcess());
//     HANDLE h;
//     ULONG len, size;
//     TOKEN_USER* tu;
//     NTSTATUS Status;
//     UINT32 uid = UID_NOBODY;
//     LIST_ENTRY* le;
//     uid_map* um;
// //     char s[256];
// 
//     Status = ObOpenObjectByPointer(at, OBJ_KERNEL_HANDLE, NULL, GENERIC_READ, NULL, KernelMode, &h);
//     if (!NT_SUCCESS(Status)) {
//         ERR("ObOpenObjectByPointer returned %08x\n", Status);
//         goto exit;
//     }
//     
//     Status = ZwQueryInformationToken(h, TokenUser, NULL, 0, &len);
//     if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_TOO_SMALL) {
//         ERR("ZwQueryInformationToken(1) returned %08x (len = %u)\n", Status, len);
//         goto exit2;
//     }
// 
// //     TRACE("len = %u\n", len);
//     
//     tu = ExAllocatePoolWithTag(PagedPool, len, ALLOC_TAG);
//     
//     Status = ZwQueryInformationToken(h, TokenUser, tu, len, &len);
//     
//     if (!NT_SUCCESS(Status)) {
//         ERR("ZwQueryInformationToken(2) returned %08x\n", Status);
//         goto exit3;
//     }
//     
//     size = 8 + (4 * ((sid_header*)tu->User.Sid)->elements);
//     
//     le = uid_map_list.Flink;
//     while (le != &uid_map_list) {
//         um = CONTAINING_RECORD(le, uid_map, listentry);
//         
//         if (((sid_header*)um->sid)->elements == ((sid_header*)tu->User.Sid)->elements &&
//             RtlCompareMemory(um->sid, tu->User.Sid, size) == size) {
//             uid = um->uid;
//             break;
//         }
//         
//         le = le->Flink;
//     }
//     
// //     sid_to_string(tu->User.Sid, s);
//     
// //     TRACE("got SID: %s\n", s);
//     TRACE("uid = %u\n", uid);
//     
// exit3:
//     ExFreePool(tu);
//     
// exit2:
//     ZwClose(h);
//     
// exit:
//     PsDereferencePrimaryToken(at);
//     
//     return uid;
// }

void add_user_mapping(WCHAR* sidstring, ULONG sidstringlength, UINT32 uid) {
    unsigned int i, np;
    UINT8 numdashes;
    UINT64 val;
    ULONG sidsize;
    sid_header* sid;
    uid_map* um;
//     char s[255];
    
    if (sidstringlength < 4 ||
        sidstring[0] != 'S' ||
        sidstring[1] != '-' ||
        sidstring[2] != '1' ||
        sidstring[3] != '-') {
        ERR("invalid SID\n");
        return;
    }
    
    sidstring = &sidstring[4];
    sidstringlength -= 4;
    
    numdashes = 0;
    for (i = 0; i < sidstringlength; i++) {
        if (sidstring[i] == '-') {
            numdashes++;
            sidstring[i] = 0;
        }
    }
    
    sidsize = 8 + (numdashes * 4);
    sid = (sid_header*)ExAllocatePoolWithTag(PagedPool, sidsize, ALLOC_TAG);
    if (!sid) {
        ERR("out of memory\n");
        return;
    }
    
    sid->revision = 0x01;
    sid->elements = numdashes;
    
    np = 0;
    while (sidstringlength > 0) {
        val = 0;
        i = 0;
        while (sidstring[i] != '-' && i < sidstringlength) {
            if (sidstring[i] >= '0' && sidstring[i] <= '9') {
                val *= 10;
                val += sidstring[i] - '0';
            } else
                break;
            
            i++;
        }
        
        i++;
        TRACE("val = %u, i = %u, ssl = %u\n", (UINT32)val, i, sidstringlength);
        
        if (np == 0) {
            sid->auth[0] = (val & 0xff0000000000) >> 40;
            sid->auth[1] = (val & 0xff00000000) >> 32;
            sid->auth[2] = (val & 0xff000000) >> 24;
            sid->auth[3] = (val & 0xff0000) >> 16;
            sid->auth[4] = (val & 0xff00) >> 8;
            sid->auth[5] = val & 0xff;
        } else {
            sid->nums[np-1] = (UINT32)val;
        }
        
        np++;
        
        if (sidstringlength > i) {
            sidstringlength -= i;

            sidstring = &sidstring[i];
        } else
            break;
    }
    
//     sid_to_string(sid, s);
    
//     TRACE("%s\n", s);
    um = (uid_map*)ExAllocatePoolWithTag(PagedPool, sizeof(uid_map), ALLOC_TAG);
    if (!um) {
        ERR("out of memory\n");
        return;
    }
    
    um->sid = sid;
    um->uid = uid;
    
    InsertTailList(&uid_map_list, &um->listentry);
}

static void uid_to_sid(UINT32 uid, PSID* sid) {
    LIST_ENTRY* le;
    uid_map* um;
    sid_header* sh;
    UCHAR els;
    
    le = uid_map_list.Flink;
    while (le != &uid_map_list) {
        um = CONTAINING_RECORD(le, uid_map, listentry);
        
        if (um->uid == uid) {
            *sid = ExAllocatePoolWithTag(PagedPool, RtlLengthSid(um->sid), ALLOC_TAG);
            if (!*sid) {
                ERR("out of memory\n");
                return;
            }
            
            RtlCopyMemory(*sid, um->sid, RtlLengthSid(um->sid));
            return;
        }
        
        le = le->Flink;
    }
    
    if (uid == 0) { // root
        // FIXME - find actual Administrator account, rather than SYSTEM (S-1-5-18)
        // (of form S-1-5-21-...-500)
        
        els = 1;
        
        sh = (sid_header*)ExAllocatePoolWithTag(PagedPool, sizeof(sid_header) + ((els - 1) * sizeof(UINT32)), ALLOC_TAG);
        if (!sh) {
            ERR("out of memory\n");
            *sid = NULL;
            return;
        }
    
        sh->revision = 1;
        sh->elements = els;
        
        sh->auth[0] = 0;
        sh->auth[1] = 0;
        sh->auth[2] = 0;
        sh->auth[3] = 0;
        sh->auth[4] = 0;
        sh->auth[5] = 5;
        
        sh->nums[0] = 18;
    } else {    
        // fallback to S-1-22-1-X, Samba's SID scheme
        sh = (sid_header*)ExAllocatePoolWithTag(PagedPool, sizeof(sid_header), ALLOC_TAG);
        if (!sh) {
            ERR("out of memory\n");
            *sid = NULL;
            return;
        }
        
        sh->revision = 1;
        sh->elements = 2;
        
        sh->auth[0] = 0;
        sh->auth[1] = 0;
        sh->auth[2] = 0;
        sh->auth[3] = 0;
        sh->auth[4] = 0;
        sh->auth[5] = 22;
        
        sh->nums[0] = 1;
        sh->nums[1] = uid;
    }

    *sid = sh;
}

static UINT32 sid_to_uid(PSID sid) {
    LIST_ENTRY* le;
    uid_map* um;
    sid_header* sh = (sid_header*)sid;

    le = uid_map_list.Flink;
    while (le != &uid_map_list) {
        um = CONTAINING_RECORD(le, uid_map, listentry);
        
        if (RtlEqualSid(sid, um->sid))
            return um->uid;
        
        le = le->Flink;
    }
    
    if (RtlEqualSid(sid, &sid_SY))
        return 0; // root
        
    // Samba's SID scheme: S-1-22-1-X
    if (sh->revision == 1 && sh->elements == 2 && sh->auth[0] == 0 && sh->auth[1] == 0 && sh->auth[2] == 0 && sh->auth[3] == 0 &&
        sh->auth[4] == 0 && sh->auth[5] == 22 && sh->nums[0] == 1)
        return sh->nums[1];

    return UID_NOBODY;
}

static void gid_to_sid(UINT32 gid, PSID* sid) {
    sid_header* sh;
    UCHAR els;
    
    // FIXME - do this properly?
    
    // fallback to S-1-22-2-X, Samba's SID scheme
    els = 2;
    sh = (sid_header*)ExAllocatePoolWithTag(PagedPool, sizeof(sid_header) + ((els - 1) * sizeof(UINT32)), ALLOC_TAG);
    if (!sh) {
        ERR("out of memory\n");
        *sid = NULL;
        return;
    }
    
    sh->revision = 1;
    sh->elements = els;
    
    sh->auth[0] = 0;
    sh->auth[1] = 0;
    sh->auth[2] = 0;
    sh->auth[3] = 0;
    sh->auth[4] = 0;
    sh->auth[5] = 22;
    
    sh->nums[0] = 2;
    sh->nums[1] = gid;

    *sid = sh;
}

static ACL* load_default_acl() {
    ULONG size;
    ACL* acl;
    ACCESS_ALLOWED_ACE* aaa;
    UINT32 i;
    
    size = sizeof(ACL);
    i = 0;
    while (def_dacls[i].sid) {
        size += sizeof(ACCESS_ALLOWED_ACE);
        size += 8 + (def_dacls[i].sid->elements * sizeof(UINT32)) - sizeof(ULONG);
        i++;
    }
    
    acl = (ACL*)ExAllocatePoolWithTag(PagedPool, size, ALLOC_TAG);
    if (!acl) {
        ERR("out of memory\n");
        return NULL;
    }
    
    acl->AclRevision = ACL_REVISION;
    acl->Sbz1 = 0;
    acl->AclSize = size;
    acl->AceCount = i;
    acl->Sbz2 = 0;
    
    aaa = (ACCESS_ALLOWED_ACE*)&acl[1];
    i = 0;
    while (def_dacls[i].sid) {
        aaa->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
        aaa->Header.AceFlags = def_dacls[i].flags;
        aaa->Header.AceSize = sizeof(ACCESS_ALLOWED_ACE) - sizeof(ULONG) + 8 + (def_dacls[i].sid->elements * sizeof(UINT32));
        aaa->Mask = def_dacls[i].mask;
        
        RtlCopyMemory(&aaa->SidStart, def_dacls[i].sid, 8 + (def_dacls[i].sid->elements * sizeof(UINT32)));
        
        aaa = (ACCESS_ALLOWED_ACE*)((UINT8*)aaa + aaa->Header.AceSize);
        
        i++;
    }
    
    return acl;
}

static ACL* inherit_acl(SECURITY_DESCRIPTOR* parsd, BOOL file) {
    ULONG size;
    NTSTATUS Status;
    ACL *paracl, *acl;
    BOOLEAN parhasdacl, pardefaulted;
    ACE_HEADER *ah, *parah;
    UINT32 i;
    USHORT num_aces;
    
    // FIXME - replace this with SeAssignSecurity
    
    Status = RtlGetDaclSecurityDescriptor(parsd, &parhasdacl, &paracl, &pardefaulted);
    if (!NT_SUCCESS(Status)) {
        ERR("RtlGetDaclSecurityDescriptor returned %08x\n", Status);
        return NULL;
    }
    
    // FIXME - handle parhasdacl == FALSE

//     OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE
    num_aces = 0;
    size = sizeof(ACL);
    ah = (ACE_HEADER*)&paracl[1];
    for (i = 0; i < paracl->AceCount; i++) {
        if (!file && ah->AceFlags & CONTAINER_INHERIT_ACE) {
            num_aces++;
            size += ah->AceSize;
            
            if (ah->AceFlags & INHERIT_ONLY_ACE) {
                num_aces++;
                size += ah->AceSize;
            }
        }
        
        if (ah->AceFlags & OBJECT_INHERIT_ACE && (file || !(ah->AceFlags & CONTAINER_INHERIT_ACE))) {
            num_aces++;
            size += ah->AceSize;
        }
        
        ah = (ACE_HEADER*)((UINT8*)ah + ah->AceSize);
    }
    
    acl = (ACL*)ExAllocatePoolWithTag(PagedPool, size, ALLOC_TAG);
    if (!acl) {
        ERR("out of memory\n");
        return NULL;
    }
    
    acl->AclRevision = ACL_REVISION;
    acl->Sbz1 = 0;
    acl->AclSize = size;
    acl->AceCount = num_aces;
    acl->Sbz2 = 0;
    
    ah = (ACE_HEADER*)&acl[1];
    parah = (ACE_HEADER*)&paracl[1];
    for (i = 0; i < paracl->AceCount; i++) {
        if (!file && parah->AceFlags & CONTAINER_INHERIT_ACE) {
            if (parah->AceFlags & INHERIT_ONLY_ACE) {
                RtlCopyMemory(ah, parah, parah->AceSize);
                ah->AceFlags &= ~INHERIT_ONLY_ACE;
                ah->AceFlags |= INHERITED_ACE;
                ah->AceFlags &= ~(OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE);
                
                ah = (ACE_HEADER*)((UINT8*)ah + ah->AceSize);
            }
            
            RtlCopyMemory(ah, parah, parah->AceSize);
            ah->AceFlags |= INHERITED_ACE;
            
            if (ah->AceFlags & NO_PROPAGATE_INHERIT_ACE)
                ah->AceFlags &= ~(OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE);
            
            ah = (ACE_HEADER*)((UINT8*)ah + ah->AceSize);
        }
        
        if (parah->AceFlags & OBJECT_INHERIT_ACE && (file || !(parah->AceFlags & CONTAINER_INHERIT_ACE))) {
            RtlCopyMemory(ah, parah, parah->AceSize);
            ah->AceFlags |= INHERITED_ACE;
            
            if (file)
                ah->AceFlags &= ~INHERIT_ONLY_ACE;
            else
                ah->AceFlags |= INHERIT_ONLY_ACE;
            
            if (ah->AceFlags & NO_PROPAGATE_INHERIT_ACE || file)
                ah->AceFlags &= ~(OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE);
            
            ah = (ACE_HEADER*)((UINT8*)ah + ah->AceSize);
        }
        
        parah = (ACE_HEADER*)((UINT8*)parah + parah->AceSize);
    }
    
    return acl;
}

// static void STDCALL sid_to_string(PSID sid, char* s) {
//     sid_header* sh = (sid_header*)sid;
//     LARGE_INTEGER authnum;
//     UINT8 i;
//     
//     authnum.LowPart = sh->auth[5] | (sh->auth[4] << 8) | (sh->auth[3] << 16) | (sh->auth[2] << 24);
//     authnum.HighPart =  sh->auth[1] | (sh->auth[0] << 8);
//     
//     sprintf(s, "S-%u-%u", sh->revision, (UINT32)authnum.QuadPart);
//     
//     for (i = 0; i < sh->elements; i++) {
//         sprintf(s, "%s-%u", s, sh->nums[i]);
//     }
// }

static BOOL get_sd_from_xattr(fcb* fcb) {
    ULONG buflen;
    NTSTATUS Status;
    PSID sid, usersid;
    
    if (!get_xattr(fcb->Vcb, fcb->subvol, fcb->inode, EA_NTACL, EA_NTACL_HASH, (UINT8**)&fcb->sd, (UINT16*)&buflen))
        return FALSE;
    
    TRACE("using xattr " EA_NTACL " for security descriptor\n");
    
    if (fcb->inode_item.st_uid != UID_NOBODY) {
        BOOLEAN defaulted;
        
        Status = RtlGetOwnerSecurityDescriptor(fcb->sd, &sid, &defaulted);
        if (!NT_SUCCESS(Status)) {
            ERR("RtlGetOwnerSecurityDescriptor returned %08x\n", Status);
        } else {
            uid_to_sid(fcb->inode_item.st_uid, &usersid);
            
            if (!usersid) {
                ERR("out of memory\n");
                return FALSE;
            }
            
            if (!RtlEqualSid(sid, usersid)) {
                SECURITY_DESCRIPTOR *newsd, *newsd2;
                ULONG sdsize, daclsize, saclsize, ownersize, groupsize;
                ACL *dacl, *sacl;
                PSID owner, group;
                
                sdsize = daclsize = saclsize = ownersize = groupsize = 0;
                
                Status = RtlSelfRelativeToAbsoluteSD(fcb->sd, NULL, &sdsize, NULL, &daclsize, NULL, &saclsize, NULL, &ownersize, NULL, &groupsize);
                
                if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_TOO_SMALL) {
                    ERR("RtlSelfRelativeToAbsoluteSD 1 returned %08x\n", Status);
                }
                
                ERR("sdsize = %u, daclsize = %u, saclsize = %u, ownersize = %u, groupsize = %u\n", sdsize, daclsize, saclsize, ownersize, groupsize);
                
                newsd2 = (SECURITY_DESCRIPTOR*)(sdsize == 0 ? NULL : ExAllocatePoolWithTag(PagedPool, sdsize, ALLOC_TAG));
                dacl = (ACL*)(daclsize == 0 ? NULL : ExAllocatePoolWithTag(PagedPool, daclsize, ALLOC_TAG));
                sacl = (ACL*)(saclsize == 0 ? NULL : ExAllocatePoolWithTag(PagedPool, saclsize, ALLOC_TAG));
                owner = ownersize == 0 ? NULL : ExAllocatePoolWithTag(PagedPool, ownersize, ALLOC_TAG);
                group = groupsize == 0 ? NULL : ExAllocatePoolWithTag(PagedPool, groupsize, ALLOC_TAG);
                
                if ((sdsize > 0 && !newsd2) || (daclsize > 0 && !dacl) || (saclsize > 0 && !sacl) || (ownersize > 0 && !owner) || (groupsize > 0 || !group)) {
                    ERR("out of memory\n");
                    if (newsd2) ExFreePool(newsd2);
                    if (dacl) ExFreePool(dacl);
                    if (sacl) ExFreePool(sacl);
                    if (owner) ExFreePool(owner);
                    if (group) ExFreePool(group);
                    ExFreePool(usersid);
                    return FALSE;
                }
                
                Status = RtlSelfRelativeToAbsoluteSD(fcb->sd, newsd2, &sdsize, dacl, &daclsize, sacl, &saclsize, owner, &ownersize, group, &groupsize);
                
                if (!NT_SUCCESS(Status)) {
                    ERR("RtlSelfRelativeToAbsoluteSD returned %08x\n", Status);
                    if (newsd2) ExFreePool(newsd2);
                    if (dacl) ExFreePool(dacl);
                    if (sacl) ExFreePool(sacl);
                    if (owner) ExFreePool(owner);
                    if (group) ExFreePool(group);
                    ExFreePool(usersid);
                    return FALSE;
                }
                
                Status = RtlSetOwnerSecurityDescriptor(newsd2, usersid, FALSE);
                if (!NT_SUCCESS(Status)) {
                    ERR("RtlSetOwnerSecurityDescriptor returned %08x\n", Status);
                    if (newsd2) ExFreePool(newsd2);
                    if (dacl) ExFreePool(dacl);
                    if (sacl) ExFreePool(sacl);
                    if (owner) ExFreePool(owner);
                    if (group) ExFreePool(group);
                    ExFreePool(usersid);
                    return FALSE;
                }
                
                buflen = 0;
                Status = RtlAbsoluteToSelfRelativeSD(newsd2, NULL, &buflen);
                if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_TOO_SMALL) {
                    ERR("RtlAbsoluteToSelfRelativeSD 1 returned %08x\n", Status);
                    if (newsd2) ExFreePool(newsd2);
                    if (dacl) ExFreePool(dacl);
                    if (sacl) ExFreePool(sacl);
                    if (owner) ExFreePool(owner);
                    if (group) ExFreePool(group);
                    ExFreePool(usersid);
                    return FALSE;
                }
                
                if (buflen == 0 || NT_SUCCESS(Status)) {
                    ERR("RtlAbsoluteToSelfRelativeSD said SD is zero-length\n");
                    if (newsd2) ExFreePool(newsd2);
                    if (dacl) ExFreePool(dacl);
                    if (sacl) ExFreePool(sacl);
                    if (owner) ExFreePool(owner);
                    if (group) ExFreePool(group);
                    ExFreePool(usersid);
                    return FALSE;
                }
                
                newsd = (SECURITY_DESCRIPTOR*)ExAllocatePoolWithTag(PagedPool, buflen, ALLOC_TAG);
                if (!newsd) {
                    ERR("out of memory\n");
                    if (newsd2) ExFreePool(newsd2);
                    if (dacl) ExFreePool(dacl);
                    if (sacl) ExFreePool(sacl);
                    if (owner) ExFreePool(owner);
                    if (group) ExFreePool(group);
                    ExFreePool(usersid);
                    return FALSE;
                }
                
                Status = RtlAbsoluteToSelfRelativeSD(newsd2, newsd, &buflen);
                
                if (!NT_SUCCESS(Status)) {
                    ERR("RtlAbsoluteToSelfRelativeSD 2 returned %08x\n", Status);
                    if (newsd2) ExFreePool(newsd2);
                    if (dacl) ExFreePool(dacl);
                    if (sacl) ExFreePool(sacl);
                    if (owner) ExFreePool(owner);
                    if (group) ExFreePool(group);
                    ExFreePool(usersid);
                    ExFreePool(newsd);
                    return FALSE;
                }
                
                ExFreePool(fcb->sd);
                
                fcb->sd = newsd;
                
                if (newsd2) ExFreePool(newsd2);
                if (dacl) ExFreePool(dacl);
                if (sacl) ExFreePool(sacl);
                if (owner) ExFreePool(owner);
                if (group) ExFreePool(group);
            }
            
            ExFreePool(usersid);
        }
    }
    
    // FIXME - check GID here if not GID_NOBODY
    
    return TRUE;
}

void fcb_get_sd(fcb* fcb) {
    NTSTATUS Status;
    SECURITY_DESCRIPTOR sd;
    ULONG buflen;
    ACL* acl = NULL;
    PSID usersid = NULL, groupsid = NULL;
    
    if (get_sd_from_xattr(fcb))
        goto end;
    
    Status = RtlCreateSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    
    if (!NT_SUCCESS(Status)) {
        ERR("RtlCreateSecurityDescriptor returned %08x\n", Status);
        goto end;
    }
    
//     if (fcb->inode_item.st_uid != UID_NOBODY) {
        uid_to_sid(fcb->inode_item.st_uid, &usersid);
        if (!usersid) {
            ERR("out of memory\n");
            goto end;
        }
        
        RtlSetOwnerSecurityDescriptor(&sd, usersid, FALSE);
        
        if (!NT_SUCCESS(Status)) {
            ERR("RtlSetOwnerSecurityDescriptor returned %08x\n", Status);
            goto end;
        }
//     }
    
//     if (fcb->inode_item.st_gid != GID_NOBODY) {
        gid_to_sid(fcb->inode_item.st_gid, &groupsid);
        if (!groupsid) {
            ERR("out of memory\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }
        
        RtlSetGroupSecurityDescriptor(&sd, groupsid, FALSE);
        
        if (!NT_SUCCESS(Status)) {
            ERR("RtlSetGroupSecurityDescriptor returned %08x\n", Status);
            goto end;
        }
//     }
    
    if (!fcb->par)
        acl = load_default_acl();
    else
        acl = inherit_acl(fcb->par->sd, fcb->type != BTRFS_TYPE_DIRECTORY);
    
    if (!acl) {
        ERR("out of memory\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }

    Status = RtlSetDaclSecurityDescriptor(&sd, TRUE, acl, FALSE);
    
    if (!NT_SUCCESS(Status)) {
        ERR("RtlSetDaclSecurityDescriptor returned %08x\n", Status);
        goto end;
    }
    
    // FIXME - SACL_SECURITY_INFORMATION
    
    buflen = 0;
    
    // get sd size
    Status = RtlAbsoluteToSelfRelativeSD(&sd, NULL, &buflen);
    if (Status != STATUS_SUCCESS && Status != STATUS_BUFFER_TOO_SMALL) {
        ERR("RtlAbsoluteToSelfRelativeSD 1 returned %08x\n", Status);
        goto end;
    }
    
//     fcb->sdlen = buflen;
    
    if (buflen == 0 || Status == STATUS_SUCCESS) {
        TRACE("RtlAbsoluteToSelfRelativeSD said SD is zero-length\n");
        goto end;
    }
    
    fcb->sd = (SECURITY_DESCRIPTOR*)ExAllocatePoolWithTag(PagedPool, buflen, ALLOC_TAG);
    if (!fcb->sd) {
        ERR("out of memory\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }
    
    Status = RtlAbsoluteToSelfRelativeSD(&sd, fcb->sd, &buflen);
    
    if (!NT_SUCCESS(Status)) {
        ERR("RtlAbsoluteToSelfRelativeSD 2 returned %08x\n", Status);
        goto end;
    }
    
end:
    if (acl)
        ExFreePool(acl);
    
    if (usersid)
        ExFreePool(usersid);
    
    if (groupsid)
        ExFreePool(groupsid);
}

static NTSTATUS STDCALL get_file_security(device_extension* Vcb, PFILE_OBJECT FileObject, SECURITY_DESCRIPTOR* relsd, ULONG* buflen, SECURITY_INFORMATION flags) {
    NTSTATUS Status;
    fcb* fcb = (_fcb*)FileObject->FsContext;
    
    if (fcb->ads)
        fcb = fcb->par;
    
//     TRACE("buflen = %u, fcb->sdlen = %u\n", *buflen, fcb->sdlen);

    // Why (void**)? Is this a bug in mingw?
    Status = SeQuerySecurityDescriptorInfo(&flags, relsd, buflen, (void**)&fcb->sd);
    
    if (Status == STATUS_BUFFER_TOO_SMALL)
        TRACE("SeQuerySecurityDescriptorInfo returned %08x\n", Status);
    else if (!NT_SUCCESS(Status))
        ERR("SeQuerySecurityDescriptorInfo returned %08x\n", Status);
    
    return Status;
}

NTSTATUS STDCALL drv_query_security(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    NTSTATUS Status;
    SECURITY_DESCRIPTOR* sd;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG buflen;
    BOOL top_level;

    TRACE("query security\n");
    
    FsRtlEnterFileSystem();

    top_level = is_top_level(Irp);
    
    Status = STATUS_SUCCESS;
    
    Irp->IoStatus.Information = 0;
    
    if (IrpSp->Parameters.QuerySecurity.SecurityInformation & OWNER_SECURITY_INFORMATION)
        TRACE("OWNER_SECURITY_INFORMATION\n");

    if (IrpSp->Parameters.QuerySecurity.SecurityInformation & GROUP_SECURITY_INFORMATION)
        TRACE("GROUP_SECURITY_INFORMATION\n");

    if (IrpSp->Parameters.QuerySecurity.SecurityInformation & DACL_SECURITY_INFORMATION)
        TRACE("DACL_SECURITY_INFORMATION\n");

    if (IrpSp->Parameters.QuerySecurity.SecurityInformation & SACL_SECURITY_INFORMATION)
        TRACE("SACL_SECURITY_INFORMATION\n");
    
    TRACE("length = %u\n", IrpSp->Parameters.QuerySecurity.Length);
    
    sd = (SECURITY_DESCRIPTOR*)map_user_buffer(Irp);
//     sd = Irp->AssociatedIrp.SystemBuffer;
    TRACE("sd = %p\n", sd);
    
    buflen = IrpSp->Parameters.QuerySecurity.Length;
    
    Status = get_file_security((device_extension*)DeviceObject->DeviceExtension, IrpSp->FileObject, sd, &buflen, IrpSp->Parameters.QuerySecurity.SecurityInformation);
    
    if (NT_SUCCESS(Status))
        Irp->IoStatus.Information = IrpSp->Parameters.QuerySecurity.Length;
    else if (Status == STATUS_BUFFER_TOO_SMALL) {
        Irp->IoStatus.Information = buflen;
        Status = STATUS_BUFFER_OVERFLOW;
    } else
        Irp->IoStatus.Information = 0;
    
    TRACE("Irp->IoStatus.Information = %u\n", Irp->IoStatus.Information);
    
    Irp->IoStatus.Status = Status;

    IoCompleteRequest( Irp, IO_NO_INCREMENT );
    
    if (top_level) 
        IoSetTopLevelIrp(NULL);    
    
    FsRtlExitFileSystem();

    TRACE("returning %08x\n", Status);
    
    return Status;
}

static NTSTATUS STDCALL set_file_security(device_extension* Vcb, PFILE_OBJECT FileObject, SECURITY_DESCRIPTOR* sd, SECURITY_INFORMATION flags) {
    NTSTATUS Status;
    fcb* fcb = (_fcb*)FileObject->FsContext;
    SECURITY_DESCRIPTOR* oldsd;
    INODE_ITEM* ii;
    KEY searchkey;
    traverse_ptr tp;
    LARGE_INTEGER time;
    BTRFS_TIME now;
    LIST_ENTRY rollback;
    
    TRACE("(%p, %p, %p, %x)\n", Vcb, FileObject, sd, flags);
    
    InitializeListHead(&rollback);
    
    if (Vcb->readonly)
        return STATUS_MEDIA_WRITE_PROTECTED;
    
    acquire_tree_lock(Vcb, TRUE);
    
    if (fcb->ads)
        fcb = fcb->par;
    
    if (fcb->subvol->root_item.flags & BTRFS_SUBVOL_READONLY) {
        Status = STATUS_ACCESS_DENIED;
        goto end;
    }
     
    oldsd = fcb->sd;
    
    Status = SeSetSecurityDescriptorInfo(NULL, &flags, sd, (void**)&fcb->sd, PagedPool, IoGetFileObjectGenericMapping());
    
    if (!NT_SUCCESS(Status)) {
        ERR("SeSetSecurityDescriptorInfo returned %08x\n", Status);
        goto end;
    }
    
    ExFreePool(oldsd);
    
    searchkey.obj_id = fcb->inode;
    searchkey.obj_type = TYPE_INODE_ITEM;
    searchkey.offset = 0;
    
    if (!find_item(Vcb, fcb->subvol, &tp, &searchkey, FALSE)) {
        ERR("error - could not find any entries in subvolume %llx\n", fcb->subvol->id);
        Status = STATUS_INTERNAL_ERROR;
        goto end;
    }
    
    if (keycmp(&tp.item->key, &searchkey)) {
        ERR("error - could not find INODE_ITEM for inode %llx in subvol %llx\n", fcb->inode, fcb->subvol->id);
        Status = STATUS_INTERNAL_ERROR;
        free_traverse_ptr(&tp);
        goto end;
    }
    
    delete_tree_item(Vcb, &tp, &rollback);
    free_traverse_ptr(&tp);
    
    KeQuerySystemTime(&time);
    win_time_to_unix(time, &now);
    
    fcb->inode_item.transid = Vcb->superblock.generation;
    fcb->inode_item.st_ctime = now;
    fcb->inode_item.sequence++;
    
    if (flags & OWNER_SECURITY_INFORMATION) {
        PSID owner;
        BOOLEAN defaulted;
        
        Status = RtlGetOwnerSecurityDescriptor(sd, &owner, &defaulted);
        
        if (!NT_SUCCESS(Status)) {
            ERR("RtlGetOwnerSecurityDescriptor returned %08x\n", Status);
            goto end;
        }
        
        fcb->inode_item.st_uid = sid_to_uid(owner);
    }
    
    ii = (INODE_ITEM*)ExAllocatePoolWithTag(PagedPool, sizeof(INODE_ITEM), ALLOC_TAG);
    if (!ii) {
        ERR("out of memory\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }
    
    RtlCopyMemory(ii, &fcb->inode_item, sizeof(INODE_ITEM));
    
    if (!insert_tree_item(Vcb, fcb->subvol, fcb->inode, TYPE_INODE_ITEM, 0, ii, sizeof(INODE_ITEM), NULL, &rollback)) {
        ERR("error - failed to insert INODE_ITEM\n");
        Status = STATUS_INTERNAL_ERROR;
        ExFreePool(ii);
        goto end;
    }
    
    Status = set_xattr(Vcb, fcb->subvol, fcb->inode, EA_NTACL, EA_NTACL_HASH, (UINT8*)fcb->sd, RtlLengthSecurityDescriptor(fcb->sd), &rollback);
    if (!NT_SUCCESS(Status)) {
        ERR("set_xattr returned %08x\n", Status);
        ExFreePool(ii);
        goto end;
    }
    
    fcb->subvol->root_item.ctransid = Vcb->superblock.generation;
    fcb->subvol->root_item.ctime = now;
    
    Status = consider_write(Vcb);
    
end:
    if (NT_SUCCESS(Status))
        clear_rollback(&rollback);
    else
        do_rollback(Vcb, &rollback);

    release_tree_lock(Vcb, TRUE);
    
    return Status;
}

NTSTATUS STDCALL drv_set_security(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    NTSTATUS Status;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    BOOL top_level;

    TRACE("set security\n");
    
    FsRtlEnterFileSystem();

    top_level = is_top_level(Irp);
    
    Status = STATUS_SUCCESS;
    
    Irp->IoStatus.Information = 0;
    
    if (IrpSp->Parameters.QuerySecurity.SecurityInformation & OWNER_SECURITY_INFORMATION)
        TRACE("OWNER_SECURITY_INFORMATION\n");

    if (IrpSp->Parameters.QuerySecurity.SecurityInformation & GROUP_SECURITY_INFORMATION)
        TRACE("GROUP_SECURITY_INFORMATION\n");

    if (IrpSp->Parameters.QuerySecurity.SecurityInformation & DACL_SECURITY_INFORMATION)
        TRACE("DACL_SECURITY_INFORMATION\n");

    if (IrpSp->Parameters.QuerySecurity.SecurityInformation & SACL_SECURITY_INFORMATION)
        TRACE("SACL_SECURITY_INFORMATION\n");
    
    Status = set_file_security((device_extension*)DeviceObject->DeviceExtension, IrpSp->FileObject, (SECURITY_DESCRIPTOR*)IrpSp->Parameters.SetSecurity.SecurityDescriptor,
                               IrpSp->Parameters.SetSecurity.SecurityInformation);
    
    Irp->IoStatus.Status = Status;

    IoCompleteRequest( Irp, IO_NO_INCREMENT );
    
    if (top_level) 
        IoSetTopLevelIrp(NULL);

    TRACE("returning %08x\n", Status);
    
    if (top_level) 
        IoSetTopLevelIrp(NULL);

    FsRtlExitFileSystem();
    
    return Status;
}

NTSTATUS fcb_get_new_sd(fcb* fcb, ACCESS_STATE* as) {
    NTSTATUS Status;
    PSID owner;
    BOOLEAN defaulted;
    
    Status = SeAssignSecurity(fcb->par ? fcb->par->sd : NULL, as->SecurityDescriptor, (void**)&fcb->sd, fcb->type == BTRFS_TYPE_DIRECTORY,
                              &as->SubjectSecurityContext, IoGetFileObjectGenericMapping(), PagedPool);
    
    if (!NT_SUCCESS(Status)) {
        ERR("SeAssignSecurity returned %08x\n", Status);
        return Status;
    }
    
    Status = RtlGetOwnerSecurityDescriptor(fcb->sd, &owner, &defaulted);
    if (!NT_SUCCESS(Status)) {
        ERR("RtlGetOwnerSecurityDescriptor returned %08x\n", Status);
        fcb->inode_item.st_uid = UID_NOBODY;
    } else {
        fcb->inode_item.st_uid = sid_to_uid(&owner);
    }
    
    return STATUS_SUCCESS;
}
