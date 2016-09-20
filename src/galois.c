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

// The code from the following functions is derived from the paper
// "The mathematics of RAID-6", by H. Peter Anvin.
// https://www.kernel.org/pub/linux/kernel/people/hpa/raid6.pdf

#ifdef __x86_64__
static UINT64 __inline galois_double_mask64(UINT64 v) {
    v &= 0x8080808080808080;
    return (v << 1) - (v >> 7);
}
#else
static UINT32 __inline galois_double_mask32(UINT32 v) {
    v &= 0x80808080;
    return (v << 1) - (v >> 7);
}
#endif

void galois_double(UINT8* data, UINT32 len) {
    // FIXME - SIMD?
    
#ifdef __x86_64__
    while (len > sizeof(UINT64)) {
        UINT64 v = *((UINT64*)data), vv;
        
        vv = (v << 1) & 0xfefefefefefefefe;
        vv ^= galois_double_mask64(v) & 0x1d1d1d1d1d1d1d1d;
        *((UINT64*)data) = vv;
        
        data += sizeof(UINT64);
        len -= sizeof(UINT64);
    }
#else
    while (len > sizeof(UINT32)) {
        UINT32 v = *((UINT32*)data), vv;
        
        vv = (v << 1) & 0xfefefefe;
        vv ^= galois_double_mask32(v) & 0x1d1d1d1d;
        *((UINT32*)data) = vv;
        
        data += sizeof(UINT32);
        len -= sizeof(UINT32);
    }
#endif
    
    while (len > 0) {
        data[0] = (data[0] << 1) ^ ((data[0] & 0x80) ? 0x1d : 0);
        data++;
        len--;
    }
}
