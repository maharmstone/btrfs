/* Copyright (c) Mark Harmstone 2020
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

.intel_syntax noprefix

#ifdef __x86_64__

.global do_xor_sse2

/* void do_xor_sse2(uint8_t* buf1, uint8_t* buf2, uint32_t len); */
do_xor_sse2:
    /* rcx = buf1
    *  rdx = buf2
    *  r8d = len
    *  rax = tmp1
    *  r9 = tmp2
    *  xmm0 = tmp3
    *  xmm1 = tmp4 */

    mov rax, rcx
    and rax, 15
    cmp rax, 0
    jne stragglers2

    mov rax, rdx
    and rax, 15
    cmp rax, 0
    jne stragglers2

do_xor_sse2_loop:
    cmp r8d, 16
    jl stragglers2

    movdqa xmm0, [rcx]
    movdqa xmm1, [rdx]
    pxor xmm0, xmm1
    movdqa [rcx], xmm0

    add rcx, 16
    add rdx, 16
    sub r8d, 16

    jmp do_xor_sse2_loop

stragglers2:

    cmp r8d, 8
    jl stragglers

    mov rax, [rcx]
    mov r9, [rdx]
    xor rax, r9
    mov [rcx], rax

    add rcx, 8
    add rdx, 8
    sub r8d, 8

    jmp stragglers2

stragglers:

    cmp r8d, 0
    je do_xor_sse2_end

    mov al, [rcx]
    mov r9b, [rdx]
    xor al, r9b
    mov [rcx], al

    inc rcx
    inc rdx
    dec r8d

    jmp stragglers

do_xor_sse2_end:
    ret

#else

.global _do_xor_sse2@12

/* void __stdcall do_xor_sse2(uint8_t* buf1, uint8_t* buf2, uint32_t len); */
_do_xor_sse2@12:
    /* edi = buf1
    *  edx = buf2
    *  esi = len
    *  eax = tmp1
    *  ecx = tmp2
    *  xmm0 = tmp3
    *  xmm1 = tmp4 */

    push ebp
    mov ebp, esp

    push esi
    push edi

    mov edi, [ebp+8]
    mov edx, [ebp+12]
    mov esi, [ebp+16]

    mov eax, edi
    and eax, 15
    cmp eax, 0
    jne stragglers2

    mov eax, edx
    and eax, 15
    cmp eax, 0
    jne stragglers2

do_xor_sse2_loop:
    cmp esi, 16
    jl stragglers2

    movdqa xmm0, [edi]
    movdqa xmm1, [edx]
    pxor xmm0, xmm1
    movdqa [edi], xmm0

    add edi, 16
    add edx, 16
    sub esi, 16

    jmp do_xor_sse2_loop

stragglers2:

    cmp esi, 4
    jl stragglers

    mov eax, [edi]
    mov ecx, [edx]
    xor eax, ecx
    mov [edi], eax

    add edi, 4
    add edx, 4
    sub esi, 4

    jmp stragglers2

stragglers:

    cmp esi, 0
    je do_xor_sse2_end

    mov al, [edi]
    mov cl, [edx]
    xor al, cl
    mov [edi], al

    inc edi
    inc edx
    dec esi

    jmp stragglers

do_xor_sse2_end:
    pop edi
    pop esi
    pop ebp

    ret 12

#endif
