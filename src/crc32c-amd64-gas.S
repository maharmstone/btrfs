.intel_syntax noprefix

.extern _crctable
.global _calc_crc32c_sw@12

/* uint32_t __stdcall calc_crc32c_sw(uint32_t seed, uint8_t* msg, uint32_t msglen); */

_calc_crc32c_sw@12:

/* rax = crc / seed
 * rdx = buf
 * r8 = len
 * rcx = tmp
 * r10 = tmp2 */

mov rax, rcx

crcloop:
test r8, r8
jz crcend

mov rcx, rax
shr rcx, 8
mov r10b, byte ptr [rdx]
xor al, r10b
and rax, 255
shl rax, 2
mov rax, [_crctable + rax]
xor rax, rcx

inc rdx
dec r8

jmp crcloop

crcend:
ret

/****************************************************/

/* uint32_t __stdcall calc_crc32c_hw(uint32_t seed, uint8_t* msg, uint32_t msglen); */

_calc_crc32c_hw@12:

/* rax = crc / seed
 * rdx = buf
 * r8 = len */

mov rax, rcx

crchw_loop:
cmp r8, 8
jl crchw_stragglers

crc32 rax, qword ptr [rdx]

add rdx, 8
sub r8, 8
jmp crchw_loop

crchw_stragglers:
cmp r8, 4
jl crchw_stragglers2

crc32 eax, dword ptr [rdx]

add rdx, 4
sub r8, 4

crchw_stragglers2:
cmp r8, 2
jl crchw_stragglers3

crc32 eax, word ptr [rdx]

add rdx, 2
sub r8, 2

crchw_stragglers3:
test r8, r8
jz crchw_end

crc32 eax, byte ptr [rdx]
inc rdx
dec r8
jmp crchw_stragglers3

crchw_end:
ret
