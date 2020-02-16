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
