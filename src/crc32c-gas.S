.intel_syntax noprefix

.extern _crctable
.global _calc_crc32c_sw@12

/* uint32_t __stdcall calc_crc32c_sw(uint32_t seed, uint8_t* msg, uint32_t msglen); */

_calc_crc32c_sw@12:

push ebp
mov ebp, esp

push esi
push ebx

mov eax, [ebp+8]
mov edx, [ebp+12]
mov ebx, [ebp+16]

/* eax = crc / seed
 * ebx = len
 * esi = tmp
 * edx = buf
 * ecx = tmp2 */

crcloop:
test ebx, ebx
jz crcend

mov esi, eax
shr esi, 8
mov cl, byte ptr [edx]
xor al, cl
and eax, 255
shl eax, 2
mov eax, [_crctable + eax]
xor eax, esi

inc edx
dec ebx

jmp crcloop

crcend:
pop ebx
pop esi

pop ebp

ret 12
