EXTERN crctable:qword

_TEXT  SEGMENT

PUBLIC calc_crc32c_sw

; uint32_t __stdcall calc_crc32c_sw(uint32_t seed, uint8_t* msg, uint32_t msglen);

calc_crc32c_sw:

; rax = crc / seed
; rdx = buf
; r8 = len
; rcx = tmp
; r10 = tmp2

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
mov r10, offset crctable
mov eax, dword ptr [r10 + rax]
xor rax, rcx

inc rdx
dec r8

jmp crcloop

crcend:
ret

_TEXT  ENDS

end
