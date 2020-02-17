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

; ****************************************************

; uint32_t __stdcall calc_crc32c_hw(uint32_t seed, uint8_t* msg, uint32_t msglen);

PUBLIC calc_crc32c_hw

calc_crc32c_hw:

; rax = crc / seed
; rdx = buf
; r8 = len

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

_TEXT  ENDS

end
