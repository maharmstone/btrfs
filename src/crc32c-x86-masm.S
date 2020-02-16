.686P

EXTERN _crctable:ABS

_TEXT  SEGMENT

; uint32_t __stdcall calc_crc32c_sw(uint32_t seed, uint8_t* msg, uint32_t msglen);

PUBLIC _calc_crc32c_sw@12

_calc_crc32c_sw@12:

push ebp
mov ebp, esp

push esi
push ebx

mov eax, [ebp+8]
mov edx, [ebp+12]
mov ebx, [ebp+16]

; eax = crc / seed
; ebx = len
; esi = tmp
; edx = buf
; ecx = tmp2

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

; ****************************************************

; uint32_t __stdcall calc_crc32c_hw(uint32_t seed, uint8_t* msg, uint32_t msglen);

PUBLIC _calc_crc32c_hw@12

_calc_crc32c_hw@12:

push ebp
mov ebp, esp

mov eax, [ebp+8]
mov edx, [ebp+12]
mov ecx, [ebp+16]

; eax = crc / seed
; ecx = len
; edx = buf

crchw_loop:
cmp ecx, 4
jl crchw_stragglers

crc32 eax, dword ptr [edx]

add edx, 4
sub ecx, 4
jmp crchw_loop

crchw_stragglers:
cmp ecx, 2
jl crchw_stragglers2

crc32 eax, word ptr [edx]

add edx, 2
sub ecx, 2

crchw_stragglers2:
test ecx, ecx
jz crchw_end

crc32 eax, byte ptr [edx]
inc edx
dec ecx
jmp crchw_stragglers2

crchw_end:
pop ebp

ret 12

_TEXT  ENDS

end
