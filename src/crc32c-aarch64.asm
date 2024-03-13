    AREA .text, CODE, READONLY

    GLOBAL calc_crc32c_hw

; uint32_t calc_crc32c_hw(uint32_t seed, const uint8_t* buf, uint32_t len);
calc_crc32c_hw
    ; w0 = crc / seed
    ; x1 = buf
    ; w2 = len
    ; x3 = scratch

    cmp w2, #8
    b.lt crchw_stragglers

    ldr x3, [x1]
    crc32cx w0, w0, x3

    add x1, x1, #8
    sub w2, w2, #8
    b calc_crc32c_hw

crchw_stragglers
    cmp w2, #4
    b.lt crchw_stragglers2

    ldr w3, [x1]
    crc32cw w0, w0, w3

    add x1, x1, #4
    sub w2, w2, #4

crchw_stragglers2
    cmp w2, #2
    b.lt crchw_stragglers3

    ldrh w3, [x1]
    crc32ch w0, w0, w3

    add x1, x1, #2
    sub w2, w2, #2

crchw_stragglers3
    cmp w2, #0
    b.eq crchw_end

    ldrb w3, [x1]
    crc32cb w0, w0, w3

crchw_end
    ret

    END
