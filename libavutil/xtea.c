/*
 * A 32-bit implementation of the XTEA algorithm
 * Copyright (c) 2012 Samuel Pitoiset
 *
 * loosely based on the implementation of David Wheeler and Roger Needham
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "libavutil/intreadwrite.h"

#include "avutil.h"
#include "common.h"
#include "xtea.h"

void av_xtea_init(AVXTEA *ctx, const uint8_t key[16])
{
    int i;

    for (i = 0; i < 4; i++)
        ctx->key[i] = AV_RB32(key + (i << 2));
}

static void xtea_crypt_ecb(AVXTEA *ctx, uint8_t *dst, const uint8_t *src,
                           int decrypt)
{
    uint32_t v0, v1;
    int i;

    v0 = AV_RB32(src);
    v1 = AV_RB32(src + 4);

    if (decrypt) {
        uint32_t delta = 0x9E3779B9, sum = delta * 32;

        for (i = 0; i < 32; i++) {
            v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + ctx->key[(sum >> 11) & 3]);
            sum -= delta;
            v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + ctx->key[sum & 3]);
        }
    } else {
        uint32_t sum = 0, delta = 0x9E3779B9;

        for (i = 0; i < 32; i++) {
            v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + ctx->key[sum & 3]);
            sum += delta;
            v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + ctx->key[(sum >> 11) & 3]);
        }
    }

    AV_WB32(dst, v0);
    AV_WB32(dst + 4, v1);
}

void av_xtea_crypt(AVXTEA *ctx, uint8_t *dst, const uint8_t *src, int count,
                   uint8_t *iv, int decrypt)
{
    int i;

    if (decrypt) {
        while (count--) {
            xtea_crypt_ecb(ctx, dst, src, decrypt);

            if (iv) {
                for (i = 0; i < 8; i++)
                    dst[i] = dst[i] ^ iv[i];
                memcpy(iv, src, 8);
            }

            src   += 8;
            dst   += 8;
        }
    } else {
        while (count--) {
            if (iv) {
                for (i = 0; i < 8; i++)
                    dst[i] = src[i] ^ iv[i];
                xtea_crypt_ecb(ctx, dst, dst, decrypt);
                memcpy(iv, dst, 8);
            } else {
                xtea_crypt_ecb(ctx, dst, src, decrypt);
            }
            src   += 8;
            dst   += 8;
        }
    }
}

#ifdef TEST
#include <stdio.h>
#undef printf

#define XTEA_NUM_TESTS 6

static const uint8_t xtea_test_key[XTEA_NUM_TESTS][16] = {
    { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
    { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
    { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
};

static const uint8_t xtea_test_pt[XTEA_NUM_TESTS][8] = {
    { 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 },
    { 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41 },
    { 0x5a, 0x5b, 0x6e, 0x27, 0x89, 0x48, 0xd7, 0x7f },
    { 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 },
    { 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41 },
    { 0x70, 0xe1, 0x22, 0x5d, 0x6e, 0x4e, 0x76, 0x55 }
};

static const uint8_t xtea_test_ct[XTEA_NUM_TESTS][8] = {
    { 0x49, 0x7d, 0xf3, 0xd0, 0x72, 0x61, 0x2c, 0xb5 },
    { 0xe7, 0x8f, 0x2d, 0x13, 0x74, 0x43, 0x41, 0xd8 },
    { 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41 },
    { 0xa0, 0x39, 0x05, 0x89, 0xf8, 0xb8, 0xef, 0xa5 },
    { 0xed, 0x23, 0x37, 0x5a, 0x82, 0x1a, 0x8c, 0x2d },
    { 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41 }
};

int main(void)
{
    AVXTEA ctx;
    uint8_t buf[8];
    int i;

    for (i = 0; i < XTEA_NUM_TESTS; i++) {
        av_xtea_init(&ctx, xtea_test_key[i]);

        av_xtea_crypt(&ctx, buf, xtea_test_pt[i], 1, NULL, 0);
        if (memcmp(buf, xtea_test_ct[i], 8)) {
            printf("Test encryption failed.\n");
            return 1;
        }

        av_xtea_crypt(&ctx, buf, xtea_test_ct[i], 1, NULL, 1);
        if (memcmp(buf, xtea_test_pt[i], 8)) {
            printf("Test decryption failed.\n");
            return 1;
        }
    }
    printf("Test encryption/decryption success.\n");

    return 0;
}

#endif
