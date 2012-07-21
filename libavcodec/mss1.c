/*
 * Microsoft Screen 1 (aka Windows Media Video V7 Screen) decoder
 * Copyright (c) 2012 Konstantin Shishkov
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

/**
 * @file
 * Microsoft Screen 1 (aka Windows Media Video V7 Screen) decoder
 */

#include "libavutil/intfloat.h"
#include "libavutil/intreadwrite.h"
#include "avcodec.h"
#include "get_bits.h"

enum SplitMode {
    SPLIT_VERT = 0,
    SPLIT_HOR,
    SPLIT_NONE
};

typedef struct ArithCoder {
    int low, high, value;
    GetBitContext *gb;
} ArithCoder;

#define MODEL_MIN_SYMS    2
#define MODEL_MAX_SYMS  256
#define THRESH_ADAPTIVE  -1
#define THRESH_LOW       15
#define THRESH_HIGH      50

typedef struct Model {
    int cum_prob[MODEL_MAX_SYMS + 1];
    int weights[MODEL_MAX_SYMS + 1];
    int idx2sym[MODEL_MAX_SYMS + 1];
    int sym2idx[MODEL_MAX_SYMS + 1];
    int num_syms;
    int thr_weight, threshold;
} Model;

static const int sec_order_sizes[4] = { 1, 7, 6, 1 };

enum ContextDirection {
    TOP_LEFT = 0,
    TOP,
    TOP_RIGHT,
    LEFT
};

typedef struct PixContext {
    int cache_size, num_syms;
    uint8_t cache[12];
    Model cache_model, full_model;
    Model sec_models[4][8][4];
} PixContext;

typedef struct MSS1Context {
    AVCodecContext *avctx;
    AVFrame        pic;
    uint8_t        *pic_start;
    int            pic_stride;
    uint8_t        *mask;
    int            mask_linesize;
    uint32_t       pal[256];
    int            free_colours;
    Model          intra_region, inter_region;
    Model          pivot, edge_mode, split_mode;
    PixContext     intra_pix_ctx, inter_pix_ctx;
    int            corrupted;
} MSS1Context;

static void arith_init(ArithCoder *c, GetBitContext *gb)
{
    c->low   = 0;
    c->high  = 0xFFFF;
    c->value = get_bits(gb, 16);
    c->gb    = gb;
}

static void arith_normalise(ArithCoder *c)
{
    for (;;) {
        if (c->high >= 0x8000) {
            if (c->low < 0x8000) {
                if (c->low >= 0x4000 && c->high < 0xC000) {
                    c->value -= 0x4000;
                    c->low   -= 0x4000;
                    c->high  -= 0x4000;
                } else {
                    return;
                }
            } else {
                c->value -= 0x8000;
                c->low   -= 0x8000;
                c->high  -= 0x8000;
            }
        }
        c->value <<= 1;
        c->low   <<= 1;
        c->high  <<= 1;
        c->high   |= 1;
        c->value  |= get_bits1(c->gb);
    }
}

static int arith_get_bit(ArithCoder *c)
{
    int range = c->high - c->low + 1;
    int bit   = (((c->value - c->low) << 1) + 1) / range;

    if (bit)
        c->low += range >> 1;
    else
        c->high = c->low + (range >> 1) - 1;

    arith_normalise(c);

    return bit;
}

static int arith_get_bits(ArithCoder *c, int bits)
{
    int range = c->high - c->low + 1;
    int val   = (((c->value - c->low + 1) << bits) - 1) / range;
    int prob  = range * val;

    c->high   = ((prob + range) >> bits) + c->low - 1;
    c->low   += prob >> bits;

    arith_normalise(c);

    return val;
}

static int arith_get_number(ArithCoder *c, int mod_val)
{
    int range = c->high - c->low + 1;
    int val   = ((c->value - c->low + 1) * mod_val - 1) / range;
    int prob  = range * val;

    c->high   = (prob + range) / mod_val + c->low - 1;
    c->low   += prob / mod_val;

    arith_normalise(c);

    return val;
}

static int arith_get_prob(ArithCoder *c, int *probs)
{
    int range = c->high - c->low + 1;
    int val   = ((c->value - c->low + 1) * probs[0] - 1) / range;
    int sym   = 1;

    while (probs[sym] > val)
        sym++;

    c->high = range * probs[sym - 1] / probs[0] + c->low - 1;
    c->low += range * probs[sym]     / probs[0];

    return sym;
}

static int model_calc_threshold(Model *m)
{
    int thr;

    if (m->thr_weight == -1) {
        thr = 2 * m->weights[m->num_syms] - 1;
        thr = ((thr >> 1) + 4 * m->cum_prob[0]) / thr;
    } else {
        thr = m->num_syms * m->thr_weight;
    }

    return FFMIN(thr, 0x3FFF);
}

static void model_reset(Model *m)
{
    int i;

    for (i = 0; i <= m->num_syms; i++) {
        m->weights[i]  = 1;
        m->cum_prob[i] = m->num_syms - i;
    }
    m->weights[0]           = -1;
    m->idx2sym[0]           = -1;
    m->sym2idx[m->num_syms] = -1;
    for (i = 0; i < m->num_syms; i++) {
        m->sym2idx[i]     = i + 1;
        m->idx2sym[i + 1] = i;
    }
}

static av_cold void model_init(Model *m, int num_syms, int thr_weight)
{
    m->num_syms   = num_syms;
    m->thr_weight = thr_weight;
    m->threshold  = model_calc_threshold(m);
    model_reset(m);
}

static void model_rescale_weights(Model *m)
{
    int i;
    int cum_prob;

    if (m->thr_weight == -1)
        m->threshold = model_calc_threshold(m);
    while (m->cum_prob[0] > m->threshold) {
        cum_prob = 0;
        for (i = m->num_syms; i >= 0; i--) {
            m->cum_prob[i] = cum_prob;
            m->weights[i]  = (m->weights[i] + 1) >> 1;
            cum_prob      += m->weights[i];
        }
    }
}

static void model_update(Model *m, int val)
{
    int i;

    if (m->weights[val] == m->weights[val - 1]) {
        for (i = val; m->weights[i - 1] == m->weights[val]; i--);
        if (i != val) {
            int sym1, sym2;

            sym1 = m->idx2sym[val];
            sym2 = m->idx2sym[i];

            m->idx2sym[val]  = sym2;
            m->idx2sym[i]    = sym1;
            m->sym2idx[sym1] = i;
            m->sym2idx[sym2] = val;

            val = i;
        }
    }
    m->weights[val]++;
    for (i = val - 1; i >= 0; i--)
        m->cum_prob[i]++;
    model_rescale_weights(m);
}

static int arith_get_model_sym(ArithCoder *c, Model *m)
{
    int idx, val;

    idx = arith_get_prob(c, m->cum_prob);

    val = m->idx2sym[idx];
    model_update(m, idx);

    arith_normalise(c);

    return val;
}

static void pixctx_reset(PixContext *ctx)
{
    int i, j, k;

    for (i = 0; i < ctx->cache_size; i++)
        ctx->cache[i] = i;

    model_reset(&ctx->cache_model);
    model_reset(&ctx->full_model);

    for (i = 0; i < 4; i++)
        for (j = 0; j < sec_order_sizes[i]; j++)
            for (k = 0; k < 4; k++)
                model_reset(&ctx->sec_models[i][j][k]);
}

static av_cold void pixctx_init(PixContext *ctx, int cache_size)
{
    int i, j, k;

    ctx->cache_size = cache_size + 4;
    ctx->num_syms   = cache_size;

    for (i = 0; i < ctx->cache_size; i++)
        ctx->cache[i] = i;

    model_init(&ctx->cache_model, ctx->num_syms + 1, THRESH_LOW);
    model_init(&ctx->full_model, 256, THRESH_HIGH);

    for (i = 0; i < 4; i++) {
        for (j = 0; j < sec_order_sizes[i]; j++) {
            for (k = 0; k < 4; k++) {
                model_init(&ctx->sec_models[i][j][k], 2 + i,
                           i ? THRESH_LOW : THRESH_ADAPTIVE);
            }
        }
    }
}

static int decode_top_left_pixel(ArithCoder *acoder, PixContext *pctx)
{
    int i, val, pix;

    val = arith_get_model_sym(acoder, &pctx->cache_model);
    if (val < pctx->num_syms) {
        pix = pctx->cache[val];
    } else {
        pix = arith_get_model_sym(acoder, &pctx->full_model);
        for (i = 0; i < pctx->cache_size - 1; i++)
            if (pctx->cache[i] == pix)
                break;
        val = i;
    }
    if (val) {
        for (i = val; i > 0; i--)
            pctx->cache[i] = pctx->cache[i - 1];
        pctx->cache[0] = pix;
    }

    return pix;
}

static int decode_pixel(ArithCoder *acoder, PixContext *pctx,
                        uint8_t *ngb, int num_ngb)
{
    int i, val, pix;

    val = arith_get_model_sym(acoder, &pctx->cache_model);
    if (val < pctx->num_syms) {
        int idx, j;


        idx = 0;
        for (i = 0; i < pctx->cache_size; i++) {
            for (j = 0; j < num_ngb; j++)
                if (pctx->cache[i] == ngb[j])
                    break;
            if (j == num_ngb) {
                if (idx == val)
                    break;
                idx++;
            }
        }
        val = FFMIN(i, pctx->cache_size - 1);
        pix = pctx->cache[val];
    } else {
        pix = arith_get_model_sym(acoder, &pctx->full_model);
        for (i = 0; i < pctx->cache_size - 1; i++)
            if (pctx->cache[i] == pix)
                break;
        val = i;
    }
    if (val) {
        for (i = val; i > 0; i--)
            pctx->cache[i] = pctx->cache[i - 1];
        pctx->cache[0] = pix;
    }

    return pix;
}

static int decode_pixel_in_context(ArithCoder *acoder, PixContext *pctx,
                                   uint8_t *src, int stride, int x, int y,
                                   int has_right)
{
    uint8_t neighbours[4];
    uint8_t ref_pix[4];
    int nlen;
    int layer = 0, sub;
    int pix;
    int i, j;

    if (!y) {
        memset(neighbours, src[-1], 4);
    } else {
        neighbours[TOP] = src[-stride];
        if (!x) {
            neighbours[TOP_LEFT] = neighbours[LEFT] = neighbours[TOP];
        } else {
            neighbours[TOP_LEFT] = src[-stride - 1];
            neighbours[    LEFT] = src[-1];
        }
        if (has_right)
            neighbours[TOP_RIGHT] = src[-stride + 1];
        else
            neighbours[TOP_RIGHT] = neighbours[TOP];
    }

    sub = 0;
    if (x >= 2 && src[-2] == neighbours[LEFT])
        sub  = 1;
    if (y >= 2 && src[-2 * stride] == neighbours[TOP])
        sub |= 2;

    nlen = 1;
    ref_pix[0] = neighbours[0];
    for (i = 1; i < 4; i++) {
        for (j = 0; j < nlen; j++)
            if (ref_pix[j] == neighbours[i])
                break;
        if (j == nlen)
            ref_pix[nlen++] = neighbours[i];
    }

    switch (nlen) {
    case 1:
    case 4:
        layer = 0;
        break;
    case 2:
        if (neighbours[TOP] == neighbours[TOP_LEFT]) {
            if (neighbours[TOP_RIGHT] == neighbours[TOP_LEFT])
                layer = 3;
            else if (neighbours[LEFT] == neighbours[TOP_LEFT])
                layer = 2;
            else
                layer = 4;
        } else if (neighbours[TOP_RIGHT] == neighbours[TOP_LEFT]) {
            if (neighbours[LEFT] == neighbours[TOP_LEFT])
                layer = 1;
            else
                layer = 5;
        } else if (neighbours[LEFT] == neighbours[TOP_LEFT]) {
            layer = 6;
        } else {
            layer = 0;
        }
        break;
    case 3:
        if (neighbours[TOP] == neighbours[TOP_LEFT])
            layer = 0;
        else if (neighbours[TOP_RIGHT] == neighbours[TOP_LEFT])
            layer = 1;
        else if (neighbours[LEFT] == neighbours[TOP_LEFT])
            layer = 2;
        else if (neighbours[TOP_RIGHT] == neighbours[TOP])
            layer = 3;
        else if (neighbours[TOP] == neighbours[LEFT])
            layer = 4;
        else
            layer = 5;
        break;
    }

    pix = arith_get_model_sym(acoder, &pctx->sec_models[nlen - 1][layer][sub]);
    if (pix < nlen)
        return ref_pix[pix];
    else
        return decode_pixel(acoder, pctx, ref_pix, nlen);
}

static int decode_region(MSS1Context *ctx, ArithCoder *acoder, uint8_t *dst,
                         int x, int y, int width, int height, int stride,
                         PixContext *pctx)
{
    int i, j;

    dst += x + y * stride;

    dst[0] = decode_top_left_pixel(acoder, pctx);
    for (j = 0; j < height; j++) {
        for (i = 0; i < width; i++) {
            if (!i && !j)
                continue;

            dst[i] = decode_pixel_in_context(acoder, pctx, dst + i, stride,
                                             i, j, width - i - 1);
        }
        dst += stride;
    }

    return 0;
}

static int decode_region_masked(MSS1Context *ctx, ArithCoder *acoder,
                                uint8_t *dst, int stride, uint8_t *mask,
                                int mask_stride, int x, int y,
                                int width, int height,
                                PixContext *pctx)
{
    int i, j;

    dst  += x + y * stride;
    mask += x + y * mask_stride;

    if (mask[0] == 0xFF)
        dst[0] = decode_top_left_pixel(acoder, pctx);
    for (j = 0; j < height; j++) {
        for (i = 0; i < width; i++) {
            if (!i && !j || mask[i] != 0xFF)
                continue;

            dst[i] = decode_pixel_in_context(acoder, pctx, dst + i, stride,
                                             i, j, width - i - 1);
        }
        dst  += stride;
        mask += mask_stride;
    }

    return 0;
}

static av_cold void codec_init(MSS1Context *ctx)
{
    model_init(&ctx->intra_region, 2, THRESH_ADAPTIVE);
    model_init(&ctx->inter_region, 2, THRESH_ADAPTIVE);
    model_init(&ctx->split_mode,   3, THRESH_HIGH);
    model_init(&ctx->edge_mode,    2, THRESH_HIGH);
    model_init(&ctx->pivot,        3, THRESH_LOW);
    pixctx_init(&ctx->intra_pix_ctx, 8);
    pixctx_init(&ctx->inter_pix_ctx, 2);
    ctx->corrupted = 1;
}

static void codec_reset(MSS1Context *ctx)
{
    model_reset(&ctx->intra_region);
    model_reset(&ctx->inter_region);
    model_reset(&ctx->split_mode);
    model_reset(&ctx->edge_mode);
    model_reset(&ctx->pivot);
    pixctx_reset(&ctx->intra_pix_ctx);
    pixctx_reset(&ctx->inter_pix_ctx);

    ctx->corrupted = 0;
}

static int decode_pal(MSS1Context *ctx, ArithCoder *acoder)
{
    int i, ncol, r, g, b;
    uint32_t *pal = ctx->pal + 256 - ctx->free_colours;

    if (!ctx->free_colours)
        return 0;

    ncol = arith_get_number(acoder, ctx->free_colours + 1);
    for (i = 0; i < ncol; i++) {
        r = arith_get_bits(acoder, 8);
        g = arith_get_bits(acoder, 8);
        b = arith_get_bits(acoder, 8);
        *pal++ = (0xFF << 24) | (r << 16) | (g << 8) | b;
    }

    return !!ncol;
}

static int decode_pivot(MSS1Context *ctx, ArithCoder *acoder, int base)
{
    int val, inv;

    inv = arith_get_model_sym(acoder, &ctx->edge_mode);
    val = arith_get_model_sym(acoder, &ctx->pivot) + 1;

    if (val > 2) {
        if ((base + 1) / 2 - 2 <= 0) {
            ctx->corrupted = 1;
            return 0;
        }
        val = arith_get_number(acoder, (base + 1) / 2 - 2) + 3;
    }

    if ((unsigned)val >= base) {
        ctx->corrupted = 1;
        return 0;
    }

    return inv ? base - val : val;
}

static int decode_region_intra(MSS1Context *ctx, ArithCoder *acoder,
                               int x, int y, int width, int height)
{
    int mode;

    mode = arith_get_model_sym(acoder, &ctx->intra_region);

    if (!mode) {
        int i, pix;
        int stride = ctx->pic_stride;
        uint8_t *dst = ctx->pic_start + x + y * stride;

        pix = decode_top_left_pixel(acoder, &ctx->intra_pix_ctx);
        for (i = 0; i < height; i++, dst += stride)
            memset(dst, pix, width);
    } else {
        return decode_region(ctx, acoder, ctx->pic_start,
                             x, y, width, height, ctx->pic_stride,
                             &ctx->intra_pix_ctx);
    }

    return 0;
}

static int decode_intra(MSS1Context *ctx, ArithCoder *acoder,
                        int x, int y, int width, int height)
{
    int mode, pivot;

    if (ctx->corrupted)
        return -1;

    mode = arith_get_model_sym(acoder, &ctx->split_mode);

    switch (mode) {
    case SPLIT_VERT:
        pivot = decode_pivot(ctx, acoder, height);
        if (ctx->corrupted)
            return -1;
        if (decode_intra(ctx, acoder, x, y, width, pivot))
            return -1;
        if (decode_intra(ctx, acoder, x, y + pivot, width, height - pivot))
            return -1;
        break;
    case SPLIT_HOR:
        pivot = decode_pivot(ctx, acoder, width);
        if (ctx->corrupted)
            return -1;
        if (decode_intra(ctx, acoder, x, y, pivot, height))
            return -1;
        if (decode_intra(ctx, acoder, x + pivot, y, width - pivot, height))
            return -1;
        break;
    case SPLIT_NONE:
        return decode_region_intra(ctx, acoder, x, y, width, height);
    default:
        return -1;
    }

    return 0;
}

static int decode_region_inter(MSS1Context *ctx, ArithCoder *acoder,
                               int x, int y, int width, int height)
{
    int mode;

    mode = arith_get_model_sym(acoder, &ctx->inter_region);

    if (!mode) {
        mode = decode_top_left_pixel(acoder, &ctx->inter_pix_ctx);
        if (mode != 0xFF) {
            return 0;
        } else {
            return decode_region_intra(ctx, acoder, x, y, width, height);
        }
    } else {
        if (decode_region(ctx, acoder, ctx->mask,
                          x, y, width, height, ctx->mask_linesize,
                          &ctx->inter_pix_ctx) < 0)
            return -1;
        return decode_region_masked(ctx, acoder, ctx->pic_start,
                                    -ctx->pic.linesize[0], ctx->mask,
                                    ctx->mask_linesize,
                                    x, y, width, height,
                                    &ctx->intra_pix_ctx);
    }

    return 0;
}

static int decode_inter(MSS1Context *ctx, ArithCoder *acoder,
                        int x, int y, int width, int height)
{
    int mode, pivot;

    if (ctx->corrupted)
        return -1;

    mode = arith_get_model_sym(acoder, &ctx->split_mode);

    switch (mode) {
    case SPLIT_VERT:
        pivot = decode_pivot(ctx, acoder, height);
        if (decode_inter(ctx, acoder, x, y, width, pivot))
            return -1;
        if (decode_inter(ctx, acoder, x, y + pivot, width, height - pivot))
            return -1;
        break;
    case SPLIT_HOR:
        pivot = decode_pivot(ctx, acoder, width);
        if (decode_inter(ctx, acoder, x, y, pivot, height))
            return -1;
        if (decode_inter(ctx, acoder, x + pivot, y, width - pivot, height))
            return -1;
        break;
    case SPLIT_NONE:
        return decode_region_inter(ctx, acoder, x, y, width, height);
    default:
        return -1;
    }

    return 0;
}

static int mss1_decode_frame(AVCodecContext *avctx, void *data, int *data_size,
                             AVPacket *avpkt)
{
    const uint8_t *buf = avpkt->data;
    int buf_size = avpkt->size;
    MSS1Context *c = avctx->priv_data;
    GetBitContext gb;
    ArithCoder acoder;
    int pal_changed = 0;
    int ret;

    init_get_bits(&gb, buf, buf_size * 8);
    arith_init(&acoder, &gb);

    c->pic.reference    = 3;
    c->pic.buffer_hints = FF_BUFFER_HINTS_VALID | FF_BUFFER_HINTS_PRESERVE |
                          FF_BUFFER_HINTS_REUSABLE;
    if ((ret = avctx->reget_buffer(avctx, &c->pic)) < 0) {
        av_log(avctx, AV_LOG_ERROR, "reget_buffer() failed\n");
        return ret;
    }

    c->pic_start  = c->pic.data[0] + c->pic.linesize[0] * (avctx->height - 1);
    c->pic_stride = -c->pic.linesize[0];
    if (!arith_get_bit(&acoder)) {
        codec_reset(c);
        pal_changed      = decode_pal(c, &acoder);
        c->corrupted     = decode_intra(c, &acoder, 0, 0,
                                        avctx->width, avctx->height);
        c->pic.key_frame = 1;
        c->pic.pict_type = AV_PICTURE_TYPE_I;
    } else {
        if (c->corrupted)
            return AVERROR_INVALIDDATA;
        c->corrupted     = decode_inter(c, &acoder, 0, 0,
                                        avctx->width, avctx->height);
        c->pic.key_frame = 0;
        c->pic.pict_type = AV_PICTURE_TYPE_P;
    }
    if (c->corrupted)
        return AVERROR_INVALIDDATA;
    memcpy(c->pic.data[1], c->pal, AVPALETTE_SIZE);
    c->pic.palette_has_changed = pal_changed;

    *data_size = sizeof(AVFrame);
    *(AVFrame*)data = c->pic;

    /* always report that the buffer was completely consumed */
    return buf_size;
}

static av_cold int mss1_decode_init(AVCodecContext *avctx)
{
    MSS1Context * const c = avctx->priv_data;
    int i;

    c->avctx = avctx;

    if (avctx->extradata_size < 52 + 256 * 3) {
        av_log(avctx, AV_LOG_ERROR, "Insufficient extradata size %d\n",
               avctx->extradata_size);
        return AVERROR_INVALIDDATA;
    }

    if (AV_RB32(avctx->extradata) < avctx->extradata_size) {
        av_log(avctx, AV_LOG_ERROR,
               "Insufficient extradata size: expected %d got %d\n",
               AV_RB32(avctx->extradata),
               avctx->extradata_size);
        return AVERROR_INVALIDDATA;
    }

    av_log(avctx, AV_LOG_DEBUG, "Encoder version %d.%d\n",
           AV_RB32(avctx->extradata + 4), AV_RB32(avctx->extradata + 8));
    c->free_colours     = AV_RB32(avctx->extradata + 48);
    if ((unsigned)c->free_colours > 256) {
        av_log(avctx, AV_LOG_ERROR,
               "Incorrect number of changeable palette entries: %d\n",
               c->free_colours);
        return AVERROR_INVALIDDATA;
    }
    av_log(avctx, AV_LOG_DEBUG, "%d free colour(s)\n", c->free_colours);
    avctx->coded_width  = AV_RB32(avctx->extradata + 20);
    avctx->coded_height = AV_RB32(avctx->extradata + 24);

    av_log(avctx, AV_LOG_DEBUG, "Display dimensions %dx%d\n",
           AV_RB32(avctx->extradata + 12), AV_RB32(avctx->extradata + 16));
    av_log(avctx, AV_LOG_DEBUG, "Coded dimensions %dx%d\n",
           avctx->coded_width, avctx->coded_height);
    av_log(avctx, AV_LOG_DEBUG, "%g frames per second\n",
           av_int2float(AV_RB32(avctx->extradata + 28)));
    av_log(avctx, AV_LOG_DEBUG, "Bitrate %d bps\n",
           AV_RB32(avctx->extradata + 32));
    av_log(avctx, AV_LOG_DEBUG, "Max. lead time %g ms\n",
           av_int2float(AV_RB32(avctx->extradata + 36)));
    av_log(avctx, AV_LOG_DEBUG, "Max. lag time %g ms\n",
           av_int2float(AV_RB32(avctx->extradata + 40)));
    av_log(avctx, AV_LOG_DEBUG, "Max. seek time %g ms\n",
           av_int2float(AV_RB32(avctx->extradata + 44)));

    for (i = 0; i < 256; i++)
        c->pal[i] = 0xFF << 24 | AV_RB24(avctx->extradata + 52 + i * 3);

    avctx->pix_fmt = PIX_FMT_PAL8;

    c->mask_linesize = FFALIGN(avctx->width, 16);
    c->mask          = av_malloc(c->mask_linesize * avctx->height);
    if (!c->mask) {
        av_log(avctx, AV_LOG_ERROR, "Cannot allocate mask plane\n");
        return AVERROR(ENOMEM);
    }

    avctx->coded_frame = &c->pic;

    codec_init(c);

    return 0;
}

static av_cold int mss1_decode_end(AVCodecContext *avctx)
{
    MSS1Context * const c = avctx->priv_data;

    if (c->pic.data[0])
        avctx->release_buffer(avctx, &c->pic);
    av_freep(&c->mask);

    return 0;
}

AVCodec ff_mss1_decoder = {
    .name           = "mss1",
    .type           = AVMEDIA_TYPE_VIDEO,
    .id             = CODEC_ID_MSS1,
    .priv_data_size = sizeof(MSS1Context),
    .init           = mss1_decode_init,
    .close          = mss1_decode_end,
    .decode         = mss1_decode_frame,
    .capabilities   = CODEC_CAP_DR1,
    .long_name      = NULL_IF_CONFIG_SMALL("MS Screen 1"),
};
