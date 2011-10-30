/*
 * RealAudio 2.0 (28.8K)
 * Copyright (c) 2003 the ffmpeg project
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

#include "avcodec.h"
#define ALT_BITSTREAM_READER_LE
#include "get_bits.h"
#include "ra288.h"
#include "lpc.h"
#include "celp_math.h"
#include "celp_filters.h"

#define MAX_BACKWARD_FILTER_ORDER  36
#define MAX_BACKWARD_FILTER_LEN    40
#define MAX_BACKWARD_FILTER_NONREC 35

#define RA288_BLOCK_SIZE        5
#define RA288_BLOCKS_PER_FRAME 32

typedef struct {
    float sp_lpc[36];      ///< LPC coefficients for speech data (spec: A)
    float gain_lpc[10];    ///< LPC coefficients for gain        (spec: GB)

    /** speech data history                                      (spec: SB).
     *  Its first 70 coefficients are updated only at backward filtering.
     */
    float sp_hist[111];

    /// speech part of the gain autocorrelation                  (spec: REXP)
    float sp_rec[37];

    /** log-gain history                                         (spec: SBLG).
     *  Its first 28 coefficients are updated only at backward filtering.
     */
    float gain_hist[38];

    /// recursive part of the gain autocorrelation               (spec: REXPLG)
    float gain_rec[11];
} RA288Context;

static av_cold int ra288_decode_init(AVCodecContext *avctx)
{
    avctx->sample_fmt = AV_SAMPLE_FMT_FLT;
    return 0;
}

static void apply_window(float *tgt, const float *m1, const float *m2, int n)
{
    while (n--)
        *tgt++ = *m1++ * *m2++;
}

static void convolve(float *tgt, const float *src, int len, int n)
{
    for (; n >= 0; n--)
        tgt[n] = ff_dot_productf(src, src - n, len);

}

static void decode(RA288Context *ractx, float gain, int cb_coef)
{
    int i;
    double sumsum;
    float sum, buffer[5];
    float *block = ractx->sp_hist + 70 + 36; // current block
    float *gain_block = ractx->gain_hist + 28;

    memmove(ractx->sp_hist + 70, ractx->sp_hist + 75, 36*sizeof(*block));

    /* block 46 of G.728 spec */
    sum = 32.;
    for (i=0; i < 10; i++)
        sum -= gain_block[9-i] * ractx->gain_lpc[i];

    /* block 47 of G.728 spec */
    sum = av_clipf(sum, 0, 60);

    /* block 48 of G.728 spec */
    /* exp(sum * 0.1151292546497) == pow(10.0,sum/20) */
    sumsum = exp(sum * 0.1151292546497) * gain * (1.0/(1<<23));

    for (i=0; i < 5; i++)
        buffer[i] = codetable[cb_coef][i] * sumsum;

    sum = ff_dot_productf(buffer, buffer, 5);

    sum = FFMAX(sum, 5. / (1<<24));

    /* shift and store */
    memmove(gain_block, gain_block + 1, 9 * sizeof(*gain_block));

    gain_block[9] = 10 * log10(sum) + (10*log10(((1<<24)/5.)) - 32);

    ff_celp_lp_synthesis_filterf(block, ractx->sp_lpc, buffer, 5, 36);
}

/**
 * Hybrid window filtering, see blocks 36 and 49 of the G.728 specification.
 *
 * @param order   filter order
 * @param n       input length
 * @param non_rec number of non-recursive samples
 * @param out     filter output
 * @param hist    pointer to the input history of the filter
 * @param out     pointer to the non-recursive part of the output
 * @param out2    pointer to the recursive part of the output
 * @param window  pointer to the windowing function table
 */
static void do_hybrid_window(int order, int n, int non_rec, float *out,
                             float *hist, float *out2, const float *window)
{
    int i;
    float buffer1[MAX_BACKWARD_FILTER_ORDER + 1];
    float buffer2[MAX_BACKWARD_FILTER_ORDER + 1];
    float work[MAX_BACKWARD_FILTER_ORDER + MAX_BACKWARD_FILTER_LEN + MAX_BACKWARD_FILTER_NONREC];

    apply_window(work, window, hist, order + n + non_rec);

    convolve(buffer1, work + order    , n      , order);
    convolve(buffer2, work + order + n, non_rec, order);

    for (i=0; i <= order; i++) {
        out2[i] = out2[i] * 0.5625 + buffer1[i];
        out [i] = out2[i]          + buffer2[i];
    }

    /* Multiply by the white noise correcting factor (WNCF). */
    *out *= 257./256.;
}

/**
 * Backward synthesis filter, find the LPC coefficients from past speech data.
 */
static void backward_filter(float *hist, float *rec, const float *window,
                            float *lpc, const float *tab,
                            int order, int n, int non_rec, int move_size)
{
    float temp[MAX_BACKWARD_FILTER_ORDER+1];

    do_hybrid_window(order, n, non_rec, temp, hist, rec, window);

    if (!compute_lpc_coefs(temp, order, lpc, 0, 1, 1))
        apply_window(lpc, lpc, tab, order);

    memmove(hist, hist + n, move_size*sizeof(*hist));
}

static int ra288_decode_frame(AVCodecContext * avctx, void *data,
                              int *data_size, AVPacket *avpkt)
{
    const uint8_t *buf = avpkt->data;
    int buf_size = avpkt->size;
    float *out = data;
    int i, j, out_size;
    RA288Context *ractx = avctx->priv_data;
    GetBitContext gb;

    if (buf_size < avctx->block_align) {
        av_log(avctx, AV_LOG_ERROR,
               "Error! Input buffer is too small [%d<%d]\n",
               buf_size, avctx->block_align);
        return 0;
    }

    out_size = RA288_BLOCK_SIZE * RA288_BLOCKS_PER_FRAME *
               av_get_bytes_per_sample(avctx->sample_fmt);
    if (*data_size < out_size) {
        av_log(avctx, AV_LOG_ERROR, "Output buffer is too small\n");
        return AVERROR(EINVAL);
    }

    init_get_bits(&gb, buf, avctx->block_align * 8);

    for (i=0; i < RA288_BLOCKS_PER_FRAME; i++) {
        float gain = amptable[get_bits(&gb, 3)];
        int cb_coef = get_bits(&gb, 6 + (i&1));

        decode(ractx, gain, cb_coef);

        for (j=0; j < RA288_BLOCK_SIZE; j++)
            *(out++) = ractx->sp_hist[70 + 36 + j];

        if ((i & 7) == 3) {
            backward_filter(ractx->sp_hist, ractx->sp_rec, syn_window,
                            ractx->sp_lpc, syn_bw_tab, 36, 40, 35, 70);

            backward_filter(ractx->gain_hist, ractx->gain_rec, gain_window,
                            ractx->gain_lpc, gain_bw_tab, 10, 8, 20, 28);
        }
    }

    *data_size = out_size;
    return avctx->block_align;
}

AVCodec ff_ra_288_decoder = {
    .name           = "real_288",
    .type           = AVMEDIA_TYPE_AUDIO,
    .id             = CODEC_ID_RA_288,
    .priv_data_size = sizeof(RA288Context),
    .init           = ra288_decode_init,
    .decode         = ra288_decode_frame,
    .long_name      = NULL_IF_CONFIG_SMALL("RealAudio 2.0 (28.8K)"),
};
