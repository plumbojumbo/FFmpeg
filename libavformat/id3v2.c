/*
 * Copyright (c) 2003 Fabrice Bellard
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
 * ID3v2 header parser
 *
 * Specifications available at:
 * http://id3.org/Developer_Information
 */

#include "id3v2.h"
#include "id3v1.h"
#include "libavutil/avstring.h"
#include "libavutil/intreadwrite.h"
#include "libavutil/dict.h"
#include "avio_internal.h"

int ff_id3v2_match(const uint8_t *buf, const char * magic)
{
    return  buf[0]         == magic[0] &&
            buf[1]         == magic[1] &&
            buf[2]         == magic[2] &&
            buf[3]         != 0xff &&
            buf[4]         != 0xff &&
           (buf[6] & 0x80) ==    0 &&
           (buf[7] & 0x80) ==    0 &&
           (buf[8] & 0x80) ==    0 &&
           (buf[9] & 0x80) ==    0;
}

int ff_id3v2_tag_len(const uint8_t * buf)
{
    int len = ((buf[6] & 0x7f) << 21) +
              ((buf[7] & 0x7f) << 14) +
              ((buf[8] & 0x7f) << 7) +
               (buf[9] & 0x7f) +
              ID3v2_HEADER_SIZE;
    if (buf[5] & 0x10)
        len += ID3v2_HEADER_SIZE;
    return len;
}

static unsigned int get_size(AVIOContext *s, int len)
{
    int v = 0;
    while (len--)
        v = (v << 7) + (avio_r8(s) & 0x7F);
    return v;
}

/**
 * Decode content to UTF-8 according to encoding type
 */
static void decode_content(AVFormatContext *s, AVIOContext *pb, int type, char *dst, int dstlen, int taglen, const char *key)
{
    char *q;
    int len;
    unsigned int (*get)(AVIOContext*) = avio_rb16;

    switch (type) { /* encoding type */

    case ID3v2_ENCODING_ISO8859:
        q = dst;
        while (taglen-- && q - dst < dstlen - 7) {
            uint8_t tmp;
            PUT_UTF8(avio_r8(pb), tmp, *q++ = tmp;)
        }
        *q = 0;
        break;

    case ID3v2_ENCODING_UTF16BOM:
        taglen -= 2;
        switch (avio_rb16(pb)) {
        case 0xfffe:
            get = avio_rl16;
        case 0xfeff:
            break;
        default:
            av_log(s, AV_LOG_ERROR, "Incorrect BOM value in tag %s.\n", key);
            return;
        }
        // fall-through

    case ID3v2_ENCODING_UTF16BE:
        q = dst;
        while (taglen > 1 && q - dst < dstlen - 7) {
            uint32_t ch;
            uint8_t tmp;

            GET_UTF16(ch, ((taglen -= 2) >= 0 ? get(pb) : 0), break;)
            PUT_UTF8(ch, tmp, *q++ = tmp;)
        }
        *q = 0;
        break;

    case ID3v2_ENCODING_UTF8:
        len = FFMIN(taglen, dstlen);
        avio_read(pb, dst, len);
        dst[len] = 0;
        break;
    default:
        av_log(s, AV_LOG_WARNING, "Unknown encoding in tag %s.\n", key);
    }
}

/**
 * Parse a text tag.
 */
static void read_ttag(AVFormatContext *s, AVIOContext *pb, int taglen, const char *key)
{
    char dst[512];
    const char *val = NULL;
    int len, dstlen = sizeof(dst) - 1;
    unsigned genre;

    dst[0] = 0;
    if (taglen < 1)
        return;

    taglen--; /* account for encoding type byte */

    decode_content(s, pb, avio_r8(pb), dst, dstlen, taglen, key);

    if (!(strcmp(key, "TCON") && strcmp(key, "TCO"))
        && (sscanf(dst, "(%d)", &genre) == 1 || sscanf(dst, "%d", &genre) == 1)
        && genre <= ID3v1_GENRE_MAX)
        val = ff_id3v1_genre_str[genre];
    else if (!(strcmp(key, "TXXX") && strcmp(key, "TXX"))) {
        /* dst now contains two 0-terminated strings */
        dst[dstlen] = 0;
        len = strlen(dst);
        key = dst;
        val = dst + FFMIN(len + 1, dstlen);
    }
    else if (*dst)
        val = dst;

    if (val)
        av_dict_set(&s->metadata, key, val, AV_DICT_DONT_OVERWRITE);
}

/**
 * Parse GEOB tag into a ID3v2ExtraMetaGEOB struct.
 */
static void read_geobtag(AVFormatContext *s, AVIOContext *pb, int taglen, char *tag, ID3v2ExtraMeta **extra_meta)
{
    ID3v2ExtraMetaGEOB *geob_data;
    ID3v2ExtraMeta *new_extra;
    char encoding;
    unsigned char buf[512];
    unsigned int len;
    int64_t pos;
    int (*get_str)(AVIOContext*, int, char*, int);

    if (taglen < 1)
        return;

    geob_data = av_mallocz(sizeof(ID3v2ExtraMetaGEOB));
    if (!geob_data) {
        av_log(s, AV_LOG_ERROR, "Failed to alloc %d bytes\n", sizeof(ID3v2ExtraMetaGEOB));
        return;
    }

    new_extra = av_mallocz(sizeof(ID3v2ExtraMeta));
    if (!new_extra) {
        av_log(s, AV_LOG_ERROR, "Failed to alloc %d bytes\n", sizeof(ID3v2ExtraMeta));
        return;
    }

    /* read encoding type byte */
    encoding = avio_r8(pb);
    taglen--;
    switch (encoding) {
        case ID3v2_ENCODING_ISO8859:
        case ID3v2_ENCODING_UTF8:
            get_str = avio_get_str;
            break;
        case ID3v2_ENCODING_UTF16BE:
        case ID3v2_ENCODING_UTF16BOM:
            get_str = avio_get_str16be;
            break;
        default:
            av_log(s, AV_LOG_ERROR, "Unknown encoding in GEOB tag.\n");
            return;
    }

    /* peek forward to figure out the length of the content part and decode it */
#define PEEK_DECODE(get, key, encoding) \
    pos = avio_tell(pb);\
    len = get(pb, taglen, buf, sizeof(buf));\
    geob_data->key = av_mallocz(len + 7);\
    if (!geob_data->key) {\
        av_log(s, AV_LOG_ERROR, "Failed to alloc %d bytes\n", len + 7);\
        return;\
    }\
    avio_seek(pb, pos, SEEK_SET);\
    decode_content(s, pb, encoding, geob_data->key, len + 7, len, "GEOB");\
    taglen -= len;\

    /* read MIME type (always ISO-8859) and save as UTF-8 */
    PEEK_DECODE(avio_get_str, mime_type, ID3v2_ENCODING_ISO8859)

    /* read file name and save as UTF-8 */
    PEEK_DECODE(get_str, file_name, encoding)

    /* read content description and save as UTF-8 */
    PEEK_DECODE(get_str, description, encoding)

    /* save encapsulated binary data */
    geob_data->data = av_malloc(taglen);
    if (!geob_data->data) {
        av_log(s, AV_LOG_ERROR, "Failed to alloc %d bytes\n", taglen);
        return;
    }
    if ((len = avio_read(pb, geob_data->data, taglen)) < taglen)
        av_log(s, AV_LOG_WARNING, "Error reading GEOB frame, data truncated.\n");
    geob_data->datasize = len;

    /* add data to the list */
    new_extra->tag = "GEOB";
    new_extra->data = geob_data;
    new_extra->next = *extra_meta;
    *extra_meta = new_extra;
}

/**
 * Free GEOB type extra metadata.
 */
static void free_geobtag(ID3v2ExtraMetaGEOB *geob)
{
    av_free(geob->mime_type);
    av_free(geob->file_name);
    av_free(geob->description);
    av_free(geob->data);
    av_free(geob);
}

static int is_number(const char *str)
{
    while (*str >= '0' && *str <= '9') str++;
    return !*str;
}

static AVDictionaryEntry* get_date_tag(AVDictionary *m, const char *tag)
{
    AVDictionaryEntry *t;
    if ((t = av_dict_get(m, tag, NULL, AV_DICT_MATCH_CASE)) &&
        strlen(t->value) == 4 && is_number(t->value))
        return t;
    return NULL;
}

static void merge_date(AVDictionary **m)
{
    AVDictionaryEntry *t;
    char date[17] = {0};      // YYYY-MM-DD hh:mm

    if (!(t = get_date_tag(*m, "TYER")) &&
        !(t = get_date_tag(*m, "TYE")))
        return;
    av_strlcpy(date, t->value, 5);
    av_dict_set(m, "TYER", NULL, 0);
    av_dict_set(m, "TYE",  NULL, 0);

    if (!(t = get_date_tag(*m, "TDAT")) &&
        !(t = get_date_tag(*m, "TDA")))
        goto finish;
    snprintf(date + 4, sizeof(date) - 4, "-%.2s-%.2s", t->value + 2, t->value);
    av_dict_set(m, "TDAT", NULL, 0);
    av_dict_set(m, "TDA",  NULL, 0);

    if (!(t = get_date_tag(*m, "TIME")) &&
        !(t = get_date_tag(*m, "TIM")))
        goto finish;
    snprintf(date + 10, sizeof(date) - 10, " %.2s:%.2s", t->value, t->value + 2);
    av_dict_set(m, "TIME", NULL, 0);
    av_dict_set(m, "TIM",  NULL, 0);

finish:
    if (date[0])
        av_dict_set(m, "date", date, 0);
}

/**
 * Get the corresponding function to parse a certain tag type or free the parsed data.
 * @param isv34 Determines if v2.2 or v2.3/4 strings are used
 * @param read Determines if the function to read or to free data is returned
 * @return If read is non-zero, a pointer to the parse function is returned. If read is zero a pointer to the free function is returned. If no function for the tag could be found, NULL is returned.
 */
static void *get_extra_meta_func(const char *tag, int isv34, int read)
{
#define funcs ff_id3v2_extra_meta_funcs
    int i = 0;
    while (funcs[i].tag3) {
        if (!memcmp(tag,
                   (isv34 ? funcs[i].tag4 : funcs[i].tag3),
                   (isv34 ? 4 : 3)))
            return (read ? funcs[i].read : funcs[i].free);
        i++;
    }
    return NULL;
#undef funcs
}

static void ff_id3v2_parse(AVFormatContext *s, int len, uint8_t version, uint8_t flags, ID3v2ExtraMeta **extra_meta)
{
    int isv34, unsync;
    unsigned tlen;
    char tag[5];
    int64_t next, end = avio_tell(s->pb) + len;
    int taghdrlen;
    const char *reason = NULL;
    AVIOContext pb;
    AVIOContext *pbx;
    unsigned char *buffer = NULL;
    int buffer_size = 0;
    void (*extra_func)(AVFormatContext*, AVIOContext*, int, char*, ID3v2ExtraMeta**) = NULL;

    switch (version) {
    case 2:
        if (flags & 0x40) {
            reason = "compression";
            goto error;
        }
        isv34 = 0;
        taghdrlen = 6;
        break;

    case 3:
    case 4:
        isv34 = 1;
        taghdrlen = 10;
        break;

    default:
        reason = "version";
        goto error;
    }

    unsync = flags & 0x80;

    if (isv34 && flags & 0x40) /* Extended header present, just skip over it */
        avio_skip(s->pb, get_size(s->pb, 4));

    while (len >= taghdrlen) {
        unsigned int tflags = 0;
        int tunsync = 0;

        if (isv34) {
            avio_read(s->pb, tag, 4);
            tag[4] = 0;
            if(version==3){
                tlen = avio_rb32(s->pb);
            }else
                tlen = get_size(s->pb, 4);
            tflags = avio_rb16(s->pb);
            tunsync = tflags & ID3v2_FLAG_UNSYNCH;
        } else {
            avio_read(s->pb, tag, 3);
            tag[3] = 0;
            tlen = avio_rb24(s->pb);
        }
        if (tlen > (1<<28) || !tlen)
            break;
        len -= taghdrlen + tlen;

        if (len < 0)
            break;

        next = avio_tell(s->pb) + tlen;

        if (tflags & ID3v2_FLAG_DATALEN) {
            if (tlen < 4)
                break;
            avio_rb32(s->pb);
            tlen -= 4;
        }

        if (tflags & (ID3v2_FLAG_ENCRYPTION | ID3v2_FLAG_COMPRESSION)) {
            av_log(s, AV_LOG_WARNING, "Skipping encrypted/compressed ID3v2 frame %s.\n", tag);
            avio_skip(s->pb, tlen);
        /* check for text tag or supported special meta tag */
        } else if (tag[0] == 'T' || (extra_meta && (extra_func = get_extra_meta_func(tag, isv34, 1)))) {
            if (unsync || tunsync) {
                int i, j;
                av_fast_malloc(&buffer, &buffer_size, tlen);
                if (!buffer) {
                    av_log(s, AV_LOG_ERROR, "Failed to alloc %d bytes\n", tlen);
                    goto seek;
                }
                for (i = 0, j = 0; i < tlen; i++, j++) {
                    buffer[j] = avio_r8(s->pb);
                    if (j > 0 && !buffer[j] && buffer[j - 1] == 0xff) {
                        /* Unsynchronised byte, skip it */
                        j--;
                    }
                }
                ffio_init_context(&pb, buffer, j, 0, NULL, NULL, NULL, NULL);
                tlen = j;
                pbx = &pb; // read from sync buffer
            } else {
                pbx = s->pb; // read straight from input
            }
            if (tag[0] == 'T')
                /* parse text tag */
                read_ttag(s, pbx, tlen, tag);
            else
                /* parse special meta tag */
                extra_func(s, pbx, tlen, tag, extra_meta);
        }
        else if (!tag[0]) {
            if (tag[1])
                av_log(s, AV_LOG_WARNING, "invalid frame id, assuming padding");
            avio_skip(s->pb, tlen);
            break;
        }
        /* Skip to end of tag */
seek:
        avio_seek(s->pb, next, SEEK_SET);
    }

    if (version == 4 && flags & 0x10) /* Footer preset, always 10 bytes, skip over it */
        end += 10;

  error:
    if (reason)
        av_log(s, AV_LOG_INFO, "ID3v2.%d tag skipped, cannot handle %s\n", version, reason);
    avio_seek(s->pb, end, SEEK_SET);
    av_free(buffer);
    return;
}

void ff_id3v2_read_all(AVFormatContext *s, const char *magic, ID3v2ExtraMeta **extra_meta)
{
    int len, ret;
    uint8_t buf[ID3v2_HEADER_SIZE];
    int     found_header;
    int64_t off;

    do {
        /* save the current offset in case there's nothing to read/skip */
        off = avio_tell(s->pb);
        ret = avio_read(s->pb, buf, ID3v2_HEADER_SIZE);
        if (ret != ID3v2_HEADER_SIZE)
            break;
        found_header = ff_id3v2_match(buf, magic);
        if (found_header) {
            /* parse ID3v2 header */
            len = ((buf[6] & 0x7f) << 21) |
                  ((buf[7] & 0x7f) << 14) |
                  ((buf[8] & 0x7f) << 7) |
                   (buf[9] & 0x7f);
            ff_id3v2_parse(s, len, buf[3], buf[5], extra_meta);
        } else {
            avio_seek(s->pb, off, SEEK_SET);
        }
    } while (found_header);
    ff_metadata_conv(&s->metadata, NULL, ff_id3v2_34_metadata_conv);
    ff_metadata_conv(&s->metadata, NULL, ff_id3v2_2_metadata_conv);
    ff_metadata_conv(&s->metadata, NULL, ff_id3v2_4_metadata_conv);
    merge_date(&s->metadata);
}

void ff_id3v2_read(AVFormatContext *s, const char *magic)
{
    ff_id3v2_read_all(s, magic, NULL);
}

void ff_id3v2_free_extra_meta(ID3v2ExtraMeta **extra_meta)
{
    ID3v2ExtraMeta *current = *extra_meta, *next;
    void (*free_func)(ID3v2ExtraMeta*);

    while (current) {
        if ((free_func = get_extra_meta_func(current->tag, 1, 0)))
            free_func(current->data);
        next = current->next;
        av_freep(&current);
        current = next;
    }
}

const struct ID3v2EMFunc ff_id3v2_extra_meta_funcs[] = {
    { "GEO", "GEOB", read_geobtag, free_geobtag },
    { NULL }
};

const AVMetadataConv ff_id3v2_34_metadata_conv[] = {
    { "TALB", "album"},
    { "TCOM", "composer"},
    { "TCON", "genre"},
    { "TCOP", "copyright"},
    { "TENC", "encoded_by"},
    { "TIT2", "title"},
    { "TLAN", "language"},
    { "TPE1", "artist"},
    { "TPE2", "album_artist"},
    { "TPE3", "performer"},
    { "TPOS", "disc"},
    { "TPUB", "publisher"},
    { "TRCK", "track"},
    { "TSSE", "encoder"},
    { 0 }
};

const AVMetadataConv ff_id3v2_4_metadata_conv[] = {
    { "TDRL", "date"},
    { "TDRC", "date"},
    { "TDEN", "creation_time"},
    { "TSOA", "album-sort"},
    { "TSOP", "artist-sort"},
    { "TSOT", "title-sort"},
    { 0 }
};

const AVMetadataConv ff_id3v2_2_metadata_conv[] = {
    { "TAL",  "album"},
    { "TCO",  "genre"},
    { "TT2",  "title"},
    { "TEN",  "encoded_by"},
    { "TP1",  "artist"},
    { "TP2",  "album_artist"},
    { "TP3",  "performer"},
    { "TRK",  "track"},
    { 0 }
};


const char ff_id3v2_tags[][4] = {
   "TALB", "TBPM", "TCOM", "TCON", "TCOP", "TDLY", "TENC", "TEXT",
   "TFLT", "TIT1", "TIT2", "TIT3", "TKEY", "TLAN", "TLEN", "TMED",
   "TOAL", "TOFN", "TOLY", "TOPE", "TOWN", "TPE1", "TPE2", "TPE3",
   "TPE4", "TPOS", "TPUB", "TRCK", "TRSN", "TRSO", "TSRC", "TSSE",
   { 0 },
};

const char ff_id3v2_4_tags[][4] = {
   "TDEN", "TDOR", "TDRC", "TDRL", "TDTG", "TIPL", "TMCL", "TMOO",
   "TPRO", "TSOA", "TSOP", "TSOT", "TSST",
   { 0 },
};

const char ff_id3v2_3_tags[][4] = {
   "TDAT", "TIME", "TORY", "TRDA", "TSIZ", "TYER",
   { 0 },
};
