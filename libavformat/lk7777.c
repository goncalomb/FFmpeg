#include "avformat.h"
#include "libavutil/aes.h"
#include "libavutil/opt.h"

#define LK7777_MAGIC_0 0x74
#define LK7777_MAGIC_1 0x47
#define LK7777_MAGIC_2 0x74

// TODO: some logs should probably be removed to avoid excessive av_log calls
// TODO: demuxer should not crash with random input data / lost packets (test!)
// TODO: address sync issues (pkt->pts pkt->dts ?)

// add decryption key here, this will be a command line option in the future
const uint8_t key[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

static void lk7777_decrypt_packet(AVFormatContext *s, struct AVAES *aes_decrypt, AVPacket *pkt) {
    int sz = 1024;

    if (pkt->size < 1024) {
        sz = pkt->size;
    }

    // TODO: there are cases where video packets can have less than 1024 bytes
    //       and are not multiple of the cipher block size (16)
    //       e.g. lower bitrate while transmitting static imagery
    //       it's not known what to do in this case
    //       should we decrypt only to the nearest block size?
    //       is this right? i don't see any decoding artifacts on the output
    //       more research may be needed (h264)

    if (sz % 16 != 0) {
        // TODO: what to do?
        av_log(s, AV_LOG_DEBUG, "packet size (%d) is not multiple of cipher block size (16)\n", sz);
    }

    av_aes_crypt(aes_decrypt, pkt->data, pkt->data, sz >> 4, NULL, 1);
}

typedef struct LK7777Context {
    struct AVAES *aes_decrypt;
} LK7777Context;

static int lk7777_read_probe(const AVProbeData *p)
{
    av_log(NULL, AV_LOG_TRACE, "lk7777_read_probe %d %s\n", p->buf_size, p->filename);

    // TODO: probe should be improved to increase score by reading more packets
    if (
        p->buf_size >= 3
        && p->buf[0] == LK7777_MAGIC_0
        && p->buf[1] == LK7777_MAGIC_1
        && p->buf[2] == LK7777_MAGIC_2
    ) {
        return AVPROBE_SCORE_MAX / 3 - 1;
    }
    return 0;
}

static int lk7777_read_header(AVFormatContext *s)
{
    LK7777Context *c = s->priv_data;
    int ret;
    AVStream *stv;
    AVStream *sta;

    av_log(s, AV_LOG_TRACE, "lk7777_read_header\n");

    // create audio stream (index 0)
    stv = avformat_new_stream(s, NULL);
    if (!stv) {
        return AVERROR(ENOMEM);
    }
    stv->codecpar->codec_type = AVMEDIA_TYPE_VIDEO;
    stv->codecpar->codec_id = AV_CODEC_ID_H264;
    stv->need_parsing = AVSTREAM_PARSE_FULL_RAW;

    // create audio stream (index 1)
    sta = avformat_new_stream(s, NULL);
    if (!sta) {
        return AVERROR(ENOMEM);
    }
    sta->codecpar->codec_type = AVMEDIA_TYPE_AUDIO;
    sta->codecpar->codec_id = AV_CODEC_ID_MP2;
    sta->need_parsing = AVSTREAM_PARSE_FULL_RAW;

    // init decrypt
    c->aes_decrypt = av_aes_alloc();
    if (!c->aes_decrypt) {
        return AVERROR(ENOMEM);
    }
    ret = av_aes_init(c->aes_decrypt, key, 128, 1);
    if (ret < 0) {
        return ret;
    }

    return 0;
}

static int lk7777_read_packet(AVFormatContext *s, AVPacket *pkt)
{
    LK7777Context *c = s->priv_data;
    int t, sz, ct, ret;

    // av_log(s, AV_LOG_TRACE, "lk7777_read_packet\n");

    if (avio_r8(s->pb) != LK7777_MAGIC_0) return AVERROR_BUG; // TODO: this should not be AVERROR_BUG
    if (avio_r8(s->pb) != LK7777_MAGIC_1) return AVERROR_BUG;
    if (avio_r8(s->pb) != LK7777_MAGIC_2) return AVERROR_BUG;

    t = avio_r8(s->pb); // packet type
    sz = avio_rb32(s->pb) - 4; // packet size
    ct = avio_rb32(s->pb);

    switch (t) {
        case 0x00:
            av_log(s, AV_LOG_TRACE, "video data plain %d %d\n", sz, ct);
            ret = av_get_packet(s->pb, pkt, sz);
            pkt->stream_index = 0;
            break;

        case 0x80:
            av_log(s, AV_LOG_TRACE, "video data encrypted %d %d\n", sz, ct);
            ret = av_get_packet(s->pb, pkt, sz);
            pkt->stream_index = 0;
            lk7777_decrypt_packet(s, c->aes_decrypt, pkt);
            break;

        case 0x81:
            av_log(s, AV_LOG_TRACE, "audio data encrypted %d %d\n", sz, ct);
            ret = av_get_packet(s->pb, pkt, sz);
            pkt->stream_index = 1;
            lk7777_decrypt_packet(s, c->aes_decrypt, pkt);
            break;

        default:
            av_log(s, AV_LOG_DEBUG, "unknown packet 0x%x\n", t);
        case 0x82:
            av_log(s, AV_LOG_DEBUG, "unknown %d %d\n", sz, ct);
            ret = avio_skip(s->pb, sz); // just skip these bytes
            break;
    }

    return ret;
}

static int lk7777_read_close(AVFormatContext *s)
{
    LK7777Context *c = s->priv_data;

    av_log(s, AV_LOG_TRACE, "lk7777_read_close\n");

    // free decrypt
    av_free(c->aes_decrypt);

    return 0;
}

static int lk7777_read_seek(AVFormatContext *s, int stream_index, int64_t timestamp, int flags)
{
    // TODO: seeking is not possible... is it? maybe if input is a udp capture
    av_log(s, AV_LOG_TRACE, "lk7777_read_seek\n");
    return 0;
}

static const AVOption lk7777_options[] = {
    // TODO: enabling options right now will result in segmentation fault
    //       it's something related to aes_decrypt on the context (priv_data)
    //       i think options are saved on priv_data automatically
    // TODO: add decryption key to options
    {NULL}
};

static const AVClass lk7777_class = {
    .class_name = "lk7777 demuxer",
    .item_name  = av_default_item_name,
    .option     = lk7777_options,
    .version    = LIBAVUTIL_VERSION_INT,
};

AVInputFormat ff_lk7777_demuxer = {
    .name           = "lk7777",
    .long_name      = NULL_IF_CONFIG_SMALL("LK 7777 Streaming"),
    // .priv_class     = &lk7777_class, // TODO: enable options
    .priv_data_size = sizeof(LK7777Context),
    .flags          = AVFMT_NOGENSEARCH | AVFMT_TS_DISCONT, // TODO: what do these flags do? these are probably not good
    .read_probe     = lk7777_read_probe,
    .read_header    = lk7777_read_header,
    .read_packet    = lk7777_read_packet,
    .read_close     = lk7777_read_close,
    // .read_seek      = lk7777_read_seek, // TODO: how does seeking work?
};
