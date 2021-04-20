#include "avformat.h"
#include "libavutil/opt.h"

// initial skeleton based on hls.c

typedef struct LK7777Context {
    int nop;
} LK7777Context;

static int lk7777_read_probe(const AVProbeData *p)
{
    av_log(NULL, AV_LOG_TRACE, "lk7777_read_probe %d %s\n", p->buf_size, p->filename);
    return 0;
}

static int lk7777_read_header(AVFormatContext *s)
{
    av_log(s, AV_LOG_TRACE, "lk7777_read_header\n");
    return 0;
}

static int lk7777_read_packet(AVFormatContext *s, AVPacket *pkt)
{
    av_log(s, AV_LOG_TRACE, "lk7777_read_packet\n");
    return AVERROR_EOF;
}

static int lk7777_read_close(AVFormatContext *s)
{
    av_log(s, AV_LOG_TRACE, "lk7777_read_close\n");
    return 0;
}

static int lk7777_read_seek(AVFormatContext *s, int stream_index, int64_t timestamp, int flags)
{
    av_log(s, AV_LOG_TRACE, "lk7777_read_seek\n");
    return 0;
}

static const AVOption lk7777_options[] = {
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
    .priv_class     = &lk7777_class,
    .priv_data_size = sizeof(LK7777Context),
    .flags          = AVFMT_NOGENSEARCH | AVFMT_TS_DISCONT,
    .read_probe     = lk7777_read_probe,
    .read_header    = lk7777_read_header,
    .read_packet    = lk7777_read_packet,
    .read_close     = lk7777_read_close,
    .read_seek      = lk7777_read_seek,
};
