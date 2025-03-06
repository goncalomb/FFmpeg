#include "lk7777.h"

#ifndef UDP_MAX_PKT_SIZE
#include "udp.c"
#endif

typedef struct LKPlistItem {
    struct LKPlist *list;
    struct LKPlistItem *prev;
    struct LKPlistItem *next;
    // user fields
    int tail;
    int size;
    char buf[LK7777_PLIST_BUF_SIZE];
} LKPlistItem;

typedef struct LKPlist {
    int size;
    struct LKPlistItem *first;
    struct LKPlistItem data[LK7777_PLIST_SIZE];
} LKPlist;

typedef struct UDPContextLK {
    UDPContext base;
    LKPlist plist; // packet queue
    int psend; // packets to send
    int bsent; // bytes sent
} UDPContextLK;

static int lk_plist_full(LKPlist *lst)
{
    return lst->size >= LK7777_PLIST_SIZE;
}

static LKPlistItem *lk_plist_empty_item(LKPlist *lst)
{
    for (int i = 0; i < LK7777_PLIST_SIZE; i++) {
        if (!lst->data[i].list) {
            return &lst->data[i];
        }
    }
    return NULL;
}

static void lk_plist_insert(LKPlist *lst, LKPlistItem *itm)
{
    itm->list = lst;
    itm->prev = NULL;
    itm->next = lst->first;
    if (lst->first) {
        lst->first->prev = itm;
    }
    lst->size++;
    lst->first = itm;
}

static void lk_plist_remove(LKPlistItem *itm)
{
    if (itm->next) {
        itm->next->prev = itm->prev;
    }
    if (itm->prev) {
        itm->prev->next = itm->next;
    } else {
        itm->list->first = itm->next;
    }
    itm->list->size--;
    itm->list = NULL;
}

static int lk_plist_move(LKPlistItem *itm)
{
    if (itm->next) {
        LKPlistItem *oth = itm->next;
        if (itm->prev) {
            itm->prev->next = oth;
        } else {
            itm->list->first = oth;
        }
        if (oth->next) {
            oth->next->prev = itm;
        }
        oth->prev = itm->prev;
        itm->prev = itm->next;
        itm->next = oth->next;
        oth->next = itm;
        return 1;
    }
    return 0;
}

static void lk_p_log(void* avcl, LKPlist *lst, int level) {
    LKPlistItem *itm = lst->first;
    if (level > av_log_get_level()) return; // return early
    av_log(avcl, level, "size=%d", lst->size);
    while (itm) {
        if (itm->tail < 0) {
            av_log(avcl, level, "|DATA:%d,%d", itm->size, itm->tail);
        } else if (itm->tail) {
            av_log(avcl, level, "|FRAG:%d,%d", itm->size, itm->tail);
        } else {
            av_log(avcl, level, "|FULL:%d,%d", itm->size, itm->tail);
        }
        itm = itm->next;
    }
    av_log(avcl, level, "\n");
}

static int udplk7777_open(URLContext *h, const char *uri, int flags)
{
    UDPContext *s = h->priv_data;
    int ret;

    s->circular_buffer_size = 0;
    ret = udp_open(h, uri, flags);
    if (s->circular_buffer_size) {
        // the base udp code has an internal circular buffer, see 'udp_read'
        // for our use we need direct reads (i.e. 'recvfrom') to get the full
        // udp messages, otherwise we wouldn't know when a packet ends the
        // next one starts
        // if the circular buffer is enabled, we'll disable our heuristics
        av_log(h, AV_LOG_WARNING, "'fifo_size' must be set to 0 (current: %d), remove the 'fifo_size' option\n", s->circular_buffer_size / 188);
    }

    return ret;
}

static int udplk7777_read(URLContext *h, uint8_t *buf, int size)
{
    UDPContextLK *s = h->priv_data;
    int ret = 0;

    if (s->base.circular_buffer_size) {
        // disable our heuristics, act as normal udp
        return udp_read(h, buf, size);
    }

    // read new packet into the queue
    if (!s->psend && !lk_plist_full(&s->plist)) {
        LKPlistItem *itm = lk_plist_empty_item(&s->plist);
        itm->size = udp_read(h, itm->buf, LK7777_PLIST_BUF_SIZE);
        if (itm->size < 0) return itm->size; // error
        if (itm->size) {
            lk_plist_insert(&s->plist, itm);

            // identify packet
            // tail:
            //   -1: magic bytes (header) not found, continuation packet?, raw
            //    0: header found, full packet
            //   >0: header found, fragmented packet, expect extra raw packets
            itm->tail = -1;
            if (
                itm->size >= 12
                && itm->buf[0] == LK7777_MAGIC_0
                && itm->buf[1] == LK7777_MAGIC_1
                && itm->buf[2] == LK7777_MAGIC_2
            ) {
                int sz = ((u_char) itm->buf[4] << 24) | ((u_char) itm->buf[5] << 16) | ((u_char) itm->buf[6] << 8) | (u_char) itm->buf[7];
                // int ct = ((u_char) itm->buf[8] << 24) | ((u_char) itm->buf[9] << 16) | ((u_char) itm->buf[10] << 8) | (u_char) itm->buf[11];
                itm->tail = sz - 4 + 12 - itm->size;
            }

            // heuristics to try to move the new packet to the correct position
            if (itm->tail < 0) { // raw data (packet continuation)
                // heuristic: find fragmented packet that can accept this data
                // find suitable space on queue
                LKPlistItem *it = s->plist.first;
                LKPlistItem *fra, *res = NULL;
                int cont = 0;
                while (it) {
                    if (cont) {
                        if (it->tail < 0) {
                            cont -= it->size;
                            if (cont <= 0) { // already full
                                cont = 0;
                            }
                        } else if (cont >= itm->size) { // end of fragment, test if fits
                            cont = 0;
                            res = fra;
                            if (cont == itm->size) break; // exact match
                        }
                    } else if (it->tail > 0) {
                        fra = it;
                        cont = it->tail;
                    }
                    if (it->next == NULL && cont >= itm->size) { // end of queue, test if fits
                        res = fra;
                    }
                    it = it->next;
                }
                if (res) {
                    // found space for it, move to that position
                    // XXX: make function to insert at position (insert before)?
                    while (itm->next && itm->prev != res) {
                        lk_plist_move(itm);
                    }
                    // sort data packets by size (inside fragment)
                    while (itm->next && itm->next->tail < 0 && itm->next->size > itm->size) {
                        lk_plist_move(itm);
                    }
                } else {
                    // keep it at the start
                    while (itm->next && itm->next->tail == 0) { // move past full packets
                        lk_plist_move(itm);
                    }
                    // XXX: old heuristics
                    /*
                    while (itm->next && (
                        itm->next->tail > 0 // move past fragmented packets
                        || (itm->next->tail < 0 && itm->next->size > itm->size) // sort data packets by size
                    )) {
                        lk_plist_move(itm);
                    }
                    */
                }
            } else if (itm->tail) { // fragmented packet
                // heuristic: send to the back if next in queue is not a data packet
                while (itm->next && itm->next->tail == 0) { // move past full packets
                    lk_plist_move(itm);
                }
                // TODO: check if fragment actually fits with data packets at the start of the queue
                if (itm->next && itm->next->tail >= 0) {
                    while (itm->next) lk_plist_move(itm); // move to last
                }
            } else { // full packet
                // heuristic: send to the back every time
                while (itm->next) lk_plist_move(itm); // move to last
            }
        }
    }

    // heuristics to detect if any packets are ready be sent forward
    if (!s->psend) {
        int frag = 0; // fragment count (fragmented and data packets)
        int cont = 0; // continuation bytes
        LKPlistItem *itm = s->plist.first;
        while (itm) {
            if (itm->tail < 0) { // raw data (packet continuation)
                frag++;
                if (!cont) {
                    // data packet but not expected before fragmented start
                    break;
                }
                cont -= itm->size;
                if (cont < 0) {
                    // data packet too large, heuristics failed
                    // desync is inevitable
                    s->psend += frag;
                    lk_p_log(h, &s->plist, AV_LOG_DEBUG);
                    av_log(h, AV_LOG_WARNING, "unexpected data (bytes: %d), dumping %d packet(s)\n", itm->size, frag);
                    break;
                } else if (cont == 0) {
                    // fragmented packet is complete, mark to be sent
                    s->psend += frag;
                    break;
                } // else: incomplete, continue looking for extra data
            } else if (cont) {
                // next packet is not a data packet and the current
                // fragmented packet is not complete, break
                break;
            } else if (itm->tail) { // fragmented packet
                // continue checking to see if we have all the pieces
                // won't send any more packets before this one is complete
                frag++;
                cont = itm->tail;
            } else { // full packet
                // just mark to be sent
                s->psend++;
            }
            itm = itm->next;
        }

        if (!s->psend && lk_plist_full(&s->plist)) {
            // nothing to send and the queue is full, heuristics failed
            // or data is missing, desync is inevitable
            // send incomplete fragmented packet that is blocking the queue
            // or dump the entire queue
            s->psend = frag ? frag : s->plist.size;
            lk_p_log(h, &s->plist, AV_LOG_DEBUG);
            av_log(h, AV_LOG_WARNING, "full queue with missing data, dumping %d packet(s)\n", s->psend);
        }
    }

    // debug log
    if (s->plist.size > 1) {
        lk_p_log(h, &s->plist, AV_LOG_DEBUG);
    } else {
        lk_p_log(h, &s->plist, AV_LOG_TRACE);
    }

    // send packet (i.e. copy data to buf)
    if (s->psend) {
        LKPlistItem *itm = s->plist.first;
        ret = size < itm->size - s->bsent ? size : itm->size - s->bsent;
        memcpy(buf, itm->buf + s->bsent, ret);
        s->bsent += ret;
        if (s->bsent >= itm->size) {
            // full packet sent, remove it from queue
            lk_plist_remove(itm);
            s->psend--;
            s->bsent = 0;
        }
    }
    return ret;
}

const URLProtocol ff_udplk7777_protocol = {
    .name                = "udplk7777",
    .url_open            = udplk7777_open,
    .url_read            = udplk7777_read,
    .url_write           = udp_write,
    .url_close           = udp_close,
    .url_get_file_handle = udp_get_file_handle,
    .priv_data_size      = sizeof(UDPContextLK),
    .priv_data_class     = &udp_class,
    .flags               = URL_PROTOCOL_FLAG_NETWORK,
};
