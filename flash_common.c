/* flash_common.c */
#include <winsock2.h>
#include <stdio.h>
#include <string.h>

#include "flash_common.h"

uint16_t flash_ip_checksum(const void *buf, int len)
{
    const uint8_t *p = (const uint8_t *)buf;
    uint32_t sum = 0;
    int i = 0;

    if (!buf || len <= 0)
        return 0;

    /* 以网络序（大端）解释每 16 位字，结果与主机字节序无关 */
    for (; i + 1 < len; i += 2)
        sum += ((uint32_t)p[i] << 8) | (uint32_t)p[i + 1];
    if (i < len)
        sum += (uint32_t)p[i] << 8;

    while (sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);

    return (uint16_t)(~sum & 0xFFFFu);
}

uint32_t flash_crc32(const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    uint32_t crc = 0xFFFFFFFFu;
    size_t i;

    for (i = 0; i < len; ++i) {
        int k;
        crc ^= (uint32_t)p[i];
        for (k = 0; k < 8; ++k)
            crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
    }
    return crc ^ 0xFFFFFFFFu;
}

void flash_header_hton(FlashHeader *h)
{
    uint32_t v[FLASH_HDR_U32_COUNT];
    int i;
    memcpy(v, h, sizeof(v));
    for (i = 0; i < FLASH_HDR_U32_COUNT; ++i)
        v[i] = htonl(v[i]);
    memcpy(h, v, sizeof(v));
}

void flash_header_ntoh(FlashHeader *h)
{
    uint32_t v[FLASH_HDR_U32_COUNT];
    int i;
    memcpy(v, h, sizeof(v));
    for (i = 0; i < FLASH_HDR_U32_COUNT; ++i)
        v[i] = ntohl(v[i]);
    memcpy(h, v, sizeof(v));
}

int flash_parse_ipv4(const char *s, uint8_t out[4])
{
    unsigned v[4];
    int i;
    const char *p = s;

    if (!s || !out)
        return 0;
    for (i = 0; i < 4; ++i) {
        unsigned val = 0;
        int digits = 0;
        while (*p >= '0' && *p <= '9') {
            val = val * 10u + (unsigned)(*p - '0');
            if (val > 255u)
                return 0;
            ++p;
            ++digits;
        }
        if (digits == 0)
            return 0;
        v[i] = val;
        if (i < 3) {
            if (*p != '.')
                return 0;
            ++p;
        }
    }
    if (*p != '\0')
        return 0;
    for (i = 0; i < 4; ++i)
        out[i] = (uint8_t)v[i];
    return 1;
}

void flash_ip_to_str(const uint8_t ip[4], char *out, size_t cap)
{
    if (cap == 0)
        return;
    snprintf(out, cap, "%u.%u.%u.%u",
             (unsigned)ip[0], (unsigned)ip[1],
             (unsigned)ip[2], (unsigned)ip[3]);
}

/* ===================== 接收端重组核心 ===================== */
#include <stdlib.h>
#include <time.h>

Session  *g_sessions = NULL;
int       g_verbose = 0;
char      g_outdir[1024] = ".";
uint8_t   g_target[4];
int       g_target_set = 0;
time_t    g_last_packet;

Session *session_get(uint32_t id, int create)
{
    Session *s;
    for (s = g_sessions; s; s = s->next)
        if (s->id == id)
            return s;
    if (!create)
        return NULL;
    s = (Session *)calloc(1, sizeof(Session));
    if (!s)
        return NULL;
    s->id = id;
    s->next = g_sessions;
    g_sessions = s;
    return s;
}

void session_free(Session *s)
{
    uint32_t i;
    if (!s)
        return;
    if (s->frags) {
        for (i = 0; i < s->cap; ++i)
            free(s->frags[i].data);
        free(s->frags);
    }
    free(s);
}

int ensure_cap(Session *s, uint32_t idx)
{
    uint32_t need, newcap;
    Fragment *nf;

    if (idx > FLASH_MAX_FRAGMENTS)
        return 0;
    need = idx + 1;
    if (need <= s->cap)
        return 1;
    newcap = s->cap ? s->cap : 64;
    while (newcap < need) {
        if (newcap > 0x40000000u) {
            newcap = need;
            break;
        }
        newcap *= 2;
    }
    nf = (Fragment *)realloc(s->frags, (size_t)newcap * sizeof(Fragment));
    if (!nf)
        return 0;
    memset(nf + s->cap, 0, (size_t)(newcap - s->cap) * sizeof(Fragment));
    s->frags = nf;
    s->cap = newcap;
    return 1;
}

uint32_t count_received(const Session *s)
{
    uint32_t c = 0, i, upto = s->total;
    if (upto >= s->cap)
        upto = s->cap ? s->cap - 1 : 0;
    for (i = 1; i <= upto; ++i)
        if (s->frags[i].data)
            ++c;
    return c;
}

void sanitize_name(const char *in, char *out, size_t cap)
{
    const char *base = in;
    const char *p;
    size_t j = 0;

    for (p = in; *p; ++p)
        if (*p == '\\' || *p == '/')
            base = p + 1;
    for (p = base; *p && j + 1 < cap; ++p) {
        unsigned char c = (unsigned char)*p;
        if (c < 32 || c == '\\' || c == '/' || c == ':' || c == '*' ||
            c == '?' || c == '"' || c == '<' || c == '>' || c == '|')
            c = '_';
        out[j++] = (char)c;
    }
    out[j] = '\0';
    if (j == 0 || (j == 1 && out[0] == '.') ||
        (j == 2 && out[0] == '.' && out[1] == '.'))
        memcpy(out, "received.bin", sizeof("received.bin"));
}

void unique_path(char *path, size_t cap)
{
    char base[2048];
    FILE *f;
    int n;

    f = fopen(path, "rb");
    if (!f)
        return;
    fclose(f);
    snprintf(base, sizeof(base), "%s", path);
    for (n = 1; n < 10000; ++n) {
        snprintf(path, cap, "%s.%d", base, n);
        f = fopen(path, "rb");
        if (!f)
            return;
        fclose(f);
    }
}

void write_zeros(FILE *f, uint64_t n)
{
    static const uint8_t zeros[4096] = { 0 };
    while (n) {
        size_t k = (n > sizeof(zeros)) ? sizeof(zeros) : (size_t)n;
        fwrite(zeros, 1, k, f);
        n -= k;
    }
}

/* 把会话落盘。partial=1 时对缺失分片补零，文件名加 .partial 后缀。 */
void write_session_file(Session *s, int partial)
{
    char name[FLASH_MAX_NAME + 1];
    char path[2048];
    FILE *f;
    uint64_t remaining;
    uint32_t i, limit, chunk;
    uint64_t unknown = ~(uint64_t)0;

    sanitize_name(s->has_meta ? s->name : "received.bin", name, sizeof(name));
    if (partial)
        snprintf(path, sizeof(path), "%s\\%s.partial", g_outdir, name);
    else {
        snprintf(path, sizeof(path), "%s\\%s", g_outdir, name);
        unique_path(path, sizeof(path));
    }

    f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "[错误] 无法创建文件 %s\n", path);
        return;
    }

    chunk = s->chunk_size ? s->chunk_size : FLASH_DEFAULT_CHUNK;
    limit = s->total ? s->total : (s->cap ? s->cap - 1 : 0);
    remaining = s->file_size ? s->file_size : unknown;

    for (i = 1; i <= limit; ++i) {
        uint64_t expect;
        uint32_t todo, n = 0;

        if (remaining != unknown && remaining == 0)
            break;
        expect = (remaining == unknown) ? chunk
                 : (remaining < chunk ? remaining : chunk);
        if (expect == 0)
            break;
        todo = (uint32_t)expect;

        if (i < s->cap && s->frags[i].data) {
            n = s->frags[i].len < todo ? s->frags[i].len : todo;
            if (n)
                fwrite(s->frags[i].data, 1, n, f);
        }
        if (n < todo)
            write_zeros(f, (uint64_t)(todo - n));   /* 缺失分片补零 */

        if (remaining != unknown)
            remaining -= todo;
    }
    fclose(f);

    if (partial)
        printf("[超时] 会话=0x%08X 只收到 %u/%u 分片，写出不完整文件 -> %s\n",
               s->id, s->received, s->total, path);
    else
        printf("[完成] 会话=0x%08X 文件 \"%s\" 已还原 %u/%u 分片，"
               "%llu 字节 -> %s\n",
               s->id, s->name, s->received, s->total,
               (unsigned long long)s->file_size, path);
    fflush(stdout);
}

void check_complete(Session *s)
{
    if (s->complete || s->total == 0)
        return;
    if (s->received < s->total)
        return;
    if (!s->has_meta) {
        snprintf(s->name, sizeof(s->name), "flash_0x%08X.bin", s->id);
        s->has_meta = 1;
        printf("[提示] 会话=0x%08X 始终未收到文件名报文，使用默认名 \"%s\"\n",
               s->id, s->name);
        fflush(stdout);
    }
    s->complete = 1;
    write_session_file(s, 0);
}

void flush_partials(void)
{
    Session **pp = &g_sessions;
    while (*pp) {
        Session *s = *pp;
        if (!s->complete && (s->received > 0 || s->has_meta)) {
            write_session_file(s, 1);
            *pp = s->next;
            session_free(s);
        } else {
            pp = &s->next;
        }
    }
}

void handle_packet(const uint8_t *buf, int len)
{
    const IPv4Header *ip;
    const ICMPEchoHeader *ic;
    FlashHeader h;
    const uint8_t *body;
    Session *s;
    size_t avail;
    int ihl, ip_total, icmp_len, frag;
    char srcstr[16], dststr[16];

    if (len < (int)sizeof(IPv4Header))
        return;
    ip = (const IPv4Header *)buf;
    if ((ip->ver_ihl >> 4) != 4)
        return;
    ihl = (ip->ver_ihl & 0x0F) * 4;
    if (ihl < (int)sizeof(IPv4Header) || ip->protocol != 1)
        return;

    frag = ntohs(ip->frag_off);
    if ((frag & 0x1FFF) || (frag & 0x2000))
        return;   /* IP 分片，跳过 */
    ip_total = ntohs(ip->total_len);
    if (ip_total < ihl + (int)sizeof(ICMPEchoHeader) || ip_total > len)
        return;

    /* 核心过滤：若指定了目的 IP，则只收目的地址等于它的报文；否则(抓包端省略目标)不过滤 */
    if (g_target_set && memcmp(ip->dst, g_target, 4) != 0)
        return;

    ic = (const ICMPEchoHeader *)(buf + ihl);
    if (ic->type != 8 && ic->type != 0)   /* Echo Request / Reply */
        return;
    icmp_len = ip_total - ihl;
    if (g_verbose) {
        flash_ip_to_str(ip->src, srcstr, sizeof(srcstr));
        flash_ip_to_str(ip->dst, dststr, sizeof(dststr));
        printf("[监听] ICMP type=%u seq=%u 载荷=%d B 源=%s -> 目的=%s\n",
               (unsigned)ic->type, (unsigned)ntohs(ic->seq),
               icmp_len - (int)sizeof(ICMPEchoHeader), srcstr, dststr);
        fflush(stdout);
    }
    if (ic->code != 0)
        return;
    if (icmp_len < (int)(sizeof(ICMPEchoHeader) + sizeof(FlashHeader)))
        return;

    memcpy(&h, buf + ihl + sizeof(ICMPEchoHeader), sizeof(h));
    flash_header_ntoh(&h);
    if (h.magic != FLASH_MAGIC || h.version != FLASH_VERSION)
        return;
    if (h.total > FLASH_MAX_FRAGMENTS || h.index > FLASH_MAX_FRAGMENTS)
        return;

    avail = (size_t)icmp_len - sizeof(ICMPEchoHeader) - sizeof(FlashHeader);
    if ((uint64_t)h.length > avail)
        return;
    body = buf + ihl + sizeof(ICMPEchoHeader) + sizeof(FlashHeader);
    if (flash_crc32(body, h.length) != h.crc32) {
        printf("[警告] 会话=0x%08X 分片 %u CRC 校验失败，已丢弃\n",
               h.session, h.index);
        fflush(stdout);
        return;
    }

    g_last_packet = time(NULL);
    flash_ip_to_str(ip->src, srcstr, sizeof(srcstr));
    flash_ip_to_str(ip->dst, dststr, sizeof(dststr));

    /* ---------- 元信息报文（编号 0，携带文件名） ---------- */
    if (h.type == FLASH_TYPE_META) {
        if (h.index != 0 || h.name_len > FLASH_MAX_NAME || h.name_len != h.length)
            return;
        s = session_get(h.session, 1);
        if (!s || s->complete)
            return;
        if (!s->has_meta) {
            memcpy(s->name, body, h.name_len);
            s->name[h.name_len] = '\0';
            s->has_meta = 1;
            s->total = h.total;
            s->chunk_size = h.chunk_size;
            s->file_size = ((uint64_t)h.file_size_hi << 32) | h.file_size_lo;
            (void)ensure_cap(s, s->total);
            s->received = count_received(s);
            printf("[元信息] 会话=0x%08X 文件名=\"%s\" 共 %u 片 大小=%llu B "
                   "分片大小=%u B 目的=%s\n",
                   h.session, s->name, s->total,
                   (unsigned long long)s->file_size, s->chunk_size, dststr);
            fflush(stdout);
        }
        check_complete(s);
        return;
    }

    if (h.type != FLASH_TYPE_DATA || h.index == 0)
        return;

    /* ---------- 数据分片 ---------- */
    s = session_get(h.session, 1);
    if (!s || s->complete)
        return;

    /* 元信息报文可能丢失/后到：先从数据报文里补齐总数，保证进度可显示 */
    if (s->total == 0 && h.total > 0) {
        s->total = h.total;
        s->chunk_size = h.chunk_size;
        s->file_size = ((uint64_t)h.file_size_hi << 32) | h.file_size_lo;
    }
    if (h.index > s->total)
        return;
    if (!ensure_cap(s, h.index))
        return;
    if (s->frags[h.index].data) {
        if (g_verbose)
            printf("[重复] 会话=0x%08X 分片 %u/%u 已收到，忽略\n",
                   h.session, h.index, s->total);
        return;
    }

    s->frags[h.index].data = (uint8_t *)malloc(h.length ? h.length : 1);
    if (!s->frags[h.index].data)
        return;
    if (h.length)
        memcpy(s->frags[h.index].data, body, h.length);
    s->frags[h.index].len = h.length;
    ++s->received;

    if (s->total) {
        double pct = 100.0 * (double)s->received / (double)s->total;
        printf("[接收] 会话=0x%08X 分片 %u/%u  %u B  源=%s -> 目的=%s  "
               "已收到 %u/%u (%.1f%%)\n",
               h.session, h.index, s->total, h.length, srcstr, dststr,
               s->received, s->total, pct);
    } else {
        printf("[接收] 会话=0x%08X 分片 %u/?  %u B  源=%s -> 目的=%s  "
               "已收到 %u 片（总数未知，等待元信息报文）\n",
               h.session, h.index, h.length, srcstr, dststr, s->received);
    }
    fflush(stdout);

    check_complete(s);
}
