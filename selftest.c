/*
 * selftest.c —— FlashCopy 回归自测
 * 直接调用 flash_common.c 中的真实接收逻辑（handle_packet / 重组 / 落盘），
 * 喂入「与 FlashSend 经 nping 发出的完全一致」的载荷（FlashHeader+body），
 * 验证：正常顺序、乱序+重复去重、元信息丢失+缺片补零、目的 IP 过滤。
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "flash_common.h"

static uint8_t g_src[4]  = { 10, 0, 0, 1 };
static uint8_t g_dst[4]  = { 192, 168, 1, 255 };

/* ============ FlashSend 现在生成的载荷（与 FlashSend.c 完全一致） ============ */
static size_t build_payload(uint8_t *buf, size_t cap,
                            uint32_t session, uint32_t type, uint32_t index,
                            uint32_t total, uint64_t file_size, uint32_t chunk_size,
                            const char *name, uint32_t name_len,
                            const uint8_t *data, uint32_t data_len)
{
    const uint8_t *body = (type == FLASH_TYPE_META) ? (const uint8_t *)name : data;
    uint32_t body_len = (type == FLASH_TYPE_META) ? name_len : data_len;
    size_t len = sizeof(FlashHeader) + body_len;
    FlashHeader h;

    if (len > cap) return 0;
    memset(&h, 0, sizeof(h));
    h.magic         = FLASH_MAGIC;
    h.version       = FLASH_VERSION;
    h.session        = session;
    h.type           = type;
    h.index          = index;
    h.total          = total;
    h.length         = body_len;
    h.file_size_hi   = (uint32_t)(file_size >> 32);
    h.file_size_lo   = (uint32_t)(file_size & 0xFFFFFFFFu);
    h.name_len       = name_len;
    h.chunk_size     = chunk_size;
    h.crc32          = flash_crc32(body, body_len);
    flash_header_hton(&h);
    memcpy(buf, &h, sizeof(h));
    if (body_len) memcpy(buf + sizeof(h), body, body_len);
    return len;
}

/* 把载荷包成完整 IPv4+ICMP Echo 报文（模拟 nping 线上字节），喂给真实解析函数 */
static void feed(const uint8_t *payload, size_t pay_len)
{
    uint8_t pkt[64 + FLASH_MAX_CHUNK + 64];
    IPv4Header *ip;
    ICMPEchoHeader *ic;
    int ihl = 20, icmp_len, total_len;

    memset(pkt, 0, sizeof(pkt));
    ip = (IPv4Header *)pkt;
    ic = (ICMPEchoHeader *)(pkt + ihl);
    icmp_len = 8 + (int)pay_len;
    total_len = ihl + icmp_len;

    ip->ver_ihl     = 0x45;
    ip->total_len   = htons((uint16_t)total_len);
    ip->ttl         = 64;
    ip->protocol    = 1;
    memcpy(ip->src, g_src, 4);
    memcpy(ip->dst, g_dst, 4);
    ic->type = 8; ic->code = 0;
    ic->id  = htons(1);
    ic->seq = htons(1);
    memcpy(pkt + ihl + 8, payload, pay_len);

    handle_packet(pkt, total_len);
}

static void feed_meta(uint32_t session, uint32_t total, uint64_t fs, uint32_t chunk,
                      const char *name)
{
    uint8_t p[sizeof(FlashHeader) + FLASH_MAX_NAME + 16];
    size_t n = build_payload(p, sizeof(p), session, FLASH_TYPE_META, 0, total, fs, chunk,
                             name, (uint32_t)strlen(name), NULL, 0);
    feed(p, n);
}

static void feed_data(uint32_t session, uint32_t idx, uint32_t total, uint64_t fs,
                      uint32_t chunk, const uint8_t *data, uint32_t data_len)
{
    uint8_t p[sizeof(FlashHeader) + FLASH_MAX_CHUNK + 16];
    size_t n = build_payload(p, sizeof(p), session, FLASH_TYPE_DATA, idx, total, fs, chunk,
                             NULL, 0, data, data_len);
    feed(p, n);
}

/* ============ 测试基础设施 ============ */
#define OUTDIR "selftest_out"
static int g_fail = 0;

static void reset_state(void)
{
    while (g_sessions) {
        Session *nx = g_sessions->next;
        session_free(g_sessions);
        g_sessions = nx;
    }
    memset(g_outdir, 0, sizeof(g_outdir));
    snprintf(g_outdir, sizeof(g_outdir), "%s", OUTDIR);
    g_verbose = 0;
    memcpy(g_target, g_dst, 4);
    g_target_set = 1;   /* 启用目的 IP 过滤，与 FlashReceive/FlashPcap 行为一致 */
}

static void cleanup_outdir(void)
{
    WIN32_FIND_DATAA fd;
    char pat[1024];
    HANDLE h;
    snprintf(pat, sizeof(pat), "%s\\*", OUTDIR);
    h = FindFirstFileA(pat, &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (strcmp(fd.cFileName, ".") && strcmp(fd.cFileName, "..")) {
                char full[1024];
                snprintf(full, sizeof(full), "%s\\%s", OUTDIR, fd.cFileName);
                DeleteFileA(full);
            }
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
}

static int compare_file(const char *fname, const uint8_t *expected, size_t len)
{
    char path[1024];
    FILE *f;
    uint8_t *buf;
    size_t got;
    int ok;
    snprintf(path, sizeof(path), "%s\\%s", OUTDIR, fname);
    f = fopen(path, "rb");
    if (!f) { printf("    [FAIL] 未生成文件 %s\n", fname); return 0; }
    fseek(f, 0, SEEK_END);
    if ((size_t)ftell(f) != len) {
        printf("    [FAIL] %s 大小不一致 (期望 %zu, 实际 %ld)\n", fname, len, ftell(f));
        fclose(f); return 0;
    }
    fseek(f, 0, SEEK_SET);
    buf = (uint8_t *)malloc(len ? len : 1);
    got = fread(buf, 1, len, f);
    fclose(f);
    ok = (got == len) && (memcmp(buf, expected, len) == 0);
    if (!ok) printf("    [FAIL] %s 内容与期望不一致\n", fname);
    free(buf);
    return ok;
}

static void assert_eq(const char *name, int cond)
{
    printf("  %s: %s\n", name, cond ? "PASS" : "FAIL");
    if (!cond) g_fail = 1;
}

int main(void)
{
    uint8_t *in;
    uint64_t fs = 2500;
    uint32_t chunk = 1024, total = 3, session = 0x12345678u;
    const char *fname = "selftest_in.bin";
    uint32_t f0len, f1len, f2len;
    uint8_t *expect_partial;

    SetConsoleOutputCP(CP_UTF8);
    CreateDirectoryA(OUTDIR, NULL);
    in = (uint8_t *)malloc((size_t)fs);
    {
        uint64_t i;
        for (i = 0; i < fs; ++i) in[i] = (uint8_t)((i * 7 + 3) & 0xFF);
    }
    f0len = 1024; f1len = 1024; f2len = (uint32_t)(fs - 2048); /* 452 */

    /* ---------- 场景1：正常顺序 + 元信息 ---------- */
    printf("[场景1] 正常顺序 + 元信息\n");
    reset_state(); cleanup_outdir();
    feed_meta(session, total, fs, chunk, fname);
    feed_data(session, 1, total, fs, chunk, in, f0len);
    feed_data(session, 2, total, fs, chunk, in + 1024, f1len);
    feed_data(session, 3, total, fs, chunk, in + 2048, f2len);
    assert_eq("完整还原", compare_file(fname, in, (size_t)fs));

    /* ---------- 场景2：乱序(3,1,2) + 重复分片 ---------- */
    printf("[场景2] 乱序 + 重复分片（顺序无关 + 去重）\n");
    reset_state(); cleanup_outdir();
    feed_data(session, 3, total, fs, chunk, in + 2048, f2len); /* 先到 3 */
    feed_data(session, 1, total, fs, chunk, in, f0len);
    feed_meta(session, total, fs, chunk, fname);
    feed_data(session, 2, total, fs, chunk, in + 1024, f1len);
    feed_data(session, 1, total, fs, chunk, in, f0len); /* 重复 */
    feed_data(session, 2, total, fs, chunk, in + 1024, f1len); /* 重复 */
    assert_eq("乱序去重后完整还原", compare_file(fname, in, (size_t)fs));

    /* ---------- 场景3：元信息丢失 + 缺一片(分片2) -> .partial ---------- */
    printf("[场景3] 元信息丢失 + 缺片 -> 补零 .partial\n");
    reset_state(); cleanup_outdir();
    feed_data(session, 1, total, fs, chunk, in, f0len);
    feed_data(session, 3, total, fs, chunk, in + 2048, f2len);
    /* 缺分片2，且没发元信息：用默认名，收到 1/3 触发不了完成，需 flush */
    flush_partials();
    {
        /* 元信息丢失 -> has_meta 始终为假，flush 时回退默认名 received.bin.partial */
        char expect_name[FLASH_MAX_NAME + 16];
        snprintf(expect_name, sizeof(expect_name), "received.bin.partial");
        /* 期望：分片2区域(偏移1024..2048)全 0，其余与 in 一致 */
        expect_partial = (uint8_t *)malloc((size_t)fs);
        memcpy(expect_partial, in, (size_t)fs);
        memset(expect_partial + 1024, 0, 1024);
        assert_eq("缺片补零还原", compare_file(expect_name, expect_partial, (size_t)fs));
        free(expect_partial);
    }

    /* ---------- 场景4：目的 IP 不匹配 -> 被过滤 ---------- */
    printf("[场景4] 目的 IP 不匹配 -> 忽略\n");
    reset_state(); cleanup_outdir();
    {
        uint8_t wrong_dst[4] = { 9, 9, 9, 9 };
        uint8_t p[sizeof(FlashHeader) + FLASH_MAX_NAME + 16];
        size_t n;
        memcpy(g_dst, wrong_dst, 4);   /* 让 feed() 把包的目的地设为 9.9.9.9 */
        memcpy(g_target, g_dst, 4);
        g_target[0] = 1; g_target[1] = 2; g_target[2] = 3; g_target[3] = 4; /* 监听 1.2.3.4 */
        n = build_payload(p, sizeof(p), session, FLASH_TYPE_META, 0, total, fs, chunk,
                          fname, (uint32_t)strlen(fname), NULL, 0);
        feed(p, n);
        assert_eq("不匹配目的IP时无会话建立", g_sessions == NULL);
    }

    printf("\n==== %s ====\n", g_fail ? "有失败用例" : "全部通过");
    free(in);
    return g_fail ? 1 : 0;
}
