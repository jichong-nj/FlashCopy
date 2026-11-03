/*
 * FlashPcap.c
 * 离线从 .pcap 抓包文件里还原文件：读取 pcap，取出「目的 IP 为指定地址」的
 * ICMP Echo 报文，用 flash_common.c 里与 FlashReceive 完全相同的解析/重组核心
 * 还原出文件。适合把 Wireshark 抓到的包事后还原，无需管理员、无需网卡权限。
 *
 * 直接复用 flash_common 的 handle_packet()：pcap 里每条记录去掉链路层头之后，
 * 剩下的就是 IPv4 报文（IP 头 + ICMP 头 + 载荷），与 handle_packet 期望的输入一致。
 *
 * 用法: FlashPcap.exe <抓包文件.pcap> <目的IP> [选项]
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "flash_common.h"

/* ---------------- pcap 文件解析（libpcap 经典格式，纯手工解析，无外部依赖） ---------------- */

/* 全局头 24 字节：magic / ver_maj / ver_min / thiszone / sigfigs / snaplen / network */
#define PCAP_GHDR_LEN    24
#define PCAP_RECHDR_LEN  16   /* ts_sec / ts_usec / incl_len / orig_len */

static int g_swap = 0;        /* 文件字节序与主机不一致时需要交换 */

static uint32_t rd32(const uint8_t *p)
{
    if (g_swap)
        return ((uint32_t)p[3]) | ((uint32_t)p[2] << 8) |
               ((uint32_t)p[1] << 16) | ((uint32_t)p[0] << 24);
    return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void print_usage(const char *prog)
{
    printf(
        "FlashPcap - 从 pcap 抓包文件还原 FlashSend 发出的文件\n"
        "\n"
        "用法: %s <抓包文件.pcap> <目的IP> [选项]\n"
        "\n"
        "  <抓包文件.pcap>   Wireshark/tcpdump 录制的抓包文件\n"
        "  <目的IP>          只处理 IP 头目的地址等于该值的 ICMP 报文\n"
        "                    （即 FlashSend 当时填的目的 IP）\n"
        "\n"
        "选项:\n"
        "  -o <目录>   还原文件输出目录，默认当前目录\n"
        "  -l <字节>   链路层头长度（覆盖自动探测），如以太网=14、原始IP=0、Linux SLL=16\n"
        "  -v          详细模式，打印每条命中的 ICMP 报文\n"
        "  -h          显示本帮助\n"
        "\n"
        "说明: 读的是 pcap 文件，不需要管理员，也不依赖任何抓包驱动。\n"
        "      重组逻辑与 FlashReceive 完全一致，可处理乱序/重复/缺片/元信息丢失。\n"
        "\n",
        prog);
}

int main(int argc, char **argv)
{
    const char *pcap_path = NULL;
    const char *target_str = NULL;
    const char *outdir = ".";
    int link_override = -1;       /* <0 表示自动探测 */
    FILE *fp = NULL;
    uint8_t ghdr[PCAP_GHDR_LEN];
    uint8_t rec[PCAP_RECHDR_LEN];
    uint32_t network;
    int link_off;
    size_t n;
    uint64_t pkt_total = 0, pkt_match = 0;
    int i;

    SetConsoleOutputCP(CP_UTF8);

    for (i = 1; i < argc; ++i) {
        if (argv[i][0] == '-') {
            if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
                print_usage(argv[0]);
                return 0;
            } else if (!strcmp(argv[i], "-o") && i + 1 < argc) {
                outdir = argv[++i];
            } else if (!strcmp(argv[i], "-l") && i + 1 < argc) {
                link_override = atoi(argv[++i]);
            } else if (!strcmp(argv[i], "-v")) {
                g_verbose = 1;
            } else {
                fprintf(stderr, "[错误] 未知选项或缺少参数: %s\n", argv[i]);
                return 2;
            }
        } else {
            if (!pcap_path)       pcap_path = argv[i];
            else if (!target_str) target_str = argv[i];
            else {
                fprintf(stderr, "[错误] 参数过多: %s\n", argv[i]);
                return 2;
            }
        }
    }

    if (!pcap_path || !target_str) {
        print_usage(argv[0]);
        return 2;
    }
    if (!flash_parse_ipv4(target_str, g_target)) {
        fprintf(stderr, "[错误] 非法的 IPv4 地址: %s\n", target_str);
        return 2;
    }
    g_target_set = 1;
    snprintf(g_outdir, sizeof(g_outdir), "%s", outdir);
    if (GetFileAttributesA(g_outdir) == INVALID_FILE_ATTRIBUTES)
        CreateDirectoryA(g_outdir, NULL);

    fp = fopen(pcap_path, "rb");
    if (!fp) {
        fprintf(stderr, "[错误] 无法打开 pcap 文件: %s\n", pcap_path);
        return 1;
    }

    n = fread(ghdr, 1, PCAP_GHDR_LEN, fp);
    if (n != PCAP_GHDR_LEN) {
        fprintf(stderr, "[错误] pcap 文件过短或不是合法的 pcap 文件\n");
        fclose(fp);
        return 1;
    }

    /* 判定字节序与是否为纳秒精度（纳秒只影响时间戳，对我们无意义） */
    {
        uint32_t magic = rd32(ghdr);
        if (magic == 0xa1b2c3d4u || magic == 0xa1b23c4du) {
            g_swap = 0;
        } else if (magic == 0xd4c3b2a1u || magic == 0x4d3cb2a1u) {
            g_swap = 1;
        } else {
            fprintf(stderr, "[错误] 无法识别的 pcap magic (0x%08X)，可能不是 libpcap 格式\n", magic);
            fclose(fp);
            return 1;
        }
    }
    network = rd32(ghdr + 20);

    /* 自动探测链路层头长度 */
    if (link_override >= 0) {
        link_off = link_override;
    } else if (network == 1) {            /* Ethernet */
        link_off = 14;
    } else if (network == 0 || network == 101) {  /* 原始 IP */
        link_off = 0;
    } else if (network == 113 || network == 228) { /* Linux cooked / SLL2 */
        link_off = 16;
    } else if (network == 12) {           /* NULL / BSD loopback */
        link_off = 4;
    } else {
        link_off = 14;
        printf("[提示] 未知链路类型 %u，按以太网(14B)处理；若解析异常请用 -l 指定链路层头长度\n",
               (unsigned)network);
    }

    printf("[启动] 读取 pcap: %s\n", pcap_path);
    printf("[启动] 链路类型=%u 链路层头=%d B  过滤目的IP=%s  输出目录=%s\n",
           (unsigned)network, link_off, target_str, outdir);
    fflush(stdout);

    /* 逐条记录读取 */
    for (;;) {
        uint32_t ts_sec, ts_usec, incl_len, orig_len;
        uint8_t *buf;
        long rec_off;
        int ip_len;

        n = fread(rec, 1, PCAP_RECHDR_LEN, fp);
        if (n == 0)
            break;                       /* 正常到文件尾 */
        if (n != PCAP_RECHDR_LEN) {
            fprintf(stderr, "[警告] pcap 文件在记录头处截断，停止解析\n");
            break;
        }
        ts_sec   = rd32(rec + 0);
        ts_usec  = rd32(rec + 4);
        incl_len = rd32(rec + 8);
        orig_len = rd32(rec + 12);
        (void)ts_sec; (void)ts_usec; (void)orig_len;

        if (incl_len == 0 || incl_len > 64 * 1024 * 1024) {
            fprintf(stderr, "[警告] 记录长度异常 (%u)，停止解析以避免内存问题\n", incl_len);
            break;
        }

        buf = (uint8_t *)malloc(incl_len);
        if (!buf) {
            fprintf(stderr, "[错误] 内存分配失败\n");
            fclose(fp);
            return 1;
        }
        rec_off = ftell(fp);
        n = fread(buf, 1, incl_len, fp);
        if (n != incl_len) {
            fprintf(stderr, "[警告] 记录数据不完整（读取 %zu/%u），停止解析\n", n, incl_len);
            free(buf);
            break;
        }
        (void)rec_off;

        ++pkt_total;

        /* 去掉链路层头，得到 IPv4 报文；先按目的 IP + 协议预过滤，再交给重组核心 */
        if ((int)incl_len > link_off) {
            const uint8_t *ip = buf + link_off;
            ip_len = (int)incl_len - link_off;

            int is_eth = (link_off >= 14 && buf[12] == 0x08 && buf[13] == 0x00);
            int is_raw = (link_off < 14);
            if (is_eth || is_raw) {
                const IPv4Header *vip = (const IPv4Header *)ip;
                if (ip_len >= (int)sizeof(IPv4Header) &&
                    vip->protocol == 1 &&
                    memcmp(vip->dst, g_target, 4) == 0) {
                    handle_packet(ip, ip_len);
                    ++pkt_match;
                }
            }
        }
        free(buf);
    }

    /* 收尾：把未收齐的会话写成 .partial */
    flush_partials();

    printf("\n[统计] 共读取记录 %llu 条，命中目的IP的 ICMP 报文 %llu 条\n",
           (unsigned long long)pkt_total, (unsigned long long)pkt_match);
    printf("[完成] pcap 解析与还原结束。\n");
    fflush(stdout);

    /* 释放会话状态 */
    while (g_sessions) {
        Session *nx = g_sessions->next;
        session_free(g_sessions);
        g_sessions = nx;
    }
    fclose(fp);
    return 0;
}
