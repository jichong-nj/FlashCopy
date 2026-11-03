/*
 * FlashRecvPcap.c
 * 用 Npcap（与 Wireshark 相同的抓包引擎）以「非混杂模式」抓取 ICMP Echo 报文，
 * 取出目的 IP 等于指定地址的包，复用 flash_common.c 里与 FlashReceive/FlashPcap
 * 完全相同的重组核心还原文件。
 *
 * 与 FlashReceive 的区别：不使用 Raw Socket + SIO_RCVALL 混杂抓包，而是用 pcap 接口，
 * 默认 promisc=0（非混杂模式，只能看到发给本机 / 广播 / 组播的包）。
 *
 * 依赖：运行时需要 wpcap.dll（Npcap）。本程序通过 LoadLibrary 动态加载，无需 SDK 头/库。
 *       抓包在 Windows 上仍需要管理员权限（与 Wireshark 一致）。
 *
 * 用法: FlashRecvPcap.exe <目的IP> [-i <设备>] [-o <输出目录>] [-t <超时秒>] [-v]
 *       省略 -i 时列出本机所有抓包设备并交互选择。
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "flash_common.h"

/* ===================== 与 wpcap.dll 的运行时绑定 ===================== */
/* 仅声明本程序需要用到的一小部分 pcap API，结构体按 Npcap 64 位 ABI 手动画出。 */

struct pcap_addr {
    struct pcap_addr *next;
    void *addr, *netmask, *broadaddr, *dstaddr;
};
struct pcap_if {
    struct pcap_if  *next;
    char            *name;
    char            *description;
    struct pcap_addr *addresses;
    unsigned int     flags;
};

struct bpf_program {
    unsigned int bf_len;
    void        *bf_insns;
};

struct pcap_pkthdr {
    long  tv_sec;
    long  tv_usec;
    unsigned int caplen;
    unsigned int len;
};

typedef void pcap_t;

typedef int  (*PF_findalldevs)(struct pcap_if **, char *);
typedef void (*PF_freealldevs)(struct pcap_if *);
typedef pcap_t* (*PF_open_live)(const char *, int, int, int, char *);
typedef int  (*PF_compile)(pcap_t *, struct bpf_program *, const char *, int, unsigned int);
typedef int  (*PF_setfilter)(pcap_t *, struct bpf_program *);
typedef int  (*PF_datalink)(pcap_t *);
typedef int  (*PF_next_ex)(pcap_t *, struct pcap_pkthdr **, const unsigned char **);
typedef void (*PF_breakloop)(pcap_t *);
typedef void (*PF_close)(pcap_t *);
typedef char* (*PF_geterr)(pcap_t *);
typedef void (*PF_freecode)(struct bpf_program *);

static HMODULE         g_wpc = NULL;
static PF_findalldevs  fp_findalldevs  = NULL;
static PF_freealldevs  fp_freealldevs  = NULL;
static PF_open_live    fp_open_live    = NULL;
static PF_compile      fp_compile      = NULL;
static PF_setfilter    fp_setfilter    = NULL;
static PF_datalink     fp_datalink     = NULL;
static PF_next_ex      fp_next_ex      = NULL;
static PF_breakloop    fp_breakloop    = NULL;
static PF_close        fp_close        = NULL;
static PF_geterr       fp_geterr       = NULL;
static PF_freecode     fp_freecode     = NULL;

/* Npcap 链路层类型（pcap_datalink 返回值，仅用到的几个） */
#define DLT_NULL      0
#define DLT_EN10MB    1
#define DLT_RAW       12
#define DLT_LINUX_SLL 113
#define LINKTYPE_RAW  101

static int load_wpcap(void)
{
    /*
     * 关键：只用 "System32" 路径，绝不写死 "SysWOW64"。
     * 32 位进程在 WOW64 下会被系统自动把 System32 重定向到 SysWOW64，
     * 所以无论本程序是 32 还是 64 位，下面这些路径都会解析到【匹配位数】的 wpcap.dll，
     * 避免 LoadLibrary 返回 193 (ERROR_BAD_EXE_FORMAT) 的位数不匹配问题。
     */
    static const char *candidates[] = {
        "wpcap.dll",
        "C:\\Windows\\System32\\wpcap.dll",
        "C:\\Windows\\System32\\Npcap\\wpcap.dll",
        NULL
    };
    int i;
    DWORD last_err = 0;

    /* 让 packet.dll（wpcap 的依赖）能被找到：把 Npcap 目录加入 DLL 搜索路径。
     * 同样只用 System32\Npcap，32 位进程由 WOW64 透明重定向到 SysWOW64\Npcap。 */
    SetDllDirectoryA("C:\\Windows\\System32\\Npcap");

    for (i = 0; candidates[i]; ++i) {
        g_wpc = LoadLibraryA(candidates[i]);
        if (g_wpc)
            break;
        last_err = GetLastError();
    }
    if (!g_wpc) {
        fprintf(stderr, "[错误] 无法加载 wpcap.dll（请确认已安装 Npcap）。LastError=%lu%s\n",
                (unsigned long)last_err,
                last_err == 193 ? "（位数不匹配：exe 与 wpcap.dll 架构不同，请用同位数编译）" : "");
        return 0;
    }
#define LOAD(name) do { \
        fp_##name = (PF_##name)GetProcAddress(g_wpc, "pcap_" #name); \
        if (!fp_##name) { \
            fprintf(stderr, "[错误] wpcap.dll 缺少导出函数: pcap_%s\n", #name); \
            return 0; \
        } \
    } while (0)
    LOAD(findalldevs);
    LOAD(freealldevs);
    LOAD(open_live);
    LOAD(compile);
    LOAD(setfilter);
    LOAD(datalink);
    LOAD(next_ex);
    LOAD(breakloop);
    LOAD(close);
    LOAD(geterr);
    LOAD(freecode);
#undef LOAD
    return 1;
}

/* ===================== 控制台中断处理 ===================== */
static volatile LONG g_stop = 0;
static pcap_t *g_pcap = NULL;

static BOOL WINAPI console_handler(DWORD ctrl)
{
    if (ctrl == CTRL_C_EVENT || ctrl == CTRL_BREAK_EVENT) {
        g_stop = 1;
        if (g_pcap)
            fp_breakloop(g_pcap);   /* 让 pcap_next_ex 立即返回 */
        return TRUE;
    }
    return FALSE;
}

static void print_usage(const char *prog)
{
    printf(
        "FlashRecvPcap - 用 Npcap（与 Wireshark 相同方式，非混杂模式）抓 ICMP 包并还原文件\n"
        "\n"
        "用法: %s [目的IP] [选项]\n"
        "\n"
        "  [目的IP]   可选。给定时只处理 ICMP Echo 中目的地址等于该值的包（即 FlashSend 填的\n"
        "             目的 IP）；省略则捕获该网卡上的【全部 ICMP】，便于抓取本机自己发出的\n"
        "             ping（例如 ping 一个不存在的 IP）等场景。\n"
        "\n"
        "选项:\n"
        "  -i <设备>   抓包设备（Npcap 设备名）；省略则列出设备并交互选择\n"
        "  -o <目录>   还原文件输出目录，默认当前目录\n"
        "  -t <秒>     无新包后继续等待的超时秒数；到时后写出 .partial 并退出\n"
        "  -v          详细模式，逐条打印捕获到的 ICMP 报文（含普通 ping）\n"
        "  -h          显示本帮助\n"
        "\n"
        "说明: 抓包依赖 Npcap（Wireshark 同款），需要管理员权限；默认非混杂模式（promisc=0）。\n"
        "      普通 ping 不含文件数据，无法还原成文件，但会被计数并显示（便于确认已抓到）。\n"
        "\n",
        prog);
}

/* 依据链路层类型给出需要跳过的头部长度 */
static int link_off_for(int dl)
{
    switch (dl) {
        case DLT_EN10MB:    return 14;   /* 以太网 */
        case DLT_RAW:
        case LINKTYPE_RAW:  return 0;    /* 原始 IP */
        case DLT_LINUX_SLL: return 16;   /* Linux cooked */
        case DLT_NULL:      return 4;    /* BSD loopback */
        default:            return 14;   /* 未知，按以太网尝试 */
    }
}

int main(int argc, char **argv)
{
    const char *target_str = NULL;
    const char *device = NULL;
    const char *outdir = ".";
    int timeout_sec = 0;
    char errbuf[256];
    struct pcap_if *devs = NULL, *d;
    pcap_t *p = NULL;
    struct bpf_program fp;
    int datalink, link_off;
    int i;
    DWORD t0 = 0, last_pkt = 0;
    char filter[128];
    int icmp_seen = 0, nonflash = 0;

    SetConsoleOutputCP(CP_UTF8);
    if (!load_wpcap()) {
        fprintf(stderr, "[错误] 无法加载 wpcap.dll（请确认已安装 Npcap）。\n");
        return 1;
    }

    for (i = 1; i < argc; ++i) {
        if (argv[i][0] == '-') {
            if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
                print_usage(argv[0]);
                return 0;
            } else if (!strcmp(argv[i], "-i") && i + 1 < argc) {
                device = argv[++i];
            } else if (!strcmp(argv[i], "-o") && i + 1 < argc) {
                outdir = argv[++i];
            } else if (!strcmp(argv[i], "-t") && i + 1 < argc) {
                timeout_sec = atoi(argv[++i]);
            } else if (!strcmp(argv[i], "-v")) {
                g_verbose = 1;
            } else {
                fprintf(stderr, "[错误] 未知选项或缺少参数: %s\n", argv[i]);
                return 2;
            }
        } else if (!target_str) {
            target_str = argv[i];
        } else {
            fprintf(stderr, "[错误] 参数过多: %s\n", argv[i]);
            return 2;
        }
    }

    if (target_str) {
        if (!flash_parse_ipv4(target_str, g_target)) {
            fprintf(stderr, "[错误] 非法的 IPv4 地址: %s\n", target_str);
            return 2;
        }
        g_target_set = 1;
    } else {
        /* 不指定目的 IP：捕获该网卡上所有 ICMP，便于抓取本机自己发出的 ping 等 */
        g_target_set = 0;
    }
    snprintf(g_outdir, sizeof(g_outdir), "%s", outdir);
    if (GetFileAttributesA(g_outdir) == INVALID_FILE_ATTRIBUTES)
        CreateDirectoryA(g_outdir, NULL);

    /* 设备选择：未指定 -i 则列出并交互选择 */
    if (!device) {
        if (fp_findalldevs(&devs, errbuf) == -1 || !devs) {
            fprintf(stderr, "[错误] 列举抓包设备失败: %s\n", errbuf);
            return 1;
        }
        printf("可用抓包设备:\n");
        i = 0;
        for (d = devs; d; d = d->next)
            printf("  [%d] %s  (%s)\n", ++i, d->name,
                   d->description ? d->description : "无描述");
        printf("请选择设备编号: ");
        fflush(stdout);
        if (scanf_s("%d", &i) != 1 || i < 1) {
            fprintf(stderr, "[错误] 无效选择\n");
            fp_freealldevs(devs);
            return 2;
        }
        for (d = devs, --i; i > 0 && d; d = d->next, --i)
            ;
        if (!d) {
            fprintf(stderr, "[错误] 无效选择\n");
            fp_freealldevs(devs);
            return 2;
        }
        device = d->name;
    }

    /* 以非混杂模式打开抓包 */
    p = fp_open_live(device, 65536, 0 /*promisc=0 非混杂*/, 1000 /*read timeout ms*/, errbuf);
    if (!p) {
        fprintf(stderr, "[错误] 无法打开设备 %s: %s\n", device, errbuf);
        if (devs) fp_freealldevs(devs);
        return 1;
    }
    g_pcap = p;
    SetConsoleCtrlHandler(console_handler, TRUE);

    /* 指定目的 IP 时只抓发往它的 ICMP；否则抓全部 ICMP（含本机自己发出的 ping） */
    if (g_target_set)
        snprintf(filter, sizeof(filter), "icmp and dst host %u.%u.%u.%u",
                 g_target[0], g_target[1], g_target[2], g_target[3]);
    else
        snprintf(filter, sizeof(filter), "icmp");
    if (fp_compile(p, &fp, filter, 1, 0) == -1 || fp_setfilter(p, &fp) == -1) {
        fprintf(stderr, "[错误] 设置 BPF 过滤器失败: %s\n", fp_geterr(p));
        fp_close(p);
        if (devs) fp_freealldevs(devs);
        return 1;
    }
    fp_freecode(&fp);

    datalink = fp_datalink(p);
    link_off = link_off_for(datalink);

    printf("[启动] 抓包设备=%s  链路类型=%d 链路层头=%d B\n", device, datalink, link_off);
    printf("[启动] 非混杂模式(promisc=0)  过滤=\"%s\"  输出目录=%s\n", filter, outdir);
    printf("[提示] 按 Ctrl+C 停止；%s\n", timeout_sec > 0
           ? "超时后写出 .partial 并退出" : "将一直运行直到 Ctrl+C");
    fflush(stdout);

    t0 = GetTickCount();
    last_pkt = t0;

    for (;;) {
        struct pcap_pkthdr *ph;
        const unsigned char *pd;
        int r = fp_next_ex(p, &ph, &pd);

        if (g_stop)
            break;

        if (r == 0) {
            /* 读超时：检查整体超时 */
            if (timeout_sec > 0 &&
                GetTickCount() - last_pkt > (DWORD)timeout_sec * 1000)
                break;
            continue;
        }
        if (r == -1) {
            fprintf(stderr, "[错误] 抓包出错: %s\n", fp_geterr(p));
            break;
        }
        if (r != 1)
            continue;

        last_pkt = GetTickCount();

        /* 去掉链路层头，交给与 FlashReceive/FlashPcap 相同的重组核心 */
        if ((int)ph->caplen > link_off) {
            const unsigned char *ip = pd + link_off;
            int ip_len = (int)ph->caplen - link_off;
            /* 以太网需确认 ethertype==0x0800，否则跳过（ARP 等） */
            int is_eth = (link_off >= 14 && pd[12] == 0x08 && pd[13] == 0x00);
            int is_raw = (link_off < 14);
            if (is_eth || is_raw) {
                const IPv4Header *vip = (const IPv4Header *)ip;
                if (ip_len >= (int)sizeof(IPv4Header) && vip->protocol == 1) {
                    int ihl2 = (vip->ver_ihl & 0x0F) * 4;
                    const unsigned char *icmp = ip + ihl2;
                    int icmp_len = ip_len - ihl2;
                    int is_flash = (icmp_len >= 8 + 4) &&
                                   memcmp(icmp + 8, "FSSP", 4) == 0;
                    char dst[16];
                    flash_ip_to_str(vip->dst, dst, sizeof(dst));
                    if (g_verbose)
                        printf("[ICMP] type=%u 目的=%s 载荷=%d B %s\n",
                               (unsigned)icmp[0], dst, icmp_len - 8,
                               is_flash ? "[Flash报文]" : "[普通ping]");
                    ++icmp_seen;
                    if (!is_flash)
                        ++nonflash;
                    /* 指定了目的 IP 时，只处理目的地址等于它的报文 */
                    if (g_target_set && memcmp(vip->dst, g_target, 4) != 0)
                        continue;
                    handle_packet(ip, ip_len);
                }
            }
        }
    }

    printf("\n[统计] 共捕获 ICMP 报文 %d 个，其中非 Flash 普通 ping %d 个。\n",
           icmp_seen, nonflash);
    printf("[收尾] 写出未收齐的会话...\n");
    fflush(stdout);
    flush_partials();

    /* 释放会话状态 */
    while (g_sessions) {
        Session *nx = g_sessions->next;
        session_free(g_sessions);
        g_sessions = nx;
    }

    fp_close(p);
    if (devs)
        fp_freealldevs(devs);
    if (g_wpc)
        FreeLibrary(g_wpc);
    return 0;
}
