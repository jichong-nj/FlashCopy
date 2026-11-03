/*
 * FlashReceive.c
 * 用 Windows Raw Socket + SIO_RCVALL（混杂模式）抓取网卡上收到的所有 IPv4
 * 报文，过滤「目的 IP == 指定 IP」的 ICMP Echo 报文，按 FlashSend 的逆逻辑
 * 重组还原文件。乱序、重复、元信息丢失、分片丢失都能处理。
 *
 * 接收端解析/重组逻辑位于 flash_common.c（与回归自测共享同一份代码）。
 * 需要管理员权限（SIO_RCVALL 混杂抓包）。
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "flash_common.h"

#ifndef SIO_RCVALL
#define SIO_RCVALL _WSAIOW(IOC_VENDOR, 1)
#endif
#ifndef RCVALL_ON
#define RCVALL_ON 1
#endif
#ifndef RCVALL_OFF
#define RCVALL_OFF 0
#endif

static volatile LONG g_stop = 0;

static BOOL WINAPI console_handler(DWORD type)
{
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT) {
        InterlockedExchange(&g_stop, 1);
        return TRUE;
    }
    return FALSE;
}

static void print_usage(const char *prog)
{
    printf(
        "FlashReceive - 混杂模式监听指定目的 IP 的 Ping 报文并还原文件\n"
        "\n"
        "用法: %s <目的IP> [选项]\n"
        "\n"
        "  <目的IP>   只处理 IP 头中目的地址等于该值的 ICMP 报文\n"
        "             （通常填 FlashSend 使用的那个目的 IP）\n"
        "\n"
        "选项:\n"
        "  -o <目录>  还原文件的输出目录，默认当前目录\n"
        "  -b <本机IP> 绑定到哪块本地网卡，默认自动探测\n"
        "  -t <秒>    空闲超时，超时后把未收齐的文件写成 .partial；0 表示不超时，默认 60\n"
        "  -v         详细模式，打印所有命中目的 IP 的 Ping 报文\n"
        "  -h         显示本帮助\n"
        "\n"
        "说明: 需要以管理员身份运行；实时显示 已收到/总数 的进度，例如 10/100。\n"
        "      发送端 FlashSend 现已改为通过 nping.exe 发包，本端抓包逻辑不变。\n"
        "\n",
        prog);
}

/* 自动挑选一块非回环的本机 IPv4 地址（网络序 4 字节） */
static int pick_bind_ip(uint8_t out[4])
{
    SOCKET t;
    struct sockaddr_in remote, local;
    char host[256];
    struct addrinfo hints, *res = NULL, *a;
    int len;

    /* 方法1：用 UDP connect 做一次路由查表，取得默认出口的本机 IP（不发包） */
    t = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (t != INVALID_SOCKET) {
        memset(&remote, 0, sizeof(remote));
        remote.sin_family = AF_INET;
        remote.sin_addr.s_addr = htonl(0x08080808u);  /* 8.8.8.8 */
        remote.sin_port = htons(53);
        if (connect(t, (struct sockaddr *)&remote, sizeof(remote)) == 0) {
            len = sizeof(local);
            if (getsockname(t, (struct sockaddr *)&local, &len) == 0) {
                uint8_t *b = (uint8_t *)&local.sin_addr.s_addr;
                if (b[0] != 0 && b[0] != 127) {
                    memcpy(out, b, 4);
                    closesocket(t);
                    return 1;
                }
            }
        }
        closesocket(t);
    }

    /* 方法2：主机名解析兜底 */
    if (gethostname(host, sizeof(host)) != 0)
        return 0;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0)
        return 0;
    for (a = res; a; a = a->ai_next) {
        struct sockaddr_in *sin = (struct sockaddr_in *)a->ai_addr;
        uint8_t *b;
        if (a->ai_family != AF_INET || !sin)
            continue;
        b = (uint8_t *)&sin->sin_addr.s_addr;
        if (b[0] == 127 || (b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0))
            continue;
        memcpy(out, b, 4);
        freeaddrinfo(res);
        return 1;
    }
    freeaddrinfo(res);
    return 0;
}

int main(int argc, char **argv)
{
    WSADATA wsa;
    int wsa_ok = 0;
    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in bind_addr;
    uint8_t bind_ip[4] = { 0, 0, 0, 0 };
    uint8_t *buf = NULL;
    const char *target_str = NULL, *bind_str = NULL;
    int timeout = 60;
    DWORD opt = RCVALL_ON, bytes = 0;
    char bindstr[16], targetstr[16];
    int i;

    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCtrlHandler(console_handler, TRUE);

    for (i = 1; i < argc; ++i) {
        if (argv[i][0] == '-') {
            if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
                print_usage(argv[0]);
                return 0;
            } else if (!strcmp(argv[i], "-o") && i + 1 < argc) {
                snprintf(g_outdir, sizeof(g_outdir), "%s", argv[++i]);
            } else if (!strcmp(argv[i], "-b") && i + 1 < argc) {
                bind_str = argv[++i];
            } else if (!strcmp(argv[i], "-t") && i + 1 < argc) {
                timeout = atoi(argv[++i]);
            } else if (!strcmp(argv[i], "-v")) {
                g_verbose = 1;
            } else {
                fprintf(stderr, "[错误] 未知选项或缺少参数: %s\n", argv[i]);
                return 2;
            }
        } else {
            if (!target_str)     target_str = argv[i];
            else {
                fprintf(stderr, "[错误] 参数过多: %s\n", argv[i]);
                return 2;
            }
        }
    }

    if (!target_str) {
        print_usage(argv[0]);
        return 2;
    }
    if (!flash_parse_ipv4(target_str, g_target)) {
        fprintf(stderr, "[错误] 非法的 IPv4 地址: %s\n", target_str);
        return 2;
    }
    g_target_set = 1;
    if (timeout < 0)
        timeout = 0;

    if (bind_str) {
        if (!flash_parse_ipv4(bind_str, bind_ip)) {
            fprintf(stderr, "[错误] -b 指定的本机 IP 非法: %s\n", bind_str);
            return 2;
        }
    } else if (!pick_bind_ip(bind_ip)) {
        printf("[警告] 未能自动探测本机网卡 IP，尝试使用 0.0.0.0；"
               "若开启混杂模式失败请用 -b <本机IP> 指定。\n");
    }

    if (GetFileAttributesA(g_outdir) == INVALID_FILE_ATTRIBUTES)
        CreateDirectoryA(g_outdir, NULL);

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "[错误] WSAStartup 失败\n");
        return 1;
    }
    wsa_ok = 1;

    sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (sock == INVALID_SOCKET) {
        fprintf(stderr,
                "[错误] 创建 SOCK_RAW 失败，WSAGetLastError=%d\n"
                "       Windows 下使用 Raw Socket 必须以管理员身份运行。\n",
                WSAGetLastError());
        goto done;
    }

    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    memcpy(&bind_addr.sin_addr.s_addr, bind_ip, 4);
    bind_addr.sin_port = 0;
    if (bind(sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) == SOCKET_ERROR) {
        fprintf(stderr, "[错误] bind 失败，WSAGetLastError=%d（请用 -b 指定本机网卡 IP）\n",
                WSAGetLastError());
        goto done;
    }

    /* SIO_RCVALL：Windows 下的混杂模式，抓取网卡收到的所有 IPv4 报文 */
    if (WSAIoctl(sock, SIO_RCVALL, &opt, sizeof(opt), NULL, 0,
                 &bytes, NULL, NULL) == SOCKET_ERROR) {
        fprintf(stderr,
                "[错误] 开启混杂模式(SIO_RCVALL)失败，WSAGetLastError=%d\n"
                "       请以管理员身份运行，并用 -b 指定一块真实的本机网卡 IP。\n",
                WSAGetLastError());
        goto done;
    }

    buf = (uint8_t *)malloc(FLASH_BUFFER_SIZE);
    if (!buf) {
        fprintf(stderr, "[错误] 内存分配失败\n");
        goto done;
    }

    flash_ip_to_str(bind_ip, bindstr, sizeof(bindstr));
    flash_ip_to_str(g_target, targetstr, sizeof(targetstr));
    printf("[启动] FlashReceive 混杂监听已开启\n");
    printf("[启动] 绑定网卡=%s  过滤目的IP=%s  输出目录=%s  空闲超时=%d 秒\n",
           bindstr, targetstr, g_outdir, timeout);
    printf("[启动] 收到分片时实时显示 已收到/总数，例如 10/100。按 Ctrl+C 退出。\n");
    fflush(stdout);

    g_last_packet = time(NULL);

    while (!InterlockedCompareExchange(&g_stop, 0, 0)) {
        fd_set rd;
        struct timeval tv;
        int n;

        FD_ZERO(&rd);
        FD_SET(sock, &rd);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        n = select(0, &rd, NULL, NULL, &tv);
        if (n == SOCKET_ERROR) {
            Sleep(100);
            continue;
        }
        if (n > 0 && FD_ISSET(sock, &rd)) {
            struct sockaddr_in from;
            int fromlen = sizeof(from);
            int len = recvfrom(sock, (char *)buf, FLASH_BUFFER_SIZE, 0,
                              (struct sockaddr *)&from, &fromlen);
            if (len > 0)
                handle_packet(buf, len);
        }
        if (timeout > 0 && time(NULL) - g_last_packet >= timeout) {
            flush_partials();
            g_last_packet = time(NULL);
        }
    }

    printf("\n[退出] 正在停止监听并保存未收齐的文件...\n");
    fflush(stdout);
    flush_partials();

done:
    if (sock != INVALID_SOCKET) {
        opt = RCVALL_OFF;
        bytes = 0;
        WSAIoctl(sock, SIO_RCVALL, &opt, sizeof(opt), NULL, 0,
                 &bytes, NULL, NULL);
        closesocket(sock);
    }
    free(buf);
    while (g_sessions) {
        Session *next = g_sessions->next;
        session_free(g_sessions);
        g_sessions = next;
    }
    if (wsa_ok)
        WSACleanup();
    SetConsoleCtrlHandler(console_handler, FALSE);
    return 0;
}
