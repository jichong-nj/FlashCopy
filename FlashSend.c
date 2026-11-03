/*
 * FlashSend.c
 * 将一个文件切分成带编号的 ICMP Echo Request 报文（文件名放在编号 0 的元信息
 * 报文里），通过 nping.exe 发往指定的目的 IP。只发不等收：nping 以 -N 运行，
 * 不等待任何 Echo Reply；目的 IP 是否存在、是否可达都不影响发送流程。
 *
 * 用法: FlashSend.exe <目的IP> <文件> [选项]
 * 依赖: nping.exe（Nmap 自带）必须在 PATH 中。
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "flash_common.h"

/* 是否打印每个报文传给 nping 的载荷（FlashHeader+body）十六进制转储，由 -x 开启 */
static int g_dump = 0;
static int g_parallel = 5;   /* 并发 nping 进程数，由 -n 指定 */

/* 传给 nping --data 的载荷上限：FlashHeader + 最大分片/最大文件名 + 余量 */
#define MAX_PAYLOAD (sizeof(FlashHeader) + FLASH_MAX_CHUNK + FLASH_MAX_NAME + 16)

/* 把一段缓冲区按 16 字节一行做经典 hex+ascii 转储 */
static void hexdump(const uint8_t *p, size_t len, const char *tag)
{
    size_t i, j;
    printf("    [%s] 载荷共 %u 字节 (ICMP 头由 nping 生成):\n", tag ? tag : "PAY", (unsigned)len);
    for (i = 0; i < len; i += 16) {
        printf("    %04X: ", (unsigned)i);
        for (j = 0; j < 16; ++j) {
            if (i + j < len)
                printf("%02X ", p[i + j]);
            else
                printf("   ");
        }
        printf(" |");
        for (j = 0; j < 16 && i + j < len; ++j) {
            uint8_t c = p[i + j];
            putchar((c >= 0x20 && c < 0x7F) ? (int)c : '.');
        }
        printf("|\n");
    }
    fflush(stdout);
}

static void print_usage(const char *prog)
{
    printf(
        "FlashSend - 通过 nping.exe 把文件切成带编号的 Ping 报文发往指定目的 IP（只发不等收）\n"
        "\n"
        "用法: %s <目的IP> <文件> [选项]\n"
        "\n"
        "  <目的IP>   目的地址，可以是一个并不存在的地址\n"
        "  <文件>     要发送的文件路径\n"
        "\n"
        "选项:\n"
        "  -s <字节>  分片大小，默认 1024，范围 64..1400\n"
        "  -d <毫秒>  同一 nping 进程内重复报文之间的间隔，默认 2（0 表示不等待）\n"
        "  -r <次数>  整份文件重复发送的次数，默认 1\n"
        "  -m <次数>  元信息报文在每轮中的重发次数，默认 3\n"
        "  -n <并发>  并发启动的 nping 进程数（加速大文件发送），默认 5\n"
        "  -b <本机IP> 通过 nping -S 指定源 IP（默认由系统路由决定）\n"
        "  -x         打印每个报文传给 nping 的载荷（十六进制转储）\n"
        "  -h         显示本帮助\n"
        "\n"
        "说明: 依赖 nping.exe（Nmap 自带），需让其位于 PATH；程序不会等待任何回显报文。\n"
        "      若希望同一局域网内其它主机抓到这些包，可把 <目的IP> 设为广播地址\n"
        "      （如 192.168.1.255），接收端用同一个地址作为过滤目标。\n"
        "\n",
        prog);
}

static void basename_of(const char *path, char *out, size_t cap)
{
    const char *base = path;
    const char *p;
    size_t n;

    for (p = path; *p; ++p)
        if (*p == '\\' || *p == '/')
            base = p + 1;
    n = strlen(base);
    if (n >= cap)
        n = cap - 1;
    memcpy(out, base, n);
    out[n] = '\0';
}

/*
 * 构造传给 nping --data 的载荷：FlashHeader(48B) + body(文件名或分片)。
 * 返回载荷字节数；buffer 不足时返回 0。
 */
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

    if (len > cap)
        return 0;

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
    if (body_len)
        memcpy(buf + sizeof(h), body, body_len);
    return len;
}

static void to_hex(const uint8_t *p, size_t len, char *out)
{
    static const char *hx = "0123456789ABCDEF";
    size_t i;
    for (i = 0; i < len; ++i) {
        out[2 * i]     = hx[(p[i] >> 4) & 0xF];
        out[2 * i + 1] = hx[p[i] & 0xF];
    }
    out[2 * len] = '\0';
}

/*
 * 并发池：最多同时运行 g_parallel 个 nping 子进程。
 * g_pool 存放仍在运行的子进程句柄，g_pool_n 为当前数量。
 */
#define MAX_PARALLEL 64
static HANDLE g_pool[MAX_PARALLEL];
static int    g_pool_n = 0;

/*
 * 通过 nping.exe 发送 count 个相同的载荷（同一分片内容相同，故可一次性批量发送）。
 * 用 CreateProcess 启动 nping，并把它的 stdout/stderr 重定向到 NUL（FlashSend 只发不等收，
 * 不需要 nping 的输出，也避免多个并发进程的输出在控制台交错）。
 * 返回子进程句柄供并发池管理；返回 NULL 表示启动失败（已打印告警）。
 */
static HANDLE spawn_nping(const char *dest_ip, const char *bind_str,
                          const uint8_t *payload, size_t pay_len,
                          uint32_t count, int delay_ms)
{
    char hex[2 * MAX_PAYLOAD + 1];
    char cmd[8192];
    int off = 0;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    SECURITY_ATTRIBUTES sa;
    HANDLE hnul;
    BOOL ok;

    to_hex(payload, pay_len, hex);
    off += snprintf(cmd + off, sizeof(cmd) - off,
                    "nping --icmp --icmp-type 8 --icmp-code 0 --icmp-id 1 "
                    "--data %s -c %u -N", hex, count);
    if (delay_ms > 0)
        off += snprintf(cmd + off, sizeof(cmd) - off, " --delay %dms", delay_ms);
    if (bind_str)
        off += snprintf(cmd + off, sizeof(cmd) - off, " -S %s", bind_str);
    off += snprintf(cmd + off, sizeof(cmd) - off, " %s", dest_ip);

    /* 把 nping 的输出重定向到 NUL */
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    hnul = CreateFileA("NUL", GENERIC_WRITE, FILE_SHARE_WRITE, &sa,
                       OPEN_EXISTING, 0, NULL);

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput  = (hnul != INVALID_HANDLE_VALUE) ? hnul : GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = (hnul != INVALID_HANDLE_VALUE) ? hnul : GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError  = (hnul != INVALID_HANDLE_VALUE) ? hnul : GetStdHandle(STD_ERROR_HANDLE);

    ZeroMemory(&pi, sizeof(pi));
    ok = CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
    if (hnul != INVALID_HANDLE_VALUE)
        CloseHandle(hnul);

    if (!ok) {
        fprintf(stderr, "[错误] 无法启动 nping（CreateProcess 失败，请确认 nping.exe 在 PATH 中）\n");
        return NULL;
    }
    CloseHandle(pi.hThread);
    return pi.hProcess;   /* 调用方负责 WaitForSingleObject + CloseHandle */
}

/* 等待池中任意一个 nping 结束，回收其句柄并打印非零退出告警 */
static void pool_wait_one(void)
{
    DWORD r = WaitForMultipleObjects((DWORD)g_pool_n, g_pool, FALSE, INFINITE);
    if (r >= WAIT_OBJECT_0 && r < WAIT_OBJECT_0 + (DWORD)g_pool_n) {
        int k = (int)(r - WAIT_OBJECT_0);
        DWORD ec = 0;
        if (GetExitCodeProcess(g_pool[k], &ec) && ec != 0)
            fprintf(stderr, "[警告] nping 退出码 %lu（可能权限不足或发送失败）\n",
                    (unsigned long)ec);
        CloseHandle(g_pool[k]);
        g_pool[k] = g_pool[g_pool_n - 1];
        g_pool_n--;
    }
}

/* 等待并回收池中所有仍在运行的 nping */
static void pool_drain(void)
{
    while (g_pool_n > 0)
        pool_wait_one();
}

int main(int argc, char **argv)
{
    HANDLE hf = INVALID_HANDLE_VALUE;
    LARGE_INTEGER li, zero;
    uint64_t file_size = 0;
    uint32_t total = 0;
    uint32_t session;
    uint32_t chunk = FLASH_DEFAULT_CHUNK;
    int delay_ms = 2;
    int rounds = 1;
    int meta_repeat = 3;
    const char *dest_ip = NULL;
    const char *path = NULL;
    const char *bind_str = NULL;
    uint8_t dst_ip[4];
    uint8_t bind_ip[4];
    int has_bind = 0;
    char name[FLASH_MAX_NAME + 1];
    uint8_t *payload = NULL;
    uint8_t *data_buf = NULL;
    uint32_t sent_data = 0, sent_meta = 0;
    DWORD t0;
    int i;
    uint32_t idx;

    SetConsoleOutputCP(CP_UTF8);

    for (i = 1; i < argc; ++i) {
        if (argv[i][0] == '-') {
            if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
                print_usage(argv[0]);
                return 0;
            } else if (!strcmp(argv[i], "-s") && i + 1 < argc) {
                chunk = (uint32_t)strtoul(argv[++i], NULL, 10);
            } else if (!strcmp(argv[i], "-d") && i + 1 < argc) {
                delay_ms = atoi(argv[++i]);
            } else if (!strcmp(argv[i], "-r") && i + 1 < argc) {
                rounds = atoi(argv[++i]);
            } else if (!strcmp(argv[i], "-m") && i + 1 < argc) {
                meta_repeat = atoi(argv[++i]);
            } else if (!strcmp(argv[i], "-n") && i + 1 < argc) {
                g_parallel = atoi(argv[++i]);
            } else if (!strcmp(argv[i], "-b") && i + 1 < argc) {
                bind_str = argv[++i];
            } else if (!strcmp(argv[i], "-x") || !strcmp(argv[i], "--dump")) {
                g_dump = 1;
            } else {
                fprintf(stderr, "[错误] 未知选项或缺少参数: %s\n", argv[i]);
                return 2;
            }
        } else {
            if (!dest_ip)      dest_ip = argv[i];
            else if (!path)    path = argv[i];
            else {
                fprintf(stderr, "[错误] 参数过多: %s\n", argv[i]);
                return 2;
            }
        }
    }

    if (!dest_ip || !path) {
        print_usage(argv[0]);
        return 2;
    }
    if (chunk < FLASH_MIN_CHUNK || chunk > FLASH_MAX_CHUNK) {
        fprintf(stderr, "[错误] 分片大小必须在 %d..%d 之间\n",
                FLASH_MIN_CHUNK, FLASH_MAX_CHUNK);
        return 2;
    }
    if (delay_ms < 0 || rounds < 1 || meta_repeat < 1) {
        fprintf(stderr, "[错误] -d/-r/-m 参数不合法\n");
        return 2;
    }
    if (g_parallel < 1 || g_parallel > MAX_PARALLEL) {
        fprintf(stderr, "[错误] -n 并发数必须在 1..%d 之间\n", MAX_PARALLEL);
        return 2;
    }
    if (!flash_parse_ipv4(dest_ip, dst_ip)) {
        fprintf(stderr, "[错误] 非法的 IPv4 地址: %s\n", dest_ip);
        return 2;
    }
    if (bind_str) {
        if (!flash_parse_ipv4(bind_str, bind_ip)) {
            fprintf(stderr, "[错误] -b 指定的本机 IP 非法: %s\n", bind_str);
            return 2;
        }
        has_bind = 1;
    }

    basename_of(path, name, sizeof(name));

    hf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                     NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[错误] 无法打开文件 %s，GetLastError=%lu\n",
                path, (unsigned long)GetLastError());
        return 1;
    }
    if (!GetFileSizeEx(hf, &li)) {
        fprintf(stderr, "[错误] 无法取得文件大小，GetLastError=%lu\n",
                (unsigned long)GetLastError());
        CloseHandle(hf);
        return 1;
    }
    file_size = (uint64_t)li.QuadPart;
    if (file_size / chunk > FLASH_MAX_FRAGMENTS) {
        fprintf(stderr, "[错误] 文件过大，分片数超过上限 %u\n", FLASH_MAX_FRAGMENTS);
        CloseHandle(hf);
        return 1;
    }
    total = (uint32_t)((file_size + chunk - 1) / chunk);
    if (total == 0)
        total = 1;   /* 空文件也发一个 0 字节分片，保证接收端能收敛 */

    srand((unsigned)(GetTickCount() ^ (DWORD)GetCurrentProcessId()
                     ^ (DWORD)time(NULL)));
    session = ((uint32_t)GetTickCount() << 11)
              ^ ((uint32_t)GetCurrentProcessId() << 3)
              ^ (uint32_t)rand() ^ ((uint32_t)rand() << 16);
    if (session == 0)
        session = 0xA5A55A5Au;

    payload  = (uint8_t *)malloc(MAX_PAYLOAD);
    data_buf = (uint8_t *)malloc(chunk);
    if (!payload || !data_buf) {
        fprintf(stderr, "[错误] 内存分配失败\n");
        goto done;
    }

    printf("[启动] 文件=\"%s\" 大小=%llu B 分片大小=%u B 分片数=%u 会话=0x%08X\n",
           path, (unsigned long long)file_size, chunk, total, session);
    printf("[启动] 目的IP=%s 源IP=%s 轮数=%d 元信息重发=%d 间隔=%d ms 并发=%d（经 nping 发送，只发不等收）\n",
           dest_ip, has_bind ? bind_str : "系统路由决定",
           rounds, meta_repeat, delay_ms, g_parallel);
    fflush(stdout);

    t0 = GetTickCount();

    /* 元信息：一次性批量发送 meta_repeat*rounds 次 */
    {
        size_t pl = build_payload(payload, MAX_PAYLOAD, session, FLASH_TYPE_META, 0,
                                  total, file_size, chunk,
                                  name, (uint32_t)strlen(name), NULL, 0);
        uint32_t meta_count = (uint32_t)meta_repeat * (uint32_t)rounds;
        if (pl == 0) {
            fprintf(stderr, "[错误] 元信息载荷过长\n");
            goto done;
        }
        if (g_dump)
            hexdump(payload, pl, "元信息");
        if (g_pool_n >= g_parallel) pool_wait_one();
        {
            HANDLE h = spawn_nping(dest_ip, has_bind ? bind_str : NULL,
                                   payload, pl, meta_count, delay_ms);
            if (h) {
                g_pool[g_pool_n++] = h;
                sent_meta += meta_count;
            }
        }
        printf("[发送] 元信息 会话=0x%08X 文件名=\"%s\" 共 %u 片 大小=%llu B 重发=%u -> %s\n",
               session, name, total,
               (unsigned long long)file_size, meta_count, dest_ip);
        fflush(stdout);
    }

    /* 数据分片：每片批量发送 rounds 次 */
    zero.QuadPart = 0;
    if (!SetFilePointerEx(hf, zero, NULL, FILE_BEGIN)) {
        fprintf(stderr, "[错误] 重置文件指针失败，GetLastError=%lu\n",
                (unsigned long)GetLastError());
        goto done;
    }

    for (idx = 1; idx <= total; ++idx) {
        uint64_t off = (uint64_t)(idx - 1) * chunk;
        uint64_t rem = (off < file_size) ? (file_size - off) : 0;
        DWORD want = (DWORD)((rem > chunk) ? chunk : rem);
        DWORD got = 0;
        size_t pl;

        if (want > 0) {
            if (!ReadFile(hf, data_buf, want, &got, NULL)) {
                fprintf(stderr, "[错误] 读取文件失败，GetLastError=%lu\n",
                        (unsigned long)GetLastError());
                goto done;
            }
        }

        pl = build_payload(payload, MAX_PAYLOAD, session, FLASH_TYPE_DATA, idx,
                           total, file_size, chunk, NULL, 0, data_buf, (uint32_t)got);
        if (pl == 0) {
            fprintf(stderr, "[错误] 数据载荷过长\n");
            goto done;
        }
        if (g_dump) {
            char tag[32];
            snprintf(tag, sizeof(tag), "数据#%u", idx);
            hexdump(payload, pl, tag);
        }
        if (g_pool_n >= g_parallel) pool_wait_one();
        {
            HANDLE h = spawn_nping(dest_ip, has_bind ? bind_str : NULL,
                                  payload, pl, (uint32_t)rounds, delay_ms);
            if (h) {
                g_pool[g_pool_n++] = h;
                sent_data += (uint32_t)rounds;
            }
        }
        printf("[发送] 第 %u/%u 片  %u B  重发=%u  会话=0x%08X -> %s\n",
               idx, total, (unsigned)got, (unsigned)rounds, session, dest_ip);
        fflush(stdout);
    }

    pool_drain();   /* 等所有并发 nping 真正发完，再统计耗时 */

    printf("\n[完成] 会话=0x%08X 共经 nping 发出 元信息 %u 个 / 数据分片 %u 个，"
           "耗时 %lu ms\n",
           session, sent_meta, sent_data,
           (unsigned long)(GetTickCount() - t0));
    printf("[完成] 全程未等待、未接收任何回显报文（只发不等收）。\n");
    fflush(stdout);

done:
    pool_drain();   /* 回收仍在运行的 nping 子进程，避免句柄泄漏 */
    if (hf != INVALID_HANDLE_VALUE)
        CloseHandle(hf);
    free(payload);
    free(data_buf);
    return 0;
}
