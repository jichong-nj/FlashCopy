/*
 * flash_common.h
 * FlashSend / FlashReceive 共用的线上报文格式与工具函数。
 *
 * 报文承载方式：ICMP Echo Request (Type=8, Code=0) 的载荷。
 * 载荷布局：  ICMPEchoHeader(8B) + FlashHeader(48B) + body
 *   body = META 报文 -> 文件名原始字节
 *   body = DATA 报文 -> 文件分片原始字节
 *
 * FlashHeader 全部字段为 uint32_t，统一以网络字节序（大端）传输。
 */
#ifndef FLASH_COMMON_H
#define FLASH_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define FLASH_MAGIC          0x46535350u  /* "FSSP" */
#define FLASH_VERSION        1u
#define FLASH_TYPE_META      0u           /* index = 0，携带文件名 */
#define FLASH_TYPE_DATA      1u           /* index = 1..total */
#define FLASH_HDR_U32_COUNT  12
#define FLASH_MAX_NAME        255
#define FLASH_DEFAULT_CHUNK  1024
#define FLASH_MIN_CHUNK      64
#define FLASH_MAX_CHUNK      1400        /* 8+48+1400+20 = 1476 < 1500 MTU */
#define FLASH_BUFFER_SIZE    65536
#define FLASH_MAX_FRAGMENTS  1000000u    /* 防御异常报文导致内存膨胀 */

#pragma pack(push, 1)
typedef struct FlashHeader {
    uint32_t magic;         /* FLASH_MAGIC */
    uint32_t version;      /* FLASH_VERSION */
    uint32_t session;      /* 一次传输的随机 ID，用于区分不同文件 */
    uint32_t type;         /* FLASH_TYPE_META / FLASH_TYPE_DATA */
    uint32_t index;        /* 分片编号：0=META，1..total=DATA */
    uint32_t total;        /* DATA 分片总数 */
    uint32_t length;       /* 紧跟其后的 body 字节数 */
    uint32_t file_size_hi; /* 原文件大小高 32 位 */
    uint32_t file_size_lo; /* 原文件大小低 32 位 */
    uint32_t name_len;     /* META 有效 */
    uint32_t chunk_size;   /* 分片大小，便于缺失分片补零 */
    uint32_t crc32;         /* body 的 CRC32 */
} FlashHeader;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct IPv4Header {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint8_t  src[4];
    uint8_t  dst[4];
} IPv4Header;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct ICMPEchoHeader {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
} ICMPEchoHeader;
#pragma pack(pop)

typedef char flash_header_size_check[sizeof(FlashHeader) == FLASH_HDR_U32_COUNT * 4 ? 1 : -1];
typedef char flash_ipv4_size_check[sizeof(IPv4Header) == 20 ? 1 : -1];
typedef char flash_icmp_size_check[sizeof(ICMPEchoHeader) == 8 ? 1 : -1];

/* RFC 1071 Internet 校验和。返回的是「网络序数值」，写入报文前请 htons()。 */
uint16_t flash_ip_checksum(const void *buf, int len);
/* 标准 CRC-32 (IEEE 802.3, poly 0xEDB88320) */
uint32_t flash_crc32(const void *buf, size_t len);
/* FlashHeader 全部字段在主机序 / 网络序之间原地转换 */
void flash_header_hton(FlashHeader *h);
void flash_header_ntoh(FlashHeader *h);
/* 点分十进制 <-> 网络序 4 字节 IPv4 */
int  flash_parse_ipv4(const char *s, uint8_t out[4]);
void flash_ip_to_str(const uint8_t ip[4], char *out, size_t cap);

/* ===================== 接收端重组核心 ===================== */
/* 以下状态与函数被 FlashReceive 与回归自测共享，确保测试的就是线上逻辑。 */

typedef struct Fragment {
    uint8_t  *data;   /* NULL 表示该编号的分片尚未收到 */
    uint32_t  len;
} Fragment;

typedef struct Session {
    uint32_t  id;
    char      name[FLASH_MAX_NAME + 1];
    int       has_meta;      /* 是否已拿到文件名（或已生成默认名） */
    uint32_t  total;         /* DATA 分片总数，0 表示未知 */
    uint64_t  file_size;
    uint32_t  chunk_size;
    uint32_t  cap;           /* frags 已分配的槽位数 */
    Fragment *frags;
    uint32_t  received;      /* 1..total 中已收到的分片数 */
    int       complete;
    struct Session *next;
} Session;

extern Session  *g_sessions;
extern int       g_verbose;
extern char      g_outdir[1024];
extern uint8_t   g_target[4];
extern int       g_target_set;   /* 0=不过滤目的IP(捕获全部ICMP)，1=只收 g_target */
extern time_t    g_last_packet;

Session *session_get(uint32_t id, int create);
void     session_free(Session *s);
int      ensure_cap(Session *s, uint32_t idx);
uint32_t count_received(const Session *s);
void     sanitize_name(const char *in, char *out, size_t cap);
void     unique_path(char *path, size_t cap);
void     write_zeros(FILE *f, uint64_t n);
void     write_session_file(Session *s, int partial);
void     check_complete(Session *s);
void     flush_partials(void);
void     handle_packet(const uint8_t *buf, int len);

#endif /* FLASH_COMMON_H */
