/*
 * @Author: LuZizheng lu.zizheng@byd.com
 * @Date: 2025-02-27 18:48:11
 * @LastEditors: LuZizheng lu.zizheng@byd.com
 * @LastEditTime: 2025-02-28 13:32:12
 * @FilePath: /logMgr_deepseek/lognwf.h
 * @Description: 
 * 
 * Copyright (c) 2025 by BYD, All Rights Reserved. 
 */

#ifndef LOGNWF_H
#define LOGNWF_H

#include <stdint.h>
#include <arpa/inet.h>
#include "logMgr.h"

/* 在协议头文件添加字节序转换宏 */
#if defined(_WIN32) || defined(_WIN64)
# include <winsock2.h>
#else
# include <arpa/inet.h>
#endif


/* 修正字节序转换宏 */
#if defined(__linux__)
# include <endian.h>
#elif defined(__FreeBSD__)
# include <sys/endian.h>
#elif defined(_WIN32)
# define __LITTLE_ENDIAN 1234
# define __BYTE_ORDER __LITTLE_ENDIAN
#endif





/* 64位整型字节序转换 */
#ifndef htonll
# if __BYTE_ORDER == __LITTLE_ENDIAN
#  define htonll(x) ((((uint64_t)htonl((x) & 0xFFFFFFFFUL)) << 32) | htonl(((x) >> 32) & 0xFFFFFFFFUL))
# else
#  define htonll(x) (x)
# endif
#endif

/* 原子操作实现（C89兼容） */
#define atomic_fetch_add(ptr, val) __sync_fetch_and_add(ptr, val)



/* 协议头固定14字节 */
#pragma pack(push, 1)
typedef struct {
    uint16_t magic;        // 协议标识 0xA55A
    uint8_t  version;      // 协议版本 0x01
    uint8_t  cmd_type;     // 命令类型
    uint32_t seq_num;      // 序列号（用于请求响应匹配）
    uint32_t data_len;     // 数据部分长度（网络字节序）
    uint16_t checksum;     // 头部校验和（CRC16）
} NetPacketHeader;

/* 协议体根据命令类型变化 */
typedef struct {
    NetPacketHeader header;
    uint8_t data[];        // 变长数据部分
} NetPacket;
#pragma pack(pop)

/* 命令数据格式定义 */
// 0x00 获取信息响应
typedef struct {
    LogMgrLevel current_level;
    LogMgrMode current_mode;
    uint16_t port;         // 当前使用的端口
} GetInfoResponse;

// 0x01 设置级别请求 
typedef struct {
    LogMgrLevel new_level;
    LogMgrMode new_mode;
} SetLevelRequest;

// 0x04 实时日志数据
typedef struct {
    uint64_t timestamp;    // 毫秒时间戳
    uint32_t pid;          // 进程ID
    uint8_t log_level;     // 日志级别
    char     log_msg[];    // 变长日志内容
} RealtimeLogData;


/* 重传控制结构 */
typedef struct {
    uint32_t seq_num;
    time_t send_time;
    int retry_count;
    uint8_t* packet_data;
    size_t packet_len;
    int target_fd;
} RetryItem;

#define MAX_RETRY_QUEUE 64
#define RETRY_TIMEOUT 2  /* 秒 */
#define MAX_RETRIES 3






#endif