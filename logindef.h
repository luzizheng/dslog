/*
 * @Author: LuZizheng lu.zizheng@byd.com
 * @Date: 2025-02-27 19:56:08
 * @LastEditors: LuZizheng lu.zizheng@byd.com
 * @LastEditTime: 2025-02-28 09:33:22
 * @FilePath: /logMgr_deepseek/logindef.h
 * @Description: 
 * 
 * Copyright (c) 2025 by BYD, All Rights Reserved. 
 */
#ifndef LOG_INDEF_H
#define LOG_INDEF_H

#include "logMgr.h"
#include <pthread.h>
#define MAX_APPID_LEN      64
#define MAX_PATH_LEN       256
#define MAX_CLIENTS        32
#define MAX_PORT_RETRIES   10


typedef struct LogContext {
    /* 基础信息 */
    char appId[MAX_APPID_LEN];      // 应用标识
    volatile int running;           // 运行状态标志

    /* 日志配置 */
    LogMgrLevel level;              // 当前日志级别
    LogMgrMode verbose_mode;        // 普通级别输出模式
    LogMgrMode warn_mode;           // 警告级别输出模式
    LogMgrMode error_mode;          // 错误级别输出模式
    
    /* 文件相关配置 */
    size_t log_file_max_size;       // 单个文件最大尺寸（字节）
    char log_file_dir[MAX_PATH_LEN];// 文件日志存储路径
    char log_mem_dir[MAX_PATH_LEN]; // 内存日志存储路径
    
    /* 网络相关 */
    int sockfd;                     // 主监听套接字
    uint16_t listen_port;           // 实际监听端口
    struct {
        uint16_t start;             // 端口起始范围
        uint16_t end;              // 端口结束范围
        uint16_t offset;            // 端口偏移量（来自XML配置）
    } port_config;
    
    /* 客户端连接管理 */
    pthread_mutex_t client_lock;    // 客户端列表锁
    int client_fds[MAX_CLIENTS];    // 客户端连接描述符数组
    int num_clients;               // 当前连接客户端数
    
    /* 线程管理 */
    pthread_t network_thread;       // 网络服务线程
    pthread_mutex_t log_lock;       // 日志输出锁
    
    /* 网络重传队列 */
    struct {
        RetryItem items[MAX_RETRY_QUEUE];
        int size;
    } retry_queue;
    
    /* 统计信息 */
    struct {
        uint64_t log_count;         // 总日志数量
        uint64_t net_errors;        // 网络错误计数
        uint64_t drop_count;        // 丢弃日志计数
    } stats;
    
    /* 原子操作计数器 */
    volatile uint32_t seq_counter;  // 包序列号生成器
    
    /* DDS相关预留字段 */
    void* dds_writer;               // DDS数据写入器指针
    
    /* 内存日志缓存（环形缓冲区） */
    struct {
        char* buffer;               // 缓冲区指针
        size_t capacity;            // 总容量
        size_t head;                // 写入位置
        size_t tail;                // 读取位置
    } mem_buffer;
} LogContext;




#endif 