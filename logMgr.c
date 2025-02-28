/* log_service.c - 核心实现 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdbool.h>
#include "lognwf.h"
#include <pthread.h>
#include "logindef.h"

/* 函数声明 */

extern void *network_thread_func(void *arg);
extern void handle_set_level(LogContext *ctx, int fd, NetPacket *packet);
extern void remove_from_retry_queue(uint32_t seq_num);
extern void send_error_response(int fd, uint32_t seq_num, DLTRC error_code);
extern void send_response(int fd, NetPacket *packet, size_t pkt_len);
static void handle_get_info(LogContext *ctx, int fd, NetPacket *packet);
void send_log_to_network(LogContext *ctx, const char *formatted_log, LogMgrLevel level);

static pthread_mutex_t contexts_lock = PTHREAD_MUTEX_INITIALIZER;
static LogContext **contexts = NULL;
static size_t num_contexts = 0;


static void handle_subscribe_log(LogContext* ctx, int fd)
{
    /* 检查客户端是否已存在 */
    pthread_mutex_lock(&ctx->client_lock);
    
    int already_subscribed = 0;
    for(int i=0; i<ctx->num_clients; ++i) {
        if(ctx->client_fds[i] == fd) {
            already_subscribed = 1;
            break;
        }
    }

    /* 添加新订阅 */
    if(!already_subscribed && ctx->num_clients < MAX_CLIENTS) {
        ctx->client_fds[ctx->num_clients++] = fd;
        
        /* 发送订阅确认 */
        NetPacket ack = {
            .header = {
                .magic = 0xA55A,
                .version = 0x01,
                .cmd_type = 0x04,
                .seq_num = atomic_fetch_add(&ctx->seq_counter, 1),
                .data_len = htonl(0)
            }
        };
        send_response(fd, &ack, sizeof(NetPacketHeader));
    } else {
        /* 发送错误响应 */
        send_error_response(fd, 0, DLTRC_NOT_SUPPORTED);
    }

    pthread_mutex_unlock(&ctx->client_lock);
}

/* 命令处理函数 */
void process_client_command(LogContext *ctx, int fd,
                                   NetPacketHeader *header)
{
    uint32_t data_len = ntohl(header->data_len);
    uint8_t *buffer = malloc(sizeof(NetPacketHeader) + data_len);

    // 读取完整报文
    ssize_t total = recv(fd, buffer, sizeof(NetPacketHeader) + data_len, 0);
    if (total != (ssize_t)(sizeof(NetPacketHeader) + data_len))
    {
        free(buffer);
        return;
    }

    NetPacket *packet = (NetPacket *)buffer;
    switch (packet->header.cmd_type)
    {
    case 0x00: // 获取信息
        handle_get_info(ctx, fd, packet);
        break;
    case 0x01: // 设置级别
        handle_set_level(ctx, fd, packet);
        break;
    case 0x04: // 订阅实时日志
        handle_subscribe_log(ctx, fd);
        break;
    case 0x05: // ACK处理
    {
        uint32_t ack_seq = ntohl(*(uint32_t *)packet->data);
        remove_from_retry_queue(ack_seq);
        break;
    }
    }
    free(buffer);
}

/* 处理获取信息请求 */
static void handle_get_info(LogContext *ctx, int fd, NetPacket *packet)
{
    NetPacket response;
    response.header.magic = htons(0xA55A);
    response.header.version = 0x01;
    response.header.cmd_type = 0x00;
    response.header.seq_num = packet->header.seq_num;

    GetInfoResponse info = {
        .current_level = ctx->level,
        .current_mode = ctx->verbose_mode, // 示例取verbose模式
        .port = htons(ctx->listen_port)};

    response.header.data_len = htonl(sizeof(GetInfoResponse));
    // 计算checksum...

    send(fd, &response, sizeof(NetPacketHeader), 0);
    send(fd, &info, sizeof(GetInfoResponse), 0);
}

/* 初始化上下文示例 */
LogContext* create_context(const char* appId) {
    LogContext* ctx = calloc(1, sizeof(LogContext));
    strncpy(ctx->appId, appId, MAX_APPID_LEN-1);
    
    pthread_mutex_init(&ctx->client_lock, NULL);
    pthread_mutex_init(&ctx->log_lock, NULL);
    
    ctx->port_config.start = 8000;
    ctx->port_config.end = 8500;
    ctx->running = 1;
    
    return ctx;
}

/* 配套资源管理函数 */
void destroy_context(LogContext* ctx) {
    if(ctx->sockfd > 0) close(ctx->sockfd);
    if(ctx->mem_buffer.buffer) free(ctx->mem_buffer.buffer);
    pthread_mutex_destroy(&ctx->client_lock);
    pthread_mutex_destroy(&ctx->log_lock);
    free(ctx);
}


const char* log_level_str(LogMgrLevel level)
{
    static const char* const level_strings[] = {
        "OFF",      // 0
        "FATAL",    // 1
        "ERROR",    // 2
        "WARN",     // 3
        "INFO",     // 4
        "DEBUG",    // 5
        "VERBOSE",  // 6
        "UNKNOWN"   // 7
    };

    const size_t max_index = sizeof(level_strings)/sizeof(level_strings[0]) - 1;
    const unsigned int index = (level < 0) ? 0 : ( (level > max_index) ? max_index : level );
    return level_strings[index];
}

void parse_xml_config(LogContext * _cxt, const char *appid)
{
    // 需要实现
}

/* 初始化 */
DLTRC dlt_init_client(const char *appId) 
{
    /* 参数校验 */
    if (!appId || strlen(appId) >= MAX_APPID_LEN)
        return DLTRC_PARAMS_ERR;

    pthread_mutex_lock(&contexts_lock);

    /* 检查重复初始化 */
    for (size_t i = 0; i < num_contexts; ++i) {
        if (strcmp(contexts[i]->appId, appId) == 0) {
            pthread_mutex_unlock(&contexts_lock);
            return DLTRC_FW_EXIST;
        }
    }

    /* 分配上下文 */
    LogContext* ctx = calloc(1, sizeof(LogContext));
    if (!ctx) {
        pthread_mutex_unlock(&contexts_lock);
        return DLTRC_OUTOF_MEM;
    }

    /* 基础初始化 */
    strncpy(ctx->appId, appId, MAX_APPID_LEN-1);
    ctx->running = 1;
    ctx->seq_counter = 0;
    
    /* 初始化互斥锁 */
    pthread_mutex_init(&ctx->client_lock, NULL);
    pthread_mutex_init(&ctx->log_lock, NULL);

    /* 解析XML配置 */
    parse_xml_config(ctx,appId); // 伪函数，需实现XML解析

    /* 网络端口初始化 */
    int port = ctx->port_config.start + ctx->port_config.offset;
    for (int retry = 0; retry < MAX_PORT_RETRIES; ++retry) {
        ctx->sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (ctx->sockfd < 0) break;

        struct sockaddr_in addr = {
            .sin_family = AF_INET,
            .sin_addr.s_addr = INADDR_ANY,
            .sin_port = htons(port)
        };

        if (bind(ctx->sockfd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            ctx->listen_port = port;
            listen(ctx->sockfd, 5);
            break;
        }
        close(ctx->sockfd);
        port = (port + 1) % (ctx->port_config.end + 1);
    }

    if (ctx->sockfd < 0) {
        free(ctx);
        pthread_mutex_unlock(&contexts_lock);
        return DLTRC_WRITER_INIT_ERR;
    }

    /* 启动网络线程 */
    if (pthread_create(&ctx->network_thread, NULL, 
                      network_thread_func, ctx) != 0) {
        close(ctx->sockfd);
        free(ctx);
        pthread_mutex_unlock(&contexts_lock);
        return DLTRC_WRITER_INIT_ERR;
    }

    /* 添加到全局列表 */
    contexts = realloc(contexts, (num_contexts+1)*sizeof(LogContext*));
    contexts[num_contexts++] = ctx;

    pthread_mutex_unlock(&contexts_lock);
    return DLTRC_OK;
}

static bool levelFilter(LogMgrLevel defaultLv, LogMgrLevel curLv)
{

    if (defaultLv == LogLevel_Debug || defaultLv == LogLevel_Info || defaultLv == LogLevel_Verbose)
    {
        return true;
    }
    else if (defaultLv == LogLevel_Warn)
    {
        if (curLv == LogLevel_Warn || curLv == LogLevel_Error || curLv == LogLevel_Fatal)
        {
            return true;
        }
    }
    else if (defaultLv == LogLevel_Fatal || defaultLv == LogLevel_Error)
    {
        if (curLv == LogLevel_Error || curLv == LogLevel_Fatal)
        {
            return true;
        }
    }
    else if (defaultLv == LogLevel_OFF)
    {
        return false;
    }
    return false;
}

/* 通用日志实现 */ 
static DLTRC log_common(
    const char* appId, 
    LogMgrLevel level,
    const char* szFormat,
    va_list args)
{
    LogContext* ctx = NULL;
    
    /* 查找上下文 */
    pthread_mutex_lock(&contexts_lock);
    for (size_t i=0; i<num_contexts; ++i) {
        if (strcmp(contexts[i]->appId, appId) == 0) {
            ctx = contexts[i];
            break;
        }
    }
    pthread_mutex_unlock(&contexts_lock);

    if (!ctx) return DLTRC_NOT_FOUND_APP;
    if (ctx->level == LogLevel_OFF) return DLTRC_LOGENABLE_FALSE;
    if (levelFilter(ctx->level,level) == false) return DLTRC_LEVEL_ABORT;

    /* 生成日志头 */
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm_buf;
    localtime_r(&tv.tv_sec, &tm_buf);

    char header[256];
    snprintf(header, sizeof(header),
        "[%04d-%02d-%02d %02d:%02d:%02d.%03ld][PID:%d][%s]",
        tm_buf.tm_year+1900, tm_buf.tm_mon+1, tm_buf.tm_mday,
        tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec, tv.tv_usec/1000,
        getpid(), log_level_str(level));

    /* 格式化消息体 */
    char message[4096];
    vsnprintf(message, sizeof(message), szFormat, args);

    /* 组合完整日志 */
    char full_log[4352]; // 256+4096+分隔符
    snprintf(full_log, sizeof(full_log), "%s %s\n", header, message);

    /* 确定输出模式 */
    LogMgrMode mode;
    switch(level) {
        case LogLevel_Fatal:
        case LogLevel_Error: mode = ctx->error_mode; break;
        case LogLevel_Warn:  mode = ctx->warn_mode;  break;
        default:             mode = ctx->verbose_mode;
    }

    /* 输出到不同目标 */
    pthread_mutex_lock(&ctx->log_lock);
    
    // 控制台输出
    if (mode & LogMode_Console) {
        fputs(full_log, stdout);
        fflush(stdout);
    }

    // 网络输出
    if (mode & LogMode_Network) {
        send_log_to_network(ctx, full_log, level);
    }

    // 文件输出（预留接口）
    if (mode & LogMode_File) {
        // file_writer_write(ctx, full_log);
    }

    // 内存缓存（环形缓冲区）
    if (mode & LogMode_Mem) {
        size_t len = strlen(full_log);
        pthread_mutex_lock(&ctx->log_lock);
        if (ctx->mem_buffer.capacity > 0) {
            size_t avail = ctx->mem_buffer.capacity - 
                (ctx->mem_buffer.head - ctx->mem_buffer.tail);
            if (avail < len) {
                ctx->stats.drop_count++;
            } else {
                size_t wrap = ctx->mem_buffer.capacity - 
                    (ctx->mem_buffer.head % ctx->mem_buffer.capacity);
                size_t copy_len = (len > wrap) ? wrap : len;
                memcpy(ctx->mem_buffer.buffer + ctx->mem_buffer.head, 
                      full_log, copy_len);
                if (copy_len < len) {
                    memcpy(ctx->mem_buffer.buffer, 
                          full_log + copy_len, len - copy_len);
                }
                ctx->mem_buffer.head += len;
            }
        }
        pthread_mutex_unlock(&ctx->log_lock);
    }

    pthread_mutex_unlock(&ctx->log_lock);
    ctx->stats.log_count++;
    return DLTRC_OK;
}

DLTRC dlt_log_fatal(const char *appId, const char *szFormat, ...)
{
    va_list args;
    va_start(args, szFormat);
    DLTRC ret = log_common(appId, LogLevel_Fatal, szFormat, args);
    va_end(args);
    return ret;
}
DLTRC dlt_log_error(const char *appId, const char *szFormat, ...)
{
    va_list args;
    va_start(args, szFormat);
    DLTRC ret = log_common(appId, LogLevel_Error, szFormat, args);
    va_end(args);
    return ret;
}
DLTRC dlt_log_warn(const char *appId, const char *szFormat, ...)
{
    va_list args;
    va_start(args, szFormat);
    DLTRC ret = log_common(appId, LogLevel_Warn, szFormat, args);
    va_end(args);
    return ret;
}
DLTRC dlt_log_info(const char *appId, const char *szFormat, ...)
{
    va_list args;
    va_start(args, szFormat);
    DLTRC ret = log_common(appId, LogLevel_Info, szFormat, args);
    va_end(args);
    return ret;
}
DLTRC dlt_log_debug(const char *appId, const char *szFormat, ...)
{
    va_list args;
    va_start(args, szFormat);
    DLTRC ret = log_common(appId, LogLevel_Debug, szFormat, args);
    va_end(args);
    return ret;
}
DLTRC dlt_log_verbose(const char *appId, const char *szFormat, ...)
{
    va_list args;
    va_start(args, szFormat);
    DLTRC ret = log_common(appId, LogLevel_Verbose, szFormat, args);
    va_end(args);
    return ret;
}

/* 清理资源 ... */
void dlt_free_client(const char *appId)
{
    pthread_mutex_lock(&contexts_lock);
    
    for (size_t i = 0; i < num_contexts; ++i) {
        if (strcmp(contexts[i]->appId, appId) != 0) 
            continue;

        LogContext* ctx = contexts[i];
        
        /* 停止网络线程 */
        ctx->running = 0;
        pthread_join(ctx->network_thread, NULL);

        /* 关闭网络连接 */
        close(ctx->sockfd);
        pthread_mutex_lock(&ctx->client_lock);
        for (int j=0; j<ctx->num_clients; ++j) {
            close(ctx->client_fds[j]);
        }
        ctx->num_clients = 0;
        pthread_mutex_unlock(&ctx->client_lock);

        /* 释放内存资源 */
        if (ctx->mem_buffer.buffer) 
            free(ctx->mem_buffer.buffer);

        /* 销毁互斥锁 */
        pthread_mutex_destroy(&ctx->client_lock);
        pthread_mutex_destroy(&ctx->log_lock);

        /* 从全局列表移除 */
        memmove(&contexts[i], &contexts[i+1], 
               (num_contexts-i-1)*sizeof(LogContext*));
        num_contexts--;
        free(ctx);
        break;
    }

    pthread_mutex_unlock(&contexts_lock);
}