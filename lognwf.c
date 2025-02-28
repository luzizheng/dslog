#include "lognwf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>  // 用于定义socklen_t等类型
#include <sys/socket.h> // 用于定义sockaddr_in结构体和socket相关函数
#include <netinet/in.h> // 用于定义sockaddr_in结构体的具体内容
#include <errno.h>
#include <fcntl.h>
#include "logindef.h"

static void remove_client(LogContext *ctx, int fd);
static pthread_mutex_t retry_queue_lock = PTHREAD_MUTEX_INITIALIZER;
static RetryItem retry_queue[MAX_RETRY_QUEUE];
static int retry_queue_size = 0;
void send_response(int fd, NetPacket *packet, size_t pkt_len);
extern void process_client_command(LogContext *ctx, int fd, NetPacketHeader *header);

/* 原子操作实现（C89兼容） */
static volatile unsigned long seq_counter = 0;

/* 64位时间戳转换（Windows兼容） */
#ifdef _WIN32
#define gettimeofday(tv, tz)                                                   \
    do                                                                         \
    {                                                                          \
        FILETIME ft;                                                           \
        GetSystemTimeAsFileTime(&ft);                                          \
        unsigned long long tmp = (ft.dwHighDateTime << 32) | ft.dwLowDateTime; \
        tmp -= 116444736000000000ULL;                                          \
        tv->tv_sec = tmp / 10000000ULL;                                        \
        tv->tv_usec = (tmp % 10000000ULL) / 10;                                \
    } while (0)
#endif

// /* 结构体字段转换函数 */
// static void header_to_host(NetPacketHeader *hdr)
// {
//     hdr->magic = ntohs(hdr->magic);
//     hdr->seq_num = ntohl(hdr->seq_num);
//     hdr->data_len = ntohl(hdr->data_len);
//     hdr->checksum = ntohs(hdr->checksum);
// }

// static void header_to_network(NetPacketHeader *hdr)
// {
//     hdr->magic = htons(hdr->magic);
//     hdr->seq_num = htonl(hdr->seq_num);
//     hdr->data_len = htonl(hdr->data_len);
//     hdr->checksum = htons(hdr->checksum);
// }

/* 添加到重传队列 */
static void add_to_retry_queue(int fd, NetPacket *pkt, size_t pkt_len)
{
    pthread_mutex_lock(&retry_queue_lock);

    if (retry_queue_size >= MAX_RETRY_QUEUE)
    {
        /* 淘汰最旧的数据 */
        free(retry_queue[0].packet_data);
        memmove(retry_queue, retry_queue + 1,
                (MAX_RETRY_QUEUE - 1) * sizeof(RetryItem));
        retry_queue_size--;
    }

    RetryItem *item = &retry_queue[retry_queue_size++];
    item->seq_num = ntohl(pkt->header.seq_num);
    item->send_time = time(NULL);
    item->retry_count = 0;
    item->packet_data = malloc(pkt_len);
    memcpy(item->packet_data, pkt, pkt_len);
    item->packet_len = pkt_len;
    item->target_fd = fd;

    pthread_mutex_unlock(&retry_queue_lock);
}

/* 检查需要重传的数据 */
static void check_retry_queue()
{
    time_t now = time(NULL);
    pthread_mutex_lock(&retry_queue_lock);

    for (int i = 0; i < retry_queue_size;)
    {
        RetryItem *item = &retry_queue[i];

        if (now - item->send_time > RETRY_TIMEOUT)
        {
            if (item->retry_count >= MAX_RETRIES)
            {
                /* 移除超过重试次数的条目 */
                free(item->packet_data);
                memmove(&retry_queue[i], &retry_queue[i + 1],
                        (retry_queue_size - i - 1) * sizeof(RetryItem));
                retry_queue_size--;
                continue;
            }

            /* 执行重传 */
            send(item->target_fd, item->packet_data, item->packet_len, 0);
            item->send_time = now;
            item->retry_count++;
            i++;
        }
        else
        {
            i++;
        }
    }

    pthread_mutex_unlock(&retry_queue_lock);
}

/* 在消息确认时移除队列 */
void remove_from_retry_queue(uint32_t seq_num)
{
    pthread_mutex_lock(&retry_queue_lock);
    for (int i = 0; i < retry_queue_size;)
    {
        if (retry_queue[i].seq_num == seq_num)
        {
            free(retry_queue[i].packet_data);
            memmove(&retry_queue[i], &retry_queue[i + 1],
                    (retry_queue_size - i - 1) * sizeof(RetryItem));
            retry_queue_size--;
        }
        else
        {
            i++;
        }
    }
    pthread_mutex_unlock(&retry_queue_lock);
}

/* 网络线程主函数（完整版） */
void *network_thread_func(void *arg)
{
    LogContext *ctx = (LogContext *)arg;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    fd_set readfds;
    int max_fd;
    struct timeval timeout;
    time_t last_retry_check = 0;

    /* 主循环 */
    while (ctx->running)
    {
        /* 检查重传队列（每秒一次） */
        time_t now = time(NULL);
        if (now - last_retry_check >= 1)
        {
            check_retry_queue();
            last_retry_check = now;
        }

        FD_ZERO(&readfds);
        FD_SET(ctx->sockfd, &readfds);
        max_fd = ctx->sockfd;

        /* 添加客户端套接字到监控集合 */
        pthread_mutex_lock(&ctx->client_lock);
        for (int i = 0; i < ctx->num_clients; ++i)
        {
            if (ctx->client_fds[i] > 0)
            {
                FD_SET(ctx->client_fds[i], &readfds);
                if (ctx->client_fds[i] > max_fd)
                    max_fd = ctx->client_fds[i];
            }
        }
        pthread_mutex_unlock(&ctx->client_lock);

        /* 设置超时（100ms） */
        timeout.tv_sec = 0;
        timeout.tv_usec = 100000;

        int activity = select(max_fd + 1, &readfds, NULL, NULL, &timeout);
        if ((activity < 0) && (errno != EINTR))
        {
            perror("select error");
            continue;
        }

        /* 处理新连接 */
        if (FD_ISSET(ctx->sockfd, &readfds))
        {
            int client_fd = accept(ctx->sockfd, (struct sockaddr *)&addr, &addr_len);
            if (client_fd > 0)
            {
                pthread_mutex_lock(&ctx->client_lock);
                if (ctx->num_clients < MAX_CLIENTS)
                {
                    /* 设置非阻塞模式 */
                    int flags = fcntl(client_fd, F_GETFL, 0);
                    fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);

                    ctx->client_fds[ctx->num_clients++] = client_fd;
                }
                else
                {
                    close(client_fd);
                }
                pthread_mutex_unlock(&ctx->client_lock);
            }
            else
            {
                if (errno == EINTR)
                    continue; // 处理系统中断
                perror("[log-err] accept failed");
                break;
            }
        }

        /* 处理客户端数据 */
        pthread_mutex_lock(&ctx->client_lock);
        for (int i = 0; i < ctx->num_clients;)
        {
            int fd = ctx->client_fds[i];
            if (FD_ISSET(fd, &readfds))
            {
                NetPacketHeader header;
                ssize_t n = recv(fd, &header, sizeof(header), MSG_PEEK);

                if (n <= 0)
                { /* 连接断开 */
                    remove_client(ctx, fd);
                    continue;
                }

                /* 转换字节序 */
                uint16_t magic = ntohs(header.magic);
                if (magic != 0xA55A)
                { /* 协议标识错误 */
                    i++;
                    continue;
                }

                /* 处理完整报文 */
                process_client_command(ctx, fd, &header);
            }
            i++;
        }
        pthread_mutex_unlock(&ctx->client_lock);
    }
    return NULL;
}

/* CRC16校验和计算 */
static uint16_t calc_checksum(const void *data, size_t len)
{
    const uint8_t *bytes = (const uint8_t *)data;
    uint16_t crc = 0xFFFF;

    for (size_t i = 0; i < len; ++i)
    {
        crc ^= bytes[i];
        for (int j = 0; j < 8; ++j)
        {
            if (crc & 0x0001)
            {
                crc = (crc >> 1) ^ 0xA001;
            }
            else
            {
                crc >>= 1;
            }
        }
    }
    return crc;
}

/* 客户端移除函数（线程安全） */
static void remove_client(LogContext *ctx, int fd)
{
    if (fd <= 0)
        return;

    pthread_mutex_lock(&ctx->client_lock);

    /* 遍历查找目标客户端 */
    for (int i = 0; i < ctx->num_clients; ++i)
    {
        if (ctx->client_fds[i] != fd)
            continue;

        /* 关闭套接字 */
        if (close(ctx->client_fds[i]) == -1)
        {
            perror("close client fd failed");
        }

        /* 从数组移除（保持顺序不重要时可优化为交换末尾元素） */
        const int elements_to_move = ctx->num_clients - i - 1;
        if (elements_to_move > 0)
        {
            memmove(&ctx->client_fds[i],
                    &ctx->client_fds[i + 1],
                    elements_to_move * sizeof(int));
        }

        ctx->num_clients--;
        ctx->stats.net_errors++; // 更新统计信息

        /* 因数组已变更，需要重新检查当前位置 */
        i--;
    }

    pthread_mutex_unlock(&ctx->client_lock);

    /* 同时清理重传队列 */
    pthread_mutex_lock(&retry_queue_lock);
    for (int i = 0; i < retry_queue_size;)
    {
        if (retry_queue[i].target_fd == fd)
        { // 直接访问数组
            free(retry_queue[i].packet_data);

            /* 高效移除：交换末尾元素 */
            retry_queue[i] = retry_queue[retry_queue_size - 1];
            retry_queue_size--;
        }
        else
        {
            i++;
        }
    }
    pthread_mutex_unlock(&retry_queue_lock);
}

extern pthread_mutex_t contexts_lock;
extern size_t num_contexts;
extern LogContext **contexts;
/* 通过fd查找上下文（需在全局上下文列表遍历） */
static LogContext *get_context_by_fd(int fd)
{
    pthread_mutex_lock(&contexts_lock);
    for (size_t i = 0; i < num_contexts; ++i)
    {
        for (int j = 0; j < contexts[i]->num_clients; ++j)
        {
            if (contexts[i]->client_fds[j] == fd)
            {
                pthread_mutex_unlock(&contexts_lock);
                return contexts[i];
            }
        }
    }
    pthread_mutex_unlock(&contexts_lock);
    return NULL;
}

/* 增强的响应发送函数（带重传） */
void send_response(int fd, NetPacket *packet, size_t pkt_len)
{
    /* 转换网络字节序 */
    packet->header.magic = htons(packet->header.magic);
    packet->header.seq_num = htonl(packet->header.seq_num);
    packet->header.data_len = htonl(packet->header.data_len);

    /* 计算校验和 */
    packet->header.checksum = 0;
    uint16_t checksum = calc_checksum(packet, pkt_len);
    packet->header.checksum = htons(checksum);

    /* 非阻塞发送并处理错误 */
    ssize_t sent = send(fd, packet, pkt_len, MSG_NOSIGNAL);
    if (sent == -1)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            add_to_retry_queue(fd, packet, pkt_len);
        }
        else if (errno == EPIPE)
        {
            remove_client(get_context_by_fd(fd), fd); // 需要实现fd到上下文的查找
        }
    }
    else if ((size_t)sent < pkt_len)
    {
        /* 部分发送处理 */
        add_partial_to_retry_queue(fd, packet, pkt_len, sent);
    }
    else
    {
        /* 成功发送则加入确认等待队列 */
        add_to_retry_queue(fd, packet, pkt_len);
    }
}

/* 日志网络发送函数（完整跨平台处理） */
void send_log_to_network(LogContext *ctx, const char *formatted_log,
                         LogMgrLevel level)
{
    /* 构造日志数据包 */
    RealtimeLogData log_data;
    struct timeval tv;
    gettimeofday(&tv, NULL);

    /* 填充数据（主机字节序） */
    log_data.timestamp = (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
    log_data.pid = getpid();
    log_data.log_level = (uint8_t)level;
    size_t msg_len = strlen(formatted_log);

    /* 计算总长度 */
    size_t total_len = sizeof(NetPacketHeader) + sizeof(RealtimeLogData) + msg_len;
    NetPacket *packet = malloc(total_len);
    if (!packet)
    {
        ctx->stats.net_errors++;
        return;
    }

    /* 填充协议头 */
    packet->header.magic = 0xA55A; /* 稍后转换字节序 */
    packet->header.version = 0x01;
    packet->header.cmd_type = 0x04;
    packet->header.seq_num = atomic_fetch_add(&ctx->seq_counter, 1);
    packet->header.data_len = sizeof(RealtimeLogData) + msg_len;

    /* 填充日志数据（转换为网络字节序） */
    RealtimeLogData *net_data = (RealtimeLogData *)packet->data;
    net_data->timestamp = htonll(log_data.timestamp);
    net_data->pid = htonl(log_data.pid);
    net_data->log_level = log_data.log_level;
    memcpy(net_data->log_msg, formatted_log, msg_len);

    /* 发送给所有客户端 */
    pthread_mutex_lock(&ctx->client_lock);
    for (int i = 0; i < ctx->num_clients; ++i)
    {
        send_response(ctx->client_fds[i], packet, total_len);
    }
    pthread_mutex_unlock(&ctx->client_lock);

    free(packet);
}

void send_error_response(int fd, uint32_t seq_num, DLTRC error_code)
{
    /* 构建错误消息体 */
#pragma pack(push, 1)
    typedef struct
    {
        uint32_t error_code;
        char error_msg[64];
    } ErrorResponse;
#pragma pack(pop)

    const char *error_str = NULL;
    switch (error_code)
    {
    case DLTRC_PARAMS_ERR:
        error_str = "Invalid parameters";
        break;
    case DLTRC_NOT_SUPPORTED:
        error_str = "Not supported";
        break;
    default:
        error_str = "Unknown error";
    }

    ErrorResponse err_data = {
        .error_code = htonl(error_code),
        .error_msg = {0}};
    strncpy(err_data.error_msg, error_str, sizeof(err_data.error_msg) - 1);

    /* 构建协议头 */
    NetPacket response = {
        .header = {
            .magic = 0xA55A,
            .version = 0x01,
            .cmd_type = 0xFF, // 错误响应类型
            .seq_num = htonl(seq_num),
            .data_len = htonl(sizeof(ErrorResponse))}};

    /* 发送完整报文 */
    uint8_t buffer[sizeof(NetPacketHeader) + sizeof(ErrorResponse)];
    memcpy(buffer, &response, sizeof(NetPacketHeader));
    memcpy(buffer + sizeof(NetPacketHeader), &err_data, sizeof(ErrorResponse));

    send_response(fd, (NetPacket *)buffer, sizeof(buffer));
}

/* 处理设置级别命令 */
void handle_set_level(LogContext *ctx, int fd, NetPacket *packet)
{
    /* 解析请求数据 */
    SetLevelRequest *req = (SetLevelRequest *)packet->data;
    LogMgrLevel new_level = (LogMgrLevel)ntohl(req->new_level);
    LogMgrMode new_mode = (LogMgrMode)ntohl(req->new_mode);

    /* 有效性检查 */
    if (new_level < LogLevel_OFF || new_level > LogLevel_Verbose)
    {
        send_error_response(fd, packet->header.seq_num, DLTRC_PARAMS_ERR);
        return;
    }

    /* 更新上下文 */
    pthread_mutex_lock(&ctx->log_lock);
    ctx->level = new_level;

    /* 模式更新策略：仅更新对应级别的模式 */
    switch (new_level)
    {
    case LogLevel_Fatal:
    case LogLevel_Error:
        ctx->error_mode = new_mode;
        break;
    case LogLevel_Warn:
        ctx->warn_mode = new_mode;
        break;
    default:
        ctx->verbose_mode = new_mode;
        break;
    }
    pthread_mutex_unlock(&ctx->log_lock);

    /* 发送确认响应 */
    NetPacket response = {
        .header = {
            .magic = 0xA55A,
            .version = 0x01,
            .cmd_type = 0x01,
            .seq_num = packet->header.seq_num,
            .data_len = 0}};
    send_response(fd, &response, sizeof(NetPacketHeader));
}
