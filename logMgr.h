/*
 * @Author: LuZizheng lu.zizheng@byd.com
 * @Date: 2025-02-27 18:30:51
 * @LastEditors: LuZizheng lu.zizheng@byd.com
 * @LastEditTime: 2025-02-28 13:29:28
 * @FilePath: /logMgr_deepseek/logMgr.h
 * @Description: 
 * 
 * Copyright (c) 2025 by BYD, All Rights Reserved. 
 */
/* log_service.h - 严格C89兼容 */
#ifndef LOG_MGR_H
#define LOG_MGR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include <stdint.h>


#define MAX_LOG_LEN 256

typedef enum
{
    LogLevel_NotDefine = -1,
    LogLevel_OFF       = 0,
    LogLevel_Fatal     = 1,
    LogLevel_Error     = 2, // = LogLevel_Fatal
    LogLevel_Warn      = 3,
    LogLevel_Info      = 4,  //  = LogLevel_Verbose
    LogLevel_Debug     = 5, // = LogLevel_Verbose
    LogLevel_Verbose   = 6,
    LogLevel_Unkown    = 7
} LogMgrLevel;
typedef enum
{
    LogMode_NotDefine = -1,
    LogModeNone       = 0,
    LogMode_File      = 1 << 0,
    LogMode_Mem       = 1 << 1,
    LogMode_Console   = 1 << 2,
    LogMode_DDS       = 1 << 3,
    LogMode_Network   = 1 << 4
} LogMgrMode;

/** 打包日志错误码定义 **/
#define PACKLOG_OK (0x00)
#define PACKLOG_ERR_PARAM (0x01)
#define PACKLOG_ERR_ACCESS (0x02)
#define PACKLOG_ERR_OUT_MEM (0x03)
#define PACKLOG_ERR_OUT_BUFFSZ (0x04)
#define PACKLOG_ERR_TAR (0x05)
#define PACKLOG_ERR (0x06)
#define PACKLOG_PACKAGING (0x07)
#define PACKLOG_OFF (0x08)

/** 一些错误码定义 **/
#define DLTRC_OK (0x00)
#define DLTRC_NOT_SUPPORTED (0x0b)
#define DLTRC_ERROR (0x0c)
#define DLTRC_FW_NOT_INIT (0x0d)
#define DLTRC_XML_ERR (0x0e)
#define DLTRC_XML_PARSE_ERR (0x0f)
#define DLTRC_NOT_FOUND_APP (0x10)
#define DLTRC_DDS_INIT_ERR (0x11)
#define DLTRC_FW_EXIST (0x12)
#define DLTRC_LOGENABLE_FALSE (0x13)
#define DLTRC_NO_APPID (0x14)
#define DLTRC_PARAMS_ERR (0x15)
#define DLTRC_OUTOF_MEM (0x16)
#define DLTRC_LEVEL_ABORT (0x17)
#define DLTRC_WRITER_INIT_ERR (0x18)
#define DLTRC_SUBSCRIBE_FULL   0x20  // 订阅客户端已满
#define DLTRC_ALREADY_SUB      0x21  // 已经订阅



typedef struct LogContext LogContext;

typedef int8_t DLTRC; 

DLTRC dlt_init_client(const char *appId);
DLTRC dlt_log_fatal(const char *appId, const char *szFormat, ...);
DLTRC dlt_log_error(const char *appId, const char *szFormat, ...);
DLTRC dlt_log_warn(const char *appId, const char *szFormat, ...);
DLTRC dlt_log_info(const char *appId, const char *szFormat, ...);
DLTRC dlt_log_debug(const char *appId, const char *szFormat, ...);
DLTRC dlt_log_verbose(const char *appId, const char *szFormat, ...);
void dlt_free_client(const char *appId);

#ifdef __cplusplus
}
#endif
#endif