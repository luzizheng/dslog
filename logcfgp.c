#include "logcfgp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// 定义节和键值对的结构体
typedef struct KeyValue {
    char* key;
    char* value;
    struct KeyValue* next;
} KeyValue;

typedef struct Section {
    char* name;
    KeyValue* head;
    struct Section* next;
} Section;

typedef struct ConfigHandle {
    Section* config;
    Section* currentSection;  // 当前正在处理的节
    Section* iterator;        // 用于遍历节的指针
} ConfigHandle;

// 工具函数：去头尾空格
static void trim(char* str) {
    char* end;
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return;
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    *(end + 1) = 0;
}

// 添加一个键值对到当前节
static void addKeyValue(Section* currentSection, char* key, char* value) {
    KeyValue* newKeyValue = (KeyValue*)malloc(sizeof(KeyValue));
    newKeyValue->key = strdup(key);
    newKeyValue->value = strdup(value);
    newKeyValue->next = currentSection->head;
    currentSection->head = newKeyValue;
}

// 添加一个节到句柄的配置
static void addSection(ConfigHandle* handle, char* name) {
    Section* newSection = (Section*)malloc(sizeof(Section));
    newSection->name = strdup(name);
    newSection->head = NULL;
    newSection->next = handle->config;
    handle->config = newSection;
    handle->currentSection = newSection;  // 更新当前节
}

// 解析配置文件的每一行
static void parseLine(ConfigHandle* handle, char* line) {
    char* trimed = strdup(line);
    trim(trimed);

    if (trimed[0] == '[' && trimed[strlen(trimed) - 1] == ']') {
        // 是节
        char* sectionName = strchr(trimed, '[') + 1;
        sectionName[strlen(trimed) - 2] = '\0'; // 去掉尾部的 ] 并滤掉可能的中间空格
        addSection(handle, sectionName);
    } else if (strchr(trimed, '=') != NULL) {
        // 是键值对
        char* key = strtok(trimed, "=");
        char* value = strtok(NULL, "=");

        trim(key);
        trim(value);

        addKeyValue(handle->currentSection, key, value);
    } else if (trimed[0] == '#' || trimed[0] == '\0') {
        // 注释或空白行，跳过
    } else {
        printf("Invalid line: %s\n", line);
    }

    free(trimed);
}

// 初始化配置解析句柄
ConfigHandle* initConfigParser() {
    ConfigHandle* handle = (ConfigHandle*)malloc(sizeof(ConfigHandle));
    handle->config = NULL;
    handle->currentSection = NULL;
    handle->iterator = NULL;
    return handle;
}

// 解析配置文件
void parseConfigFile(ConfigHandle* handle, const char* filename) {
    handle->currentSection = NULL;
    handle->iterator = NULL;

    // 清理之前的配置数据
    Section* current = handle->config;
    while (current != NULL) {
        Section* next = current->next;

        KeyValue* kv = current->head;
        while (kv != NULL) {
            KeyValue* next_kv = kv->next;
            free(kv->key);
            free(kv->value);
            free(kv);
            kv = next_kv;
        }

        free(current->name);
        free(current);
        current = next;
    }

    handle->config = NULL;

    FILE* fp = fopen(filename, "r");
    if (!fp) {
        perror("Failed to open file");
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        parseLine(handle, line);
    }

    fclose(fp);
}

// 获取指定节的键值对
char* getKeyValue(ConfigHandle* handle, const char* section, const char* key) {
    Section* current = handle->config;
    while (current != NULL) {
        if (strcmp(current->name, section) == 0) {
            KeyValue* kv = current->head;
            while (kv != NULL) {
                if (strcmp(kv->key, key) == 0) {
                    return kv->value;
                }
                kv = kv->next;
            }
            break;
        }
        current = current->next;
    }
    return NULL;
}

// 开始遍历所有节
void startSectionIteration(ConfigHandle* handle) {
    handle->iterator = handle->config;
}

// 获取下一个节
const char* getNextSection(ConfigHandle* handle) {
    if (handle->iterator == NULL) {
        return NULL;
    }

    const char* sectionName = handle->iterator->name;
    handle->iterator = handle->iterator->next;
    return sectionName;
}

// 销毁句柄并释放资源
void destroyConfigParser(ConfigHandle* handle) {
    Section* current = handle->config;
    while (current != NULL) {
        Section* next = current->next;

        KeyValue* kv = current->head;
        while (kv != NULL) {
            KeyValue* next_kv = kv->next;
            free(kv->key);
            free(kv->value);
            free(kv);
            kv = next_kv;
        }

        free(current->name);
        free(current);
        current = next;
    }

    free(handle);
}