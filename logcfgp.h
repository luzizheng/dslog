#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

typedef struct ConfigHandle ConfigHandle;

// 初始化配置解析句柄
ConfigHandle* initConfigParser();

// 解析配置文件
void parseConfigFile(ConfigHandle* handle, const char* filename);

// 获取指定节的键值对
char* getKeyValue(ConfigHandle* handle, const char* section, const char* key);

// 开始遍历所有节
void startSectionIteration(ConfigHandle* handle);

// 获取下一个节
const char* getNextSection(ConfigHandle* handle);

// 销毁句柄并释放资源
void destroyConfigParser(ConfigHandle* handle);

#endif // CONFIG_PARSER_H