cmake_minimum_required(VERSION 3.10)
project(m_log VERSION 1.0.0 LANGUAGES C)

# 编译选项
set(CMAKE_C_STANDARD 89)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -Wall -Wextra")

# 查找依赖
# find_package(LibXml2 REQUIRED)
# find_package(Threads REQUIRED)

# 源文件
add_library(m_log SHARED
    logMgr.c
    lognwf.c
)

# 头文件路径
target_include_directories(m_log PRIVATE
    ${LIBXML2_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# 链接库
# target_link_libraries(m_log
#     ${CMAKE_THREAD_LIBS_INIT}
#     ${LIBXML2_LIBRARIES}
# )

# 安装配置
install(TARGETS m_log
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(FILES logMgr.h
    DESTINATION include
)

# 版本符号控制
set_target_properties(m_log PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
)