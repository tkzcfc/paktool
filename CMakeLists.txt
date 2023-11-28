cmake_minimum_required(VERSION 3.8)



add_definitions(-DZLIB_DLL=0)

set(name paktool)
project(${name})


set(_Sources
    ${CMAKE_CURRENT_LIST_DIR}/main.cpp
    ${CMAKE_CURRENT_LIST_DIR}/Crc32.cpp
    ${CMAKE_CURRENT_LIST_DIR}/Crc32.h
)

source_group("" FILES ${_Sources})
source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${_Sources})

set(CMAKE_CXX_STANDARD 20)
set(CXX_STANDARD_FLAG -std=c++20)


# 头文件搜索路径添加
include_directories (${CMAKE_CURRENT_LIST_DIR})
include_directories (${CMAKE_CURRENT_LIST_DIR}/zlib/)

if(MSVC)     
    # Use the static C library for all build types
    foreach(var 
        CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE
        CMAKE_C_FLAGS_MINSIZEREL CMAKE_C_FLAGS_RELWITHDEBINFO
        CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE
        CMAKE_CXX_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_RELWITHDEBINFO
      )
      if(${var} MATCHES "/MD")
        string(REGEX REPLACE "/MD" "/MT" ${var} "${${var}}")
      endif()
    endforeach()    
endif(MSVC)

add_subdirectory(zlib)
add_executable(${PROJECT_NAME} ${_Sources})
target_link_libraries(${PROJECT_NAME} PRIVATE zlib)


set(GameBinDir ${CMAKE_BINARY_DIR}/Bin)
set_target_properties(${name} PROPERTIES
    FOLDER "Apps"
    RUNTIME_OUTPUT_DIRECTORY                "${GameBinDir}"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG          "${GameBinDir}"
    RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${GameBinDir}"
    RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL     "${GameBinDir}"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE        "${GameBinDir}"
    DEBUG_POSTFIX                           _d
    RELWITHDEBINGO_POSTFIX                  _rd
    #MINSIZEREL_POSTFIX                      _r
    VS_DEBUGGER_WORKING_DIRECTORY           ${GameBinDir}
)
