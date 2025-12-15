cmake_minimum_required(VERSION 3.10)
project(lvm LANGUAGES C ASM)

set(CMAKE_C_STANDARD 11)

option(FORCE_32BIT "Force 32-bit compilation" ON)

if(FORCE_32BIT AND NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(STATUS "Forcing 32-bit compilation")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32")
    set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -m32")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -m32")
endif()

set(HEADER_FILES
	tools/bytecode_def.h
	tools/verifier.h
	runtime/runtime.h
	tools/decode.h
	tools/idiom.h
    tools/opcode_names.h
)

add_library(Tools STATIC
    tools/decode.c
    tools/idiom.c
    tools/verifier.c
    tools/opcode_names.c
)

add_library(Runtime STATIC
    runtime/runtime.c
    runtime/gc_runtime.s
)

set_source_files_properties(runtime/gc_runtime.s PROPERTIES LANGUAGE ASM)

target_compile_options(Runtime PRIVATE
    -g                      
    -fstack-protector-all   
    -Wall                   
    -Wextra                 
)

target_compile_options(Tools PRIVATE
    -g                      
    -fstack-protector-all   
    -Wall                   
    -Wextra                 
)

# ← ПРАВИЛЬНО
target_include_directories(Tools PUBLIC tools)
target_include_directories(Runtime PUBLIC runtime)

add_executable(lvm lvm.c)

target_compile_options(lvm PRIVATE
    -g
    -Wall
    -Wextra
)

target_include_directories(lvm PRIVATE tools runtime)

target_link_libraries(lvm PRIVATE Tools Runtime m)

configure_file(runtime/Std.i ${CMAKE_CURRENT_BINARY_DIR}/Std.i COPYONLY)

