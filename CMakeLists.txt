cmake_minimum_required(VERSION 3.22.1)
project(root)

macro(strip_and_move NAME)
    add_custom_command(TARGET ${NAME} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E make_directory ${DEBUG_SYMBOLS_PATH}
            COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${NAME}> ${DEBUG_SYMBOLS_PATH}/$<TARGET_FILE_NAME:${NAME}>
            COMMAND ${CMAKE_STRIP} --strip-all $<TARGET_FILE:${NAME}>
    )
endmacro()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_ANDROID_STL_TYPE c++_static)

add_compile_options(-fvisibility=hidden -fno-exceptions -fno-rtti)
if ("${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo")
    add_link_options( 
        -Wl,--exclude-libs,ALL
        -Wl,-z,start-stop-visibility=hidden
        -Wl,--gc-sections
        -Wl,--icf=all
    )
    add_compile_options(-O3 -flto)
endif()

add_subdirectory(external)
add_subdirectory(base)
add_subdirectory(init_injector)
add_subdirectory(elf_parser)
add_subdirectory(maps_scan)
