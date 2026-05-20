cmake_minimum_required(VERSION 3.22.1)
project(root)

macro(define_stripped NAME OUTNAME)
    add_custom_command(
            OUTPUT ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/${OUTNAME}
            COMMAND ${CMAKE_STRIP} --strip-all $<TARGET_FILE:${NAME}_unstripped> -o $<TARGET_FILE_DIR:${NAME}_unstripped>/${OUTNAME}
            DEPENDS ${NAME}_unstripped
    )
    add_custom_target(${NAME}
        DEPENDS ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/${OUTNAME}
    )
endmacro()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_ANDROID_STL_TYPE c++_static)

add_compile_options(-fvisibility=hidden -fno-exceptions -fno-rtti)
add_link_options(-Wl,--exclude-libs,ALL)
if ("${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo")
    add_link_options( 
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
