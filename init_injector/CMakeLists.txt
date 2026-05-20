project(init_injector)

enable_language(ASM)

link_libraries(elf_parser maps_scan base)

add_executable(injectrc_unstripped injector.cpp ptrace_utils.cpp embed.S)
define_stripped(injectrc injectrc)
set_source_files_properties(embed.S PROPERTIES 
    OBJECT_DEPENDS ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libinjectrclib.so
    COMPILE_OPTIONS -I${CMAKE_LIBRARY_OUTPUT_DIRECTORY}
)

add_library(injectrclib_unstripped SHARED payload.cpp)
define_stripped(injectrclib libinjectrclib.so)
