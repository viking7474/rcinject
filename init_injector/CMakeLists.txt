project(init_injector)

link_libraries(elf_parser maps_scan base)

add_executable(injectrc injector.cpp ptrace_utils.cpp)
strip_and_move(injectrc)

add_library(injectrclib SHARED payload.cpp)
strip_and_move(injectrclib)
