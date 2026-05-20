project(base)

link_libraries(fmt-header-only log)

add_library(base STATIC logging.cpp misc.cpp)
target_include_directories(base PUBLIC include)
