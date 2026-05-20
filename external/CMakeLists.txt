project(external)

macro(SET_OPTION option value)
    set(${option} ${value} CACHE INTERNAL "" FORCE)
endmacro()

SET_OPTION(FMT_OS OFF)
SET_OPTION(FMT_INSTALL OFF)
SET_OPTION(FMT_UNICODE OFF)
add_subdirectory(fmt)
target_compile_definitions(fmt-header-only INTERFACE
        FMT_USE_LOCALE=0
        FMT_BUILTIN_TYPES=0
        FMT_USE_FLOAT128=0
        FMT_OPTIMIZE_SIZE=2
)
