##################################################################
#
# cFE Event Services (EVS) module CMake build recipe
#
##################################################################

project(CFE_EVS C)

if(DEFINED ENV{ENABLE_FUZZ_TESTS})
    add_compile_options(-fsanitize=fuzzer-no-link -fno-omit-frame-pointer -gline-tables-only -fprofile-instr-generate -fcoverage-mapping -pthread)
endif()
# Event services source files
set(evs_SOURCES
    fsw/src/cfe_evs.c
    fsw/src/cfe_evs_log.c
    fsw/src/cfe_evs_task.c
    fsw/src/cfe_evs_utils.c
    fsw/src/cfe_evs.c
    fsw/src/cfe_evs_log.c
    fsw/src/cfe_evs_task.c
    fsw/src/cfe_evs_utils.c
)

if(DEFINED ENV{ENABLE_FUZZ_TESTS})
    set(evs_SOURCES ${evs_SOURCES} fsw/src/fuzz.c)
endif()

add_library(evs STATIC ${evs_SOURCES})

target_include_directories(evs PUBLIC fsw/inc)
target_link_libraries(evs PRIVATE core_private)

# Add unit test coverage subdirectory
if(ENABLE_UNIT_TESTS)
    add_subdirectory(ut-coverage)
endif(ENABLE_UNIT_TESTS)

cfs_app_check_intf(${DEP}
    cfe_evs_msg.h
    cfe_evs_events.h
)
