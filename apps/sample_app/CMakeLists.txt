project(CFE_SAMPLE_APP C)

include_directories(fsw/mission_inc)
include_directories(fsw/platform_inc)
include_directories(../../cfe/modules/core_private/fsw/inc ../../cfe/modules/es/fsw/src)
if(DEFINED ENV{ENABLE_FUZZ_TESTS})
    add_compile_options(-fsanitize=fuzzer-no-link -fno-omit-frame-pointer -gline-tables-only -fprofile-instr-generate -fcoverage-mapping -pthread)
endif()

# Create the app module
add_cfe_app(sample_app fsw/src/sample_app.c fsw/src/fuzz_sample_app.c)

# Include the public API from sample_lib to demonstrate how
# to call library-provided functions
add_cfe_app_dependency(sample_app sample_lib)

# Add table
add_cfe_tables(sampleAppTable fsw/tables/sample_app_tbl.c)

# If UT is enabled, then add the tests from the subdirectory
# Note that this is an app, and therefore does not provide
# stub functions, as other entities would not typically make 
# direct function calls into this application.
if (ENABLE_UNIT_TESTS)
  add_subdirectory(unit-test)
endif (ENABLE_UNIT_TESTS)
