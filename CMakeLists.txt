project(BGPSECPG C)

set(PROJECT_DESCRIPTION "Generator for BGPsec_PATH attributes")

cmake_minimum_required(VERSION 2.8.12)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -std=gnu99 -lrtr")
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wextra -ggdb")
endif(CMAKE_BUILD_TYPE STREQUAL "Debug")

include_directories(.)

add_subdirectory(bgpsecpg)

set(BGPSECPG_SRC bgpsecpg/bgpsecpg.c bgpsecpg/lib/bgpsec_structs.c bgpsecpg/lib/generators.c bgpsecpg/lib/config_parser.c bgpsecpg/lib/log.c bgpsecpg/lib/keyhandler.c)

# Create shared library
add_library(bgpsecpg SHARED ${BGPSECPG_SRC})
target_link_libraries(bgpsecpg ${BGPSECPG_LINK})

# Create static library
add_library(bgpsecpg_static STATIC ${BGPSECPG_SRC})
target_link_libraries(bgpsecpg_static ${BGPSECPG_LINK})

# Testing
add_subdirectory(tests)
enable_testing()
add_test(test_bgpsec_structs tests/test_bgpsec_structs)
add_test(test_generators tests/test_generators)
