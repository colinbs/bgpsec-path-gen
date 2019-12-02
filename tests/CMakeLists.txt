include_directories(${BGPSECPG_SOURCE_DIR}/tests)
link_directories(${BGPSECPG_BINARY_DIR}/tests)

add_executable(test_bgpsec_structs test_bgpsec_structs.c)
target_link_libraries(test_bgpsec_structs bgpsecpg)
install(TARGETS test_bgpsec_structs DESTINATION bin)

add_executable(test_generators test_generators.c)
target_link_libraries(test_generators bgpsecpg)
install(TARGETS test_generators DESTINATION bin)
