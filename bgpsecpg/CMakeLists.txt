include_directories(${BGPSECPG_SOURCE_DIR}/bgpsecpg)
link_directories(${BGPSECPG_BINARY_DIR}/bgpsecpg)

#include_directories(${BGPSECPG_SOURCE_DIR}/bgpsecpg/lib)
#link_directories(${BGPSECPG_SOURCE_DIR}/bgpsecpg/lib)

add_subdirectory(${BGPSECPG_SOURCE_DIR}/bgpsecpg/lib)

add_executable(bgpsecpgbin bgpsecpg.c)
target_link_libraries(bgpsecpgbin bgpsecpg)
install(TARGETS bgpsecpgbin DESTINATION bin)
