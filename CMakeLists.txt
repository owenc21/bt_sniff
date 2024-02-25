add_library(
    bt_sniff
    STATIC
    src/bt_sniff.hpp
    src/bt_sniff.cpp
)

target_link_libraries(bt_sniff PRIVATE bluetooth)
target_include_directories(bt_sniff PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")