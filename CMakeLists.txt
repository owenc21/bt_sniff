add_library(
    bt_sniff
    STATIC
    src/bt_sniff.hpp
    src/bt_sniff.cpp
)

add_library(
    utils
    STATIC
    utils/utils.cpp
    utils/utils.hpp
    utils/event_queue.hpp
    utils/event_queue.cpp
    utils/bluetoothdef.hpp
)

target_link_libraries(bt_sniff PRIVATE bluetooth utils) 
target_include_directories(bt_sniff PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${CMAKE_CURRENT_SOURCE_DIR}/utils"
)