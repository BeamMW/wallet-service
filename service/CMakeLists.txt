cmake_minimum_required(VERSION 3.13)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

add_library(websocket STATIC websocket_server.h websocket_server.cpp)
target_link_libraries(websocket
    PRIVATE
        beam
        utility
)

target_compile_definitions(websocket PUBLIC _SILENCE_ALL_CXX17_DEPRECATION_WARNINGS)

set(SERVICE_TARGET_NAME wallet-service${BEAM_TARGET_SUFFIX})
add_executable(${SERVICE_TARGET_NAME}
    service.cpp
    pipe.cpp
    utils.cpp
    node_connection.cpp
    keykeeper_proxy.cpp
    sessions.cpp
    service_client.cpp
    service_api.cpp
    reactor.cpp
)
target_compile_definitions(${SERVICE_TARGET_NAME} PRIVATE _SILENCE_ALL_CXX17_DEPRECATION_WARNINGS)

if(MSVC)
    # to avoid 4702 warning here, until another workaround will be found
    # const_buffer(const mutable_buffer& b) BOOST_ASIO_NOEXCEPT
    #    : data_(b.data()),
    target_compile_options(websocket PRIVATE "/wd4702")
    target_compile_options(${SERVICE_TARGET_NAME} PRIVATE /bigobj)
    target_compile_options(${SERVICE_TARGET_NAME} PRIVATE "/wd4996")
endif()

configure_file("${PROJECT_SOURCE_DIR}/version.h.in" "${CMAKE_CURRENT_BINARY_DIR}/version.h")
target_include_directories(${SERVICE_TARGET_NAME} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(${SERVICE_TARGET_NAME}
    PRIVATE
        beam
        utility
        wallet_api
        websocket
        wallet
        http
        cli
        assets
        SegFault
)

if(NOT MSVC)
    target_link_libraries(${SERVICE_TARGET_NAME}
        PRIVATE
            SegFault
)
endif()

set(MONITOR_TARGET_NAME sbbs-monitor${BEAM_TARGET_SUFFIX})
add_executable(${MONITOR_TARGET_NAME}
        monitor.cpp
        pipe.cpp
        utils.cpp
        node_connection.cpp
        sessions.cpp
        reactor.cpp
        )

target_include_directories(${MONITOR_TARGET_NAME} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(${MONITOR_TARGET_NAME}
   PRIVATE
       beam
       wallet_api
       websocket
       wallet
       utility
       cli
       SegFault
)

if(NOT MSVC)
    target_link_libraries(${MONITOR_TARGET_NAME}
        PRIVATE
            SegFault
)
endif()
