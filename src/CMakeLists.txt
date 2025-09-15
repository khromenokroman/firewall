find_package(fmt 11 REQUIRED)

set(APP_SOURCES
        main.cpp
        firewall.cpp
        interface.cpp
)

add_executable(${PROJECT_NAME} ${APP_SOURCES})

target_link_libraries(${PROJECT_NAME} PRIVATE
        fmt::fmt
        pcap
)