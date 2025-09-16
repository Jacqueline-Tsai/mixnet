add_executable(node node.c stp.c log.c)
target_link_libraries(node
    fragment
    pthread
)