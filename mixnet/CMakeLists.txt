add_executable(node node.c stp.c lsa.c log.c util.c state.c)
target_link_libraries(node
    fragment
    pthread
)