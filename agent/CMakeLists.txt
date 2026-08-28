add_executable(jocky-agent src/agent.cpp)
target_include_directories(jocky-agent PRIVATE ${CMAKE_SOURCE_DIR}/runtime/include)
target_link_libraries(jocky-agent PRIVATE jocky_runtime)
