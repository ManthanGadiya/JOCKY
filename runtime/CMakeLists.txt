add_library(jocky_runtime STATIC
  src/runtime.cpp
)
target_include_directories(jocky_runtime PUBLIC include)
