add_executable(jockyc
  src/main.cpp
  src/Lexer.cpp
  src/Parser.cpp
  src/IRGen.cpp
)

target_include_directories(jockyc PRIVATE
  ${CMAKE_SOURCE_DIR}/jocky/include
  ${CMAKE_SOURCE_DIR}/runtime/include
)

if(LLVM_FOUND)
  llvm_map_components_to_libnames(LLVM_LIBS support core irreader passes)
  target_link_libraries(jockyc PRIVATE ${LLVM_LIBS})
endif()

# Polymorphic passes as shared libs (loaded via opt)
add_library(CfgFlatten SHARED transform/CfgFlatten.cpp)
add_library(StringEncrypt SHARED transform/StringEncrypt.cpp)
add_library(ImportObfuscate SHARED transform/ImportObfuscate.cpp)
foreach(tgt CfgFlatten StringEncrypt ImportObfuscate)
  target_include_directories(${tgt} PRIVATE ${CMAKE_SOURCE_DIR}/jocky/include)
  set_target_properties(${tgt} PROPERTIES PREFIX "lib")
endforeach()
