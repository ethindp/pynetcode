cmake_minimum_required(VERSION 3.25)

# ---- Project ----

set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake"
  CACHE STRING "toolchain file")

project(
  netcode
  VERSION 0.1.0
  LANGUAGES C CXX
)
set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

# ---- Include guards ----

if(PROJECT_SOURCE_DIR STREQUAL PROJECT_BINARY_DIR)
  message(
    FATAL_ERROR
      "In-source builds not allowed. Please make a new directory (called a build directory) and run CMake from there."
  )
endif()

# ---- Add source files ----

# Note: globbing sources is considered bad practice as CMake's generators may not detect new files
# automatically. Keep that in mind when changing files, or explicitly mention them here.
file(GLOB_RECURSE headers CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h")
file(GLOB_RECURSE sources CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/source/*.cpp" "${CMAKE_CURRENT_SOURCE_DIR}/source/*.c")

# ---- Create library----
find_package(Python 3.11 COMPONENTS Interpreter Development REQUIRED)
find_package(pybind11 CONFIG REQUIRED)
pybind11_add_module(${PROJECT_NAME} ${headers} ${sources})
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
find_package(unofficial-sodium CONFIG REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE unofficial-sodium::sodium)