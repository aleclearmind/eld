cmake_minimum_required (VERSION 2.6)

# System name
# If we set the system to Clang/GCC we get "-rdynamic"
# however we need Linux for dynamic linking stuffs.
# We should probably create a custom system name
set(CMAKE_SYSTEM_NAME "Linux-CXX")

project (loader C)

# Base flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -Wall -Wextra")

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-but-set-variable")
endif()

# Disable some warnings
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-variable")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-missing-braces")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-missing-field-initializers")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-missing-field-initializers")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-function")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-parameter")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-builtin-macro-redefined")

# Use relative paths for the __FILE__ macro
set(ELD_FILE "'\"$(subst  ${CMAKE_SOURCE_DIR}/,,$(abspath $<))\"'")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__FILE__=${ELD_FILE}")

# Linker flags

# Force export of all the symbols
set(CMAKE_EXE_LINKER_FLAGS "-Wl,--export-dynamic")
# Parameter to specify the soname to ld
set(CMAKE_SHARED_LIBRARY_SONAME_C_FLAG "-Wl,-soname,")

# Include the binary directory for generated files
include_directories("${PROJECT_BINARY_DIR}")

# or1k-sim
set(OR1K_SIM_PATH "or32-elf-sim" CACHE FILEPATH "Path to the OR1K simulator")
configure_file(sim.cfg sim.cfg COPYONLY)

# Generate .h files to embed shared objects

# libmy.so
add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/libmy.so.h
  COMMAND xxd -i libmy.so > libmy.so.h
  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/libmy.so
)
add_custom_target(libmy_header
  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/libmy.so.h)

# libyour.so
add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/libyour.so.h
  COMMAND xxd -i libyour.so > libyour.so.h
  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/libyour.so
)
add_custom_target(libyour_header
  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/libyour.so.h)

# Test dynamic libraries
add_library(your SHARED libyour.c)
add_library(my SHARED libmy.c)
target_link_libraries(my your)

add_library(eld STATIC dl.c eld.c elf-object.c)

# Loader main executable
add_executable(loader test.c)
target_link_libraries(loader eld)

# Simulation targets
add_custom_target(loader_sim COMMAND ${OR1K_SIM_PATH} -f sim.cfg loader)
add_custom_target(loader_sim_debug
  COMMAND ${OR1K_SIM_PATH} -f sim.cfg --srv=9001 loader)

# Dependencies
add_dependencies(loader_sim loader)
add_dependencies(loader_sim_debug loader)

add_dependencies(loader libmy_header)
add_dependencies(libmy_header my)

add_dependencies(loader libyour_header)
add_dependencies(libyour_header your)
