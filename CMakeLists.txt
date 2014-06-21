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
#set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -mboard=or1ksim-uart")

# Parameter to specify the soname to ld
set(CMAKE_SHARED_LIBRARY_SONAME_C_FLAG "-Wl,-soname,")

# Include the binary directory for generated files
include_directories("${PROJECT_BINARY_DIR}")

# or1k-sim
set(OR1K_SIM_PATH "or32-elf-sim" CACHE FILEPATH "Path to the OR1K simulator")
configure_file(sim.cfg sim.cfg COPYONLY)

add_library(eld STATIC dl.c eld.c elf-object.c)

# Loader main executable
add_executable(loader test.c)
target_link_libraries(loader eld)

# Test dynamic libraries
add_library(your SHARED libyour.c)
add_library(my SHARED libmy.c)

# Link libmy against libyour and the main executable
target_link_libraries(my your ":loader")
add_dependencies(my loader)

# Simulation targets
# Use a script to provide the shared objects to the loader on the stdin
set(FEED_SO ${CMAKE_CURRENT_SOURCE_DIR}/feed-so.py
  ${CMAKE_CURRENT_BINARY_DIR}/libyour.so
  ${CMAKE_CURRENT_BINARY_DIR}/libmy.so)
add_custom_target(loader_sim
  COMMAND ${FEED_SO} | ${OR1K_SIM_PATH} -f sim.cfg loader)
add_custom_target(loader_sim_debug
  COMMAND ${FEED_SO} | ${OR1K_SIM_PATH} -f sim.cfg --srv=9001 loader)

# Dependencies
add_dependencies(loader_sim loader my your)
add_dependencies(loader_sim_debug loader my your)

# Install
install(TARGETS eld
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)