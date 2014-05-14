cmake_minimum_required (VERSION 2.6)

# If we set the system to Clang/GCC we get "-rdynamic"
# however we need Linux for dynamic linking stuffs.
# We should probably create a custom system name
set(CMAKE_SYSTEM_NAME "Linux-CXX")

project (loader C)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -Wall -Wextra -Wno-unused-variable -Wno-missing-braces -Wno-missing-field-initializers -Wno-unused-function -Wno-unused-parameter -Wno-unused-but-set-variable")
# XXX: ugly, but CMake seems to remove it if I put it in include_directories
set(CMAKE_SHARED_LIBRARY_SONAME_C_FLAG "-Wl,-soname,")
set(CMAKE_SHARED_LINKER_FLAGS "-static")
set(CMAKE_EXE_LINKER_FLAGS "-Wl,--export-dynamic")

include_directories("${PROJECT_BINARY_DIR}")

set(OR1K_SIM_PATH "or32-elf-sim" CACHE FILEPATH "Path to the OR1K simulator")
configure_file(sim.cfg sim.cfg COPYONLY)

add_custom_command(
	OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/libmy.so.h
	COMMAND bin2c libmy.so -n libmy > libmy.so.h
)
add_custom_target(libmy_header DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/libmy.so.h)
#set(CMAKE_C_COMPILE_OPTIONS_PIC "")

# Test dynamic library
add_library(my SHARED libmy.c)

# Loader
add_executable(loader loader.c)

# Simulation targets
add_custom_target(loader_sim COMMAND timeout 5 ${OR1K_SIM_PATH} -f sim.cfg loader)
add_custom_target(loader_sim_debug COMMAND ${OR1K_SIM_PATH} -f sim.cfg --srv=9001 loader)

# Dependencies
add_dependencies(loader_sim loader)
add_dependencies(loader_sim_debug loader)
add_dependencies(loader libmy_header)
add_dependencies(libmy_header my)

