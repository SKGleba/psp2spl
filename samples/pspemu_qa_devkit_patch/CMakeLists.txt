cmake_minimum_required(VERSION 2.8)

set(CMAKE_SYSTEM_NAME "Generic")
set(CMAKE_C_COMPILER "arm-vita-eabi-gcc")
set(CMAKE_CXX_COMPILER "arm-vita-eabi-g++")

project(HENkaku)

set(CMAKE_C_FLAGS "-Wl,-q -Wall -O3 -std=gnu99")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -std=c++11 -fno-rtti -fno-exceptions")

include_directories(
)

link_directories(
	${CMAKE_CURRENT_BINARY_DIR}
	${CMAKE_CURRENT_BINARY_DIR}/../../stubs/
)

add_executable(kplugin.elf
	main.c
)

target_link_libraries(kplugin.elf
	SKPLForKernel_stub
	SceKernelSuspendForDriver_stub
)

set_target_properties(kplugin.elf
	PROPERTIES LINK_FLAGS "-nostdlib"
	COMPILE_FLAGS "-D__VITA_KERNEL__"
)

add_custom_target(kplugin.skprx ALL
	COMMAND vita-elf-create -e ${CMAKE_SOURCE_DIR}/kplugin.yml kplugin.elf kplugin.velf
	COMMAND vita-make-fself -c kplugin.velf kplugin.skprx
)
add_dependencies(kplugin.skprx kplugin.elf)