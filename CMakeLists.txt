cmake_minimum_required(VERSION 2.8)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  else()
    message(FATAL_ERROR "Please define VITASDK to point to your SDK path!")
  endif()
endif()

project(psp2spl)
include("${VITASDK}/share/vita.cmake" REQUIRED)

set(CMAKE_C_FLAGS "-Wl,-q -Wall -O3 -std=gnu99")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -std=c++11 -fno-rtti -fno-exceptions")

include_directories(
)

link_directories(
	${CMAKE_CURRENT_BINARY_DIR}
)

add_executable(psp2spl.elf
	main.c
)

target_link_libraries(psp2spl.elf
	SceSblSmSchedProxyForKernel_stub
	SceSblSmCommForKernel_stub
	SceIofilemgrForDriver_stub
	SceSysclibForDriver_stub
	SceSysmemForDriver_stub
	SceSysrootForKernel_stub
	SceKernelSuspendForDriver_stub
)

set_target_properties(psp2spl.elf
	PROPERTIES LINK_FLAGS "-nostdlib"
	COMPILE_FLAGS "-D__VITA_KERNEL__"
)

add_custom_target(psp2spl.skprx ALL
	COMMAND vita-elf-create -e ${CMAKE_SOURCE_DIR}/psp2spl.yml psp2spl.elf psp2spl.velf
	COMMAND vita-make-fself -c psp2spl.velf psp2spl.skprx
)

add_dependencies(psp2spl.skprx psp2spl.elf)

vita_create_stubs(stubs psp2spl.elf ${CMAKE_SOURCE_DIR}/psp2spl.yml KERNEL)