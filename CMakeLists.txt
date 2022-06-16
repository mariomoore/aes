cmake_minimum_required(VERSION 3.10)
project(AES)

set(PROGRAM_NAME aesapp)

set(MAIN_FILE
	src/main.cpp
)
	
set(SRC_FILES
	src/aes.cpp
	src/aesmode.cpp
)

set(TEST_AES_FILES
	test/test_aes.cpp
	test/aestest.cpp
)

set(TEST_AESMODE_FILES
	test/test_aesmode.cpp
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(FLAGS -Wall -Wextra -Werror -pedantic -Wconversion -O3)

add_library(aes STATIC ${SRC_FILES})
target_compile_options(aes PRIVATE ${FLAGS})
target_include_directories(aes PUBLIC src)

add_executable(${PROGRAM_NAME} ${MAIN_FILE})
target_compile_options(${PROGRAM_NAME} PRIVATE ${FLAGS})
target_link_libraries(${PROGRAM_NAME} aes)

if(TARGET_GROUP STREQUAL test)
	include(CTest)

	add_library(Unity STATIC ../Unity/src/unity.c)
	target_compile_options(Unity PRIVATE ${FLAGS})
	target_include_directories(Unity PUBLIC ../Unity/src)

	add_executable(aestestapp ${TEST_AES_FILES})
	target_compile_options(aestestapp PRIVATE ${FLAGS})
	target_link_libraries(aestestapp Unity aes)
	
	add_executable(aesmodetestapp ${TEST_AESMODE_FILES})
	target_compile_options(aesmodetestapp PRIVATE ${FLAGS})
	target_link_libraries(aesmodetestapp Unity aes)
	
	add_test(aes aestestapp)
	add_test(aesmode aesmodetestapp)
endif()
