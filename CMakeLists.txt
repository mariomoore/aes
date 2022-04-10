cmake_minimum_required(VERSION 3.10)
project(AES)

set(PROGRAM_NAME aesapp)

set(MAIN_FILE
	src/main.cpp
)
	
set(SRC_FILES
	src/aes.cpp
)

set(TEST_FILES
	test/test.cpp
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

include(CTest)

add_library(Unity STATIC ../Unity/src/unity.c)
target_include_directories(Unity PUBLIC ../Unity/src)

add_executable(aestestapp ${TEST_FILES})
target_link_libraries(aestestapp Unity aes)
add_test(aes_test aestestapp)
