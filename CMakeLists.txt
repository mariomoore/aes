cmake_minimum_required(VERSION 3.10)
project(AES)

set(PROGRAM_NAME aes)

set(MAIN_FILE
	src/main.cpp
)
	
set(SRC_FILES
	src/*.cpp
	src/*.cpp
)

#set(TEST_FILES
#	test/test.cpp
#)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(FLAGS -Wall -Wextra -Werror -pedantic -Wconversion -O3)

include_directories(src)
add_library(${PROGRAM_NAME}-lib STATIC ${SRC_FILES})
target_compile_options(${PROGRAM_NAME}-lib PRIVATE ${FLAGS})
add_executable(${PROGRAM_NAME} ${MAIN_FILE})
target_compile_options(${PROGRAM_NAME} PRIVATE ${FLAGS})
target_link_libraries(${PROGRAM_NAME} ${PROGRAM_NAME}-lib)
#add_executable(${PROGRAM_NAME}-ut ${TEST_FILES})
#target_link_libraries(${PROGRAM_NAME}-ut ${PROGRAM_NAME}-lib)
