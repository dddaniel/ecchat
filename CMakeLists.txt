cmake_minimum_required(VERSION 2.6)

project(ecchat C)

add_definitions(-g3 -O2 -Wall -Wextra)

find_library(ubox NAMES ubox)
find_library(blobmsg_json NAMES blobmsg_json)

add_executable(ecchatd
		ecchatd.c
		avl.c
		contact.c
		info.c
		txqueue.c)

add_executable(ecchat-encrypt-id
		ecchat-encrypt-id.c
		crypto.c)

set(mbed_libs mbedtls mbedcrypto mbedx509)
target_link_libraries(ecchatd ${ubox} ${blobmsg_json} ${mbed_libs})
target_link_libraries(ecchat-encrypt-id ${mbed_libs})

install(TARGETS ecchatd ecchat-encrypt-id
	RUNTIME DESTINATION bin
	)
