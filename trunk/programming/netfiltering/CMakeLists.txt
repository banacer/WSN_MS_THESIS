cmake_minimum_required (VERSION 2.6)
project (sniffer)

include_directories(src)
include_directories(include)

FILE(GLOB HEADER_FILES include/*.c)
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -g")
set(CMAKE_CXX_FLAGS "-Wextra -Wall -ansi -pedantic")
add_executable(sniffer src/sniffer.c ${HEADER_FILES})
add_executable(my_sniffer src/my_sniffer.c ${HEADER_FILES})
add_executable(test src/test.c ${HEADER_FILES})

#cleaning part
IF (UNIX)
  ADD_CUSTOM_TARGET (distclean @echo cleaning for source distribution)
  SET(DISTCLEANED   
   CMakeFiles  
   cmake.depends
   cmake.check_depends
   CMakeCache.txt
   cmake.check_cache
   *.cmake
   Makefile
   core core.*
   gmon.out
   *~
  )
  
  ADD_CUSTOM_COMMAND(
    DEPENDS clean
    COMMENT "distribution clean"
    COMMAND rm
    ARGS    -Rf CMakeTmp ${DISTCLEANED}
    TARGET  distclean
  )
ENDIF(UNIX)