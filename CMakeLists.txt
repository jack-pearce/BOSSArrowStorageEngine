cmake_minimum_required(VERSION 3.10)
project(BOSSArrowStorage)

# Configure CCache if available
find_program(CCACHE_EXECUTABLE ccache)
mark_as_advanced(CCACHE_EXECUTABLE)
if(CCACHE_EXECUTABLE)
  foreach(LANG C CXX)
    if(NOT DEFINED CMAKE_${LANG}_COMPILER_LAUNCHER AND NOT CMAKE_${LANG}_COMPILER MATCHES ".*/ccache")
      message(STATUS "Enabling ccache for ${LANG}")
      set(CMAKE_${LANG}_COMPILER_LAUNCHER ${CCACHE_EXECUTABLE} CACHE STRING "")
    endif()
  endforeach()
endif()

############################## Custom build modes ###############################

set(CMAKE_CXX_FLAGS_SANITIZE "-fno-omit-frame-pointer -fsanitize=address,signed-integer-overflow,null,alignment,bounds,function,return,vla-bound -O0 -g"
  CACHE STRING
  "Flags used by the C++ compiler during Sanitize builds."
  FORCE)
set(CMAKE_C_FLAGS_SANITIZE "-fno-omit-frame-pointer -fsanitize=address,signed-integer-overflow,null,alignment,bounds,function,return,vla-bound -O0 -g"
  CACHE STRING
  "Flags used by the C compiler during Sanitize builds."
  FORCE)
set(CMAKE_EXE_LINKER_FLAGS_SANITIZE
  ${CMAKE_EXE_LINKER_FLAGS_DEBUG} CACHE STRING
  "Flags used for linking binaries during Sanitize builds."
  FORCE)
set(CMAKE_SHARED_LINKER_FLAGS_SANITIZE
  ${CMAKE_SHARED_LINKER_FLAGS_DEBUG} CACHE STRING
  "Flags used by the shared libraries linker during Sanitize builds."
  FORCE)
mark_as_advanced(
  CMAKE_CXX_FLAGS_SANITIZE		  CMAKE_EXE_LINKER_FLAGS_SANITIZE
  CMAKE_C_FLAGS_SANITIZE		  CMAKE_SHARED_LINKER_FLAGS_SANITIZE
  )

set(CMAKE_BUILD_TYPE "${CMAKE_BUILD_TYPE}" CACHE STRING
  "Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel Sanitize."
  FORCE)

############################### External Projects ###############################

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE) # make sure all dependent libraries are compiled with that option

include(ExternalProject)

# Core BOSS
if(NOT DEFINED BUILD_BOSS_FROM_SOURCE)
    set(BUILD_BOSS_FROM_SOURCE ON)
endif()
if(BUILD_BOSS_FROM_SOURCE)
  if(NOT DEFINED BOSS_SOURCE_BRANCH)
    set(BOSS_SOURCE_BRANCH main)
  endif()
  if(NOT DEFINED BOSS_SOURCE_REPOSITORY)
    if(NOT GITHUB_TOKEN)
      message( FATAL_ERROR "You need to pass -DGITHUB_TOKEN=... to pass a github token to fetch the boss release" )
    endif()
    set(BOSS_SOURCE_REPOSITORY https://little-big-h:${GITHUB_TOKEN}@github.com/symbol-store/BOSS.git)
  endif()
  message("getting boss sources from ${BOSS_SOURCE_REPOSITORY}")
  ExternalProject_Add(BOSS
      GIT_REPOSITORY ${BOSS_SOURCE_REPOSITORY}
      GIT_TAG ${BOSS_SOURCE_BRANCH}
      GIT_SHALLOW ON
    DOWNLOAD_DIR $ENV{HOME}/.cmake-downloads/${CMAKE_PROJECT_NAME}
		CMAKE_ARGS -DCMAKE_VERBOSE_MAKEFILE=${CMAKE_VERBOSE_MAKEFILE} -DCMAKE_INSTALL_PREFIX=${BOSSArrowStorage_BINARY_DIR}/deps $<IF:$<CONFIG:>,,-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}>
                   -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}  -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER} -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS}
    BUILD_BYPRODUCTS ${BOSSArrowStorage_BINARY_DIR}/deps/lib/BOSS.lib ${BOSSArrowStorage_BINARY_DIR}/deps/lib/Tests.lib
    )
else()
ExternalProject_Add(BOSS
	URL https://api.github.com/repos/symbol-store/BOSS/releases/assets/48287799
  HTTP_HEADER "Authorization: token ${GITHUB_TOKEN}" "Accept: application/octet-stream"
  DOWNLOAD_DIR $ENV{HOME}/.cmake-downloads/${CMAKE_PROJECT_NAME}
  SOURCE_DIR ${BOSSArrowStorage_BINARY_DIR}/deps
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND ""
  BUILD_BYPRODUCTS ${BOSSArrowStorage_BINARY_DIR}/deps/lib/BOSS.lib ${BOSSArrowStorage_BINARY_DIR}/deps/lib/Tests.lib
  )
endif()

####################### Other Options and Library Dependencies #######################

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

################################ ITT module interface ################################

set(VTune_DIR "" CACHE PATH "Where to look for VTune installation")
find_path(ITT_NOTIFY_INCLUDE_DIR "ittnotify.h" HINTS ${VTune_DIR}/include)

add_library(ITTNotifySupport INTERFACE)
target_sources(ITTNotifySupport INTERFACE ${PROJECT_SOURCE_DIR}/ITT/ITTNotifySupport.hpp)
target_include_directories(ITTNotifySupport INTERFACE ${PROJECT_SOURCE_DIR}/ITT/)
if(ITT_NOTIFY_INCLUDE_DIR)
  message(VERBOSE "found itt notify header in ${ITT_NOTIFY_INCLUDE_DIR}")
  target_include_directories(ITTNotifySupport SYSTEM INTERFACE ${ITT_NOTIFY_INCLUDE_DIR})
  target_link_libraries(ITTNotifySupport INTERFACE ${ITT_NOTIFY_INCLUDE_DIR}/../lib64/libittnotify${CMAKE_STATIC_LIBRARY_SUFFIX})
  if(NOT WIN32)
    target_link_libraries(ITTNotifySupport dl)
  endif(NOT WIN32)
  if ((NOT CMAKE_BUILD_TYPE STREQUAL "Release") AND (NOT ENABLE_PARALLELISATION))
    target_compile_options(ITTNotifySupport INTERFACE -DWITH_ITT_NOTIFY)
  else()
    target_compile_options(ITTNotifySupport INTERFACE -DNO_ITT_NOTIFY)
  endif()
endif(ITT_NOTIFY_INCLUDE_DIR)

#################################### BOSSArrowStorage Plugin ####################################

if(MSVC)
  # not making any difference on Windows
  # and helps Visual Studio to parse it correctly as a target
  set(LibraryType SHARED)
else()
  set(LibraryType MODULE)
endif(MSVC)

add_library(BOSSArrowStorage ${LibraryType} "Source/BOSSArrowStorageEngine.cpp")
add_dependencies(BOSSArrowStorage BOSS)
target_compile_options(BOSSArrowStorage PUBLIC -DARROW_STATIC)
if(WIN32)
    target_compile_options(BOSSArrowStorage PUBLIC /bigobj)
endif(WIN32)
	
target_link_libraries(BOSSArrowStorage ITTNotifySupport)
target_link_libraries(BOSSArrowStorage Threads::Threads)
set_target_properties(BOSSArrowStorage PROPERTIES POSITION_INDEPENDENT_CODE ON)
set_target_properties(BOSSArrowStorage PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)
if(MSVC)
    target_compile_options(BOSSArrowStorage PUBLIC "/Zc:__cplusplus")
    target_compile_options(BOSSArrowStorage PUBLIC "/EHsc")
    # to link against all needed symbols for loading BOSSArrowStorage as a plugin
    target_link_libraries(BOSSArrowStorage ${BOSSArrowStorage_BINARY_DIR}/deps/lib/BOSS.lib)
    target_link_libraries(BOSSArrowStorage ${BOSSArrowStorage_BINARY_DIR}/deps/lib/Tests.lib)
endif()
target_include_directories(BOSSArrowStorage SYSTEM PUBLIC ${BOSSArrowStorage_BINARY_DIR}/deps/include)
if(UNIX AND NOT APPLE)
    target_link_libraries(BOSSArrowStorage rt)
endif()

set_target_properties(BOSSArrowStorage PROPERTIES INSTALL_RPATH_USE_LINK_PATH TRUE)
install(TARGETS BOSSArrowStorage LIBRARY DESTINATION lib)
