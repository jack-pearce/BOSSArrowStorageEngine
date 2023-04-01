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

if(MSVC)
    set(BOSS_LINK_LIBRARY_PREFIX ${CMAKE_LINK_LIBRARY_PREFIX})
    set(BOSS_LINK_LIBRARY_SUFFIX ${CMAKE_LINK_LIBRARY_SUFFIX})
else()
    set(BOSS_LINK_LIBRARY_PREFIX ${CMAKE_SHARED_LIBRARY_PREFIX})
    set(BOSS_LINK_LIBRARY_SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
endif(MSVC)

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
    BUILD_BYPRODUCTS ${BOSSArrowStorage_BINARY_DIR}/deps/lib/${BOSS_LINK_LIBRARY_PREFIX}BOSS${BOSS_LINK_LIBRARY_SUFFIX}
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
  BUILD_BYPRODUCTS ${BOSSArrowStorage_BINARY_DIR}/deps/lib/${BOSS_LINK_LIBRARY_PREFIX}BOSS${BOSS_LINK_LIBRARY_SUFFIX}
  )
endif()

ExternalProject_Add(catch2
	URL https://github.com/catchorg/Catch2/archive/v2.13.6.tar.gz
  DOWNLOAD_DIR $ENV{HOME}/.cmake-downloads/${CMAKE_PROJECT_NAME}
	CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${BOSSArrowStorage_BINARY_DIR}/deps -DCATCH_BUILD_TESTING=NO -DBUILD_TESTING=NO -DCATCH_ENABLE_WERROR=NO -DCATCH_INSTALL_DOCS=NO
               -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}  -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER} -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS}
  )

####################### Other Options and Library Dependencies #######################

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

#################################### Targets ####################################

if(MSVC)
  # not making any difference on Windows
  # and helps Visual Studio to parse it correctly as a target
  set(LibraryType SHARED)
else()
  set(LibraryType MODULE)
endif(MSVC)

set(ImplementationFiles Source/BOSSArrowStorageEngine.cpp)
set(TestFiles Tests/BOSSArrowStorageTests.cpp)

# Plugin
add_library(BOSSArrowStorage ${LibraryType} ${ImplementationFiles})

# Tests
add_executable(BOSSArrowStorageTests ${ImplementationFiles} ${TestFiles})
add_dependencies(BOSSArrowStorageTests catch2)
if(UNIX AND NOT APPLE)
    # for now, need linking with BOSS to successfully compile the tests with the Arrow symbols required by the engine
    # ideally, we would like to plug additional tests to BOSS tests
    target_link_libraries(BOSSArrowStorageTests ${BOSSArrowStorage_BINARY_DIR}/deps/lib/${BOSS_LINK_LIBRARY_PREFIX}BOSS${BOSS_LINK_LIBRARY_SUFFIX})
endif(UNIX AND NOT APPLE)
if(MSVC)
    # On windows, we need to make sure to get the BOSS.dll in the right folder for the tests executable
    add_custom_command(TARGET BOSSArrowStorageTests POST_BUILD
      COMMAND
        ${CMAKE_COMMAND} -E copy_if_different "${BOSSArrowStorage_BINARY_DIR}/deps/bin/BOSS.dll" "${BOSSArrowStorage_BINARY_DIR}/"
    )
endif(MSVC)

list(APPEND AllTargets BOSSArrowStorage BOSSArrowStorageTests)

foreach(Target IN LISTS AllTargets)
    target_link_libraries(${Target} Threads::Threads)
    set_target_properties(${Target} PROPERTIES POSITION_INDEPENDENT_CODE ON)
    if(MSVC)
        target_compile_options(${Target} PUBLIC "/Zc:__cplusplus")
        target_compile_options(${Target} PUBLIC "/EHsc")
    endif()
    set_target_properties(${Target} PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)
    add_dependencies(${Target} BOSS)
    target_compile_options(${Target} PUBLIC -DARROW_STATIC)
    target_include_directories(${Target} SYSTEM PUBLIC ${BOSSArrowStorage_BINARY_DIR}/deps/include)
    if(UNIX AND NOT APPLE)
        target_link_libraries(${Target} rt)
    else()
        # link against all needed symbols for loading BOSSArrowStorage as a plugin
        target_link_libraries(${Target} ${BOSSArrowStorage_BINARY_DIR}/deps/lib/${BOSS_LINK_LIBRARY_PREFIX}BOSS${BOSS_LINK_LIBRARY_SUFFIX})
    endif()
endforeach()

set_target_properties(BOSSArrowStorage PROPERTIES INSTALL_RPATH_USE_LINK_PATH TRUE)
install(TARGETS BOSSArrowStorage LIBRARY DESTINATION lib)
install(TARGETS BOSSArrowStorageTests RUNTIME DESTINATION bin)
