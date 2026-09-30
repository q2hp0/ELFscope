cmake_minimum_required(VERSION 3.20)

project(ELFscope VERSION 0.9.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(CTest)
include(GNUInstallDirs)

option(ELFSCOPE_SANITIZE "build with address and undefined behavior sanitizers" OFF)
option(ELFSCOPE_WERROR "treat warnings as errors" OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "build type" FORCE)
endif()

file(GLOB_RECURSE ELFSCOPE_CORE_SOURCES CONFIGURE_DEPENDS
    src/parser/*.cpp
    src/analysis/*.cpp
    src/utils/*.cpp
    src/cli/*.cpp
)

add_library(elfscope_core ${ELFSCOPE_CORE_SOURCES})

target_include_directories(elfscope_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_definitions(elfscope_core PUBLIC
    ELFSCOPE_VERSION="${PROJECT_VERSION}"
)

if(ELFSCOPE_SANITIZE)
    target_compile_options(elfscope_core PUBLIC
        -fsanitize=address,undefined
        -fno-omit-frame-pointer
    )
    target_link_options(elfscope_core PUBLIC
        -fsanitize=address,undefined
    )
endif()

if(ELFSCOPE_WERROR)
    target_compile_options(elfscope_core PRIVATE -Werror)
endif()

target_compile_options(elfscope_core PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)

add_executable(elfscope
    src/main.cpp
)

target_link_libraries(elfscope PRIVATE
    elfscope_core
)

target_compile_options(elfscope PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)

if(BUILD_TESTING)
    # fixtures for the tests, all built from the same tiny program
    add_library(sample_object OBJECT examples/sample.c)
    set_target_properties(sample_object PROPERTIES EXCLUDE_FROM_ALL OFF)
    target_compile_options(sample_object PRIVATE -O2 -fPIC)

    add_executable(sample_hardened examples/sample.c)
    target_compile_options(sample_hardened PRIVATE
        -O2 -fPIE -fstack-protector-strong -D_FORTIFY_SOURCE=2)
    target_link_options(sample_hardened PRIVATE
        -pie -Wl,-z,relro,-z,now)

    add_executable(sample_weak examples/sample.c)
    target_compile_options(sample_weak PRIVATE
        -O0 -fno-pie -fno-stack-protector -U_FORTIFY_SOURCE)
    target_link_options(sample_weak PRIVATE
        -no-pie -Wl,-z,norelro -Wl,-z,execstack)

    add_executable(sample_rpath examples/sample.c)
    target_link_options(sample_rpath PRIVATE
        -Wl,--disable-new-dtags -Wl,-rpath,relative/libs)

    set_target_properties(sample_hardened sample_weak sample_rpath
        PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/fixtures)

    file(GLOB TEST_SOURCES CONFIGURE_DEPENDS
        tests/*_tests.cpp
    )

    foreach(TEST_SOURCE ${TEST_SOURCES})
        get_filename_component(TEST_NAME ${TEST_SOURCE} NAME_WE)

        add_executable(${TEST_NAME}
            ${TEST_SOURCE}
        )

        target_link_libraries(${TEST_NAME} PRIVATE
            elfscope_core
        )

        add_dependencies(${TEST_NAME}
            sample_object sample_hardened sample_weak sample_rpath
        )

        target_compile_definitions(${TEST_NAME} PRIVATE
            ELFSCOPE_SAMPLE_HARDENED="$<TARGET_FILE:sample_hardened>"
            ELFSCOPE_SAMPLE_WEAK="$<TARGET_FILE:sample_weak>"
            ELFSCOPE_SAMPLE_RPATH="$<TARGET_FILE:sample_rpath>"
            ELFSCOPE_SAMPLE_OBJECT="$<TARGET_OBJECTS:sample_object>"
        )

        target_compile_options(${TEST_NAME} PRIVATE
            -Wall
            -Wextra
            -Wpedantic
        )

        add_test(
            NAME ${TEST_NAME}
            COMMAND ${TEST_NAME}
        )
    endforeach()
endif()

install(TARGETS elfscope RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
