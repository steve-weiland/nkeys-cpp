cmake_minimum_required(VERSION 3.20)

# Project
project(nkeys-cpp LANGUAGES C CXX)

# --- Options ---------------------------------------------------------------
option(NKEYS_WARNINGS_AS_ERRORS "Treat warnings as errors" OFF)
option(NKEYS_USE_SYSTEM_GTEST "Prefer system-installed GTest if available" ON)
option(NKEYS_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(NKEYS_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(NKEYS_ENABLE_HARDENING "Enable security hardening flags" ON)

# --- Global settings -------------------------------------------------------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
include(GNUInstallDirs)

# Helpful warnings (compiler-specific)
if (MSVC)
    add_compile_options(/W4)
    if (NKEYS_WARNINGS_AS_ERRORS)
        add_compile_options(/WX)
    endif()
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
    if (NKEYS_WARNINGS_AS_ERRORS)
        add_compile_options(-Werror)
    endif()
endif()

# Note: This library requires exception support for error handling.
# All public APIs may throw std::invalid_argument or std::runtime_error.

# --- Sanitizers ------------------------------------------------------------
if (NKEYS_ENABLE_ASAN)
    if (MSVC)
        add_compile_options(/fsanitize=address)
        add_link_options(/fsanitize=address)
    else()
        add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address)
    endif()
    message(STATUS "AddressSanitizer enabled")
endif()

if (NKEYS_ENABLE_UBSAN)
    if (NOT MSVC)
        add_compile_options(-fsanitize=undefined -fno-omit-frame-pointer)
        add_link_options(-fsanitize=undefined)
        message(STATUS "UndefinedBehaviorSanitizer enabled")
    else()
        message(WARNING "UndefinedBehaviorSanitizer not supported on MSVC")
    endif()
endif()

# --- Security Hardening Flags ----------------------------------------------
if (NKEYS_ENABLE_HARDENING AND NOT MSVC)
    # Stack protection
    add_compile_options(-fstack-protector-strong)

    # Fortify source (requires -O1 or higher)
    if (CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
        add_compile_definitions(_FORTIFY_SOURCE=2)
    endif()

    # Position independent execution (PIE) for executables - Linux only
    if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
        add_link_options(-Wl,-z,relro,-z,now)
    endif()

    message(STATUS "Security hardening flags enabled")
endif()

# --- Sources ---------------------------------------------------------------
set(MONOCYPHER_SOURCES
        external/monocypher/monocypher.c
        external/monocypher/monocypher-ed25519.c
)

set(NKEYS_SOURCES
        src/nkeys.cpp
)

# --- Library: nkeys --------------------------------------------------------
add_library(nkeys STATIC
        ${NKEYS_SOURCES}
        ${MONOCYPHER_SOURCES}
)

target_include_directories(nkeys PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_include_directories(nkeys PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/external
)

# --- Executable: nk++ ------------------------------------------------------
add_executable(nk++ src/tools/nk-main.cpp)
target_link_libraries(nk++ PRIVATE nkeys)
target_include_directories(nk++ PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/tools
)

# --- Tests: nkeys_test (GoogleTest) ---------------------------------------
include(CTest)
if (BUILD_TESTING)
    # Threads are needed by GTest on POSIX
    find_package(Threads REQUIRED)

    set(_have_gtest FALSE)
    if (NKEYS_USE_SYSTEM_GTEST)
        find_package(GTest QUIET)
        if (GTest_FOUND)
            set(_have_gtest TRUE)
        endif()
    endif()

    if (NOT _have_gtest)
        include(FetchContent)
        FetchContent_Declare(
                googletest
                URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
                URL_HASH SHA256=1f357c27ca988c3f7c6b4bf68a9395005ac6761f034046e9dde0896e3aba00e4
                DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        )
        # For MSVC: don't override runtime flags in gtest
        set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
        FetchContent_MakeAvailable(googletest)
        set(GTEST_LIBS GTest::gtest GTest::gtest_main)
    else()
        set(GTEST_LIBS GTest::GTest GTest::Main)
    endif()

    add_executable(nkeys_test tests/nkeys_test.cpp)
    target_link_libraries(nkeys_test PRIVATE nkeys ${GTEST_LIBS} Threads::Threads)
    target_include_directories(nkeys_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_CURRENT_SOURCE_DIR}/tests
    )

    add_executable(cmd_args_test tests/cmd_args_test.cpp)
    target_link_libraries(cmd_args_test PRIVATE ${GTEST_LIBS} Threads::Threads)
    target_include_directories(cmd_args_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src/tools
            ${CMAKE_CURRENT_SOURCE_DIR}/tests
    )

    include(GoogleTest)
    gtest_discover_tests(nkeys_test)
    gtest_discover_tests(cmd_args_test)
endif()

# --- Install targets -------------------------------------------------------

# Install static library
install(TARGETS nkeys
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

# Install public headers - preserve include/nkeys/ directory structure
install(FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/include/nkeys/nkeys.hpp
        ${CMAKE_CURRENT_SOURCE_DIR}/include/nkeys/nkeys_constants.hpp
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/nkeys
)

# Install CLI tool executable
install(TARGETS nk++
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
