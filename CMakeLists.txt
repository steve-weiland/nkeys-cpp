cmake_minimum_required(VERSION 3.21)  # PROJECT_IS_TOP_LEVEL

# Project — the VERSION here is the single source of truth: it feeds the
# package config version file, the pkg-config file, and nk++ --v.
project(nkeys-cpp VERSION 1.2.0 LANGUAGES C CXX)

# --- Options ---------------------------------------------------------------
# Tests, the CLI, and install rules default off when this project is embedded
# (add_subdirectory / FetchContent) so consumers get just the library target.
option(NKEYS_WARNINGS_AS_ERRORS "Treat warnings as errors" OFF)
option(NKEYS_USE_SYSTEM_GTEST "Prefer system-installed GTest if available" ON)
option(NKEYS_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(NKEYS_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(NKEYS_ENABLE_HARDENING "Enable security hardening flags" ON)
option(NKEYS_BUILD_TESTS "Build the test suite" ${PROJECT_IS_TOP_LEVEL})
option(NKEYS_BUILD_CLI "Build the nk++ CLI tool" ${PROJECT_IS_TOP_LEVEL})
option(NKEYS_INSTALL "Generate install and package-config rules" ${PROJECT_IS_TOP_LEVEL})

# --- Global settings -------------------------------------------------------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
include(GNUInstallDirs)

# Helpful warnings (compiler-specific) — applied per-target to OUR code only.
# A global add_compile_options also compiles fetched third-party sources
# (GoogleTest) with -Werror, and a newer compiler's new warnings then break
# the build inside code we don't own (seen live: AppleClang's
# -Wcharacter-conversion firing in gtest-printers.h on the macOS CI runner).
if (MSVC)
    set(NKEYS_WARNING_FLAGS /W4)
    if (NKEYS_WARNINGS_AS_ERRORS)
        list(APPEND NKEYS_WARNING_FLAGS /WX)
    endif()
else()
    set(NKEYS_WARNING_FLAGS -Wall -Wextra -Wpedantic)
    if (NKEYS_WARNINGS_AS_ERRORS)
        list(APPEND NKEYS_WARNING_FLAGS -Werror)
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
# Static by default; honors BUILD_SHARED_LIBS=ON.
add_library(nkeys
        ${NKEYS_SOURCES}
        ${MONOCYPHER_SOURCES}
)
add_library(nkeys::nkeys ALIAS nkeys)
set_target_properties(nkeys PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
)
target_compile_features(nkeys PUBLIC cxx_std_20)

target_include_directories(nkeys PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_include_directories(nkeys PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/external
)
target_compile_options(nkeys PRIVATE ${NKEYS_WARNING_FLAGS})
# Force-include the Monocypher symbol renames into every TU of this target
# (the vendored C files AND nkeys.cpp, so callers and definitions agree).
# libnkeys then exports nkeys__crypto_* only — a consumer linking their own
# Monocypher can't collide with ours or silently service our calls. Gated by
# tests/packaging/test.sh check 5.
if (MSVC)
    target_compile_options(nkeys PRIVATE /FI${CMAKE_CURRENT_SOURCE_DIR}/src/monocypher_rename.h)
else()
    target_compile_options(nkeys PRIVATE -include ${CMAKE_CURRENT_SOURCE_DIR}/src/monocypher_rename.h)
endif()

# --- Executable: nk++ ------------------------------------------------------
if (NKEYS_BUILD_CLI)
    add_executable(nk++ src/tools/nk-main.cpp)
    target_compile_options(nk++ PRIVATE ${NKEYS_WARNING_FLAGS})
    target_compile_definitions(nk++ PRIVATE NKPP_VERSION="${PROJECT_VERSION}")
    target_link_libraries(nk++ PRIVATE nkeys)
    target_include_directories(nk++ PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_CURRENT_SOURCE_DIR}/src/tools
    )
endif()

# --- Tests: nkeys_test (GoogleTest) ---------------------------------------
if (NKEYS_BUILD_TESTS)
    include(CTest)
endif()
if (NKEYS_BUILD_TESTS AND BUILD_TESTING)
    # Threads are needed by GTest on POSIX
    find_package(Threads REQUIRED)

    set(_have_gtest FALSE)
    # Sanitizer builds must NOT link a system (uninstrumented) GTest: libc++'s
    # ASAN container annotations disagree with uninstrumented code touching the
    # same containers, and GTest's own argv setup then reports a bogus
    # container-overflow before a single test runs (seen live on macOS/Homebrew).
    # Fetch and instrument GTest alongside the code instead.
    if (NKEYS_USE_SYSTEM_GTEST AND NOT (NKEYS_ENABLE_ASAN OR NKEYS_ENABLE_UBSAN))
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
        # gmock too: the tests use gmock matchers (ContainerEq) — on macOS the
        # system install co-locates the headers and this went unnoticed; the
        # fetched build scopes them to the gmock target.
        set(GTEST_LIBS GTest::gtest GTest::gtest_main GTest::gmock)
        # Treat fetched GTest headers as system includes in OUR TUs, so our
        # -Werror doesn't fail on warnings inside gtest's inline functions.
        foreach(_gt gtest gtest_main gmock gmock_main)
            if (TARGET ${_gt})
                get_target_property(_gt_inc ${_gt} INTERFACE_INCLUDE_DIRECTORIES)
                if (_gt_inc)
                    set_target_properties(${_gt} PROPERTIES
                            INTERFACE_SYSTEM_INCLUDE_DIRECTORIES "${_gt_inc}")
                endif()
            endif()
        endforeach()
    else()
        set(GTEST_LIBS GTest::GTest GTest::Main GTest::gmock)
    endif()

    add_executable(nkeys_test tests/nkeys_test.cpp)
    # Absolute fixtures path so out-of-tree builds (CI, sanitizer dirs) find
    # them — CWD-relative lookup only worked for build dirs inside the repo.
    target_compile_definitions(nkeys_test PRIVATE
            NKEYS_TEST_FIXTURES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures")
    target_compile_options(nkeys_test PRIVATE ${NKEYS_WARNING_FLAGS})
    target_link_libraries(nkeys_test PRIVATE nkeys ${GTEST_LIBS} Threads::Threads)
    target_include_directories(nkeys_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_CURRENT_SOURCE_DIR}/tests
    )

    add_executable(cmd_args_test tests/cmd_args_test.cpp)
    target_compile_options(cmd_args_test PRIVATE ${NKEYS_WARNING_FLAGS})
    target_link_libraries(cmd_args_test PRIVATE ${GTEST_LIBS} Threads::Threads)
    target_include_directories(cmd_args_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src/tools
            ${CMAKE_CURRENT_SOURCE_DIR}/tests
    )

    include(GoogleTest)
    gtest_discover_tests(nkeys_test)
    gtest_discover_tests(cmd_args_test)

    # Interop driver: the C++ half of tests/interop/run.sh (the live Go↔C++
    # matrix). Built with tests; the matrix itself needs a Go toolchain and
    # runs via the script / CI interop job, not ctest.
    add_executable(cpp_driver tests/interop/cpp_driver.cpp)
    target_compile_options(cpp_driver PRIVATE ${NKEYS_WARNING_FLAGS})
    target_link_libraries(cpp_driver PRIVATE nkeys)
endif()

# --- Install + package config ----------------------------------------------
if (NKEYS_INSTALL)
    include(CMakePackageConfigHelpers)

    install(TARGETS nkeys
            EXPORT nkeysTargets
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )

    # Public headers - preserve include/nkeys/ directory structure
    install(FILES
            ${CMAKE_CURRENT_SOURCE_DIR}/include/nkeys/nkeys.hpp
            ${CMAKE_CURRENT_SOURCE_DIR}/include/nkeys/nkeys_constants.hpp
            ${CMAKE_CURRENT_SOURCE_DIR}/include/nkeys/nkeys_errors.hpp
            DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/nkeys
    )

    # find_package(nkeys): namespaced targets + config + version files
    install(EXPORT nkeysTargets
            FILE nkeysTargets.cmake
            NAMESPACE nkeys::
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/nkeys
    )
    configure_package_config_file(
            cmake/nkeysConfig.cmake.in
            ${CMAKE_CURRENT_BINARY_DIR}/nkeysConfig.cmake
            INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/nkeys
    )
    write_basic_package_version_file(
            ${CMAKE_CURRENT_BINARY_DIR}/nkeysConfigVersion.cmake
            VERSION ${PROJECT_VERSION}
            COMPATIBILITY SameMajorVersion
    )
    install(FILES
            ${CMAKE_CURRENT_BINARY_DIR}/nkeysConfig.cmake
            ${CMAKE_CURRENT_BINARY_DIR}/nkeysConfigVersion.cmake
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/nkeys
    )

    # pkg-config for non-CMake consumers (GNUInstallDirs vars may be relative
    # or absolute; normalize against the prefix)
    if (IS_ABSOLUTE "${CMAKE_INSTALL_LIBDIR}")
        set(PKGCONFIG_LIBDIR "${CMAKE_INSTALL_LIBDIR}")
    else()
        set(PKGCONFIG_LIBDIR "\${prefix}/${CMAKE_INSTALL_LIBDIR}")
    endif()
    if (IS_ABSOLUTE "${CMAKE_INSTALL_INCLUDEDIR}")
        set(PKGCONFIG_INCLUDEDIR "${CMAKE_INSTALL_INCLUDEDIR}")
    else()
        set(PKGCONFIG_INCLUDEDIR "\${prefix}/${CMAKE_INSTALL_INCLUDEDIR}")
    endif()
    configure_file(cmake/nkeys.pc.in ${CMAKE_CURRENT_BINARY_DIR}/nkeys.pc @ONLY)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/nkeys.pc
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
    )

    if (NKEYS_BUILD_CLI)
        install(TARGETS nk++
                RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        )
    endif()
endif()
