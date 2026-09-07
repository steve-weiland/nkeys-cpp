# Consumer project for the packaging gate: exactly what the README tells a
# user to write — find_package + the namespaced target, nothing else.
cmake_minimum_required(VERSION 3.21)
project(nkeys_consumer CXX)

find_package(nkeys 1.0 CONFIG REQUIRED)

add_executable(consumer main.cpp)
target_link_libraries(consumer PRIVATE nkeys::nkeys)
