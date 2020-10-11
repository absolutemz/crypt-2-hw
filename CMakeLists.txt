cmake_minimum_required(VERSION 3.17)
project(car_trinket)

set(CMAKE_CXX_STANDARD 17)

include_directories(project/include)

add_executable(${PROJECT_NAME} 
        main.cpp
        project/src/HCR_funcs.cpp
        project/src/sig.cpp
        project/src/crypt.cpp)

find_package(OpenSSL REQUIRED)

target_link_libraries(car_trinket OpenSSL::SSL)
