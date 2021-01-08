# -I spdlog
cmake_minimum_required(VERSION 3.5.1)

project(palisade_tutorial CXX)
set(CMAKE_CXX_STANDARD 11)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0")
# Setup code coverage
link_libraries(gcov)
set(CMAKE_EXE_LINKER_FLAGS "")
set(CMAKE_C_COMPILER cc)
set(COMPILE_FLAGS "--coverage")
set(CMAKE_EXE_LINKER_FLAGS "--coverage")

# SPDLOG flags and package
set(SPDLOG_BUILD_SHARED OFF)
set(SPDLOG_BUILD_EXAMPLE OFF)
set(SPDLOG_BUILD_EXAMPLE_HO OFF)
set(SPDLOG_BUILD_TESTS OFF)
set(SPDLOG_BUILD_TESTS_HO OFF)
set(SPDLOG_BUILD_BENCH OFF)
set(SPDLOG_SANITIZE_ADDRESS OFF)
set(SPDLOG_INSTALL OFF)
set(SPDLOG_FMT_EXTERNAL OFF)
set(SPDLOG_FMT_EXTERNAL_HO OFF)
set(SPDLOG_NO_EXCEPTIONS OFF)
add_subdirectory(third_party/spdlog)


#Add the google test subdirectory
add_subdirectory(third_party/googletest)
include_directories(third_party/googletest/include)
include_directories(third_party/googlemock/include)

# PALISADE packages and such
find_package(Palisade)
set(CMAKE_CXX_FLAGS ${PALISADE_CXX_FLAGS})
set(CMAKE_EXE_LINKER_FLAGS ${PALISADE_EXE_LINKER_FLAGS})

include_directories(${OPENMP_INCLUDES})
include_directories(${PALISADE_INCLUDE})
include_directories(${PALISADE_INCLUDE}/third-party/include)
include_directories(${PALISADE_INCLUDE}/core)
include_directories(${PALISADE_INCLUDE}/pke)

link_directories(${PALISADE_LIBDIR})
link_directories(${OPENMP_LIBRARIES})
link_libraries(${PALISADE_LIBRARIES})


# Actual execution
add_executable(palisade_ML main.cpp src/p_tensor.h src/ptensor_utils.h src/p_tensor.cpp src/datasetProvider.cpp src/datasetProvider.h)
add_executable(palisade_ML_test test/src/unittest_pTensorTensorX.cpp src/p_tensor.h src/ptensor_utils.h src/p_tensor.cpp test/src/unittest_pTensorVectorX.cpp test/src/unittest_pTensorScalarX.cpp test/src/unittest_pTensorMisc.cpp)
target_link_libraries(palisade_ML spdlog::spdlog)
#Link with GoogleTest
target_link_libraries(palisade_ML_test gtest gtest_main)

#Link with GoogleMock
target_link_libraries(palisade_ML_test gmock gmock_main)