# -I spdlog
cmake_minimum_required(VERSION 3.5.1)

project(openfhe_tutorial CXX)
set(CMAKE_CXX_STANDARD 11)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0")

##################################
# OPENFHE packages and such
##################################
find_package(OpenFHE)
set(CMAKE_CXX_FLAGS ${OPENFHE_CXX_FLAGS})
set(CMAKE_EXE_LINKER_FLAGS ${OPENFHE_EXE_LINKER_FLAGS})

include_directories(${OPENMP_INCLUDES})
include_directories(${OpenFHE_INCLUDE})
include_directories(${OpenFHE_INCLUDE}/third-party/include)
include_directories(${OpenFHE_INCLUDE}/core)
include_directories(${OpenFHE_INCLUDE}/pke)

link_directories(${OpenFHE_LIBDIR})
link_directories(${OPENMP_LIBRARIES})


##################################
# Setup code coverage
##################################
link_libraries(gcov)
set(CMAKE_EXE_LINKER_FLAGS "")
set(CMAKE_C_COMPILER cc)
set(COMPILE_FLAGS "--coverage")
set(CMAKE_EXE_LINKER_FLAGS "--coverage")

##################################
# SPDLOG flags and package
##################################

include(ExternalProject)

# third party directories
set(THIRDPARTYDIR ${CMAKE_CURRENT_SOURCE_DIR}/third-party)
include_directories(${THIRDPARTYDIR}/include)
add_subdirectory(third_party/spdlog)

##################################
#Add the google test subdirectory
##################################
add_subdirectory(third_party/googletest)
include_directories(third_party/googletest/include)
include_directories(third_party/googlemock/include)

##################################
# Actual execution
##################################
add_executable(openfhe_ML
        linear_regression_ames.cpp
        src/p_tensor.h src/p_tensor.cpp
        src/datasetProvider.h src/datasetProvider.cpp
        src/ptensor_utils.h
        src/csv_reader.cpp src/csv_reader.h)

add_executable(ml_proof_of_concept
        gradient_descent_single_step.cpp
        src/p_tensor.h src/p_tensor.cpp
        src/datasetProvider.h src/datasetProvider.cpp
        src/ptensor_utils.h
        )
add_executable(openfhe_ML_test
        # sources
        src/p_tensor.h src/p_tensor.cpp
        src/datasetProvider.h src/datasetProvider.cpp
        test/src/pTensorUtils_testing.h test/src/pTensorUtils_testing.cpp
        # Tests
        test/src/main_testall.cpp
        test/src/unittest_pTensorTensorX.cpp
        test/src/unittest_pTensorVectorX.cpp
        test/src/unittest_pTensorScalarX.cpp
        test/src/unittest_pTensorMisc.cpp
        test/src/unittest_datasetProvider.cpp
        )

#############################################
# Link the libraries
#############################################

target_link_libraries(openfhe_ML spdlog::spdlog)
#Link with GoogleTest
target_link_libraries(openfhe_ML_test gtest gtest_main)

#Link with GoogleMock
target_link_libraries(openfhe_ML_test gmock gmock_main)