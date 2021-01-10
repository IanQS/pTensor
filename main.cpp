//
// Created by ian on 12/18/20.
//

#include "src/p_tensor.h"
#include <iostream>
#include "spdlog/spdlog.h"
#include "spdlog/sinks/rotating_file_sink.h" // support for rotating file logging
#include "spdlog/sinks/stdout_color_sinks.h" // or "../stdout_sinks.h" if no colors needed
int main() {
    // create a file rotating logger with 5mb size max and 3 rotated files
    //    auto file_logger = spdlog::rotating_logger_mt("file_logger", "myfilename", 1024 * 1024 * 5, 3);

}
