/**
 * Author: Ian Quah
 * Date: 1/29/21 
 */
#ifndef CSV_READER_H
#define CSV_READER_H
#include "p_tensor.h"
#include <string>
#include <vector>
#include <complex>

using FeatureNameMap = std::map<std::string, int>;

messageTensor readFeatures(const std::string &dataFile, bool addBias=true);
messageTensor readLabels(const std::string &dataFIle);

#endif //CSV_READER_H
