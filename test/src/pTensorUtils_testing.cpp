/**
 * Author: Ian Quah
 * Date: 1/9/21 
 */

#include "pTensorUtils_testing.h"

bool messageTensorEq(messageTensor arg1, messageTensor arg2) {
    if (arg1.size() != arg2.size()) {
        return false;
    }
    if (arg1[0].size() != arg2[0].size()) {
        return false;
    }

    for (unsigned int i = 0; i < arg1.size(); ++i) {
        for (unsigned int j = 0; j < arg1[0].size(); ++j) {
            if ((arg1[i][j] - arg2[i][j]).real() > 0.0001) {
                std::cout << "Actual: " << arg1[i][j].real() << ", Expected: " << arg2[i][j].real() << std::endl;
                return false;
            }
        }
    }
    return true;
}
