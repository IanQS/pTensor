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

bool unorderedMessageTensorEq(messageTensor a1, messageTensor a2){
    std::unordered_set<double> s1;
    std::copy(a1.begin(),
              a1.end(),
              std::inserter(a1, a1.begin()));

    std::unordered_set<double> s2;
    std::copy(a2.begin(),
              a2.end(),
              std::inserter(a2, a2.begin()));

    if (s1 == s2){
        return true;
    }
    return false;
}
