/**
 * Author: Ian Quah
 * Date: 1/29/21 
 */
#include "csv_reader.h"

messageTensor readFeatures(const std::string &dataFile, bool addBias) {
    messageTensor tensorContainer;
    std::ifstream file(dataFile);

    bool passedLabels = false;
    std::string row;
    if (file.is_open()) {
        while (std::getline(file, row)) {
            if (!passedLabels) {
                passedLabels = true;
                continue;
            }

            std::istringstream ss(row);
            messageVector vectorContainer;
            std::string scalar;
            if (addBias){
                vectorContainer.emplace_back(1.0, 0.0);
            }
            while (std::getline(ss, scalar, ',')) {
                vectorContainer.emplace_back(
                    std::stod(scalar), // the real portion
                    0.0  // the complex portion
                );
            }
            tensorContainer.emplace_back(vectorContainer);
        }
    }
    return tensorContainer;
}

messageTensor readLabels(const std::string &dataFile) {
    messageTensor container;
    std::ifstream file(dataFile);

    std::string label;
    bool passedLabel = false;
    if (file.is_open()) {
        while (std::getline(file, label)) {
            if (!passedLabel) {
                passedLabel = true;
                continue;
            }

            messageVector vectorContainer;
            vectorContainer.emplace_back(std::stod(label), 0.0);
            container.emplace_back(vectorContainer);
        }
    }
    return container;
}
