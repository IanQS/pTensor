//
// Created by ian on 12/18/20.
//

#include "src/p_tensor.h"
#include <iostream>
int main() {
    // create a file rotating logger with 5mb size max and 3 rotated files
    //    auto file_logger = spdlog::rotating_logger_mt("file_logger", "myfilename", 1024 * 1024 * 5, 3);

    // First 2 rows of each class
    messageTensor ptX = {
        {5.1, 3.5, 1.4, 0.2},  //
        {4.9, 3., 1.4, 0.2},
        {7., 3.2, 4.7, 1.4},
        {6.4, 3.2, 4.5, 1.5},
        {6.3, 3.3, 6., 2.5},
        {5.8, 2.7, 5.1, 1.9},
    };  // 6, 4
    messageTensor ptY = {{0, 0, 1, 1, 2, 2}};  // 1, 6

    // encode as transpose as faster since only have #features to encrypt instead of #rows
    auto ptXT = pTensor::plainT(ptX);

    pTensor ptensorX(4, 6, ptXT);
    pTensor ptensorY(1, 6, ptY);

    // We need our weight matrix to be the same number of rows
//    auto ptensorWeightVec = pTensor::randomUniform(4, 1);
    messageTensor _weights = {{1}, {2}, {3}, {4}};

    auto shape = ptensorX.shape();
    unsigned int numSamples = std::get<1>(shape);
    unsigned int numFeatures = std::get<0>(shape);
    pTensor weights = pTensor::generateWeights(numFeatures, numSamples, _weights);
    /////////////////////////////////////////////////////////////////
    // setup the crypto parameters
    /////////////////////////////////////////////////////////////////
    uint8_t multDepth = 4;
    uint8_t scalingFactorBits = 40;
    int batchSize = 4096;

    lbcrypto::CCParams<lbcrypto::CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingFactorBits(scalingFactorBits);
    parameters.SetBatchSize(batchSize);

    lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cc = GenCryptoContext(parameters);

    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    auto keys = cc->KeyGen();

    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalSumKeyGen(keys.secretKey);

    int ringDim = cc->GetRingDimension();
    int rot = int(-ringDim / 4) + 1;
    cc->EvalAtIndexKeyGen(keys.secretKey, {-1, 1, rot});

    std::shared_ptr<lbcrypto::PublicKeyImpl<lbcrypto::DCRTPoly>> public_key;
    std::shared_ptr<lbcrypto::PrivateKeyImpl<lbcrypto::DCRTPoly>> private_key;
    public_key = keys.publicKey;
    private_key = keys.secretKey;
    /////////////////////////////////////////////////////////////////
    //Encrypt everything
    /////////////////////////////////////////////////////////////////

    pTensor::m_cc = &cc;
    pTensor::m_private_key = private_key;
    pTensor::m_public_key = public_key;

    auto X = ptensorX.encrypt();
    auto y = ptensorY.encrypt();
    auto w = weights.encrypt();

    /////////////////////////////////////////////////////////////////
    // We now do 1 step of gradient descent and check against numpy
    /////////////////////////////////////////////////////////////////
    // Step 1: inner product
    auto prediction = X.dot(w);
    // Step 2: Find the difference
    auto diff = prediction - y;
    // Calculate the gradient
    auto gradient = X.dot(diff);
    gradient.decrypt().debugMessages();
}
