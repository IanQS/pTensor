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

    // First 2 rows of each class
    messageTensor ptX = {
        {5.1, 3.5, 1.4, 0.2},  //
        {4.9, 3., 1.4, 0.2},
        {7., 3.2, 4.7, 1.4},
        {6.4, 3.2, 4.5, 1.5},
        {6.3, 3.3, 6., 2.5},
        {5.8, 2.7, 5.1, 1.9},
    };  // 6, 4
    std::cout << ptX.size() << std::endl;
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
    messageTensor weights = pTensor::generateWeights(numFeatures, numSamples, _weights);

    /////////////////////////////////////////////////////////////////
    // setup the crypto parameters
    /////////////////////////////////////////////////////////////////
    uint8_t multDepth = 4;
    uint8_t scalingFactorBits = 40;
    int batchSize = 4096;

    auto cc =
        lbcrypto::CryptoContextFactory<lbcrypto::DCRTPoly>::genCryptoContextCKKS(
            multDepth, scalingFactorBits, batchSize
        );

    cc->Enable(ENCRYPTION);
    cc->Enable(SHE);
    cc->Enable(LEVELEDSHE);
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalSumKeyGen(keys.secretKey);

    int ringDim = cc->GetRingDimension();
    int rot = int(-ringDim / 4) + 1;
    cc->EvalAtIndexKeyGen(keys.secretKey, {-1, 1, rot});

    shared_ptr<lbcrypto::LPPublicKeyImpl<lbcrypto::DCRTPoly>> public_key;
    shared_ptr<lbcrypto::LPPrivateKeyImpl<lbcrypto::DCRTPoly>> private_key;
    public_key = keys.publicKey;
    private_key = keys.secretKey;
    /////////////////////////////////////////////////////////////////
    //Encrypt everything
    /////////////////////////////////////////////////////////////////
    ptensorX.m_cc = &cc;
    ptensorX.m_public_key = public_key;
    ptensorX.m_private_key = private_key;

    ptensorY.m_cc = &cc;
    ptensorY.m_public_key = public_key;
    ptensorY.m_private_key = private_key;

    weights.m_cc = &cc;
    weights.m_public_key = public_key;
    weights.m_private_key = private_key;

    auto X = ptensorX.encrypt();
    auto y = ptensorY.encrypt();
    auto w = ptensorWeightVec.encrypt();

    /////////////////////////////////////////////////////////////////
    // We now do 1 step of gradient descent and check against numpy
    /////////////////////////////////////////////////////////////////

    // Step 1: inner product
    auto innerProduct = X.dot(w);

    auto decIP = innerProduct.decrypt();
    decIP.debugMessages();

}
