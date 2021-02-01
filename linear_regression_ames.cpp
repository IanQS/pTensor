/**
 * Author: Ian Quah
 * Date: 1/29/21
 *
 * There are 3 main steps:
 *  1) read in the data
 *  2) pass the data to our datasetProvider which shuffles the data
 *  3) Run ML on the data
 *
 *  The first 2 steps would occur on the private data lake and the second one would be on
 *      a machine that the modeler owns
 */

#include "src/p_tensor.h"
#include "src/datasetProvider.h"
#include "src/csv_reader.h"
#include "chrono"

/**
 * We construct the dataset into a vector of size num-folds
    // @NOTE: explain why we have to generate the folds before encrypting
    // @Note, we encrypt row-wise and encryption is slow, so we want to encrypt across rows.
    // Thus, we take the transpose of ptxtX.
 * @param numFolds
 * @param ptxtX
 * @param ptxtY
 * @return
 */
providedDataset constructDataset(int numFolds, messageTensor ptxtX, messageTensor ptxtY) {

    auto numObservations = ptxtX.size();
    auto numFeatures = ptxtX[0].size();

    if (numFolds > 0) {
        // No need to transpose here as we do it internally
        pTensor pX(numObservations, numFeatures, ptxtX);
        pTensor pY(numObservations, 1, ptxtY);

        datasetProvider dp(pX, pY, numFolds);
        return dp.provide(42, true);
    }

    auto ptxtX_T = pTensor::plainT(ptxtX);
    auto ptxtY_T = pTensor::plainT(ptxtY);
    pTensor pX(numFeatures, numObservations, ptxtX_T);
    pTensor pY(1, numObservations, ptxtY_T);

    auto t1 = std::chrono::high_resolution_clock::now();
    auto X = pX.encrypt();
    auto t2 = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count() * 1e-6;
    std::cout << "Encrypting X took " << duration << " seconds" << std::endl;

    auto y = pY.encrypt();
    auto t3 = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds>(t3 - t2).count() * 1e-6;
    std::cout << "Encrypting y took " << duration << " seconds" << std::endl;
    providedDataset dataset = {std::make_tuple(X, y)};
    return dataset;
}

int main() {
    /////////////////////////////////////////////////////////////////
    //Hyperparameters
    //  - We have ML hyperparameters and crypto hyperparameters
    //  - We discuss the crypto hyperparameters in the next post
    /////////////////////////////////////////////////////////////////
    unsigned int epochs = 50;

    // If numFolds > 1, we generate that many shuffles
    // If numFolds ==1, we shuffle the single dataset
    // If numFolds == 0, we keep the order
    int numFolds = 0;
    float _alpha = 0.06;
    float _l2_regularization_factor = -1;

    uint8_t multDepth = 7;
    uint8_t scalingFactorBits = 50;
    int batchSize = 8192;

    /**
     * If you are getting a "evalIndexKey not valid", up the batch size to fit the multDepth based on this:
     *
     * Batch size based on multDepth
     * Inclusive range
     * 1-2: 4096
     * 3-9: 8192
     * 10-18: 16384
     */

    /////////////////////////////////////////////////////////////////
    //Loading in the data and setting up the variables
    /////////////////////////////////////////////////////////////////
    messageTensor ptxtX = readFeatures("../ames_housing_dataset/processed_X.csv");
    messageTensor ptxtY = readLabels("../ames_housing_dataset/processed_y.csv");

    std::cout << "ptxtX shape: " << ptxtX.size() << ", " << ptxtX[0].size() << "." << std::endl;
    std::cout << "ptxtY shape: " << ptxtY.size() << ", " << ptxtY[0].size() << "." << std::endl;

    auto numObservations = ptxtX.size();
    auto numFeatures = ptxtX[0].size();
    messageTensor _scaleByNumSamples = {{numObservations}};

    /////////////////////////////////////////////////////////////////
    // Create the crypto parameters
    /////////////////////////////////////////////////////////////////

    auto t1 = std::chrono::high_resolution_clock::now();
    std::cout << "Creating crypto parameters and generating keys" << std::endl;
    auto cc = lbcrypto::CryptoContextFactory<lbcrypto::DCRTPoly>::genCryptoContextCKKS(
        multDepth, scalingFactorBits, batchSize
    );

    // @Note, we discuss this in the next blog post

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

    auto t2 = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
    std::cout << "Generating crypto parameters took " << duration * 1e-6 << " seconds" << std::endl;

    /////////////////////////////////////////////////////////////////
    // Setting up the dataset and the training
    /////////////////////////////////////////////////////////////////

    // Set the static vars
    pTensor::m_cc = &cc;
    pTensor::m_private_key = private_key;
    pTensor::m_public_key = public_key;

    messageTensor _fixed_weights = {
        {-0.121966},
        {-1.08682},
        {0.68429},
        {-1.07519},
        {0.0332695}
    };
    pTensor weights = pTensor::generateWeights(numFeatures, numObservations, _fixed_weights);

    auto t3 = std::chrono::high_resolution_clock::now();
    auto t4 = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds>(t4 - t3).count();
    std::cout << "Encrypting the weights took " << duration * 1e-6 << " seconds" << std::endl;

    std::cout << "Generating " << numFolds << " folds of the data" << std::endl;

    providedDataset dataset = constructDataset(numFolds, ptxtX, ptxtY);

    const int range_from = 0;
    const int range_to = std::max(0, numFolds - 1);
    std::random_device rand_dev;
    std::mt19937 generator(rand_dev());

    std::uniform_int_distribution<std::mt19937::result_type> distr(range_from, range_to);

    /////////////////////////////////////////////////////////////////
    //Encrypt hyperparams
    // alpha, L2, scaledSamples
    /////////////////////////////////////////////////////////////////
    auto alpha = pTensor::encryptScalar(_alpha, true);
    auto l2Scale = pTensor::encryptScalar(_l2_regularization_factor, true);
    auto scaleByNumSamples = pTensor::encryptScalar(1 / numObservations, true);

    auto w = weights.encrypt();

    messageTensor debug;
    std::cout << "Beginning training" << std::endl;
    for (unsigned int epoch = 0; epoch < epochs; ++epoch) {
        auto index = distr(generator);
        auto curr_dataset = dataset[index];
        auto X = std::get<0>(curr_dataset);
        auto y = std::get<1>(curr_dataset);

        auto prediction = X.encryptedDot(w);  // Verified
        auto residual = y - prediction;// Remember, our X is already a transpose
        debug = residual.decrypt().getMessage();
        auto _gradient = X.encryptedDot(residual);
        debug = _gradient.decrypt().getMessage();
        pTensor gradient;
        // We consider the penalized linear regression but our reporting does not take the penalty into account
        if (_l2_regularization_factor > 0) {
            auto summedW = w.sum();
            auto scaledSummedW = l2Scale * summedW;
            gradient = _gradient + scaledSummedW;
        } else {
            gradient = _gradient;
        }

        auto scaledGradient = gradient * alpha * scaleByNumSamples;

        w = pTensor::applyGradient(w, scaledGradient);
        w = w.decrypt().encrypt();
        debug = w.decrypt().getMessage();

        /**
         * Note: we have taken 2 liberties here
         *  1) the training would happen on the client's machine, not the server. Because
         *      of this, decrypting would not be possible BUT it is still possible to get the
         *      squared loss
         *  2) This is NOT a good measure of how your model is improving since you should have
         *      a holdout set and a test set. However, this is much simpler and aims to showcase
         *      the efficacy of encrypted ML.
         */
        auto decryptedResidual = residual.decrypt();
        double squaredResiduals = 0;
        for (auto &vector: decryptedResidual.getMessage()) {
            for (auto &scalar: vector) {
                squaredResiduals += (scalar.real() * scalar.real());
            }
        }
        std::cout << "Sq-Residuals at epoch " << epoch << ": " << squaredResiduals / numObservations << std::endl;
    }
    std::cout << "Done" << std::endl;
}