/**
 * Author: Ian Quah
 * Date: 1/8/21 
 */

#include "gtest/gtest.h"
#include "../../src/datasetProvider.h"
#include "pTensorUtils_testing.h"
#include "palisade.h"
// pTensor_TensorMisc
class pTensor_datasetProvider : public ::testing::Test {
 protected:
  lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cc;

  shared_ptr<lbcrypto::LPPublicKeyImpl<lbcrypto::DCRTPoly>> public_key;
  shared_ptr<lbcrypto::LPPrivateKeyImpl<lbcrypto::DCRTPoly>> private_key;

  /////////////////////////////////////////////////////////////////
  //Initialize from complex values
  /////////////////////////////////////////////////////////////////
  messageTensor msgX = {{1, 2, 3}, {4, 5, 6}, {7, 8, 9}};
  messageTensor msgY = {{1}, {2}, {3}};

  pTensor X = pTensor(3, 3, msgX);
  pTensor y = pTensor(1, 3, msgY);

  void SetUp() {
      uint8_t multDepth = 4;
      uint8_t scalingFactorBits = 40;
      int batchSize = 4096;

      cc =
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

      public_key = keys.publicKey;
      private_key = keys.secretKey;

      pTensor::m_cc = &cc;
      pTensor::m_private_key = private_key;
      pTensor::m_public_key = public_key;

  }

  void TearDown() {
      lbcrypto::CryptoContextFactory<lbcrypto::DCRTPoly>::ReleaseAllContexts();

      cc->ClearEvalMultKeys();
      cc->ClearEvalAutomorphismKeys();
      cc = nullptr;
      public_key = nullptr;
      private_key = nullptr;
  }

};

TEST_F(pTensor_datasetProvider, testProvide) {

    unsigned int numFolds = 2;
    datasetProvider dp(X, y, numFolds);

    auto shuffledData = dp.provide(42, false);

    EXPECT_EQ(shuffledData.size(), numFolds);

    for (auto &pair: shuffledData) {
        auto shuffledX = std::get<0>(pair);
        auto shuffledY = std::get<1>(pair);

        auto xShape = shuffledX.shape();
        auto yShape = shuffledY.shape();

        EXPECT_EQ(
            std::get<0>(xShape),
            std::get<0>(yShape)
        );

        EXPECT_EQ(shuffledX.messageNotEmpty(), true);
        EXPECT_EQ(shuffledX.cipherNotEmpty(), false);
        EXPECT_EQ(shuffledY.messageNotEmpty(), true);
        EXPECT_EQ(shuffledY.cipherNotEmpty(), false);

        auto yMessages = shuffledY.getMessage();
        auto xMessages = shuffledX.getMessage();
        for (unsigned int r = 0; r < std::get<0>(xShape); ++r) {

            EXPECT_EQ(yMessages[r].size(), 1);
            std::complex<double> label = yMessages[r][0];
            auto labelAsInt = static_cast<int>(label.real());
            if (labelAsInt == 1) {
                EXPECT_TRUE(messageTensorEq({xMessages[r]}, {{1, 2, 3}}));
            } else if (labelAsInt == 2) {
                EXPECT_TRUE(messageTensorEq({xMessages[r]}, {{4, 5, 6}}));
            } else {
                EXPECT_TRUE(messageTensorEq({xMessages[r]}, {{7, 8, 9}}));
            }
        }
    }

};