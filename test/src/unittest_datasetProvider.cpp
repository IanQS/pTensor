/**
 * Author: Ian Quah
 * Date: 1/8/21
 *
 * Note: we do an unordered Tensor eq because we shuffle between the rows BEFORE taking the transpose and doing the packing
 * Thus, we don't know the order in which they are packed.
 */

#include "gtest/gtest.h"
#include "../../src/datasetProvider.h"
#include "pTensorUtils_testing.h"
#include "openfhe.h"
#include "gen-cryptocontext.h"
#include "scheme/ckksrns/cryptocontext-ckksrns.h"
// pTensor_TensorMisc
class pTensor_datasetProvider : public ::testing::Test {
 protected:
  lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cc;

  std::shared_ptr<lbcrypto::PublicKeyImpl<lbcrypto::DCRTPoly>> public_key;
  std::shared_ptr<lbcrypto::PrivateKeyImpl<lbcrypto::DCRTPoly>> private_key;

  /////////////////////////////////////////////////////////////////
  //Initialize from complex values
  /////////////////////////////////////////////////////////////////
  messageTensor msgX = {{1, 2, 3}, {4, 5, 6}, {7, 8, 9}};
  messageTensor msgY = {{1}, {2}, {3}};

  pTensor X = pTensor(3, 3, msgX);
  pTensor y = pTensor(3, 1, msgY);

  void SetUp() {
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
            std::get<1>(xShape),
            std::get<1>(yShape)
        );

        EXPECT_EQ(shuffledX.messageNotEmpty(), true);
        EXPECT_EQ(shuffledX.cipherNotEmpty(), false);
        EXPECT_EQ(shuffledY.messageNotEmpty(), true);
        EXPECT_EQ(shuffledY.cipherNotEmpty(), false);

        auto yMessages = shuffledY.getMessage();
        auto xMessages = shuffledX.getMessage();

        // We know that since we transposed it, there is only 1 row and 3 elements
        EXPECT_EQ(yMessages[0].size(), 3);
        for (unsigned int r = 0; r < std::get<0>(xShape); ++r) {
            std::complex<double> label = yMessages[0][r];
            auto labelAsInt = static_cast<int>(label.real());
            if (labelAsInt == 1) {
                EXPECT_TRUE(unorderedMessageTensorEq({xMessages[r]}, {{1, 4, 7}}));
            } else if (labelAsInt == 2) {
                EXPECT_TRUE(unorderedMessageTensorEq({xMessages[r]}, {{2, 5, 8}}));
            } else {
                EXPECT_TRUE(unorderedMessageTensorEq({xMessages[r]}, {{3, 6, 9}}));
            }
        }
    }
};