/**
 * Author: Ian Quah
 * Date: 12/31/20 
 */

#include "gtest/gtest.h"
#include "../../src/p_tensor.h"
#include "pTensorUtils_testing.h"
#include "palisade.h"

class pTensor_TensorTest : public ::testing::Test {

 protected:
  lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cc;

  shared_ptr<lbcrypto::LPPublicKeyImpl<lbcrypto::DCRTPoly>> public_key;
  shared_ptr<lbcrypto::LPPrivateKeyImpl<lbcrypto::DCRTPoly>> private_key;

  /////////////////////////////////////////////////////////////////
  //Initialize from complex values
  /////////////////////////////////////////////////////////////////
  messageTensor cTensor = {{1, 2, 3}, {4, 5, 6}};
  messageTensor cVector = {{1, 2, 3}};
  messageTensor cScalar = messageTensor(1, messageVector(1, 2));

  pTensor t1 = pTensor(2, 3, cTensor);
  pTensor t2 = pTensor(1, 3, cVector);
  pTensor t3 = pTensor(1, 1, cScalar);

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

/////////////////////////////////////////////////////////////////
//Tensor - X op testing
/////////////////////////////////////////////////////////////////
TEST_F(pTensor_TensorTest, TestAdditionTensorTensor) {
    messageTensor expected = {
        {2, 4, 6}, {8, 10, 12}
    };
    auto toAdd = t1.encrypt();

    auto addedVal = toAdd + toAdd;
    auto resp = addedVal.decrypt();
    EXPECT_TRUE(messageTensorEq(resp.getMessage(), expected));

    auto addedValPT = toAdd + cTensor;
    auto respPT = addedValPT.decrypt();
    EXPECT_TRUE(messageTensorEq(respPT.getMessage(), expected));
};
TEST_F(pTensor_TensorTest, TestSubtractionTensorTensor) {
    messageTensor expected = {
        {0, 0, 0}, {0, 0, 0}
    };
    auto toSub = t1.encrypt();

    // Test the encrypted case
    auto subbedEnc = toSub - toSub;
    auto resp = subbedEnc.decrypt();
    EXPECT_TRUE(messageTensorEq(resp.getMessage(), expected));

    // Test the plaintext case
    auto subbedPT = toSub - cTensor;
    auto respPT = subbedPT.decrypt();
    EXPECT_TRUE(messageTensorEq(respPT.getMessage(), expected));
};
TEST_F(pTensor_TensorTest, TestMultTensorTensor) {
    messageTensor expected = {
        {1, 4, 9}, {16, 25, 36}
    };
    auto toMult = t1.encrypt();

    auto multVal = toMult * toMult;
    auto resp = multVal.decrypt();
    EXPECT_TRUE(messageTensorEq(resp.getMessage(), expected));

    auto multValPt = toMult * cTensor;
    auto respPT = multValPt.decrypt();
    EXPECT_TRUE(messageTensorEq(respPT.getMessage(), expected));
}

TEST_F(pTensor_TensorTest, TestAdditionTensorVector) {
    messageTensor expected = {
        {2, 4, 6}, {5, 7, 9}
    };
    auto toAdd = t1.encrypt();
    auto other = t2.encrypt();

    auto addedValEnc = toAdd + other;
    auto otherResp = addedValEnc.decrypt();
    EXPECT_TRUE(messageTensorEq(otherResp.getMessage(), expected));

    auto addedValPT = toAdd + cVector;
    auto resp = addedValPT.decrypt();
    EXPECT_TRUE(messageTensorEq(resp.getMessage(), expected));
};
TEST_F(pTensor_TensorTest, TestSubtractionTensorVector) {
    /**
     * Matrix:
     *  [1,2,3], [4,5,6]
     *
     *  vector:
     *  [1,2,3]
     *
     *  Project it across both rows and we expect [0, 0, 0], [3, 3, 3]
     */

    messageTensor expected = {
        {0, 0, 0}, {3, 3, 3}
    };
    auto toAdd = t1.encrypt();
    auto other = t2.encrypt();

    auto subbedEnc = toAdd - other;
    auto otherResp = subbedEnc.decrypt();
    EXPECT_TRUE(messageTensorEq(otherResp.getMessage(), expected));

    auto subbedPT = toAdd - cVector;
    auto resp = subbedPT.decrypt();
    EXPECT_TRUE(messageTensorEq(resp.getMessage(), expected));

};
TEST_F(pTensor_TensorTest, TestMultTensorVector) {
    messageTensor expected = {
        {1, 4, 9}, {4, 10, 18}
    };
    auto toMult = t1.encrypt();
    auto other = t2.encrypt();

    auto multValEnc = toMult * other;
    auto otherResp = multValEnc.decrypt();
    EXPECT_TRUE(messageTensorEq(otherResp.getMessage(), expected));

    auto multValPt = toMult * cVector;
    auto resp = multValPt.decrypt();
    EXPECT_TRUE(messageTensorEq(resp.getMessage(), expected));
};

TEST_F(pTensor_TensorTest, TestAdditionTensorScalar) {
    messageTensor expected = {
        {3, 4, 5}, {6, 7, 8}
    };
    auto toAdd = t1.encrypt();
    auto other = t3.encrypt();

    auto addedValEnc = toAdd + other;
    auto otherResp = addedValEnc.decrypt();
    EXPECT_TRUE(messageTensorEq(otherResp.getMessage(), expected));

    auto addedValPT = toAdd + cScalar;
    auto resp = addedValPT.decrypt();
    EXPECT_TRUE(messageTensorEq(resp.getMessage(), expected));
};
TEST_F(pTensor_TensorTest, TestSubtractionTensorScalar) {
    messageTensor expected = {
        {-1, 0, 1}, {2, 3, 4}
    };
    auto toSub = t1.encrypt();
    auto other = t3.encrypt();

    auto subbedValEnc = toSub - other;
    auto resp = subbedValEnc.decrypt();
    EXPECT_TRUE(messageTensorEq(resp.getMessage(), expected));

    auto subbedPT = toSub - cScalar;
    auto respPT = subbedPT.decrypt();
    EXPECT_TRUE(messageTensorEq(respPT.getMessage(), expected));
};
TEST_F(pTensor_TensorTest, TestMultTensorScalar) {
    messageTensor expected = {
        {2, 4, 6}, {8, 10, 12}
    };
    auto toMult = t1.encrypt();
    auto other = t3.encrypt();

    auto multValEnc = toMult * other;
    auto otherResp = multValEnc.decrypt();
    EXPECT_TRUE(messageTensorEq(otherResp.getMessage(), expected));

    auto multValPt = toMult * cScalar;
    auto resp = multValPt.decrypt();
    EXPECT_TRUE(messageTensorEq(resp.getMessage(), expected));
}

