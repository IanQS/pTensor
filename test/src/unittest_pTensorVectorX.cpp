/**
 * Author: Ian Quah
 * Date: 1/6/21 
 */


#include "gtest/gtest.h"
#include "../../src/p_tensor.h"
#include "palisade.h"

class pTensor_VectorTest : public ::testing::Test {

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

      t1.m_cc = &cc;
      t1.m_public_key = public_key;
      t1.m_private_key = private_key;

      t2.m_cc = &cc;
      t2.m_public_key = public_key;
      t2.m_private_key = private_key;

      t3.m_cc = &cc;
      t3.m_public_key = public_key;
      t3.m_private_key = private_key;

  }

  void TearDown() {
      lbcrypto::CryptoContextFactory<lbcrypto::DCRTPoly>::ReleaseAllContexts();

      cc->ClearEvalMultKeys();
      cc->ClearEvalAutomorphismKeys();
      cc = nullptr;
      public_key = nullptr;
      private_key = nullptr;
  }

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
                  std::cout << arg1[i][j].real() << "," << arg2[i][j].real() << std::endl;
                  return false;
              }
          }
      }
      return true;
  }
};

/////////////////////////////////////////////////////////////////
//Vector - X op testing
/////////////////////////////////////////////////////////////////
TEST_F(pTensor_VectorTest, TestAdditionVectorTensor) {
    messageTensor expected = {
        {2, 4, 6}, {5, 7, 9}
    };
    auto toAdd = t2.encrypt();

    auto other = t1.encrypt();

    auto addedVal = toAdd + other;
    auto resp = addedVal.decrypt();
    EXPECT_TRUE(messageTensorEq(resp.getMessage(), expected)
    );

    auto addedValPT = toAdd + cTensor;
    auto respPT = addedValPT.decrypt();
    EXPECT_TRUE(messageTensorEq(respPT.getMessage(), expected)
    );
};
TEST_F(pTensor_VectorTest, TestSubtractionVectorTensor) {
    messageTensor expected = {
        {0, 0, 0}, {3, 3, 3}
    };
    auto toSub = t2.encrypt();

    auto other = t1.encrypt();
    // Test the encrypted case
    auto subbedEnc = toSub - other;
    auto resp = subbedEnc.decrypt();
    EXPECT_TRUE(messageTensorEq(resp.getMessage(), expected)
    );

    // Test the plaintext case
    auto subbedPT = toSub - cTensor;
    auto respPT = subbedPT.decrypt();
    EXPECT_TRUE(messageTensorEq(respPT.getMessage(), expected)
    );
};
TEST_F(pTensor_VectorTest, TestMultVectorTensor) {
    messageTensor expected = {
        {1, 4, 9}, {4, 10, 18}
    };
    auto toMult = t2.encrypt();
    auto other = t1.encrypt();

    auto multVal = toMult * other;
    auto resp = multVal.decrypt();
    EXPECT_TRUE(messageTensorEq(resp.getMessage(), expected)
    );

    auto multValPt = toMult * cTensor;
    auto respPT = multValPt.decrypt();
    EXPECT_TRUE(messageTensorEq(respPT.getMessage(), expected)
    );
}

TEST_F(pTensor_VectorTest, TestAdditionVectorVector) {
    messageTensor expected = {
        {2, 4, 6}
    };
    auto toAdd = t2.encrypt();
    auto other = t2.encrypt();

    auto addedValEnc = toAdd + other;
    auto otherResp = addedValEnc.decrypt();
    EXPECT_TRUE(messageTensorEq(otherResp.getMessage(), expected)
    );

    auto addedValPT = toAdd + cVector;
    auto resp = addedValPT.decrypt();
    EXPECT_TRUE(messageTensorEq(resp.getMessage(), expected)
    );
};
TEST_F(pTensor_VectorTest, TestSubtractionVectorVector) {
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
        {0, 0, 0}
    };
    auto toAdd = t2.encrypt();
    auto other = t2.encrypt();

    auto subbedEnc = toAdd - other;
    auto otherResp = subbedEnc.decrypt();
    EXPECT_TRUE(messageTensorEq(otherResp.getMessage(), expected)
    );

    auto subbedPT = toAdd - cVector;
    auto resp = subbedPT.decrypt();
    EXPECT_TRUE(messageTensorEq(resp.getMessage(), expected)
    );

};
TEST_F(pTensor_VectorTest, TestMultVectorVector) {
    messageTensor expected = {
        {1, 4, 9}
    };
    auto toMult = t2.encrypt();
    auto other = t2.encrypt();

    auto multValEnc = toMult * other;
    auto otherResp = multValEnc.decrypt();
    EXPECT_TRUE(messageTensorEq(otherResp.getMessage(), expected)
    );

    auto multValPt = toMult * cVector;
    auto resp = multValPt.decrypt();
    EXPECT_TRUE(messageTensorEq(resp.getMessage(), expected)
    );
};

TEST_F(pTensor_VectorTest, TestAdditionVectorScalar) {
    messageTensor expected = {
        {3, 4, 6}
    };
    auto toAdd = t2.encrypt();
    auto other = t3.encrypt();

    auto addedValEnc = toAdd + other;
    auto otherResp = addedValEnc.decrypt();
    EXPECT_TRUE(messageTensorEq(otherResp.getMessage(), expected)
    );

    auto addedValPT = toAdd + cScalar;
    auto resp = addedValPT.decrypt();
    EXPECT_TRUE(messageTensorEq(resp.getMessage(), expected)
    );
};
TEST_F(pTensor_VectorTest, TestSubtractionVectorScalar) {
    messageTensor expected = {
        {-1, 0, 1}
    };
    auto toSub = t2.encrypt();
    auto other = t3.encrypt();

    auto subbedValEnc = toSub - other;
    auto resp = subbedValEnc.decrypt();
    EXPECT_TRUE(messageTensorEq(resp.getMessage(), expected)
    );

    auto subbedPT = toSub - cScalar;
    auto respPT = subbedPT.decrypt();
    EXPECT_TRUE(messageTensorEq(respPT.getMessage(), expected)
    );
};
TEST_F(pTensor_VectorTest, TestMultVectorScalar) {
    messageTensor expected = {
        {2, 4, 6}
    };
    auto toMult = t2.encrypt();
    auto other = t3.encrypt();

    auto multValEnc = toMult * other;
    auto otherResp = multValEnc.decrypt();
    EXPECT_TRUE(messageTensorEq(otherResp.getMessage(), expected)
    );

    auto multValPt = toMult * cScalar;
    auto resp = multValPt.decrypt();
    EXPECT_TRUE(messageTensorEq(resp.getMessage(), expected)
    );
}