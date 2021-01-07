/**
 * Author: Ian Quah
 * Date: 1/6/21 
 */


#include "gtest/gtest.h"
#include "../../src/p_tensor.h"
#include "palisade.h"

class pTensor_TensorMisc : public ::testing::Test {

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

TEST_F(pTensor_TensorMisc, TestShape) {
    int expectedRows = 1;
    int expectedCols = 3;

    auto actualShape = t2.shape();
    int actualRows = std::get<0>(actualShape);
    int actualCols = std::get<1>(actualShape);

    EXPECT_EQ(expectedRows, actualRows);
    EXPECT_EQ(expectedCols, actualCols);
};
TEST_F(pTensor_TensorMisc, TestEncryptionDecryption) {
    // Test the encryption process
    auto newThing = t1.encrypt();
    EXPECT_EQ(newThing.messageNotEmpty(), false);
    EXPECT_EQ(newThing.cipherNotEmpty(), true);

    // Test the decryption process
    auto decryptedNewThing = newThing.decrypt();
    EXPECT_EQ(decryptedNewThing.messageNotEmpty(), true);
    EXPECT_EQ(decryptedNewThing.cipherNotEmpty(), false);

    EXPECT_EQ(messageTensorEq(t1.getMessage(), decryptedNewThing.getMessage()), true);
};
TEST_F(pTensor_TensorMisc, TestTransposePT) {

    /////////////////////////////////////////////////////////////////
    //Tensor transpose
    /////////////////////////////////////////////////////////////////
    auto tensorTranspose = t1.plainT();
    messageTensor expectedTensorT = {
        {1, 4}, {2, 5}, {3, 6}
    };
    EXPECT_TRUE(messageTensorEq(tensorTranspose, expectedTensorT));

    /////////////////////////////////////////////////////////////////
    //Vector Transpose
    /////////////////////////////////////////////////////////////////
    auto vectorTranspose = t2.plainT();
    messageTensor expectedVectorT = {
        {1}, {2}, {3}
    };
    EXPECT_TRUE(messageTensorEq(vectorTranspose, expectedVectorT));

    /////////////////////////////////////////////////////////////////
    //Scalar Transpose
    /////////////////////////////////////////////////////////////////

    auto scalarTranspose = t3.plainT();
    messageTensor expectedScalarT = {
        {2}
    };
    EXPECT_TRUE(messageTensorEq(scalarTranspose, expectedScalarT));
};
TEST_F(pTensor_TensorMisc, TestDotTensorVector) {
    messageTensor expectedRowForm = {
        {14, 32}
    };
    messageTensor expectedColForm = {
        {14}, {32}
    };
    auto toDot = t1.encrypt();
    auto other = t2.encrypt();

    auto colFormResp = toDot.dot(other, false);
    auto decrypted = colFormResp.decrypt();
    EXPECT_TRUE(
        messageTensorEq(
            decrypted.getMessage(),
            expectedColForm)
    );

    auto rowFormResp = toDot.dot(other, true);
    decrypted = rowFormResp.decrypt();
    EXPECT_TRUE(
        messageTensorEq(
            decrypted.getMessage(),
            expectedRowForm)
    );
}
TEST_F(pTensor_TensorMisc, TestDotVectorVector) {
    messageTensor expectedRowForm = {
        {14}
    };
    messageTensor expectedColForm = {
        {14}
    };
    auto toDot = t2.encrypt();
    auto other = t2.encrypt();

    auto colFormResp = toDot.dot(other, false);
    auto decrypted = colFormResp.decrypt();
    EXPECT_TRUE(
        messageTensorEq(
            decrypted.getMessage(),
            expectedColForm)
    );

    auto rowFormResp = toDot.dot(other, true);
    decrypted = rowFormResp.decrypt();
    EXPECT_TRUE(
        messageTensorEq(
            decrypted.getMessage(),
            expectedRowForm)
    );
}

TEST_F(pTensor_TensorMisc, TestTransposeEnc){

    messageTensor expectedTensorTranspose = {
        {1, 4},
        {2, 5},
        {3, 6}
    };
    messageTensor expectedVectorTranspose = {
        {1},
        {2},
        {3}
    };

    auto tensor = t1.encrypt();
    auto vector = t2.encrypt();

    auto transposedTensor = tensor.T();
    auto transposedVector = vector.T();

    auto decTensorTransposed = transposedTensor.decrypt();
    auto decVectorTransposed = transposedVector.decrypt();

    EXPECT_TRUE(
        messageTensorEq(
            decTensorTransposed.getMessage(),
            expectedTensorTranspose)
    );

    EXPECT_TRUE(
        messageTensorEq(
            decVectorTransposed.getMessage(),
            expectedVectorTranspose)
    );

}

TEST_F(pTensor_TensorMisc, DISABLED_TestSum) {
    /////////////////////////////////////////////////////////////////
    //We need to up the parameters here so we do it locally.
    /////////////////////////////////////////////////////////////////

    uint8_t multDepth = 11;
    uint8_t scalingFactorBits = 50;
    int batchSize = 16384;

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

    cc->EvalAtIndexKeyGen(keys.secretKey, {-1, 1});

    public_key = keys.publicKey;
    private_key = keys.secretKey;

    t1.m_cc = &cc;
    t1.m_public_key = public_key;
    t1.m_private_key = private_key;

    auto encT1 = t1.encrypt();
    auto allReduce = encT1.sum();
    auto resp = allReduce.decrypt();
    EXPECT_NEAR(resp.getMessage()[0][0].real(), 21.0, 0.001);

    auto axis0 = encT1.sum(0);
    messageTensor expected0 = {{5, 7, 9}};
    resp = axis0.decrypt();
    EXPECT_TRUE(messageTensorEq(resp.getMessage(), expected0));

    auto axis1 = encT1.sum(1);
    messageTensor expected1 = {{6}, {15}};
    resp = axis1.decrypt();
    EXPECT_TRUE(messageTensorEq(resp.getMessage(), expected1));
}
