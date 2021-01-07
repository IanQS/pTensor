/**
 * Author: Ian Quah
 * Date: 18 Dec
 *
 * Although the name may suggest it, we only support rank 2 tensors and below
 * For the most part we try and mimic the numpy interface as closely as possible.
 *
 * 1) NOTE: we always require that the LHS is a ciphertext. The RHS may be either a ciphertext or raw message
 * E.g in
 *  x - y
 *  x + y
 *  x must be a ciphertext and y can be either a ciphertext or raw message
 *
 *  For now we only return an encrypted tensor. We will (maybe) support other types in the future
 *
 *  2) We don't distinguish between a scalar or a vector in the encrypted sense as we just have a ciphertext.
 *  We do, however, have a concept of a vector of ciphertexts which we call a ciphertext matrix
 *
 *  3) If we are passed in a message we by-default also generate the transpose (which is then encrypted). So, by default
 *      all pTensors which are passed in plaintexts will have their encrypted transpose for free. We also provide a function
 *      to generate the transpose for encrypted matrices but it is much slower.
 */
#ifndef PTENSOR_P_TENSOR_H
#define PTENSOR_P_TENSOR_H

#include "palisade.h"
#include <tuple>
#include <iostream>
#include <utility>
#include <vector>
#include <exception>
#include <complex>
#include "ptensor_utils.h"
#include <cassert>

/**
 * Main Palisade Tensor class
 *  - We need to initialize a static member before doing any of the operations
 */
using cipherVector = lbcrypto::Ciphertext<lbcrypto::DCRTPoly>;
using cipherTensor = std::vector<cipherVector>;

using messageScalar = std::complex<double>;
using messageVector = std::vector<messageScalar>;
using messageTensor = std::vector<messageVector>;

// Utilities for creating directly from real numbers. My IDE screams a me otherwise.
using realMessageScalar = double;
using realMessageVector = std::vector<realMessageScalar>;
using realMessageTensor = std::vector<realMessageVector>;

using palisadeBinaryOp = cipherVector (*)(cipherVector left, cipherVector right);

class pTensor {
 public:

  lbcrypto::CryptoContext<lbcrypto::DCRTPoly> *m_cc = nullptr;
  shared_ptr<lbcrypto::LPPublicKeyImpl<lbcrypto::DCRTPoly>> m_public_key = nullptr;
  shared_ptr<lbcrypto::LPPrivateKeyImpl<lbcrypto::DCRTPoly>> m_private_key = nullptr;

  pTensor()= default;

  pTensor(int rows, int cols, bool isEncrypted = false) :
      m_rows(rows), m_cols(cols), m_isEncrypted(isEncrypted) {};

  /////////////////////////////////////////////////////////////////
  //Initialize from a transpose
  /////////////////////////////////////////////////////////////////

  /**
   * Initialize a pTensor from both the tensor itself as well as the transpose
   *    that we obtained (through some means or another). This allows us to operate faster.
   * @param rows number of rows
   * @param cols number of cols
   * @param cTensor ciphertext tensor
   * @param cTensorTranspose transpose of the aforementioned ciphertext
   * @param isRepeated: whether the cipher has been repeated. If yes, we do not project it in the SCALAR case. else, we project it
   */
  pTensor(unsigned int rows,
          unsigned int cols,
          cipherTensor &cTensor,
          cipherTensor &cTensorTranspose,
          bool isRepeated = false) :
      m_rows(rows),
      m_cols(cols),
      m_isEncrypted(true),
      m_ciphertexts(cTensor),
      m_TCiphertexts(cTensorTranspose),
      m_isRepeated(isRepeated) {
      if (isRepeated) { // Can only be repeated if scalar value
          assert(rows == cols && cols == 1);

          // If we trust that the user has put in the cipher and transpose correctly, we can check the following too
          assert(cTensor.size() == 1);  // Rows must be 0.
          assert(cTensorTranspose.size()==1);
      }
  };

  /////////////////////////////////////////////////////////////////
  //Ciphertext initialization
  /////////////////////////////////////////////////////////////////

  /**
   * Instantiate the object directly from a ciphertext matrix
   * @param rows number of rows
   * @param cols number of cols. Only used in the decryption process
   * @param cipherTensor the encrypted message to store
   * @param precomputeTranspose whether to encrypt the transpose of this pTensor in addition to the actual value.
   * @param isRepeated: whether the cipher has been repeated. If yes, we do not project it in the SCALAR case. else, we project it
   */
  pTensor(unsigned int rows, unsigned int cols, cipherTensor &cipherTensor, bool isRepeated = false) :
      m_rows(rows),
      m_cols(cols),
      m_isEncrypted(true),
      m_ciphertexts(cipherTensor),
      m_isRepeated(isRepeated) {
      if (isRepeated){
          assert(rows == cols && cols == 1);
          assert(m_ciphertexts.size() ==1);  // We cannot check the cols as they are encrypted and have to take this on good faith.
      }
  };

  /////////////////////////////////////////////////////////////////
  //Destructor
  /////////////////////////////////////////////////////////////////

  ~pTensor(){}

  /////////////////////////////////////////////////////////////////
  // Initialization from messages
  /////////////////////////////////////////////////////////////////


  /**
 * Instantiate the object directly from a raw message matrix
 * @param rows number of rows
 * @param cols number of cols. Only used in the decryption process
 * @param complexTensor the raw message to store
* @param precomputeTranspose whether to encrypt the transpose of this pTensor in addition to the actual value.
 */
  pTensor(unsigned int rows, unsigned int cols, messageTensor &complexTensor) :
      m_rows(rows),
      m_cols(cols),
      m_messages(complexTensor) {
//      assert(rows == complexTensor.size());
//      assert(cols == complexTensor[0].size());
  };

//  /**
//* Instantiate the object directly from a raw real message matrix
//* @param rows number of rows
//* @param cols number of cols. Only used in the decryption process
//* @param realTensor the raw message to store
//* @param precomputeTranspose whether to encrypt the transpose of this pTensor in addition to the actual value.
//*/
//  pTensor(int rows, int cols, realMessageTensor &realTensor) :
//      m_rows(rows),
//      m_cols(cols),
//      m_isEncrypted(false),
//      m_messages(realTensor.begin(), realTensor.end())
//      {
//  }


  /////////////////////////////////////////////////////////////////
  //Implementations
  /////////////////////////////////////////////////////////////////

  /**
   * Return the shape of the matrix.
   */
  std::tuple<int, int> shape() const { return std::make_tuple(m_rows, m_cols); };

  // Misc. Functions
  // Note, we only need to know if something is a scalar or not so we can broadcast it.

  /**
   * Encrypt the matrix.
   *    NOTE: this fails if we do not have a cryptocontext, public key and m_message set.
   */
  pTensor encrypt();

  /**
   * Decrypt the matrix.
   *    NOTE: this fails if we do not have a cryptocontext, private key and m_ciphertext set.
   */
  pTensor decrypt();

  /////////////////////////////////////////////////////////////////
  //Operator Overloading
  /////////////////////////////////////////////////////////////////
  // Operator Overloading
  /**
   * Addition operator. Uses EvalAdd. The RHS can either be a message pTensor or an encrypted pTensor
   *    and we handle the internal conversions directly. In the case of the other param being a message,
   *    we just cast
   *
   * Some #precomputation happens here that can be eventually disabled.
   *
   * @param other : thing to add
   * @return
   *    Z = this + other
   */
  pTensor operator+(pTensor &other);

  /**
 * Add where the RHS is a matrix
 * @param other
 * @return
 */
  pTensor operator+(messageTensor &other);

  /**
 * Add where the RHS is a vector
 * @param other
 * @return
 */
  pTensor operator+(messageVector &other);
  /**
   * Add where the RHS is a scalar value. We project it into a vector of the number of cols of the thing we want to add.
   * @param other
   * @return
   */
  pTensor operator+(messageScalar &other);

  /**
 * Subtraction operator. Uses EvalSub. The RHS can either be a message pTensor or an encrypted pTensor
 *    and we handle the internal conversions directly
   *
   * Some #precomputation happens here that can be eventually disabled.
   *
 * @param other : thing to subtract from the current pTensor
 * @return
 *    Z = this - other
 */
  pTensor operator-(pTensor &other);

  /**
   * Subtraction where the RHS is a matrix
   * @param other
   * @return
   */
  pTensor operator-(messageTensor &other);

  /**
   * Subtraction where the RHS is a vector
   * @param other
   * @return
   */
  pTensor operator-(messageVector &other);
  /**
   * Subtraction where the RHS is a scalar. We project it into a vector of the number of cols of the thing we want to add.
   * @param other
   * @return
   */
  pTensor operator-(messageScalar &other);

  /**
 * Multiplication operator. Uses EvalAdd. The RHS can either be a message pTensor or an encrypted pTensor
 *    and we handle the internal conversions directly
   *
   * Some #precomputation happens here that can be eventually disabled.
   *
 * @param other : thing to subtract from the current pTensor
 * @return
 *    Z = this - other
 */
  pTensor operator*(pTensor &other);

  /**
   * Hadamard where the RHS is a matrix
   * @param other
   * @return
   */
  pTensor operator*(messageTensor &other);

  /**
   * Hadamard where the RHS is a vector that we broadcast
   * @param other
   * @return
   */
  pTensor operator*(messageVector &other);
  /**
   * Hadamard where RHS is a scalar that we broadcast into the number of cols of the thing we want to add.
   * @param other
   * @return
   */
  pTensor operator*(messageScalar &other);

  /**
   * Dot product only tested between vector-vector and matrix-vector. We let the user choose between a
   *    row vector or a col-vector
   *
   * Note: a col-vector is returned as a matrix. where only the first entry of each row is of interest.
   *    This is equivalent to the row-vector version.
   *
   * Some #precomputation happens here that can be eventually disabled.
   *
   * @param other
   * @return
   */
  pTensor dot(pTensor &other, bool asRowVector = true);  // dot prod

  /**
   * Reduce along both axes. Basically sum up all the elements
   *    Some #precomputation happens here that can be eventually disabled.
   * @return
   */
  pTensor sum();

  /**
   * Reduce either along the
   *    0th (sum downwards. Equivalent to iterating and summing)
   * or
   *    1st axis (sum across rows)
   *
   * Some #precomputation happens here that can be eventually disabled.
   *
   * @param axis
   * @return
   */
  pTensor sum(int axis);

  /**
   * Take the transpose of the encrypted matrix
   *
   *    Some #precomputation happens here that can eventually be disabled.
   *
   * @return
   */
  pTensor T();

  /**
   * Plaintext Transpose.
   */
  messageTensor plainT();

  void debugMessages() {
      for (auto &v: (m_messages)) {
          for (auto &s: v) {
              std::cout << s << ",";
          }
          std::cout << '\n';
      }
  };

  bool messageNotEmpty() {
      return (!m_messages.empty());
  }

  bool cipherNotEmpty() {
      return (!m_ciphertexts.empty());
  }

  /////////////////////////////////////////////////////////////////
  //Getters
  /////////////////////////////////////////////////////////////////

  messageTensor getMessage() {
      return m_messages;
  }

  bool isScalar() {
      return (m_rows == 1 && m_cols == 1);
  }

  bool isVector(){
      bool rowVec = (m_rows == 1 && m_cols != 1);
      bool colVec = (m_rows != 1 && m_cols == 1);
      return (rowVec || colVec);
  }

 private:

  /**
   * Apply the binary operation. Flag is one of
   *    {add, mult, sub}
   *    which indicates what to apply. We maintain the ordering of (lhs op rhs) for functions that are non-associative
   * @param flag
   *    What operation to apply.
   * @param other
   *    The other pTensor
   * @return
   */
  cipherTensor binaryOpAbstraction(const char *flag, pTensor other);
  /**
   * The applicator for cipher-cipher operations
   * @param opFlag
   *    What operation to apply
   * @param a1
   *    Cipher of LHS
   * @param a2
   *    Cipher of RHS
   * @return
   */
  cipherVector applyBinaryOp(const char *opFlag, const cipherVector &a1, const cipherVector &a2) const;

  /**
   * applicator of cipher-vector operations
   * @param opFlag
   *    What operation to apply
   * @param a1
   *    Cipher of LHS
   * @param a2
   *    Message of RHS
   * @return
   */
  cipherVector applyBinaryOp(const char *opFlag, const cipherVector &a1, const lbcrypto::Plaintext &a2) const;

  unsigned int m_rows = 0;
  unsigned int m_cols = 0;
  bool m_isEncrypted = false;  // Default unencrypted unless arg is passed in
  messageTensor m_messages;
  cipherTensor m_ciphertexts;
  cipherTensor m_TCiphertexts; // the encrypted transpose.
  bool m_isRepeated = false;  // Only used for scalar stuff. We record if they have been repeated (into a vector)




};

#endif // PTENSOR_P_TENSOR_H