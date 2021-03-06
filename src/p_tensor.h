/**
 * Author: Ian Quah
 * Date: 18 Dec
 *
 *
 * \details{Although the name may suggest it, we only support rank 2 tensors and below
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
 *  }
 */
#ifndef PTENSOR_P_TENSOR_H
#define PTENSOR_P_TENSOR_H

#include <stdexcept>
class NotImplementedException : public std::logic_error {
 public:
  NotImplementedException() : std::logic_error{"Function not yet implemented."} {}
};

#include "palisade.h"
#include <tuple>
#include <iostream>
#include <utility>
#include <vector>
#include <exception>
#include <complex>
#include "ptensor_utils.h"
#include <cassert>
#include <random>

/**
 * Main Palisade Tensor class
 *  - We need to initialize a static member before doing any of the operations
 */
using cipherVector = lbcrypto::Ciphertext<lbcrypto::DCRTPoly>;
using cipherTensor = std::vector<cipherVector>;

using messageScalar = std::complex<double>;
using messageVector = std::vector<messageScalar>;
using messageTensor = std::vector<messageVector>;

using realScalar = double;
using realVector = std::vector<realScalar>;

class pTensor {
 public:

  static lbcrypto::CryptoContext<lbcrypto::DCRTPoly> *m_cc;
  static shared_ptr<lbcrypto::LPPublicKeyImpl<lbcrypto::DCRTPoly>> m_public_key;
  static shared_ptr<lbcrypto::LPPrivateKeyImpl<lbcrypto::DCRTPoly>> m_private_key;

  pTensor() = default;

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
      m_isRepeated(isRepeated) {
      if (isRepeated) { // Can only be repeated if scalar value
          assert(rows == cols && cols == 1);

          // If we trust that the user has put in the cipher and transpose correctly, we can check the following too
          assert(cTensor.size() == 1);  // Rows must be 0.
          assert(cTensorTranspose.size() == 1);
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
      if (isRepeated) {
          assert(rows == cols && cols == 1);
          assert(m_ciphertexts.size()
                     == 1);  // We cannot check the cols as they are encrypted and have to take this on good faith.
      }
  };

  /////////////////////////////////////////////////////////////////
  //Destructor
  /////////////////////////////////////////////////////////////////

  ~pTensor() = default;

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
  pTensor(unsigned int rows, unsigned int cols, messageTensor &complexTensor)
      : m_rows(rows), m_cols(cols), m_messages(complexTensor) {}

  /////////////////////////////////////////////////////////////////
  //Implementations
  /////////////////////////////////////////////////////////////////

  /**
   * Return the shape of the matrix.
   */
  std::tuple<unsigned int, unsigned int> shape() const { return std::make_tuple(m_rows, m_cols); };

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
   * A dot product corresponding to how one normally thinks about a dot product
   *    Mimics the interface from numpy
   *
   * @param other
   * @return
   */
  pTensor dot(pTensor &other, bool asRowVector = true);  // dot prod

  /**
   * Encrypted dot product:
   *    Made to work on column-encrypted matrices (where we transpose then encrypt row-wise)
   *
   *    Has 2 modes:
   *        2 matrices of the same shape: first does a hadamard then a sum. Used for weights and data
   *        Matrix-vector: Given the residuals, update the gradient accordingly
   * @param other
   * @param asRowVector
   * @return
   */
  pTensor encryptedDot(pTensor &other);  // dot prod
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

  /**
   * Static plaintext transpose
   */
  static messageTensor plainT(messageTensor message);

  /**
   * Debug the messages from an UNENCRYPTED matrix. this is unrealistic and will not be available for general purposes as we
   * would need the secret key
   */
  void debugMessages() {
      for (auto &v: (m_messages)) {
          for (auto &s: v) {
              std::cout << s << ",";
          }
          std::cout << '\n';
      }
  };

  /**
   * Check if the message is non-empty
   * @return
   */
  bool messageNotEmpty() {
      return (!m_messages.empty());
  }

  /**
   * Check if the cipher is non-empty
   * @return
   */
  bool cipherNotEmpty() {
      return (!m_ciphertexts.empty());
  }

  /**
   * Generate the (n, n) identity matrix. We either return it in encrypted form or plaintext form
   *    but it is trivial to encrypt via the utility function
   * @param n
   *    The size of the matrix
   * @param encrypted
   *    Flag to denote if it should be encrypted (default false)
   * @return
   */
  static pTensor identity(unsigned int n);

  /**
   * Generate a randomUniform tensor of (rows, cols) where each element is between [low, high)
   *    The user can specify whether to encrypt the result.
   *
   *    Code based on https://cplusplus.com/reference/random/uniform_real_distribution/
   * @param rows
   *    Number of rows
   * @param cols
   *    number of cols
   * @param low
   *    minimum (inclusive) of the randomUniform values
   * @param high
   *    maximum (exclusive) of the randomUniform values
   * @param encrypted
   *    whether the result should be encrypted
   * @return
   */
  static pTensor randomUniform(unsigned int rows,
                               unsigned int cols,
                               double low = 0.0,
                               double high = 1.0);

  /**
   * Generate a randomNormal distribution tensor of (rows, cols) where each element is between [low, high)
   *    The user can specify whether to encrypt the result.
   *
   *    Answers based on
   * @param rows
   *    Number of rows
   * @param cols
   *    number of cols
   * @param low
   *    minimum (inclusive) of the random normal values
   * @param high
   *    maximum (exclusive) of the random normal values
   * @param encrypted
   *    whether the result should be encrypted
   * @return
   */
  static pTensor randomNormal(unsigned int rows, unsigned int cols, int low = 0, int high = 1);

  /**
   * Generate repeated weigts. Used for matrix-matrix dot product a la X.dot(weights). This is used because it is more
   *    efficient to encrypt the data feature-wise (num features, num observations) since, in general, there are more observations than features.
   * @param numFeatures
   *    The number of features that exist
   * @param numRepeats
   *    The number of times to repeat the weights
   * @param seed
   *    If given, we use these values to seed our weights. I.e we do not generate random values that are repeated and we just repeat whatever was given
   * @param randomInitializer
   *    Generates the distribution
   * @return
   */
  static pTensor generateWeights(unsigned int numFeatures,
                                 unsigned int numRepeats,
                                 const messageTensor &seed = {},
                                 const std::string &randomInitializer = "normal");

  /**
   * Vertically stack the tensors.
   * @param arg1
   * @param arg2
   * @return
   */
  static pTensor hstack(pTensor arg1, pTensor arg2);

  /////////////////////////////////////////////////////////////////
  //Getters
  /////////////////////////////////////////////////////////////////

  /**
   * Get the message
   * @return
   */
  messageTensor getMessage() {
      return m_messages;
  }

  /**
   * Check if the current pTensor is a scalar
   * @return
   */
  bool isScalar() const {
      return (m_rows == 1 && m_cols == 1);
  }

  /**
   * Check if the current pTensor is a vector
   * @return
   */
  bool isVector() const {
      bool rowVec = (m_rows == 1 && m_cols != 1);
      bool colVec = (m_rows != 1 && m_cols == 1);
      return (rowVec || colVec);
  }

  /**
   * We only support up to matrices so we can just determine if it is a matrix by process of elimination
   * @return
   */
  bool isMatrix() const {
      return (!isVector() && !isScalar());
  }


  /**
   * Apply the gradients to the weights. The weights are a matrix so we need to consider that while doing the application
   * as our usual broadcasting doesn't work
   * @param matrixOfWeights
   *    Current weights of shape: #features, #observations
   * @param vectorGradients
   *    Gradient to apply: 1, #features
   * @return
   *    new REPEATED weights of shape #features, #observations
   */
  static pTensor applyGradient(pTensor matrixOfWeights, pTensor vectorGradients);

  /**
   * Utility function to go from a scalar directly to a pTensor
   * @tparam numericalScalar
   *    Type of double, float, int, ....
   * @param value
   *    The actual value
   * @return
   */
  template<class numericalScalar>
  static pTensor encryptScalar(numericalScalar value, bool encrypt=false) {
      messageVector asVector = {value};

      if (encrypt){
          cipherVector container = (*m_cc)->Encrypt(
              m_public_key,
              (*m_cc)->MakeCKKSPackedPlaintext(asVector)
          );
          cipherTensor tensorContainer = {container};
          pTensor newTensor = pTensor(1, 1, tensorContainer);
          return newTensor;
      }
      messageTensor asTensor = {asVector};
      pTensor newTensor(1, 1, asTensor);
      return newTensor;
  }

  /**
   * Get the batch size for repetition of elements. The value of interest must be in the -1-th index slot (they wrap around). We
   *    effectively sum which is a cumulative sum. Now, only the last batchSize values are the values of interest so we then
   *    rotate the entire cipher around
   *
   * For the summation, we use the negative of this value
   * For the rotation, we use the actual value
   * @return
   */
  static int getRepeatBatchSize() {
      int ringDim = (*m_cc)->GetRingDimension();
      return int(-ringDim / 4) + 1;
  };

  /**
   * Used for non-repeat sums and or inner products
   * @return
   */
  static int getBatchSize() {
      return int((*m_cc)->GetRingDimension() / 4);
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
  bool m_isRepeated = false;  // Only used for scalar stuff. We record if they have been repeated (into a vector)

};

#endif // PTENSOR_P_TENSOR_H
