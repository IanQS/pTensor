/**
 * Author: Ian Quah
 * Date: 1/8/21
 *
 * Requires that the dataset is organized according to (#samples, #features)
 */
#ifndef DATASETPROVIDER_H
#define DATASETPROVIDER_H

#include "p_tensor.h"
#include <tuple>
#include <algorithm>
#include <random>

using trainingPair = std::tuple<pTensor, pTensor>;
using providedDataset = std::vector<trainingPair>;

class datasetProvider {
 public:
  /**
   * Create an instance of the dataset provider. We require that X and y are in plaintext form so that we can store them
   *    as slices
   * @param X
   * @param y
   * @param numFolds
   */
  datasetProvider(pTensor X, pTensor y, unsigned int numFolds) {
      // Check that X has in-the-clear message and is a matrix
      assert(X.messageNotEmpty());
      assert(X.isMatrix());

      // Check that y has in-the-clear message and is a vector
      assert(y.messageNotEmpty());
      assert(y.isVector());

      m_X = X;
      m_y = y;
      m_numFolds = numFolds;
  }

  /**
   *
   * @param numEpochs
   * @param randomState
   * @param encrypt
   * @return
   */
  providedDataset provide(int randomState = 42, bool encrypt = false);

 private:
  pTensor m_X;
  pTensor m_y;
  unsigned int m_numFolds;

};

#endif //DATASETPROVIDER_H
