/**
 * Author: Ian Quah
 * Date: 1/8/21
 *
 * Requires that the dataset is organized according to (#samples, #features) which allows us to index into and shuffle rows around.
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
   * @param X the feature matrix of shape (#samples, #features)
   * @param y a vector of size (1, #samples)
   * @param numFolds
   *    The number of folds to generate. The result of our "provide" method will be of this size
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
   * Provide the shuffled dataset to be iterated over
   * @param randomState
   *    The random seed to use when shuffling
   * @param encrypt
   *    Whether to encrypt the results.
   * @return
   */
  providedDataset provide(int randomState = 42, bool encrypt = false);

 private:
  pTensor m_X;
  pTensor m_y;
  unsigned int m_numFolds;

};

#endif //DATASETPROVIDER_H
