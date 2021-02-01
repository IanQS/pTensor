/**
 * Author: Ian Quah
 * Date: 1/8/21
 *
 * Requires that the dataset is organized according to (#samples, #features) which allows us to index into and shuffle rows around.
 *
 * In a prod environment the data enclave can send X folds to the consumer to start training on and then trickle in more and more folds
 * especially if we're using threads
 */
#ifndef DATASETPROVIDER_H
#define DATASETPROVIDER_H

#include "p_tensor.h"
#include <tuple>
#include <algorithm>
#include <random>
#include <chrono>


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
      if (!(X.messageNotEmpty() && X.isMatrix())) {
          std::cout << "X needs to be non-empty and a matrix" << std::endl;
          exit(1);
      }

      auto xShape = X.shape();
      auto yShape = y.shape();
      if (!(y.messageNotEmpty() && y.isVector() && std::get<1>(yShape) == 1)) {
          std::cout << "Y needs to be a non-empty row vector" << std::endl;
          exit(1);
      }

      if (std::get<0>(xShape) != std::get<0>(yShape)) {
          std::cout << "X and Y need to have same number of observations" << std::endl;
      }

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

  /**
   * If we are to encrypt, we call this at the end to go about encrypting
   * @param toBeEncrypted
   * @return
   */
  providedDataset encryptDataset(const providedDataset& toBeEncrypted);

 private:
  pTensor m_X;
  pTensor m_y;
  unsigned int m_numFolds;

};

#endif //DATASETPROVIDER_H
