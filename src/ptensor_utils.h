/**
 * Created by ian on 12/22/20.
 * https://numpy.org/devdocs/user/theory.broadcasting.html
 *
 * We base our implementation on this. To broadcast we need to receive another instance
 * of pTensor the crux of which is:
 * @param other other pTensor that we may want to broadcast over
 */

#ifndef PTENSOR_UTILS_H
#define PTENSOR_UTILS_H

#include <tuple>
#include <exception>

class BroadcastError : public std::exception {
 public:
  BroadcastError(std::tuple<int, int> s1, std::tuple<int, int> s2) : s1(std::move(s1)), s2(std::move(s2)) {

  }

  virtual const char *what() const throw() {
      auto m1_row = std::get<0>(s1);
      auto m1_col = std::get<1>(s1);

      auto m2_row = std::get<0>(s2);
      auto m2_col = std::get<1>(s2);
      auto toThrow = "Broadcasting error. The given tensors have incompatible shapes. Tensor1: (" +
          std::to_string(m1_row) + ", " + std::to_string(m1_col) +
          ") Tensor 2: (" +
          std::to_string(m2_row) + ", " + std::to_string(m2_col) + "). The last axis shape must be equal.";

      char *eMsg = new char[toThrow.length() + 1];
      strcpy(eMsg, toThrow.c_str());
      return eMsg;
  }

  std::tuple<int, int> s1;
  std::tuple<int, int> s2;

};

/**
 * Verify that the shape of the incoming arguments are correct. Used to verify
 *  if two pTensors are valid in terms of being operated on.
 * @param first : first pTensor
 * @param second : second pTensor
 * @return None, but throws an error
 */

template<typename pTensor>
// TODO: avoid circular import. This is hacky at best.
void shapeVerifier(const pTensor &first, const pTensor &second) {
    // check the cols firs
    auto firstShape = first.shape();
    auto secondShape = second.shape();
    auto firstRows = std::get<0>(firstShape);
    auto firstCols = std::get<1>(firstShape);
    auto secRows = std::get<0>(secondShape);
    auto secCols = std::get<1>(secondShape);
    bool col_same_size = (firstCols == secCols);  // if same size in the cols, no need to stretch
    bool col_stretchable = (firstCols == 1) || (secCols == 1); // only dimensions of size 1 can be stretched

    // We overwrite the values of col_same_size and col_stretchable
    // We can do this because it doesn't matter what the number of cols are
    // in the encrypted-{encrypted/ message} setting as we always just take the max
    // of the two and decrypt on that when we are done.
    // If we accepted plaintexts on both sides then we would
    // need to use the above
    col_same_size = true;
    col_stretchable = true;

    // if either of those is true we then check the rows
    bool row_same_size = (firstRows == secRows);
    bool row_stretchable = (firstRows == 1) || (secRows == 1); // only dimensions of size 1 can be stretched

    if (!((col_same_size || col_stretchable) && (row_same_size || row_stretchable))) {
        throw BroadcastError(first.shape(), second.shape());
    }
}
#endif //PTENSOR_UTILS_H
