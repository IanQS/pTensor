/**
 * Author: Ian Quah
 * Date: 1/8/21 
 */
#include "datasetProvider.h"

int f() {
    static int i = 0;
    return i++;
}

template<typename order_iterator, typename value_iterator>
void reorder(order_iterator order_begin, order_iterator order_end, value_iterator v) {
    typedef typename std::iterator_traits<value_iterator>::value_type value_t;
    typedef typename std::iterator_traits<order_iterator>::value_type index_t;
    typedef typename std::iterator_traits<order_iterator>::difference_type diff_t;

    diff_t remaining = order_end - 1 - order_begin;
    for (index_t s = index_t(), d; remaining > 0; ++s) {
        for (d = order_begin[s]; d > s; d = order_begin[d]);
        if (d == s) {
            --remaining;
            value_t temp = v[s];
            while (d = order_begin[d], d != s) {
                swap(temp, v[d]);
                --remaining;
            }
            v[s] = temp;
        }
    }
}

providedDataset datasetProvider::provide(int randomState, bool encrypt) {

    // Generate a vector of range values 0-#Rows
    auto numberOfRows = std::get<0>(m_X.shape());
    auto numberOfCols = std::get<1>(m_X.shape());
    std::vector<int> indices(numberOfRows);
    std::generate(indices.begin(), indices.end(), f);

    std::random_device rd;
    auto rng = std::default_random_engine{rd()};
    rng.seed(randomState);

    providedDataset container;
    for (unsigned int i = 0; i < m_numFolds; i++) {
        std::shuffle(std::begin(indices), std::end(indices), rng);
        messageTensor shuffledXMessages;
        messageTensor shuffledYMessages;

        messageTensor originalXMessages = m_X.getMessage();
        messageTensor originalYMessages = m_y.getMessage();

        for (auto &ind: indices) {
            shuffledXMessages.emplace_back(originalXMessages[ind]);
            shuffledYMessages.emplace_back(originalYMessages[ind]);
        }

        pTensor pTensorShuffledX(numberOfRows, numberOfCols, shuffledXMessages);
        pTensor pTensorShuffledY(numberOfRows, 1, shuffledYMessages);

        if (encrypt) {
            auto encryptedX = pTensorShuffledX.encrypt();
            auto encryptedY = pTensorShuffledY.encrypt();
            container.emplace_back(
                std::make_tuple(encryptedX, encryptedY)
            );
        } else {
            container.emplace_back(
                std::make_tuple(pTensorShuffledX, pTensorShuffledY)
            );

        }

    }
    return container;
}
