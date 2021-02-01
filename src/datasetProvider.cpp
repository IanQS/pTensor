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
    std::string mode = (encrypt) ? "encrypted fold": "plaintext fold";
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

        auto shuffledXT = pTensor::plainT(shuffledXMessages);
        auto shuffledYT = pTensor::plainT(shuffledYMessages);
        pTensor pTensorShuffledX(numberOfCols, numberOfRows, shuffledXT);
        pTensor pTensorShuffledY(1, numberOfRows, shuffledYT);

        container.emplace_back(
            std::make_tuple(pTensorShuffledX, pTensorShuffledY)
        );
    }
    if (encrypt){
        return encryptDataset(container);
    }
    return container;
}
providedDataset datasetProvider::encryptDataset(const providedDataset& toBeEncrypted) {

    auto t1 = std::chrono::high_resolution_clock::now();
    auto t2 = std::chrono::high_resolution_clock::now();
    providedDataset encryptedContainer;
    int counter = 1;
    for (auto &dataPair: toBeEncrypted){
        t1 = std::chrono::high_resolution_clock::now();
        auto X = std::get<0>(dataPair);
        auto encX = X.encrypt();

        auto y = std::get<1>(dataPair);
        auto ency = y.encrypt();

        encryptedContainer.emplace_back(std::make_tuple(encX, ency));

        t2 = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
        std::cout << "Took " << duration * 1e-6 << " seconds to encrypt fold " << counter << "/" << toBeEncrypted.size() << std::endl;
        counter += 1;
    }
    return encryptedContainer;
}
