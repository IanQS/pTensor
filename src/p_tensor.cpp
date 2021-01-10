/**
 * Author: Ian Quah
 * Date: 12/22/20
 */
#include "p_tensor.h"

lbcrypto::CryptoContext<lbcrypto::DCRTPoly> *pTensor::m_cc = nullptr;
shared_ptr<lbcrypto::LPPublicKeyImpl<lbcrypto::DCRTPoly>> pTensor::m_public_key = nullptr;
shared_ptr<lbcrypto::LPPrivateKeyImpl<lbcrypto::DCRTPoly>> pTensor::m_private_key = nullptr;

pTensor pTensor::encrypt() {
    assert(messageNotEmpty() && m_public_key != nullptr && m_cc != nullptr);
    cipherTensor ct;
    // encrypt and place into container
    for (auto &vec: m_messages) {
        lbcrypto::Plaintext packedPT = (*m_cc)->MakeCKKSPackedPlaintext(vec);
        auto resp = (*m_cc)->Encrypt(m_public_key, packedPT);
        ct.emplace_back(resp);
    }

    // modify
    cipherTensor ctT;
    messageTensor transposedTensor = pTensor::plainT();

    for (auto &vec: transposedTensor) {
        lbcrypto::Plaintext packedPT = (*m_cc)->MakeCKKSPackedPlaintext(vec);
        auto resp = (*m_cc)->Encrypt(m_public_key, packedPT);
        ctT.emplace_back(resp);
    }

    pTensor newTensor(m_rows, m_cols, ct, ctT);
    newTensor.m_isEncrypted = true;
    return newTensor;
}

pTensor pTensor::decrypt() {
    assert(cipherNotEmpty() && m_private_key != nullptr && m_cc != nullptr);
    messageTensor mt;
    lbcrypto::Plaintext pt;
    for (auto &vec: m_ciphertexts) {
        (*m_cc)->Decrypt(m_private_key, vec, &pt); // pt now contains the decrypted val
        unsigned int numCols;
        if (m_isRepeated) {
            numCols = 1;
        } else {
            numCols = m_cols;
        }
        pt->SetLength(numCols);
        mt.emplace_back(pt->GetCKKSPackedValue());
    }

    pTensor newTensor(m_rows, m_cols, mt);
    return newTensor;
}
// Cipher-Cipher
cipherVector pTensor::applyBinaryOp(const char *opFlag, const cipherVector &a1, const cipherVector &a2) const {
    cipherVector op_res;
    if (std::strcmp(opFlag, "add") == 0) {
        op_res = (*m_cc)->EvalAdd(a1, a2);
    } else if (std::strcmp(opFlag, "sub") == 0) {
        op_res = (*m_cc)->EvalSub(a1, a2);
    } else if (std::strcmp(opFlag, "mult") == 0) {
        op_res = (*m_cc)->EvalMult(a1, a2);

    }
    return op_res;
}
//Cipher-plaintext
cipherVector pTensor::applyBinaryOp(const char *opFlag, const cipherVector &a1, const lbcrypto::Plaintext &a2) const {
    cipherVector op_res;
    if (std::strcmp(opFlag, "add") == 0) {
        op_res = (*m_cc)->EvalAdd(a1, a2);
    } else if (std::strcmp(opFlag, "sub") == 0) {
        op_res = (*m_cc)->EvalSub(a1, a2);
    } else if (std::strcmp(opFlag, "mult") == 0) {
        op_res = (*m_cc)->EvalMult(a1, a2);
    }
    return op_res;
}
cipherTensor pTensor::binaryOpAbstraction(const char *flag,
                                          pTensor other) {
    cipherTensor ciphertextContainer;

    // Now, we know that it is broadcast-able. Therefore, they either have the same shape or one is shape 1 in rows
    cipherVector op_res;
    int ringDim = (*m_cc)->GetRingDimension();
    for (unsigned int i = 0; i < std::max(m_rows, other.m_rows); i++) {
        unsigned int lhsInd;
        unsigned int rhsInd;

        if (m_rows == other.m_rows) {
            lhsInd = i;
            rhsInd = i;
        } else if (m_rows > other.m_rows) {
            lhsInd = i;
            rhsInd = 0;
        } else {
            lhsInd = 0;
            rhsInd = i;
        }
        if (other.m_isEncrypted) {
            cipherVector otherVec;

            // If it is a scalar that has not been repeated, we repeat it.
            if (other.isScalar() && !(other.m_isRepeated)) {

                // Get how much to sum over and rotate.
                int rot = int(-ringDim / 4) + 1;
                // We've now summed it up and it should be projected into the back
                otherVec = (*m_cc)->EvalSum(other.m_ciphertexts[0], -rot);
                // The last rot entries are now populated with the value. We then rotate them back and we are done.
                otherVec = (*m_cc)->EvalAtIndex(otherVec, rot);

            } else {
                otherVec = other.m_ciphertexts[rhsInd];
            }
            op_res = applyBinaryOp(flag, m_ciphertexts[lhsInd], otherVec);
        } else {
            messageVector otherVec;
            if (other.isScalar()) {  // We repeat the value n_cols times across then do the operation.
                otherVec = messageVector(m_cols, other.m_messages[0][0]);
            } else {
                otherVec = other.m_messages[rhsInd];
            }
            lbcrypto::Plaintext intermediary = (*m_cc)->MakeCKKSPackedPlaintext(otherVec);
            op_res = applyBinaryOp(flag, m_ciphertexts[lhsInd], intermediary);
        }
        ciphertextContainer.emplace_back(op_res);
    }
    return ciphertextContainer;
}

pTensor pTensor::operator+(pTensor &other) {
    assert (m_cc != nullptr && (cipherNotEmpty())
                && (other.messageNotEmpty() || other.cipherNotEmpty()));
    shapeVerifier(*this, other);
    auto resCols = std::max(m_cols, other.m_cols);
    auto resRows = std::max(m_rows, other.m_rows);

    // Now, we know that it is broadcast-able. Therefore, they either have the same shape or one is shape 1 in rows
    cipherTensor ciphertextContainer = binaryOpAbstraction("add", other);
    pTensor newTensor(
        resRows, resCols, ciphertextContainer
    ); // Numpy requires that the output is the max of both
    newTensor.m_isEncrypted = m_isEncrypted;
    return newTensor;
}
pTensor pTensor::operator+(messageTensor &other) {
    auto otherTensor = pTensor(other.size(), other[0].size(), other);
    return (*this) + otherTensor;
}
pTensor pTensor::operator+(messageVector &other) {
    messageTensor messageTensorContainer;
    messageTensorContainer.emplace_back(other);
    auto otherTensor = pTensor(1, other.size(), messageTensorContainer);
    return (*this) + otherTensor;
}
pTensor pTensor::operator+(messageScalar &other) {
    messageVector messageVectorContainer;
    for (unsigned int i = 0; i < m_cols; i++) {
        messageVectorContainer.emplace_back(other);
    }
    messageTensor messageTensorContainer;
    messageTensorContainer.emplace_back(messageVectorContainer);
    auto otherTensor = pTensor(1, 1, messageTensorContainer);
    return (*this) + otherTensor;
}

pTensor pTensor::operator-(pTensor &other) {
    assert (m_cc != nullptr && (cipherNotEmpty())
                && (other.messageNotEmpty() || other.cipherNotEmpty()));
    shapeVerifier(*this, other);
    auto resCols = std::max(m_cols, other.m_cols);
    auto resRows = std::max(m_rows, other.m_rows);

    // Now, we know that it is broadcast-able. Therefore, they either have the same shape or one is shape 1 in rows
    cipherTensor ciphertextContainer = binaryOpAbstraction("sub", other);
    pTensor newTensor(
        resRows, resCols, ciphertextContainer
    ); // Numpy requires that the output is the max of both
    newTensor.m_isEncrypted = m_isEncrypted;
    return newTensor;
}
pTensor pTensor::operator-(messageTensor &other) {
    auto otherTensor = pTensor(other.size(), other[0].size(), other);
    return (*this) - otherTensor;
}
pTensor pTensor::operator-(messageVector &other) {
    messageTensor messageTensorContainer;
    messageTensorContainer.emplace_back(other);
    auto otherTensor = pTensor(1, other.size(), messageTensorContainer);
    return (*this) - otherTensor;
}
pTensor pTensor::operator-(messageScalar &other) {

    messageVector messageVectorContainer;
    for (unsigned int i = 0; i < m_cols; i++) {
        messageVectorContainer.emplace_back(other);
    }
    messageTensor messageTensorContainer;
    messageTensorContainer.emplace_back(messageVectorContainer);
    auto otherTensor = pTensor(1, 1, messageTensorContainer);
    return (*this) - otherTensor;
}

pTensor pTensor::operator*(pTensor &other) {
    assert (m_cc != nullptr && (cipherNotEmpty())
                && (other.messageNotEmpty() || other.cipherNotEmpty()));
    shapeVerifier(*this, other);
    auto resCols = std::max(m_cols, other.m_cols);
    auto resRows = std::max(m_rows, other.m_rows);

    // Now, we know that it is broadcast-able. Therefore, they either have the same shape or one is shape 1 in rows
    cipherTensor ciphertextContainer = binaryOpAbstraction("mult", other);
    pTensor newTensor(
        resRows, resCols, ciphertextContainer
    ); // Numpy requires that the output is the max of both
    newTensor.m_isEncrypted = m_isEncrypted;
    return newTensor;
}
pTensor pTensor::operator*(messageTensor &other) {
    auto otherTensor = pTensor(other.size(), other[0].size(), other);
    return (*this) * otherTensor;
}
pTensor pTensor::operator*(messageVector &other) {

    messageTensor messageTensorContainer;
    messageTensorContainer.emplace_back(other);
    auto otherTensor = pTensor(1, other.size(), messageTensorContainer);
    return (*this) * otherTensor;
}
pTensor pTensor::operator*(messageScalar &other) {

    messageVector messageVectorContainer;
    for (unsigned int i = 0; i < m_cols; i++) {
        messageVectorContainer.emplace_back(other);
    }
    messageTensor messageTensorContainer;
    messageTensorContainer.emplace_back(messageVectorContainer);
    auto otherTensor = pTensor(1, 1, messageTensorContainer);
    return (*this) * otherTensor;
}

/**
 * Dot product as vector-vector or matrix-vector
 *  Note: we also store the transpose at the same time just for some speed.
 * @param other
 *  The thing to dot prod with. In the ML setting this is a vector of the weights
 * @return
 */
pTensor pTensor::dot(pTensor &other, bool asRowVector) {
    assert (m_cc != nullptr && (cipherNotEmpty())
                && (other.messageNotEmpty() || other.cipherNotEmpty()));

    if (isMatrix() && other.isMatrix()) {
        // First do a hadamard prod
        auto elementWiseProd = (*this) * other;
        auto summed = elementWiseProd.sum(0);
        return summed;
    }

    pTensor rhs;
    if (m_cols == other.m_rows) { // we need to transpose to get it into a form amenable for our dot prod.
        rhs = other.T();
    } else {
        rhs = other;
    }

    messageVector _rowAccumulator(m_rows, 0.0);
    cipherVector rowAccumulator = (*m_cc)->Encrypt(
        m_public_key,
        (*m_cc)->MakeCKKSPackedPlaintext(_rowAccumulator));

    // We need to mask out all values but the first for the inner prod.
    messageVector _mask(m_rows, 0.0);
    _mask[0] = 1;
    cipherVector mask = (*m_cc)->Encrypt(
        m_public_key,
        (*m_cc)->MakeCKKSPackedPlaintext(_mask));

    int HARDCODED_INDEX_FOR_OTHER_VECTOR = 0;
    cipherTensor colAccumulator;
    lbcrypto::Plaintext pt;
    for (unsigned int i = 0; i < m_rows; i++) {
        auto innerProd = (*m_cc)->EvalInnerProduct(
            m_ciphertexts[i],
            rhs.m_ciphertexts[HARDCODED_INDEX_FOR_OTHER_VECTOR],
            ((*m_cc)->GetRingDimension() / 4));

        innerProd = (*m_cc)->EvalMult(innerProd, mask);

        // For the col vector
        colAccumulator.emplace_back(innerProd);

        // For the row vector
        for (unsigned int numRot = 0; numRot < i; numRot++) {
            innerProd = (*m_cc)->EvalAtIndex(innerProd, -1);
        }
        rowAccumulator = (*m_cc)->EvalAdd(rowAccumulator, innerProd);
    }

    cipherTensor rowAccumulatorAsTensor;
    rowAccumulatorAsTensor.emplace_back(rowAccumulator);

    if (asRowVector) {
        pTensor newTensor(1, m_rows, rowAccumulatorAsTensor, colAccumulator);
        newTensor.m_isEncrypted = m_isEncrypted;
        return newTensor;
    }
    pTensor newTensor(m_rows, 1, colAccumulator, rowAccumulatorAsTensor);
    newTensor.m_isEncrypted = m_isEncrypted;
    return newTensor;
}

pTensor pTensor::sum() {

    assert (m_cc != nullptr && (cipherNotEmpty()));
    auto colSummedpTensor =    //We now have values summed across the rows.
        sum(1);  // The first el is of interest. We then sum downwards
    messageVector message_accumulator(1, 0.0); // we initialize to 0

    // Accumulator is a vector
    auto accumulator = (*m_cc)->Encrypt(
        m_public_key,
        (*m_cc)->MakeCKKSPackedPlaintext(message_accumulator)
    );
    for (const auto &v : colSummedpTensor.m_ciphertexts) {
        accumulator = (*m_cc)->EvalAdd(accumulator, v);
    }
    cipherTensor asTensor;
    asTensor.emplace_back(accumulator);

    pTensor newTensor(1, 1, asTensor);
    newTensor.m_isEncrypted = m_isEncrypted;
    return newTensor;
}

pTensor pTensor::sum(int axis) {
    assert (m_cc != nullptr && (cipherNotEmpty()));
    if (!m_isEncrypted) {
        std::cout << "Trying to get sum on unencrypted data" << std::endl;
        throw std::runtime_error("sum() on unencrypted pTensors is unsupported");
    }
    if (axis == 0) {
        // Sum downwards over the rows
        messageVector message_accumulator(m_cols, 0.0); // we initialize to 0
        auto accumulator = (*m_cc)->Encrypt(
            m_public_key,
            (*m_cc)->MakeCKKSPackedPlaintext(message_accumulator)
        );
        for (auto &v: m_ciphertexts) {
            accumulator = (*m_cc)->EvalAdd(v, accumulator);
        }

        cipherTensor asTensor;
        asTensor.emplace_back(accumulator);
        pTensor newTensor(1, m_cols, asTensor);
        newTensor.m_isEncrypted = m_isEncrypted;
        return newTensor;
    } else if (axis == 1) {
        // Sum across the rows
        cipherTensor accumulator;
        for (const auto &item : m_ciphertexts) {
            auto resp = (*m_cc)->EvalSum(item, (*m_cc)->GetRingDimension() / 4);
            accumulator.emplace_back(resp);
        }

        pTensor newTensor(m_rows, 1, accumulator);
        newTensor.m_isEncrypted = m_isEncrypted;
        return newTensor;
    } else {
        std::string
            err = "Invalid axis specified on sum(axis=" + std::to_string(axis) + "). Axis must be either 0 or 1";
        throw std::runtime_error(err);
    }
}

pTensor pTensor::T() {
    // For the first row we iteratively mask out
    if (!(m_isEncrypted)) { // encrypt yourself. If we store the transpose we have it now in encrypted form.
        pTensor::encrypt();
    }

    // At this point, our m_TCiphertexts is either empty or not empty. If not empty, the user either didn't
    // want to encrypt it from the get-go OR we were passed in a ciphertext directly. In that case, we do
    // the slow encrypted transpose.
    // If NOT empty, we have the transpose that we return.
    if (!m_TCiphertexts.empty()) {
        // we flip the rows and cols. We then reassign
        pTensor newTensor(m_cols, m_rows, m_TCiphertexts, m_ciphertexts);
        return newTensor;
    }
    // Whelp, we need to transpose here I suppose.
    // We fix a column then iterate downwards through the samples. At the end, we have a vector
    // at which point we emplace back then move to the next col
    auto toTranspose = (m_ciphertexts);

    cipherTensor tContainer;
    for (unsigned int col_i = 0; col_i < m_cols; ++col_i) {
        messageVector mAccum(m_rows, 0.0);
        auto accum = (*m_cc)->Encrypt(m_public_key, (*m_cc)->MakeCKKSPackedPlaintext(mAccum));
        for (unsigned int row_i = 0; row_i < m_rows; ++row_i) {
            messageVector mask(m_rows, 0.0);
            mask[row_i] = 1;
            auto ptMask = (*m_cc)->MakeCKKSPackedPlaintext(mask);

            // First mask everything else out
            auto maskedVal = (*m_cc)->EvalMult(ptMask, toTranspose[col_i]);

            // Now, we rotate right: -1
            for (unsigned int rot = 0; rot < row_i; ++rot) {
                maskedVal = (*m_cc)->EvalAtIndex(maskedVal, 1);
            }
            accum = (*m_cc)->EvalAdd(accum, maskedVal);
        }
        tContainer.emplace_back(accum);
    }
    pTensor newTensor(m_cols, m_rows, tContainer, toTranspose);
    return newTensor;
}

messageTensor pTensor::plainT() {
    assert (messageNotEmpty());
    messageTensor
        transposeTensor((m_messages)[0].size(), messageVector());  // we take the transpose and "store" it.

    for (auto & m_message : m_messages) {
        for (unsigned int j = 0; j < (m_messages)[0].size(); j++) {
            transposeTensor[j].emplace_back(m_message[j]);
        }
    }
    return transposeTensor;
}

messageTensor pTensor::plainT(messageTensor tensor) {
    messageTensor transposeTensor(tensor[0].size(), messageVector());

    for (unsigned int i = 0; i < tensor.size(); i++) {
        for (unsigned int j = 0; j < tensor[0].size(); j++) {
            transposeTensor[j].emplace_back(tensor[i][j]);
        }
    }
    return transposeTensor;
}

pTensor pTensor::identity(unsigned int n) {
    messageTensor message(n, messageVector(n, 0));
    for (unsigned int i = 0; i < n; ++i) {
        message[i][i] = 1;
    }

    pTensor newTensor(n, n, message);
    return newTensor;
}
pTensor pTensor::randomUniform(unsigned int rows, unsigned int cols, double low, double high) {
    std::default_random_engine generator;
    std::uniform_real_distribution<double> distribution(low, high);

    messageTensor tensorContainer;
    for (unsigned int r = 0; r < rows; ++r) {
        messageVector vectorContainer;
        for (unsigned int c = 0; c < cols; ++c) {
            vectorContainer.emplace_back(distribution(generator));
        }
        tensorContainer.emplace_back(vectorContainer);
    }
    pTensor newTensor(rows, cols, tensorContainer);
    return newTensor;
}
pTensor pTensor::randomNormal(unsigned int rows, unsigned int cols, int low, int high) {
    std::default_random_engine generator;
    std::normal_distribution<double> distribution(low, high);

    messageTensor tensorContainer;
    for (unsigned int r = 0; r < rows; ++r) {
        messageVector vectorContainer;
        for (unsigned int c = 0; c < cols; ++c) {
            vectorContainer.emplace_back(distribution(generator));
        }
        tensorContainer.emplace_back(vectorContainer);
    }
    pTensor newTensor(rows, cols, tensorContainer);
    return newTensor;
}
pTensor pTensor::hstack(pTensor arg1, pTensor arg2) {
    // need to verify that we have something to concatenate
    assert(
        (arg1.messageNotEmpty() && arg2.messageNotEmpty()) ||
            (arg1.cipherNotEmpty() && arg2.cipherNotEmpty())
    );
    assert(arg1.m_cols == arg2.m_cols);

    if (arg1.messageNotEmpty()) {
        messageTensor container = arg1.m_messages;
        for (auto &vec: arg2.m_messages) {
            container.emplace_back(vec);
        }

        pTensor newTensor(arg1.m_rows + arg2.m_rows, arg1.m_cols, container);
        return newTensor;
    }
    cipherTensor container = arg1.m_ciphertexts;
    for (auto &v: arg2.m_ciphertexts) {
        container.emplace_back(v);
    }

    pTensor newTensor(arg1.m_rows + arg2.m_rows, arg1.m_cols, container);

    return newTensor;
}
pTensor pTensor::generateWeights(unsigned int numFeatures,
                                 unsigned int numRepeats,
                                 const messageTensor &seed,
                                 const std::string &randomInitializer) {
    if (!seed.empty()) {
        assert(seed.size() == numFeatures);
        messageTensor repeatedWeights;
        for (auto &vector: seed) {
            assert(vector.size() == 1);
            repeatedWeights.emplace_back(messageVector(numRepeats, vector[0]));
        }
        pTensor newTensor(numFeatures, numRepeats, repeatedWeights);
        return newTensor;
    } else {
        pTensor container;
        if (randomInitializer == "uniform") {
            container = randomUniform(numFeatures, 1);

        } else if (randomInitializer == "normal") {
            container = randomNormal(numFeatures, 1);

        } else {
            std::string errMsg = "Given unrecognized randomInitializer distribution: " + randomInitializer;
            throw std::runtime_error(errMsg);
        }

        auto msg = container.getMessage();
        messageTensor repeatedWeights;
        for (auto &vec: msg) {
            repeatedWeights.emplace_back(messageVector(numRepeats, vec[0]));
        }
        container.m_messages = repeatedWeights;
        return container;
    }
}
