# pTensor

pTensor is a wrapper around the [PALISADE](https://gitlab.com/palisade/palisade-development) library, which is a
general-purpose lattice cryptography library. pTensor composes relevant functions from PALISADE to create
a [numpy-like](https://numpy.org/) interface for use in encrypted machine learning.

## Features

- Creation of pTensors from either ciphertexts or plaintext messages
    - empty tensor
    - from cipher and cipher's transpose
    - cipher

- Encryption
    - we also take the encrypted transpose to potentially save us from the expensive operation

- Decryption

- Addition

- Subtraction

- Multiplication

- Dot product
    - Supported between Matrix-vector and vector-vector

- Sum
    - all reduce or reducing across specified axes

- Transpose
    - expensive encrypted transpose. We attempt to circumvent this by precomputing the transpose in plaintext if
      possible

- plainT
    - plaintext transpose

- Identity matrix

- Random tensor
    - uniform
    - normal