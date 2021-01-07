# pTensor

pTensor is a wrapper around the [PALISADE](https://gitlab.com/palisade/palisade-development) library, which is a general-purpose lattice cryptography library. pTensor composes relevant functions from PALISADE to create a [numpy-like](https://numpy.org/) interface for use in encrypted machine learning.

## Future Features

-[ ] Integration of logging via spdlog 

-[ ] Utility functions: 

  -[ ] Identity matrices
  -[ ] Random matrices
  -[ ] Enabling shuffling (we encode feature-wise instead of row-wise so standard shuffling is not as easy)
  -[ ] Reshape
  -[ ] hstack
  -[ ] vstack
  -[ ] outer product
