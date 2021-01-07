# A Machine Learning based introduction to PALISADE and CKKS

This is a series of tutorials using the [CKKS/HEAAN](https://eprint.iacr.org/2016/421.pdf) scheme in PALISADE to implement sample machine learning algorithms.

In this tutorial, we go through a series of tutorials which build on the previous ones.

## Audience

Anyone who is familiar with machine learning and interested in homomorphic encryption and ML.

## Topics

Part 0 (Not covered): we supply a data loader class

### Part 1: Introduction to PALISADE and a simple application. 

1) Training on a single vector of the Iris dataset. This is phrased as a linear regression because it is simpler.

2) The parameters that we need to specify and what they mean for our application.

3) Ciphertext Refreshing aka "Interactive" approach.

### Part 1.5: CKKS for the curious

0) Homomorphic Encryption: a brief history.

1) What is CKKS and what makes it work for ML? 

2) Multiplication Depth: what the mult-depth parameter does, how do we get around the issue and what are the potential issues?
    
3) Bootstrapping: what is it and why is it desirable?

4) Further Reading


### Part 2: Building reusable code

0) Creating a Matrix class for reusability

1) SIMD discussion + DCRTPoly + why you might choose DCRTPoly over the others

### Part 3: Softmax Regression

0) brief recap of everything we've done

1) Softmax regression 101

2) Use the matrix class and treat the dataset (we use Iris) as a softmax regression

### Part 4: Python??

1) Discuss `boost::python`? `pybind` ? 

