# FHAUC

This repository contains the source code of our research article

[Privacy Preserving AUC Calculation for Federated Learning using Fully Homomorphic Encryption](https://arxiv.org/abs/2403.14428)

## Requirements

- A C++ compiler (e.g., GCC, Clang)
- CMake
- [OpenFHE](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/installation.html)


### Steps

1. Clone this repository to your local machine:
    ```bash
    git clone https://github.com/mdppml/FHAUC.git
    ```

2. Navigate to the project directory:
    ```bash
    cd FHEAUC
    ```

3. Build the project using CMake:
    ```bash
    mkdir build
    cd build
    cmake ..
    make
    ```

Once you’ve successfully built the project, you can run the executable directly from the terminal.

1. Navigate to the `build` directory:
    ```bash
    cd build
    ```

2. Run the project by executing the generated binary `FHEAUC`:
    ```bash
    ./FHEAUC
    ```

    This will run the current experiment, which starts from the `src/main.cpp` file.

## Usage

Experiment parameters such as number of clients and the number of decision points can be changed from the `src/main.cpp` file.

```cpp
    // Set parameters
    const uint32_t clients = 10;
    const uint32_t noOfDecisionPoints = 100;
    const bool malicious = false;
    const int S = 5;
```

`data/` directory includes multiple readily available labels and prediction confidence scores of various sizes. You can modify the relevant paths inside the `src/main.cpp` file to run the experiment on the desired data. If you would like to run the experiments on your own  data, you need to place the required `your_labels.txt` and `your_pred_cons.txt` (pre-sorted in descending order) inside the `data/` directory.