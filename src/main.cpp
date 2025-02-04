// Refactored and Cleaned main.cpp
// Author: Cem Ata Baykara
// Date: 03.02.23

#include "clients.h"
#include "aggregator.h"
#include "utils.h"
#include <iostream>
#include <iomanip>
#include <tuple>

#include <vector>
#include <iterator>


using namespace lbcrypto;

int main() {
    // Load input data
    std::ifstream is("../data/labels.txt");
    std::istream_iterator<double> start(is), end;
    std::vector<double> labels(start, end);

    std::ifstream is2("../data/pred_cons.txt");
    std::istream_iterator<double> start2(is2), end2;
    std::vector<double> predCons(start2, end2);

    // Set parameters
    const uint32_t clients = 10;
    const uint32_t noOfDecisionPoints = 100;
    const bool malicious = false;
    const int S = 5;

    // Compute exact AUC
    double exactAUC = calcAUC(labels, predCons);

    // Setup clients
    auto [cc, kp] = clientsSetup(noOfDecisionPoints, clients, labels, predCons, malicious, S);

    // Aggregation and Verification
    double cd;

    if (malicious) {
        cd = aggregatorProcess(clients, noOfDecisionPoints * S);
    } else {
        cd = aggregatorProcess(clients, noOfDecisionPoints);
    }

    double computedAUC = clientsVerification(cc, kp, cd, malicious);

    // Display results
    std::cout << "FHAUC: " << computedAUC << "\nExact AUC: " << exactAUC << std::endl;
    return 0;
}

