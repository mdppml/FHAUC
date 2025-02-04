#include "utils.h"
#include <iostream>
#include <vector>
#include <algorithm>
#include <numeric>
#include <random>

std::random_device rd;
std::mt19937 gen(rd());
std::uniform_real_distribution<> uniformRand(0, 1);
std::uniform_real_distribution<> uniformRandto10(0, 10);
std::uniform_int_distribution<uint32_t> binaryRand(0, 1);
std::uniform_int_distribution<uint32_t> random_ties(1, 5);

std::vector<double> linspace(double start_in, double end_in, int num_in) {

    std::vector<double> linspaced;

    auto start = static_cast<double>(start_in);
    auto end = static_cast<double>(end_in);
    auto num = static_cast<double>(num_in);

    if (num == 0) { return linspaced; }
    if (num == 1) {
        linspaced.push_back(start);
        return linspaced;
    }

    double delta = (end - start) / (num - 1);

    for (int i = 0; i < num - 1; ++i) {
        linspaced.push_back(start + delta * i);
    }
    linspaced.push_back(end); // I want to ensure that start and end
    // are exactly the same as the input
    std::reverse(linspaced.begin(), linspaced.end());
    return linspaced;
}

uint32_t get_random_client(uint32_t no_of_clients) {
    std::uniform_int_distribution<uint32_t> random_clients(0, no_of_clients - 1);
    return random_clients(gen);
}

void demarcate(const std::string &msg) {
    std::cout << "******************************************\n";
    std::cout << msg << std::endl;
    std::cout << "******************************************\n";
}

double calcAUC(std::vector<double> labels, std::vector<double> predCons) {

    double previous_tp = 0;
    double previous_fp = 0;
    double numerator = 0;
    double tp = 0;
    double fp = 0;
    uint32_t inputSize = labels.size();

    for (int i = 0; i < inputSize - 1; i++) {
        tp += labels[i];
        fp += (1 - labels[i]);

        if (predCons[i] != predCons[i + 1]) { // means that current label is a threshold sample
            numerator += (tp + previous_tp) * (fp - previous_fp);

            previous_tp = tp;
            previous_fp = fp;
        }
    }

    tp += labels.back();
    fp += (1 - labels.back());

    numerator += (tp + previous_tp) * (fp - previous_fp);

    double denominator = tp * fp * 2;

    return numerator / denominator;
}

double calcAUC(std::vector<std::vector<double>> labels, std::vector<double> predCons) {

    double previous_tp = 0;
    double previous_fp = 0;
    double numerator = 0;
    double tp = 0;
    double fp = 0;
    uint32_t inputSize = labels.size();

    for (int i = 0; i < inputSize - 1; i++) {
        tp += labels[i][0];
        fp += (1 - labels[i][0]);

        if (predCons[i] != predCons[i + 1]) { // means that current label is a threshold sample
            numerator += (tp + previous_tp) * (fp - previous_fp);

            previous_tp = tp;
            previous_fp = fp;
        }
    }

    tp += labels.back()[0];
    fp += (1 - labels.back()[0]);

    numerator += (tp + previous_tp) * (fp - previous_fp);

    double denominator = tp * fp * 2;

    return numerator / denominator;
}
