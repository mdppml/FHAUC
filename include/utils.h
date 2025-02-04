#ifndef UTILS_H
#define UTILS_H

#include <vector>
#include <string>
#include <random>

std::vector<double> linspace(double start, double end, int num);
void demarcate(const std::string &msg);
double calcAUC(std::vector<double> labels, std::vector<double> predCons);
double calcAUC(std::vector<std::vector<double>> labels, std::vector<double> predCons);
uint32_t get_random_client(uint32_t no_of_clients);

// Declare a globally accessible random generator
extern std::mt19937 gen;

#endif // UTILS_H
