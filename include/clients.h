#ifndef CLIENTS_H
#define CLIENTS_H

#include "openfhe.h"
#include <vector>
#include <tuple>

std::tuple<lbcrypto::CryptoContext<lbcrypto::DCRTPoly>, lbcrypto::KeyPair<lbcrypto::DCRTPoly>>
clientsSetup(uint32_t no_of_decision_points,
             uint32_t no_of_clients,
             std::vector<double> labels,
             std::vector<double> pred_cons,
             bool malicious,
             int S);

double clientsVerification(lbcrypto::CryptoContext<lbcrypto::DCRTPoly> &cc,
                           lbcrypto::KeyPair<lbcrypto::DCRTPoly> &kp, double cd, bool malicious);

#endif // CLIENTS_H
