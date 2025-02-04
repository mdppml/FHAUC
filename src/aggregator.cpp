#include "aggregator.h"
#include "openfhe.h"
#include "utils.h"
#include "config.h"
#include <iostream>

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

using namespace lbcrypto;

// Save-load locations for RAW ciphertexts
std::string cipherOneLocation = "/ciphertext1.txt";

double aggregatorProcess(uint32_t no_of_clients, uint32_t batchSize) {
    clock_t start, end;
    CryptoContext<DCRTPoly> AggregatorCC;
    AggregatorCC->ClearEvalMultKeys();
    AggregatorCC->ClearEvalAutomorphismKeys();
    lbcrypto::CryptoContextFactory<lbcrypto::DCRTPoly>::ReleaseAllContexts();

    std::uniform_real_distribution<double> dist(0.1, 1.0);
    double c = dist(gen), d = dist(gen);

    std::vector<double> timings;

    std::cout << "Starting FHE calculations ..." << std::endl;
    start = clock();
    if (!Serial::DeserializeFromFile(dataFolder + ccLocation, AggregatorCC, SerType::BINARY)) {
        std::cerr << "I cannot read serialized data from: " << dataFolder << "/cryptocontext.txt" << std::endl;
        std::exit(1);
    }
    std::cout << "Aggregator CC deserialized" << std::endl;

    KeyPair<DCRTPoly> clientKP;  // We do NOT have a secret key. The client
    // should not have access to this
    PublicKey<DCRTPoly> clientPublicKey;
    if (!Serial::DeserializeFromFile(dataFolder + pubKeyLocation, clientPublicKey, SerType::BINARY)) {
        std::cerr << "I cannot read serialized data from: " << dataFolder << "/cryptocontext.txt" << std::endl;
        std::exit(1);
    }
    std::cout << "Aggregator KP deserialized" << '\n' << std::endl;

    std::ifstream multKeyIStream(dataFolder + multKeyLocation, std::ios::in | std::ios::binary);
    if (!multKeyIStream.is_open()) {
        std::cerr << "Cannot read serialization from " << dataFolder + multKeyLocation << std::endl;
        std::exit(1);
    }
    if (!AggregatorCC->DeserializeEvalMultKey(multKeyIStream, SerType::BINARY)) {
        std::cerr << "Could not deserialize eval mult key file" << std::endl;
        std::exit(1);
    }

    std::cout << "Deserialized eval mult keys" << '\n' << std::endl;
    std::ifstream rotKeyIStream(dataFolder + rotKeyLocation, std::ios::in | std::ios::binary);
    if (!rotKeyIStream.is_open()) {
        std::cerr << "Cannot read serialization from " << dataFolder + multKeyLocation << std::endl;
        std::exit(1);
    }
    if (!AggregatorCC->DeserializeEvalAutomorphismKey(rotKeyIStream, SerType::BINARY)) {
        std::cerr << "Could not deserialize eval rot key file" << std::endl;
        std::exit(1);
    }

    std::ifstream sumKeyIStream(dataFolder + sumKeyLocation, std::ios::in | std::ios::binary);
    if (!sumKeyIStream.is_open()) {
        std::cerr << "Cannot read serialization from " << dataFolder + sumKeyLocation << std::endl;
        std::exit(1);
    }
    if (!AggregatorCC->DeserializeEvalSumKey(sumKeyIStream, SerType::BINARY)) {
        std::cerr << "Could not deserialize eval sum key file" << std::endl;
        std::exit(1);
    }

    std::vector<
            std::shared_ptr<
                    lbcrypto::CiphertextImpl<
                            lbcrypto::DCRTPolyImpl<
                                    bigintdyn::mubintvec<
                                            bigintdyn::ubint<
                                                    unsigned int>>>>>> enc_vectors, summed_vectors;


    if (!Serial::DeserializeFromFile(dataFolder + cipherTPFPTNFNLocation, enc_vectors, SerType::BINARY)) {
        std::cerr << "Cannot read serialization from " << dataFolder + cipherOneLocation << std::endl;
        std::exit(1);
    }
    std::cout << "Deserialized ciphertext vectors" << '\n' << std::endl;

    using CiphertextPtr = std::shared_ptr<
            lbcrypto::CiphertextImpl<
                    lbcrypto::DCRTPolyImpl<
                            bigintdyn::mubintvec<
                                    bigintdyn::ubint<unsigned int>>>>>;

    std::vector<CiphertextPtr> tmp;


    for (int i = 0; i < 4; i++) {
        tmp.resize(no_of_clients);
        tmp[0] = enc_vectors[i];

        for (int j = 1; j < no_of_clients; j++) {
            tmp[j] = enc_vectors[j * 4 + i];
        }
        auto sum = AggregatorCC->EvalAddMany(tmp);
        summed_vectors.push_back(sum);
    }

    auto TP = summed_vectors[0];
    auto FP = summed_vectors[1];
    auto TP_back = summed_vectors[2];
    auto FP_back = summed_vectors[3];

    auto num = AggregatorCC->EvalMult(TP, FP); // num

    auto final_denom = AggregatorCC->EvalMult(TP_back, FP_back); // D / 2

    auto bc = AggregatorCC->EvalMult(final_denom, (2 * c)); // D * c

    final_denom = AggregatorCC->EvalMult(final_denom, (2 * d)); // b * d

    auto final_num = AggregatorCC->EvalSum(num, batchSize); // a

    final_num = AggregatorCC->EvalMult(final_num, d); // a * d

    final_num = AggregatorCC->EvalAdd(final_num, bc); // a * d + b * c

    end = clock();
    double runtime = double(end - start) / double(CLOCKS_PER_SEC);

    std::cout << "FHE calculations took : " << std::fixed
              << runtime << std::setprecision(6) << " secs " << std::endl;

    Serial::SerializeToFile(dataFolder + aggregatorNumLocation, final_num, SerType::BINARY);
    Serial::SerializeToFile(dataFolder + aggregatorDenomLocation, final_denom, SerType::BINARY);

    std::cout << "Serialized all ciphertexts from client" << '\n' << std::endl;

    return c/d;
}

