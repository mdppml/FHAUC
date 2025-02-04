#include "clients.h"
#include "openfhe.h"
#include "utils.h"
#include "config.h"
#include <iostream>

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"


using namespace lbcrypto;

std::uniform_real_distribution<double> dist_real(0.1, 1.0);
std::vector<double> R(6, dist_real(gen));

std::tuple<CryptoContext<DCRTPoly>, KeyPair<DCRTPoly>> clientsSetup(uint32_t no_of_decision_points,
                                                                         uint32_t no_of_clients,
                                                                         std::vector<double> labels,
                                                                         std::vector<double> pred_cons,
                                                                         bool malicious,
                                                                         int S) {

    const int multDepth = 3, scaleModSize = 50;

    uint32_t dataSize = labels.size();

    std::vector<std::vector<double>> A(no_of_clients - 1, std::vector<double>(S * (no_of_decision_points + 1)));
    std::vector<std::vector<double>> B(no_of_clients - 1, std::vector<double>(S * (no_of_decision_points + 1)));


    std::cout << "Number of decision points = " << no_of_decision_points << std::endl;
    std::cout << "Number of clients         = " << no_of_clients << std::endl;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    //parameters.SetBatchSize(no_of_decision_points);
    parameters.SetBatchSize(1 << 13);
    parameters.SetRingDim(1 << 31);

    CryptoContext<DCRTPoly> clientsCC = GenCryptoContext(parameters);

    clientsCC->Enable(PKE);
    clientsCC->Enable(KEYSWITCH);
    clientsCC->Enable(LEVELEDSHE);
    clientsCC->Enable(ADVANCEDSHE);

    std::cout << "Cryptocontext generated" << std::endl;

    KeyPair<DCRTPoly> clientsKP = clientsCC->KeyGen();
    std::cout << "Keypair generated" << std::endl;

    clientsCC->EvalMultKeyGen(clientsKP.secretKey);
    std::cout << "Eval Mult Keys / Relinearization keys have been generated" << std::endl;

    clientsCC->EvalSumKeyGen(clientsKP.secretKey);
    std::cout << "Eval Sum keys have been generated" << std::endl;

    // Step 2: Print the ring dimension
    uint32_t ringDim = clientsCC->GetRingDimension();
    std::cout << "Ring Dimension (N): " << ringDim << std::endl;

    // Step 3: Compute and print the slot count (vector size)
    uint32_t slotCount = ringDim / 2;
    std::cout << "Maximum Vector Size (Slots): " << slotCount << std::endl;

    // Step 4: Encode a vector to test
    std::vector<double> inputVector(slotCount, 1.23); // A vector filled with 1.23
    Plaintext plaintext = clientsCC->MakeCKKSPackedPlaintext(inputVector);

    // Print the plaintext
    std::cout << "Encoded plaintext size: " << plaintext->GetLength() << " slots" << std::endl;


    std::vector<std::vector<double>> clients;

    for (int i = 0; i < no_of_clients; i++) {
        clients.emplace_back();
        clients.emplace_back();
    }

    std::vector<double> decision_points = linspace(0, 1, (int) no_of_decision_points);

    for (int i = 0; i < dataSize; i++) {
        uint32_t random_client = get_random_client(no_of_clients);

        clients[random_client * 2].push_back(labels[i]);
        clients[random_client * 2 + 1].push_back(pred_cons[i]);
    }

    std::vector<std::vector<double>> matrices;
    std::vector<std::vector<double>> Ts_and_Fs;

    for (int i = 0; i < no_of_clients; i++) {
        matrices.emplace_back();
        matrices.emplace_back();
        matrices.emplace_back();
        matrices.emplace_back();

        Ts_and_Fs.emplace_back();
        Ts_and_Fs.emplace_back();
    }

    for (int i = 0; i < no_of_clients; i++) {

        double total_1s = 0;
        double total_0s = 0;

        for (auto &n: clients[i * 2]) {
            total_1s += n;
            total_0s += 1 - n;
        }

        double size = total_1s + total_0s;
        double ones = 0;
        double zeros = 0;
        int pred_con_index = 0;
        bool last_one_visited = false;

        for (int d = 0; d < no_of_decision_points; d++) {
            for (int p = pred_con_index; p < size; p++) {
                if (clients[i * 2 + 1][p] > decision_points[d]) {
                    if (p == size - 1) {

                        if (!last_one_visited) {
                            ones += clients[i * 2][p];
                            zeros += 1 - clients[i * 2][p];
                            last_one_visited = true;
                        }

                        matrices[i * 4].push_back(ones);
                        matrices[i * 4 + 1].push_back(zeros);
                        matrices[i * 4 + 2].push_back((total_0s - zeros));
                        matrices[i * 4 + 3].push_back((total_1s - ones));

                        pred_con_index = p;
                    } else {
                        ones += clients[i * 2][p];
                        zeros += 1 - clients[i * 2][p];
                    }
                } else {
                    matrices[i * 4].push_back(ones);
                    matrices[i * 4 + 1].push_back(zeros);
                    matrices[i * 4 + 2].push_back((total_0s - zeros));
                    matrices[i * 4 + 3].push_back((total_1s - ones));


                    pred_con_index = p;
                    break;
                }
            }
        }
    }

    std::uniform_int_distribution<int> dist(0, 100);

    // Now computing T and F from TP and FP for all clients
    for (int i = 0; i < no_of_clients; i++) {
        for (int d = 1; d < no_of_decision_points; d++) {
            auto tmpT = matrices[i * 4][d] + matrices[i * 4][d - 1];
            auto tmpF = matrices[i * 4 + 1][d] - matrices[i * 4 + 1][d - 1];
            if (malicious) {
                auto sum = 0.0;

                for (int s = 0; s < S - 1; s++) {
                    auto r = dist(gen);
                    sum += r;
                    Ts_and_Fs[i * 2].push_back(r);
                    Ts_and_Fs[i * 2 + 1].push_back(tmpF);
                }
                Ts_and_Fs[i * 2].push_back(tmpT - sum);
                Ts_and_Fs[i * 2 + 1].push_back(tmpF);
            } else {
                Ts_and_Fs[i * 2].push_back(tmpT);
                Ts_and_Fs[i * 2 + 1].push_back(tmpF);
            }

        }


        // Put total number of positives and negatives to the last index

        if (malicious) {
            auto sum = 0.0;
            auto tmpT = 2 * matrices[i * 4].back();
            auto tmpF = matrices[i * 4 + 1].back();

            for (int s = 0; s < S - 1; s++) {
                auto r = dist(gen);
                sum += r;
                Ts_and_Fs[i * 2].push_back(r);
                Ts_and_Fs[i * 2 + 1].push_back(tmpF);
            }
            Ts_and_Fs[i * 2].push_back(tmpT - sum);
            Ts_and_Fs[i * 2 + 1].push_back(tmpF);
        }

    }

    if (malicious) {

        no_of_decision_points *= S;

        for (int i = 0; i < no_of_clients - 1; i++) {

            for (int d = 0; d < no_of_decision_points; d++) {
                Ts_and_Fs[i * 2][d] += A[i][d];
                Ts_and_Fs[i * 2 + 1][d] += B[i][d];

                Ts_and_Fs[(no_of_clients - 1) * 2][d] -= A[i][d];
                Ts_and_Fs[(no_of_clients - 1) * 2 + 1][d] -= B[i][d];
            }

        }

        for (int i = 0; i < no_of_clients; i++) {

            for (int d = 0; d < no_of_decision_points - S; d++) {
                Ts_and_Fs[i * 2][d] *= R[0];
                Ts_and_Fs[i * 2 + 1][d] *= R[1];

            }
            for (int j = 1; j <= S; j++) {
                Ts_and_Fs[i * 2][no_of_decision_points - j] *= R[2];
                Ts_and_Fs[i * 2 + 1][no_of_decision_points - j] *= R[3];
            }


        }

    }

    //T and F's are computed. Now performing randomization

    std::vector<
            std::shared_ptr<
                    lbcrypto::CiphertextImpl<
                            lbcrypto::DCRTPolyImpl<
                                    bigintdyn::mubintvec<
                                            bigintdyn::ubint<
                                                    unsigned int>>>>>> enc_vectors;

    double sum_a = 0;
    double sum_b = 0;

    for (int i = 0; i < no_of_clients - 1; i++) {

        std::vector<double> TP_back = {matrices[i * 4].back()};
        std::vector<double> FP_back = {matrices[i * 4 + 1].back()};

        if (malicious) {
            TP_back = {R[4] * (matrices[i * 4].back() + A[i][no_of_decision_points])};
            FP_back = {R[5] * (matrices[i * 4 + 1].back() + B[i][no_of_decision_points])};

            sum_a += A[i][no_of_decision_points];
            sum_b += B[i][no_of_decision_points];
        }

        enc_vectors.push_back(
                clientsCC->Encrypt(clientsKP.publicKey, clientsCC->MakeCKKSPackedPlaintext(Ts_and_Fs[i * 2])));
        enc_vectors.push_back(
                clientsCC->Encrypt(clientsKP.publicKey, clientsCC->MakeCKKSPackedPlaintext(Ts_and_Fs[i * 2 + 1])));
        enc_vectors.push_back(
                clientsCC->Encrypt(clientsKP.publicKey, clientsCC->MakeCKKSPackedPlaintext(TP_back)));
        enc_vectors.push_back(
                clientsCC->Encrypt(clientsKP.publicKey, clientsCC->MakeCKKSPackedPlaintext(FP_back)));
    }

    std::vector<double> TP_back = {matrices[(no_of_clients - 1) * 4].back()};
    std::vector<double> FP_back = {matrices[(no_of_clients - 1) * 4 + 1].back()};

    if (malicious) {
        TP_back = {R[4] * (matrices[(no_of_clients - 1) * 4].back() - sum_a)};
        FP_back = {R[5] * (matrices[(no_of_clients - 1) * 4 + 1].back() - sum_b)};
    }

    enc_vectors.push_back(
            clientsCC->Encrypt(clientsKP.publicKey,
                               clientsCC->MakeCKKSPackedPlaintext(Ts_and_Fs[(no_of_clients - 1) * 2])));
    enc_vectors.push_back(
            clientsCC->Encrypt(clientsKP.publicKey,
                               clientsCC->MakeCKKSPackedPlaintext(Ts_and_Fs[(no_of_clients - 1) * 2 + 1])));
    enc_vectors.push_back(
            clientsCC->Encrypt(clientsKP.publicKey, clientsCC->MakeCKKSPackedPlaintext(TP_back)));
    enc_vectors.push_back(
            clientsCC->Encrypt(clientsKP.publicKey, clientsCC->MakeCKKSPackedPlaintext(FP_back)));

    std::cout << "Ciphertexts have been generated from Plaintexts" << std::endl;

    /*
   * Part 2:
   * We serialize the following:
   *  Cryptocontext
   *  Public key
   *  relinearization (eval mult keys)
   *  rotation keys
   *  Some ciphertext
   *
   *  We serialize all of them to files
   */

    demarcate("Part 2: Data Serialization (Clients)");

    if (!Serial::SerializeToFile(dataFolder + ccLocation, clientsCC, SerType::BINARY)) {
        std::cerr << "Error writing serialization of the crypto context to "
                     "cryptocontext.txt"
                  << std::endl;
        std::exit(1);
    }

    std::cout << "Cryptocontext serialized" << std::endl;

    if (!Serial::SerializeToFile(dataFolder + pubKeyLocation, clientsKP.publicKey, SerType::BINARY)) {
        std::cerr << "Exception writing public key to pubkey.txt" << std::endl;
        std::exit(1);
    }
    std::cout << "Public key serialized" << std::endl;

    std::ofstream multKeyFile(dataFolder + multKeyLocation, std::ios::out | std::ios::binary);
    if (multKeyFile.is_open()) {
        if (!clientsCC->SerializeEvalMultKey(multKeyFile, SerType::BINARY, "")) {
            std::cerr << "Error writing eval mult keys" << std::endl;
            std::exit(1);
        }
        std::cout << "EvalMult / relinearization keys have been serialized" << std::endl;
        multKeyFile.close();
    } else {
        std::cerr << "Error serializing EvalMult keys" << std::endl;
        std::exit(1);
    }

    std::ofstream rotationKeyFile(dataFolder + rotKeyLocation, std::ios::out | std::ios::binary);
    if (rotationKeyFile.is_open()) {
        if (!clientsCC->SerializeEvalAutomorphismKey(rotationKeyFile, SerType::BINARY, "")) {
            std::cerr << "Error writing rotation keys" << std::endl;
            std::exit(1);
        }
        std::cout << "Rotation keys have been serialized" << std::endl;
    } else {
        std::cerr << "Error serializing Rotation keys" << std::endl;
        std::exit(1);
    }

    std::ofstream sumKeyFile(dataFolder + sumKeyLocation, std::ios::out | std::ios::binary);
    if (sumKeyFile.is_open()) {
        if (!clientsCC->SerializeEvalSumKey(sumKeyFile, SerType::BINARY, "")) {
            std::cerr << "Error writing sum keys" << std::endl;
            std::exit(1);
        }
        std::cout << "Sum keys have been serialized" << std::endl;
    } else {
        std::cerr << "Error serializing Sum keys" << std::endl;
        std::exit(1);
    }


    if (!Serial::SerializeToFile(dataFolder + cipherTPFPTNFNLocation, enc_vectors, SerType::BINARY)) {
        std::cerr << " Error writing ciphertext" << std::endl;
    }

    // Assuming enc_vectors is already populated
    std::vector<std::shared_ptr<
            lbcrypto::CiphertextImpl<
                    lbcrypto::DCRTPolyImpl<
                            bigintdyn::mubintvec<
                                    bigintdyn::ubint<unsigned int>>>>>>
            firstFour(enc_vectors.begin(), enc_vectors.begin() + 4);

    if (!Serial::SerializeToFile(dataFolder + "/1_client_cipher.txt", firstFour, SerType::BINARY)) {
        std::cerr << "Error writing ciphertext" << std::endl;
    }

    return std::make_tuple(clientsCC, clientsKP);
}

double clientsVerification(CryptoContext<DCRTPoly> &cc,
                           KeyPair<DCRTPoly> &kp,
                           double cd,
                           bool malicious) {
    Ciphertext<DCRTPoly> final_num;
    Ciphertext<DCRTPoly> final_denom;

    Serial::DeserializeFromFile(dataFolder + aggregatorNumLocation, final_num, SerType::BINARY);
    Serial::DeserializeFromFile(dataFolder + aggregatorDenomLocation, final_denom, SerType::BINARY);

    demarcate("Part 5: Correctness verification");

    Plaintext num;
    Plaintext denom;

    cc->Decrypt(kp.secretKey, final_num, &num);
    cc->Decrypt(kp.secretKey, final_denom, &denom);

    double x = num->GetRealPackedValue()[0];
    double y = denom->GetRealPackedValue()[0];

    double auc;

    if (malicious) {
        double r0 = R[0] * R[1];
        double r1 = R[2] * R[3];
        double r2 = R[4] * R[5];

        auc = (x / y) - cd - (r1 / r2);
        auc *= (r2 / r0);
    } else {
        auc = (x / y) - cd;
    }

    return auc;
}

