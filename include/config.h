#ifndef CONFIG_H
#define CONFIG_H

#include <string>

// Common Data Folder
const std::string dataFolder = "../SimData";

// Common file locations
const std::string ccLocation = "/cryptocontext.txt";
const std::string pubKeyLocation = "/key_pub.txt";
const std::string multKeyLocation = "/key_mult.txt";  // Relinearization key
const std::string rotKeyLocation = "/key_rot.txt";    // Rotation key
const std::string sumKeyLocation = "/key_sum.txt";    // Sum key

// Save-load locations for ciphertexts
const std::string cipherTPFPTNFNLocation = "/cipherTPFPTNFN.txt";
const std::string aggregatorNumLocation = "/ciphertextNum.txt";
const std::string aggregatorDenomLocation = "/ciphertextDenom.txt";

#endif // CONFIG_H
