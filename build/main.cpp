#include <openfhe.h>

using namespace lbcrypto;

// Function to add two integers
Ciphertext<DCRTPoly> AddIntegers(CryptoContext<DCRTPoly> cryptoContext, const KeyPair<DCRTPoly>& keyPair, int64_t a, int64_t b) {
    // Encode integers as plaintexts
    Plaintext plaintextA = cryptoContext->MakePackedPlaintext({a});
    Plaintext plaintextB = cryptoContext->MakePackedPlaintext({b});
    
    // Encrypt plaintexts
    auto ciphertextA = cryptoContext->Encrypt(keyPair.publicKey, plaintextA);
    auto ciphertextB = cryptoContext->Encrypt(keyPair.publicKey, plaintextB);

    // Homomorphic addition
    auto ciphertextAdd = cryptoContext->EvalAdd(ciphertextA, ciphertextB);
    return ciphertextAdd;
}

// Function to add two vectors
Ciphertext<DCRTPoly> AddVectors(CryptoContext<DCRTPoly> cryptoContext, const KeyPair<DCRTPoly>& keyPair, const std::vector<int64_t>& vec1, const std::vector<int64_t>& vec2) {
    // Encode vectors as plaintexts
    Plaintext plaintextVec1 = cryptoContext->MakePackedPlaintext(vec1);
    Plaintext plaintextVec2 = cryptoContext->MakePackedPlaintext(vec2);
    
    // Encrypt plaintexts
    auto ciphertextVec1 = cryptoContext->Encrypt(keyPair.publicKey, plaintextVec1);
    auto ciphertextVec2 = cryptoContext->Encrypt(keyPair.publicKey, plaintextVec2);

    // Homomorphic addition
    auto ciphertextAdd = cryptoContext->EvalAdd(ciphertextVec1, ciphertextVec2);
    return ciphertextAdd;
}

// Function to multiply two integers
Ciphertext<DCRTPoly> MultiplyIntegers(CryptoContext<DCRTPoly> cryptoContext, const KeyPair<DCRTPoly>& keyPair, int64_t a, int64_t b) {
    // Encode integers as plaintexts
    Plaintext plaintextA = cryptoContext->MakePackedPlaintext({a});
    Plaintext plaintextB = cryptoContext->MakePackedPlaintext({b});
    
    // Encrypt plaintexts
    auto ciphertextA = cryptoContext->Encrypt(keyPair.publicKey, plaintextA);
    auto ciphertextB = cryptoContext->Encrypt(keyPair.publicKey, plaintextB);

    // Homomorphic multiplication
    auto ciphertextMul = cryptoContext->EvalMult(ciphertextA, ciphertextB);
    return ciphertextMul;
}

// Function to multiply two matrices
std::vector<Ciphertext<DCRTPoly>> MultiplyMatrices(CryptoContext<DCRTPoly> cryptoContext, const KeyPair<DCRTPoly>& keyPair, const std::vector<std::vector<int64_t>>& mat1, const std::vector<std::vector<int64_t>>& mat2) {
    // Assume mat1 is of size (m x n) and mat2 is of size (n x p)
    int m = mat1.size();
    int n = mat1[0].size();
    int p = mat2[0].size();
    
    std::vector<Ciphertext<DCRTPoly>> result(m * p);

    for (int i = 0; i < m; ++i) {
        for (int j = 0; j < p; ++j) {
            // Initialize each entry to 0
            Plaintext plaintextResult = cryptoContext->MakePackedPlaintext({0});
            auto ciphertextResult = cryptoContext->Encrypt(keyPair.publicKey, plaintextResult);

            for (int k = 0; k < n; ++k) {
                Plaintext plaintextA = cryptoContext->MakePackedPlaintext({mat1[i][k]});
                Plaintext plaintextB = cryptoContext->MakePackedPlaintext({mat2[k][j]});
                
                auto ciphertextA = cryptoContext->Encrypt(keyPair.publicKey, plaintextA);
                auto ciphertextB = cryptoContext->Encrypt(keyPair.publicKey, plaintextB);

                auto ciphertextMul = cryptoContext->EvalMult(ciphertextA, ciphertextB);
                ciphertextResult = cryptoContext->EvalAdd(ciphertextResult, ciphertextMul);
            }

            result[i * p + j] = ciphertextResult;
        }
    }
    return result;
}

int main() {
    // Set up CryptoContext, Key Generation, and other configurations as in the original code
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(2);
    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);

    KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, {1, 2, -1, -2});

    // Example usage
    auto ciphertextAddInt = AddIntegers(cryptoContext, keyPair, 3, 5);
    auto ciphertextAddVec = AddVectors(cryptoContext, keyPair, {1, 2, 3}, {4, 5, 6});
    auto ciphertextMulInt = MultiplyIntegers(cryptoContext, keyPair, 3, 5);

    std::vector<std::vector<int64_t>> mat1 = {{1, 2}, {3, 4}};
    std::vector<std::vector<int64_t>> mat2 = {{5, 6}, {7, 8}};
    auto ciphertextMulMat = MultiplyMatrices(cryptoContext, keyPair, mat1, mat2);

    // Decryption and displaying of results would follow as shown in the main code
    Plaintext plaintextAddInt;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextAddInt, &plaintextAddInt);
    // Plaintext plaintextMulInt;
    // cryptoContext->Decrypt(keyPair.secretKey, ciphertextMulInt, &ciphertextMulInt);
    // Plaintext plaintextAddVec;
    // cryptoContext->Decrypt(keyPair.secretKey, ciphertextAddVec, &ciphertextAddVec);
    // Plaintext plaintextMulMat;  
    // cryptoContext->Decrypt(keyPair.secretKey, ciphertextMulMat, &ciphertextMulMat);

    std::cout << plaintextAddInt << " Tes " << std::endl;

    return 0;
}
