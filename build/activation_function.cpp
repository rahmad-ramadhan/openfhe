#include <openfhe.h>
#include <algorithm>

using namespace lbcrypto;

Ciphertext<DCRTPoly> sigmoid(CryptoContext<DCRTPoly> cryptoContext, Ciphertext<DCRTPoly> arg, double lb, double ub, int64_t polyDegree){
    return cryptoContext->EvalLogistic(arg, lb, ub, polyDegree);
}

Ciphertext<DCRTPoly> tanh(CryptoContext<DCRTPoly> cryptoContext, Ciphertext<DCRTPoly> arg, double lb, double ub, int64_t polyDegree){
    auto temp = sigmoid(cryptoContext, arg, 2 * lb + 1, 2 * ub - 1, polyDegree);
    return cryptoContext->EvalSub(cryptoContext->EvalMult(2, temp), 1);
}

Ciphertext<DCRTPoly> swish(CryptoContext<DCRTPoly> cryptoContext, Ciphertext<DCRTPoly> arg, double lb, double ub, int64_t polyDegree){
    auto temp = sigmoid(cryptoContext, arg, lb, ub, polyDegree);
    return cryptoContext->EvalMult(arg, temp);
}

signed main() {

    CCParams<CryptoContextCKKSRNS> CKKSParams;

    CKKSParams.SetSecurityLevel(HEStd_NotSet);
    CKKSParams.SetRingDim(1 << 10);
    int64_t scalingModSize = 50;
    int64_t firstModSize   = 60;
    CKKSParams.SetScalingModSize(scalingModSize);
    CKKSParams.SetFirstModSize(firstModSize);

    uint32_t polyDegree = 16;
    uint32_t multDepth = 8;

    CKKSParams.SetMultiplicativeDepth(multDepth);
    CryptoContext<DCRTPoly> CKKSContext = GenCryptoContext(CKKSParams);
    CKKSContext->Enable(PKE);
    CKKSContext->Enable(KEYSWITCH);
    CKKSContext->Enable(LEVELEDSHE);
    CKKSContext->Enable(ADVANCEDSHE);

    auto CKKSKeypair = CKKSContext->KeyGen();
    CKKSContext->EvalMultKeyGen(CKKSKeypair.secretKey);

    std::vector<double> vectorA = {-4.0, -3.0, -2.0, -1.0, 0.0, 1.0, 2.0, 3.0, 4.0};
    size_t length = vectorA.size();
    Plaintext plaintext  = CKKSContext->MakeCKKSPackedPlaintext(vectorA);
    auto ciphertext      = CKKSContext->Encrypt(CKKSKeypair.publicKey, plaintext);

    double lowerBound = *std::min_element(std::begin(vectorA), std::end(vectorA)) - 1;
    double upperBound = *std::max_element(std::begin(vectorA), std::end(vectorA)) + 1;
    auto resultSigmoid = sigmoid(CKKSContext, ciphertext, lowerBound, upperBound, polyDegree);
    auto resultTanh = tanh(CKKSContext, ciphertext, lowerBound, upperBound, polyDegree);
    auto resultSwish = swish(CKKSContext, ciphertext, lowerBound, upperBound, polyDegree);

    Plaintext plaintextSigmoid, plaintextTanh, plaintextSwish;
    CKKSContext->Decrypt(CKKSKeypair.secretKey, resultSigmoid, &plaintextSigmoid);
    CKKSContext->Decrypt(CKKSKeypair.secretKey, resultTanh, &plaintextTanh);
    CKKSContext->Decrypt(CKKSKeypair.secretKey, resultSwish, &plaintextSwish);
    plaintextSigmoid->SetLength(length);
    plaintextTanh->SetLength(length);
    plaintextSwish->SetLength(length);
    std::cout << plaintextSigmoid << std::endl;
    std::cout << plaintextTanh << std::endl;
    std::cout << plaintextSwish<< std::endl;

    return 0;
}