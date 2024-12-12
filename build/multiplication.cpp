#include <openfhe.h>
#include <vector>

using namespace lbcrypto;

Ciphertext<DCRTPoly> multiply(CryptoContext<DCRTPoly> cryptoContext, Ciphertext<DCRTPoly> arg1, Ciphertext<DCRTPoly> arg2){
    auto res = cryptoContext->EvalMult(arg1, arg2);
    return res;
}

signed main(){

    CCParams<CryptoContextBGVRNS> BGVParams;
    BGVParams.SetMultiplicativeDepth(3);
    BGVParams.SetPlaintextModulus(65537);
    auto BGVContext = GenCryptoContext(BGVParams);
    BGVContext->Enable(PKE);
    BGVContext->Enable(KEYSWITCH);
    BGVContext->Enable(LEVELEDSHE);

    CCParams<CryptoContextBFVRNS> BFVParams;
    BFVParams.SetMultiplicativeDepth(3);
    BFVParams.SetPlaintextModulus(65537);
    auto BFVContext = GenCryptoContext(BFVParams);
    BFVContext->Enable(PKE);
    BFVContext->Enable(KEYSWITCH);
    BFVContext->Enable(LEVELEDSHE);

    CCParams<CryptoContextCKKSRNS> CKKSParams;
    CKKSParams.SetMultiplicativeDepth(3);
    CKKSParams.SetScalingModSize(50);
    CKKSParams.SetBatchSize(8);
    auto CKKSContext = GenCryptoContext(CKKSParams);
    CKKSContext->Enable(PKE);
    CKKSContext->Enable(KEYSWITCH);
    CKKSContext->Enable(LEVELEDSHE);

    auto BGVKeypair = BGVContext->KeyGen();
    auto BFVKeypair = BFVContext->KeyGen();
    auto CKKSKeypair = CKKSContext->KeyGen();

    BGVContext->EvalMultKeyGen(BGVKeypair.secretKey);
    BFVContext->EvalMultKeyGen(BFVKeypair.secretKey);
    CKKSContext->EvalMultKeyGen(CKKSKeypair.secretKey);

    {// integer addition
        std::vector <int64_t> vectorA = {1, -1, 5, 13, 155};
        std::vector <int64_t> vectorB = {1, 1, -17, 25, 65};

        auto BGVPlaintextA = BGVContext->MakePackedPlaintext(vectorA);
        auto BGVPlaintextB = BGVContext->MakePackedPlaintext(vectorB);
        auto BGVCiphertextA = BGVContext->Encrypt(BGVKeypair.publicKey, BGVPlaintextA);
        auto BGVCiphertextB = BGVContext->Encrypt(BGVKeypair.publicKey, BGVPlaintextB);
        auto BGVaddAB = multiply(BGVContext, BGVCiphertextA, BGVCiphertextB);
        Plaintext BGVaddABresult;
        BGVContext->Decrypt(BGVKeypair.secretKey, BGVaddAB, &BGVaddABresult);
        std::cout << BGVaddABresult << std::endl;

        auto BFVPlaintextA = BFVContext->MakePackedPlaintext(vectorA);
        auto BFVPlaintextB = BFVContext->MakePackedPlaintext(vectorB);
        auto BFVCiphertextA = BFVContext->Encrypt(BFVKeypair.publicKey, BFVPlaintextA);
        auto BFVCiphertextB = BFVContext->Encrypt(BFVKeypair.publicKey, BFVPlaintextB);
        auto BFVaddAB = multiply(BFVContext, BFVCiphertextA, BFVCiphertextB);
        Plaintext BFVaddABresult;
        BFVContext->Decrypt(BFVKeypair.secretKey, BFVaddAB, &BFVaddABresult);
        std::cout << BFVaddABresult << std::endl;
        
        
        std::vector <double> vectorC = {1.5, -1.0, 1.333, 0.0, 16237.0};
        std::vector <double> vectorD = {1.2, 1.0, 3.3, -1.1, 23153.5};

        auto CKKSPlaintextC = CKKSContext->MakeCKKSPackedPlaintext(vectorC);
        auto CKKSPlaintextD = CKKSContext->MakeCKKSPackedPlaintext(vectorD);
        auto CKKSCiphertextC = CKKSContext->Encrypt(CKKSKeypair.publicKey, CKKSPlaintextC);
        auto CKKSCiphertextD = CKKSContext->Encrypt(CKKSKeypair.publicKey, CKKSPlaintextD);
        auto CKKSaddAB = multiply(CKKSContext, CKKSCiphertextC, CKKSCiphertextD);
        Plaintext CKKSaddABresult;
        CKKSContext->Decrypt(CKKSKeypair.secretKey, CKKSaddAB, &CKKSaddABresult);
        std::setprecision(8);
        std::cout << CKKSaddABresult << std::endl;
        
    }

    return 0;
}