#include <openfhe.h>
#include <vector>

using namespace lbcrypto;

signed main(){

    auto scalingTechnique = FIXEDMANUAL;
    int64_t multiplicativeDepth = 17;
    int64_t firstModSize = 60;
    int64_t scalingModSize = 50;
    int64_t ringDim = 8192;
    auto securityLevel = HEStd_NotSet;
    auto slBin = TOY;
    int64_t logQ_ccLWE = 23;
    int64_t slots = 16;
    int64_t batchSize = 16;

    CCParams<CryptoContextCKKSRNS> CKKSParams;
    CKKSParams.SetMultiplicativeDepth(multiplicativeDepth);
    CKKSParams.SetFirstModSize(firstModSize);
    CKKSParams.SetScalingModSize(scalingModSize);
    CKKSParams.SetScalingTechnique(scalingTechnique);
    CKKSParams.SetSecurityLevel(securityLevel);
    CKKSParams.SetRingDim(ringDim);
    CKKSParams.SetBatchSize(batchSize);
    auto CKKSContext = GenCryptoContext(CKKSParams);
    CKKSContext->Enable(PKE);
    CKKSContext->Enable(KEYSWITCH);
    CKKSContext->Enable(LEVELEDSHE);
    CKKSContext->Enable(ADVANCEDSHE);
    CKKSContext->Enable(SCHEMESWITCH);
    CKKSContext->Enable(PRE);

    auto CKKSKeypair = CKKSContext->KeyGen();
    SchSwchParams switchParams;
    switchParams.SetSecurityLevelCKKS(securityLevel);
    switchParams.SetSecurityLevelFHEW(slBin);
    switchParams.SetCtxtModSizeFHEWLargePrec(logQ_ccLWE);
    switchParams.SetNumSlotsCKKS(slots);
    auto privateKeyFHEW = CKKSContext->EvalCKKStoFHEWSetup(switchParams);
    auto ccLWE          = CKKSContext->GetBinCCForSchemeSwitch();
    CKKSContext->EvalCKKStoFHEWKeyGen(CKKSKeypair, privateKeyFHEW);

    // double scaleSign = 256;
    // auto modulus_LWE = 1 << logQ_ccLWE;
    // auto beta = ccLWE.GetBeta();
    // auto pLWE = modulus_LWE / 2 / beta;

    CKKSContext->EvalCompareSwitchPrecompute(0, 1, false);

    CKKSContext->EvalSumKeyGen(CKKSKeypair.secretKey, CKKSKeypair.publicKey);
    CKKSContext->EvalMultKeyGen(CKKSKeypair.secretKey);
    
    std::vector <double> vec = {91, 140, 204, 50, 70, 129, 98, 57, 91, 140, 204, 50, 70, 129, 52, 52};
    auto plaintextVec = CKKSContext->MakeCKKSPackedPlaintext(vec);
    auto ciphertextVec = CKKSContext->Encrypt(CKKSKeypair.publicKey, plaintextVec);

    auto result = CKKSContext->EvalMinSchemeSwitching(ciphertextVec, CKKSKeypair.publicKey, 16, slots, false);
    Plaintext res1, res2;
    CKKSContext->Decrypt(CKKSKeypair.secretKey, result[0], &res1);
    CKKSContext->Decrypt(CKKSKeypair.secretKey, result[1], &res2);
    std::cout << res1 << ' ' << res2 << std::endl;

    return 0;
}