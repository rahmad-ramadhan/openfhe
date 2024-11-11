#include <openfhe.h>
#include <vector>

lbcrypto::Ciphertext<lbcrypto::DCRTPoly> addInt(lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cryptoContext,
                                                lbcrypto::Ciphertext<lbcrypto::DCRTPoly> arg1, 
                                                lbcrypto::Ciphertext<lbcrypto::DCRTPoly> arg2){
    return cryptoContext->EvalAdd(arg1, arg2);
}

lbcrypto::Ciphertext<lbcrypto::DCRTPoly> mulInt(lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cryptoContext, 
                                                lbcrypto::Ciphertext<lbcrypto::DCRTPoly> arg1, 
                                                lbcrypto::Ciphertext<lbcrypto::DCRTPoly> arg2){
    return cryptoContext->EvalMult(arg1, arg2);
}

std::vector < lbcrypto::Ciphertext<lbcrypto::DCRTPoly> > encrypt(lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cryptoContext, 
                                                                lbcrypto::PublicKey<lbcrypto::DCRTPoly> publicKey, 
                                                                std::vector <int64_t> arg){
    std::vector <lbcrypto::Ciphertext<lbcrypto::DCRTPoly> > res;
    for (auto i: arg){
        lbcrypto::Plaintext plaintextI = cryptoContext->MakePackedPlaintext({i});
        res.push_back(cryptoContext->Encrypt(publicKey, plaintextI));
    }
    return res;
}

std::vector < std::vector < lbcrypto::Ciphertext<lbcrypto::DCRTPoly> > > encrypt(lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cryptoContext, 
                                                                lbcrypto::PublicKey<lbcrypto::DCRTPoly> publicKey, 
                                                                std::vector < std::vector <int64_t> > arg){
    std::vector < std::vector < lbcrypto::Ciphertext<lbcrypto::DCRTPoly> > > res;
    for (auto row: arg){
        std::vector < lbcrypto::Ciphertext<lbcrypto::DCRTPoly> > temp;
        for (auto i: row){
            lbcrypto::Plaintext plaintextI = cryptoContext->MakePackedPlaintext({i});
            temp.push_back(cryptoContext->Encrypt(publicKey, plaintextI));
        }
        res.push_back(temp);
    }
    return res;
}

signed main(){
    
    lbcrypto::CCParams<lbcrypto::CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(2);

    lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cryptoContext = lbcrypto::GenCryptoContext(parameters);
    cryptoContext->Enable(lbcrypto::PKE);
    cryptoContext->Enable(lbcrypto::KEYSWITCH);
    cryptoContext->Enable(lbcrypto::LEVELEDSHE);

    lbcrypto::KeyPair<lbcrypto::DCRTPoly> keyPair = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, {1, 2, -1, -2});

    int64_t a = 23, b = -1;
    lbcrypto::Plaintext plaintextA = cryptoContext->MakePackedPlaintext({a});
    lbcrypto::Plaintext plaintextB = cryptoContext->MakePackedPlaintext({b});
    
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ciphertextA = cryptoContext->Encrypt(keyPair.publicKey, plaintextA);
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ciphertextB = cryptoContext->Encrypt(keyPair.publicKey, plaintextB);

    // std::cout << "Ciphertext A: " << ciphertextA << std::endl;
    // std::cout << "Ciphertext B: " << ciphertextB << std::endl;

    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ciphertextAaddB = addInt(cryptoContext, ciphertextA, ciphertextB);
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ciphertextAmulB = mulInt(cryptoContext, ciphertextA, ciphertextB);

    lbcrypto::Plaintext plaintextAaddB;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextAaddB, &plaintextAaddB);
    lbcrypto::Plaintext plaintextAmulB;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextAmulB, &plaintextAmulB);

    // std::cout << "A + B : " << plaintextAaddB << std::endl;
    // std::cout << "A * B : " << plaintextAmulB << std::endl;

    int64_t scalarA = 7;
    lbcrypto::Plaintext plaintextScalarA = cryptoContext->MakePackedPlaintext({scalarA});
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ciphertextScalarA = cryptoContext->Encrypt(keyPair.publicKey, plaintextScalarA);

    std::vector <int64_t> vectorA = {2, 4, 12, -9};
    std::vector < std::vector <int64_t> > vectorB = {{1, 2, 3}, {4, 5, 6}, {7, 8, 9}, {10, 11, 12}};
    std::vector < std::vector <int64_t> > vectorC = {{15, 14, 13, 12, 11}, {10, 9, 8, 7, 6}, {5, 4, 3, 2, 1}};
    

    std::vector < lbcrypto::Ciphertext<lbcrypto::DCRTPoly> > ciphertextVecA = encrypt(cryptoContext, keyPair.publicKey, vectorA);
    std::vector < std::vector < lbcrypto::Ciphertext<lbcrypto::DCRTPoly> > > ciphertextVecB = encrypt(cryptoContext, keyPair.publicKey, vectorB);
    std::vector < std::vector < lbcrypto::Ciphertext<lbcrypto::DCRTPoly> > > ciphertextVecC = encrypt(cryptoContext, keyPair.publicKey, vectorC);

    return 0;
}