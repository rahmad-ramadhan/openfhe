#include <openfhe.h>
#include <vector>
#include <ctime>

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

std::vector < std::vector < lbcrypto::Ciphertext<lbcrypto::DCRTPoly> > > mulMat(lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cryptoContext,
                                                                                lbcrypto::PublicKey<lbcrypto::DCRTPoly> publicKey,
                                                                                std::vector < std::vector < lbcrypto::Ciphertext<lbcrypto::DCRTPoly> > > arg1, 
                                                                                std::vector < std::vector < lbcrypto::Ciphertext<lbcrypto::DCRTPoly> > > arg2){
    int64_t rowSize = arg1.size(), colSize = arg2[0].size(), size = arg1[0].size();
    std::vector < std::vector < lbcrypto::Ciphertext<lbcrypto::DCRTPoly> > > res(rowSize);

    for (int64_t i = 0; i < rowSize; ++i){
        for (int64_t j = 0; j < colSize; ++j){
            lbcrypto::Plaintext plaintextTemp = cryptoContext->MakePackedPlaintext({0});
            lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ciphertextTemp = cryptoContext->Encrypt(publicKey, plaintextTemp);
            for (int64_t k = 0; k < size; ++k)
                ciphertextTemp = addInt(cryptoContext, ciphertextTemp, mulInt(cryptoContext, arg1[i][k], arg2[k][j]));
            res[i].push_back(ciphertextTemp);
        }
    }

    return res;
}

std::vector < std::vector < lbcrypto::Plaintext> > decrypt(lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cryptoContext, 
                                                            lbcrypto::KeyPair<lbcrypto::DCRTPoly> keyPair,
                                                            std::vector < std::vector <lbcrypto::Ciphertext<lbcrypto::DCRTPoly> > > arg){

    int64_t rowSize = arg.size(), colSize = arg[0].size();
    std::vector < std::vector <lbcrypto::Plaintext> > res;
    for (int64_t i = 0; i < rowSize; ++i){
        std::vector <lbcrypto::Plaintext> temp1;
        for (int64_t j = 0; j < colSize; ++j){
            lbcrypto::Plaintext temp2;
            cryptoContext->Decrypt(keyPair.secretKey, arg[i][j], &temp2);
            temp1.push_back(temp2);
        }
        res.push_back(temp1);
    }
    return res;
}

std::vector < std::vector <int64_t> > vectorB = {
    {4, 7, 17, 20, 9, 2, 8, 3, 19, 18, 6, 9, 14, 15, 23, 9},
    {3, 6, 17, 22, 18, 16, 8, 24, 9, 14, 12, 15, 2, 9, 21, 22},
    {2, 15, 2, 18, 3, 12, 10, 15, 1, 17, 12, 7, 15, 8, 9, 10},
    {1, 2, 19, 22, 22, 4, 4, 9, 22, 12, 13, 8, 20, 10, 16, 4},
    {12, 14, 18, 1, 6, 7, 11, 15, 1, 11, 1, 3, 24, 21, 14, 13},
    {15, 14, 4, 2, 20, 18, 6, 23, 5, 23, 9, 15, 6, 12, 14, 11},
    {18, 24, 22, 6, 18, 23, 2, 10, 24, 8, 1, 22, 10, 16, 14, 5},
    {6, 3, 12, 12, 5, 8, 22, 11, 1, 13, 4, 5, 19, 9, 15, 23},
    {16, 7, 16, 18, 4, 24, 20, 11, 1, 19, 20, 15, 18, 10, 4, 12},
    {14, 18, 9, 15, 9, 2, 18, 6, 18, 18, 14, 10, 12, 19, 24, 3},
    {11, 6, 8, 23, 8, 12, 21, 22, 17, 20, 17, 10, 16, 7, 14, 14},
    {6, 5, 18, 20, 17, 23, 7, 8, 15, 1, 1, 9, 8, 10, 10, 17},
    {8, 20, 21, 9, 23, 17, 22, 1, 18, 24, 19, 12, 6, 2, 1, 8},
    {7, 22, 8, 10, 20, 13, 15, 1, 6, 15, 1, 20, 3, 15, 13, 8},
    {2, 12, 19, 15, 19, 2, 4, 6, 18, 12, 19, 20, 11, 3, 13, 23},
    {4, 21, 24, 17, 12, 21, 10, 11, 2, 6, 20, 18, 13, 14, 12, 19}
};

std::vector < std::vector <int64_t> > vectorC = {
    {5, 22, 12, 9, 16, 19, 5, 18, 18, 8, 4, 20, 1, 2, 21, 7},
    {7, 8, 12, 21, 6, 16, 6, 21, 5, 16, 11, 4, 14, 5, 19, 21},
    {21, 23, 3, 7, 18, 23, 20, 9, 24, 8, 8, 11, 23, 18, 14, 16},
    {13, 5, 2, 6, 4, 22, 11, 20, 23, 17, 11, 15, 12, 4, 24, 9},
    {1, 4, 7, 23, 20, 10, 5, 6, 20, 14, 13, 17, 12, 15, 17, 16},
    {24, 17, 21, 1, 12, 5, 4, 7, 15, 19, 11, 11, 21, 19, 12, 12},
    {13, 22, 2, 18, 5, 8, 13, 22, 18, 23, 9, 24, 9, 9, 18, 23},
    {23, 21, 16, 1, 6, 23, 12, 10, 17, 10, 22, 24, 24, 13, 9, 10},
    {4, 3, 3, 7, 11, 19, 8, 5, 12, 20, 24, 14, 7, 8, 14, 1},
    {7, 15, 6, 20, 8, 20, 5, 14, 16, 5, 23, 2, 22, 19, 22, 17},
    {1, 3, 10, 15, 22, 10, 23, 13, 14, 2, 24, 16, 4, 8, 12, 22},
    {8, 8, 3, 14, 4, 4, 5, 10, 6, 2, 11, 4, 2, 20, 2, 9},
    {4, 3, 18, 18, 11, 15, 16, 10, 20, 7, 2, 15, 21, 21, 11, 5},
    {23, 24, 1, 10, 4, 22, 9, 15, 24, 14, 4, 21, 14, 14, 20, 1},
    {16, 19, 16, 22, 10, 11, 24, 7, 23, 9, 14, 23, 14, 3, 4, 18},
    {12, 19, 21, 1, 2, 15, 23, 17, 15, 3, 24, 21, 20, 13, 22, 7}
};

signed main(){

    clock_t start = clock();
    
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

    // int64_t a = 23, b = -1;
    // lbcrypto::Plaintext plaintextA = cryptoContext->MakePackedPlaintext({a});
    // lbcrypto::Plaintext plaintextB = cryptoContext->MakePackedPlaintext({b});
    
    // lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ciphertextA = cryptoContext->Encrypt(keyPair.publicKey, plaintextA);
    // lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ciphertextB = cryptoContext->Encrypt(keyPair.publicKey, plaintextB);

    // std::cout << "Ciphertext A: " << ciphertextA << std::endl;
    // std::cout << "Ciphertext B: " << ciphertextB << std::endl;

    // lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ciphertextAaddB = addInt(cryptoContext, ciphertextA, ciphertextB);
    // lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ciphertextAmulB = mulInt(cryptoContext, ciphertextA, ciphertextB);

    // lbcrypto::Plaintext plaintextAaddB;
    // cryptoContext->Decrypt(keyPair.secretKey, ciphertextAaddB, &plaintextAaddB);
    // lbcrypto::Plaintext plaintextAmulB;
    // cryptoContext->Decrypt(keyPair.secretKey, ciphertextAmulB, &plaintextAmulB);

    // std::cout << "A + B : " << plaintextAaddB << std::endl;
    // std::cout << "A * B : " << plaintextAmulB << std::endl;

    int64_t scalarA = 7;
    lbcrypto::Plaintext plaintextScalarA = cryptoContext->MakePackedPlaintext({scalarA});
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ciphertextScalarA = cryptoContext->Encrypt(keyPair.publicKey, plaintextScalarA);

    clock_t declare = clock();

    std::vector <int64_t> vectorA = {2, 4, 12, -9};
    // std::vector < std::vector <int64_t> > vectorB = {{1, 2, 3}, {4, 5, 6}, {7, 8, 9}, {10, 11, 12}};
    // std::vector < std::vector <int64_t> > vectorC = {{15, 14, 13, 12, 11}, {10, 9, 8, 7, 6}, {5, 4, 3, 2, 1}};
    

    std::vector < lbcrypto::Ciphertext<lbcrypto::DCRTPoly> > ciphertextVecA = encrypt(cryptoContext, keyPair.publicKey, vectorA);
    std::vector < std::vector < lbcrypto::Ciphertext<lbcrypto::DCRTPoly> > > ciphertextVecB = encrypt(cryptoContext, keyPair.publicKey, vectorB);
    std::vector < std::vector < lbcrypto::Ciphertext<lbcrypto::DCRTPoly> > > ciphertextVecC = encrypt(cryptoContext, keyPair.publicKey, vectorC);
    
    std::vector < std::vector < lbcrypto::Ciphertext<lbcrypto::DCRTPoly> > > ciphertextAmulB = mulMat(cryptoContext, keyPair.publicKey, ciphertextVecB, ciphertextVecC);

    std::vector < std::vector < lbcrypto::Plaintext> > plaintextAmulB = decrypt(cryptoContext, keyPair, ciphertextAmulB);
    for (auto row: plaintextAmulB){
        for (auto i: row){
            std::cout << (i->GetPackedValue()[0]) << '\t';
        }
        std::cout << std::endl;
    }

    clock_t stop = clock();

    std::cout << "Timediff between start and declare:\t" << float(declare - start) / CLOCKS_PER_SEC << std::endl;
    std::cout << "Timediff between declare and stop:\t"  << float(stop - declare)  / CLOCKS_PER_SEC << std::endl;

    return 0;
}