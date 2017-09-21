/**
*   Copyright(C) 2011-2015 Intel Corporation All Rights Reserved.
*
*   The source code, information  and  material ("Material") contained herein is
*   owned  by Intel Corporation or its suppliers or licensors, and title to such
*   Material remains  with Intel Corporation  or its suppliers or licensors. The
*   Material  contains proprietary information  of  Intel or  its  suppliers and
*   licensors. The  Material is protected by worldwide copyright laws and treaty
*   provisions. No  part  of  the  Material  may  be  used,  copied, reproduced,
*   modified, published, uploaded, posted, transmitted, distributed or disclosed
*   in any way  without Intel's  prior  express written  permission. No  license
*   under  any patent, copyright  or  other intellectual property rights  in the
*   Material  is  granted  to  or  conferred  upon  you,  either  expressly,  by
*   implication, inducement,  estoppel or  otherwise.  Any  license  under  such
*   intellectual  property  rights must  be express  and  approved  by  Intel in
*   writing.
*
*   *Third Party trademarks are the property of their respective owners.
*
*   Unless otherwise  agreed  by Intel  in writing, you may not remove  or alter
*   this  notice or  any other notice embedded  in Materials by Intel or Intel's
*   suppliers or licensors in any way.
*/

#include "sgx_stdio_util.h"
#define __need_timespec
#include "sgx_time_util.h"

#include "Bitcoin/block.h"
#include "Bitcoin/utilstrencodings.h"
#include "Bitcoin/streams.h"
#include "Bitcoin/merkleblock.h"
#include "Bitcoin/hash.h"
#include "Bitcoin/key.h"
#include "Bitcoin/base58.h"
#include "Bitcoin/transaction.h"
#include "Bitcoin/sign.h"
#include "Bitcoin/keystore.h"
#include "Bitcoin/chain.h"
#include "Bitcoin/pow.h"

#include <secp256k1.h>
#include <secp256k1_recovery.h>

#include "MyEnclave.h"
#include "MyEnclave_t.h"  /* print_string */

#include <openssl/ec.h>      // for EC_GROUP_new_by_curve_name, EC_GROUP_free, EC_KEY_new, EC_KEY_set_group, EC_KEY_generate_key, EC_KEY_free
#include <openssl/ecdsa.h>   // for ECDSA_do_sign, ECDSA_do_verify
#include <openssl/obj_mac.h> // for NID_secp192k1
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

CBlockHeader GetGenesisBlock(){ 
//Hard code the Genesis block of Regtest mode
    CBlockHeader genesis;
    genesis.SetNull();
    genesis.nVersion = 1;
    genesis.hashPrevBlock = uint256S("0000000000000000000000000000000000000000000000000000000000000000");
    genesis.hashMerkleRoot = uint256S("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");
    genesis.nTime = 1296688602;
    genesis.nBits = 0x207fffff;
    genesis.nNonce = 2;
    return genesis;
}

const CBlockHeader genesis = GetGenesisBlock();
CBlockIndex* lastIndex = new CBlockIndex(genesis);
typedef std::vector<unsigned char> valtype;
CMutableTransaction unsignedTx;
std::vector<CTransaction> prevRawTxs;
std::vector<CScript> redeemScripts;

uint32_t lock_time = 1000; //will be unlocked at block height 1000
const CAmount txFee = 5000; // fee that will be deducted
int nSize = 10; // size of the mixing set
std::string hexSignedRawTx; // with nSize > 30, copy safely content of signed Tx via ecall instead of printing it directly via ocall.

void print_EC_POINT(EC_POINT *point){
    const EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    printf("%s\n", EC_POINT_point2hex(group, point, POINT_CONVERSION_COMPRESSED, NULL));
}

void print_buffer(char* msg, unsigned char* string, int len){
    char outputBuffer[2*len+1];
    for(int i = 0; i < len; i++)
    {
        snprintf(outputBuffer + i * 2, sizeof(string), "%02x", string[i]);
    }
    outputBuffer[2*len] = 0;
    printf("%s %d: %s\n", msg, len, outputBuffer);
}

std::string ScriptToAsmStr(const CScript& script){
    std::string str;
    opcodetype opcode;
    std::vector<unsigned char> vch;
    CScript::const_iterator pc = script.begin();
    while (pc < script.end()) {
        if (!str.empty()) {
            str += " ";
        }
        if (!script.GetOp(pc, opcode, vch)) {
            str += "[error]";
            return str;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4) {
            str += HexStr(vch);
            // printf("Length vch: %d\n", vch.size());
        } else {
            str += GetOpName(opcode);
        }
    }
    return str;
}

std::vector<std::vector<unsigned char> > ScriptToVectorStr(const CScript& script){
    opcodetype opcode;
    std::vector<unsigned char> vch;
    CScript::const_iterator pc = script.begin();
    std::vector<std::vector<unsigned char> > ret;
    while (pc < script.end()) {
        script.GetOp(pc, opcode, vch);
        ret.push_back(vch);
    }
    return ret;
}

CPubKey get_sender_pkey(CTransaction tx){
    // now only can parse scriptSig in format: <sig> <pubkey>
    CScript scriptSig = tx.vin[0].scriptSig;
    std::vector<std::vector<unsigned char> > vchVector = ScriptToVectorStr(scriptSig);
    CPubKey sender_pkey(vchVector[1]);
    return sender_pkey;
}

bool DecodeHexBlk(CBlock& block, const std::string& strHexBlk)
{
    if (!IsHex(strHexBlk))
        return false;
    std::vector<unsigned char> blockData(ParseHex(strHexBlk));
    CDataStream ssBlock(blockData, SER_NETWORK, PROTOCOL_VERSION);
    try {
        ssBlock >> block;
    }
    catch (const std::exception&) {
        return false;
    }
    return true;
}

bool DecodeHexTx(CTransaction& tx, const std::string& strHexTx){
    if (!IsHex(strHexTx))
        return false;
    std::vector<unsigned char> txData(ParseHex(strHexTx));
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    try {
        ssData >> tx;
    }
    catch (const std::exception&) {
        return false;
    }
    return true;
}

bool CScript::IsMixingTx(std::vector<unsigned char>& data) const
{
    // Extra-fast test for pay-to-script-hash CScripts:
    if ((*this)[0] == OP_RETURN && (*this)[1] == 0x46 && (*this)[2] == 0x00){
        data = std::vector<unsigned char>(this->begin() + 2, this->end());
        return true;
    }
    return false;
}

bool CScript::IsPayToScriptHash(std::vector<unsigned char>& scriptHash) const
{
    // Extra-fast test for pay-to-script-hash CScripts:
    if (this->size() == 23 &&
            (*this)[0] == OP_HASH160 &&
            (*this)[1] == 0x14 &&
            (*this)[22] == OP_EQUAL){
        scriptHash = std::vector<unsigned char>(this->begin() + 2, this->begin()+22);
        return true;
    }
    return false;
}

CScript generate_redeem_script(const CPubKey user_pubkey, const CPubKey mixer_pubkey, const uint32_t lock_time){
    CScript redeemScript = CScript();
    redeemScript << OP_IF << ToByteVector(mixer_pubkey) << OP_CHECKSIG << OP_ELSE << lock_time << OP_CHECKLOCKTIMEVERIFY << OP_DROP << ToByteVector(user_pubkey) << OP_CHECKSIG << OP_ENDIF;
    return redeemScript;
}

CScript generate_returning_script(const CPubKey user_pubkey){
    CScript redeemScript = CScript();
    redeemScript << ToByteVector(user_pubkey) << OP_CHECKSIG;
    return redeemScript;
}

void hash160(unsigned char *string, int len, unsigned char* dgst)
{
    unsigned char hashFinal[RIPEMD160_DIGEST_LENGTH];
    unsigned char hash256[SHA256_DIGEST_LENGTH];

    SHA256(string, len, hash256);
    RIPEMD160(hash256, SHA256_DIGEST_LENGTH, hashFinal);
    memcpy(dgst, hashFinal, RIPEMD160_DIGEST_LENGTH);
}



// =================================ECIES=========================================================

EC_POINT *EC_POINT_mult_BN(const EC_GROUP *group, EC_POINT *P, const EC_POINT *a, const BIGNUM *b, BN_CTX *ctx)
{
    EC_POINT *O = EC_POINT_new(group);
    if (P == NULL) P = EC_POINT_new(group);

    for(int i = BN_num_bits(b); i >= 0; i--) {
        EC_POINT_dbl(group, P, P, ctx);
        if (BN_is_bit_set(b, i))
            EC_POINT_add(group, P, P, a, ctx);
        else
            EC_POINT_add(group, P, P, O, ctx);
    }

    return P;
}

int EC_KEY_public_derive_S(const EC_POINT *pkey, point_conversion_form_t fmt, BIGNUM *S, BIGNUM *R)
{
    BN_CTX *ctx = BN_CTX_new();
    const EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    const EC_POINT *Kb = pkey;
    BIGNUM *n = BN_new();
    BIGNUM *r = BN_new();
    EC_POINT *P = NULL;
    EC_POINT *Rp = EC_POINT_new(group);
    BIGNUM *Py = BN_new();
    const EC_POINT *G = EC_GROUP_get0_generator(group);
    int bits,ret=-1;
    EC_GROUP_get_order(group, n, ctx);
    bits = BN_num_bits(n);
    BN_rand(r, bits, -1, 0);
    /* calculate R = rG */
    Rp = EC_POINT_mult_BN(group, Rp, G, r, ctx);
    /* calculate S = Px, P = (Px,Py) = Kb R */
    P = EC_POINT_mult_BN(group, P, Kb, r, ctx);
    if (!EC_POINT_is_at_infinity(group, P)) {
        EC_POINT_get_affine_coordinates_GF2m(group, P, S, Py, ctx);
        EC_POINT_point2bn(group, Rp, fmt, R, ctx);
        ret = 0;
    }
    BN_free(r);
    BN_free(n);
    BN_free(Py);
    EC_POINT_free(P);
    EC_POINT_free(Rp);
    BN_CTX_free(ctx);
    return ret;
}

int EC_KEY_private_derive_S(const EC_KEY *key, const BIGNUM *R, BIGNUM *S)
{
    int ret = -1;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new();
    BIGNUM *Py = BN_new();
    const EC_GROUP *group = EC_KEY_get0_group(key);
    EC_POINT *Rp = EC_POINT_bn2point(group, R, NULL, ctx);
    const BIGNUM *kB = EC_KEY_get0_private_key(key);
    EC_GROUP_get_order(group, n, ctx);
    /* Calculate S = Px, P = (Px, Py) = R kB */
    EC_POINT *P = EC_POINT_mult_BN(group, NULL, Rp, kB, ctx);
    if (!EC_POINT_is_at_infinity(group, P)) {
        EC_POINT_get_affine_coordinates_GF2m(group, P, S, Py, ctx);
        ret = 0;
    }
    BN_free(n);
    BN_free(Py);
    EC_POINT_free(Rp);
    EC_POINT_free(P);
    BN_CTX_free(ctx);
    return ret;
}

int decipher(const EC_KEY *key, unsigned char* to,
    const unsigned char *R_in, size_t R_len, const unsigned char *c_in, size_t c_len, 
    const unsigned char *d_in, size_t d_len)
{
    BIGNUM *R = BN_bin2bn(R_in, R_len, BN_new());
    BIGNUM *S = BN_new();

    if (EC_KEY_private_derive_S(key, R, S) != 0) {
        // printf("Key derivation failed\n");
        return -1;
    }

        // printf("S_decipher = ");
        // BN_print_fp(stdout, S);
        // printf("\n");

        size_t S_len = BN_num_bytes(S);
        unsigned char password[S_len];
        BN_bn2bin(S, password);

        /* then we can move on to traditional crypto using pbkdf2 we generate keys */
        const EVP_MD *md = EVP_md5();
        const EVP_CIPHER *cipher = EVP_aes_128_ctr();
        size_t ke_len = EVP_CIPHER_key_length(cipher) + EVP_CIPHER_iv_length(cipher);
        size_t km_len = EVP_MD_block_size(md);
        unsigned char ke_km[ke_len+km_len];

        unsigned char dc_out[2048] = {0};
        size_t dc_len = 0;
        int outl = 0;

        PKCS5_PBKDF2_HMAC((const char*)password, S_len, NULL, 0, 0, md, ke_len+km_len, ke_km);

        unsigned char dv_out[km_len];
        unsigned int dv_len;
        HMAC(md, ke_km + ke_len, km_len, c_in, c_len, dv_out, &dv_len);

    if (d_len != dv_len || memcmp(dv_out, d_in, dv_len) != 0){
        // printf("MAC verification failed\n");
        return -1;
    }

        EVP_CIPHER_CTX *ectx = EVP_CIPHER_CTX_new();

        EVP_DecryptInit_ex(ectx, cipher, NULL, ke_km, ke_km + EVP_CIPHER_key_length(cipher));
        EVP_DecryptUpdate(ectx, dc_out + dc_len, &outl, c_in, c_len);
        dc_len += outl;
        EVP_DecryptFinal_ex(ectx, dc_out + dc_len, &outl);
        dc_len += outl;
    dc_out[dc_len] = 0;
    // printf("%s\n", dc_out);
    memcpy(to, dc_out, dc_len);
    return 0;
}

int encipher(const EC_POINT *pkey,
    unsigned char *R_out, size_t *R_len, unsigned char *c_out, size_t *c_len,
    unsigned char *d_out, size_t *d_len, const unsigned char *salt, size_t salt_len)
{
    BIGNUM *R = BN_new();
    BIGNUM *S = BN_new();

    /* make sure it's not at infinity */
    while(EC_KEY_public_derive_S(pkey, POINT_CONVERSION_COMPRESSED, S, R) != 0);

    // printf("R = ");
    // BN_print_fp(stdout, R);
    // printf("\n");

    // printf("S_encipher = ");
    // BN_print_fp(stdout, S);
    // printf("\n");

    size_t S_len = BN_num_bytes(S);
    unsigned char password[S_len];
    BN_bn2bin(S, password);

    /* then we can move on to traditional crypto using pbkdf2 we generate keys */
    const EVP_MD *md = EVP_md5();
    const EVP_CIPHER *cipher = EVP_aes_128_ctr();
    size_t ke_len = EVP_CIPHER_key_length(cipher) + EVP_CIPHER_iv_length(cipher);
    size_t km_len = EVP_MD_block_size(md);
    unsigned char ke_km[ke_len+km_len];
    *c_len = 0;
    int outl = 0;

    PKCS5_PBKDF2_HMAC((const char*)password, S_len, NULL, 0, 2000, md, ke_len+km_len, ke_km);

    EVP_CIPHER_CTX *ectx = EVP_CIPHER_CTX_new();

    EVP_EncryptInit_ex(ectx, cipher, NULL, ke_km, ke_km + EVP_CIPHER_key_length(cipher));
    EVP_EncryptUpdate(ectx, c_out + *c_len, &outl, (const unsigned char*)"3P14159f73E4gFr7JterCCQh9QjiTjiZrG", 33);
    *c_len += outl;
    EVP_EncryptFinal_ex(ectx, c_out + *c_len, &outl);
    *c_len += outl;

    unsigned int len;

    /* calculate MAC */
    HMAC(md, ke_km + ke_len, km_len, c_out, *c_len, d_out, &len);

    *d_len = len;

    /* then reverse operation */
    *R_len = BN_num_bytes(R);
    BN_bn2bin(R, R_out);

    return 0;
}

const EC_POINT* get_ec_pkey(){
    SGX_WRAPPER_FILE f = fopen("ec.pubkey", "r");
    fseek (f , 0 , SEEK_END);
    int pem_key_length = ftell (f);
    rewind (f);
    char* buffer = (char*) malloc(pem_key_length+1);
    fread (buffer,sizeof(char),pem_key_length,f);
    fclose(f);

    BIO *keybio = BIO_new_mem_buf(buffer, -1);
    const EC_KEY *eckey = (EC_KEY*)PEM_read_bio_EC_PUBKEY(keybio, NULL, NULL, NULL);
    const EC_POINT *ec_pkey = EC_KEY_get0_public_key(eckey);
    return ec_pkey;
}

int ECIES_private_decrypt(const unsigned char *from, unsigned char *to, const EC_KEY *eckey){
    const size_t R_len = 33;
    const size_t D_len = 16;
    const size_t c_len = 20;
    unsigned char* R = (unsigned char*) malloc(R_len);
    unsigned char* D = (unsigned char*) malloc(D_len);
    unsigned char* c = (unsigned char*) malloc(c_len);
    
    if (from[0] != 0){
        return -1;
    }
    memcpy(R, from+1, R_len);
    memcpy(D, from+1+R_len, D_len);
    memcpy(c, from+1+R_len+D_len, c_len);

    return decipher(eckey, to, R, R_len, c, c_len, D, D_len);

    // return 1;
}

// ===============================================================================================


int ec_private_decrypt(const unsigned char *from, unsigned char *to, const EC_KEY *eckey){
    const size_t compressed_length = 33;
    const size_t xor_length = 20;
    unsigned char* compressed_EC_POINT = (unsigned char*) malloc(compressed_length);
    unsigned char* c2 = (unsigned char*) malloc(xor_length);
    
    if (from[0] != 0){
        return -1;
    }
    memcpy(compressed_EC_POINT, from+1, compressed_length);
    memcpy(c2, from+1+compressed_length, xor_length);

    BN_CTX *ctx = BN_CTX_new();
    const EC_GROUP *group = EC_KEY_get0_group(eckey);
    const BIGNUM *priv_key = EC_KEY_get0_private_key(eckey);
    EC_POINT *c1 = EC_POINT_new(group);

    if (!EC_POINT_oct2point(group, c1, compressed_EC_POINT, compressed_length, ctx)){
        return -1;
    }

    EC_POINT *temp = EC_POINT_new(group);
    EC_POINT_mul(group, temp, NULL, c1, priv_key, ctx);
    size_t oct_temp_length = 0;
    unsigned char *oct_temp;
    oct_temp_length = EC_POINT_point2oct(group, temp, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    oct_temp = (unsigned char*)malloc(oct_temp_length);
    EC_POINT_point2oct(group, temp, POINT_CONVERSION_COMPRESSED, oct_temp, oct_temp_length, ctx);

    unsigned char hash_temp[20];
    hash160(oct_temp, oct_temp_length, hash_temp);
    unsigned char* decryptedtext = (unsigned char*) malloc(xor_length);
    for (int i = 0; i < xor_length; i++){
        decryptedtext[i] = c2[i] ^ hash_temp[i];
    }

    memcpy(to, decryptedtext, xor_length);
    BN_CTX_free(ctx);
    EC_GROUP_free(group);
    BN_free(priv_key);
    EC_POINT_free(temp);
    EC_POINT_free(c1);
    return 1;
}

CKey get_btc_privkey(){
    CKey temp;
    if (SGX_WRAPPER_FILE f = fopen("btc.privkey", "r")){
        fseek (f , 0 , SEEK_END);
        int btc_privkey_length = ftell (f);
        rewind (f);
        unsigned char* buffer = (unsigned char*) malloc(btc_privkey_length+1);
        fread (buffer,sizeof(unsigned char),btc_privkey_length,f);
        fclose(f);
        temp.Set(buffer, buffer + btc_privkey_length, true);
    }
    else{
        f = fopen("btc.privkey", "w");
        temp.MakeNewKey(true);
        fwrite(temp.begin(), sizeof(unsigned char), temp.size(), f);
        fclose(f);
    }
    return temp;
}

EC_KEY* get_ec_privkey(){
    EC_KEY* temp;
    temp = EC_KEY_new();
    EC_GROUP *group= EC_GROUP_new_by_curve_name(NID_secp256k1);
    EC_KEY_set_group(temp, group);
    if (SGX_WRAPPER_FILE f = fopen("ec.privkey", "r")){
        fseek (f , 0 , SEEK_END);
        int lSize = ftell (f);
        rewind (f);
        unsigned char* buffer = (unsigned char*) malloc(lSize+1);
        fread (buffer,sizeof(unsigned char),lSize,f);
        fclose(f);
        BIO *keybio = BIO_new_mem_buf(buffer, -1);
        temp = PEM_read_bio_ECPrivateKey(keybio, &temp,NULL, NULL);
        EC_GROUP_free(group);
        BIO_free(keybio);
    }
    else{
        f = fopen("ec.privkey", "w");
        EC_KEY_generate_key(temp);
        BIO* bp_private = BIO_new(BIO_s_mem());
        PEM_write_bio_ECPrivateKey(bp_private, temp, NULL, NULL, 0, NULL, NULL);
        int keylen = BIO_pending(bp_private);
        unsigned char* pem_key = (unsigned char*) malloc(keylen+1);
        BIO_read(bp_private, pem_key, keylen);
        pem_key[keylen] = '\0';
        fwrite(pem_key, sizeof(unsigned char), keylen, f);
        fclose(f);
        EC_GROUP_free(group);
        BIO_free(bp_private);
    }
    return temp;
}

void ecall_gen_new_pubkey(){
    //call this everytime mixer starts scanning the blockchain
    if (SGX_WRAPPER_FILE f_ec = fopen("ec.pubkey", "r")){
        fclose(f_ec);
    }
    else{
        f_ec = fopen("ec.pubkey", "w");
        EC_KEY* eckey = get_ec_privkey();
        BIO* bp_public = BIO_new(BIO_s_mem());
        PEM_write_bio_EC_PUBKEY(bp_public, eckey);
        int len = BIO_pending(bp_public);
        char* pem_key = (char*) malloc(len+1);
        BIO_read(bp_public, pem_key, len);
        pem_key[len] = '\0';
        fwrite(pem_key, sizeof(uint8_t), len, f_ec);
        fclose(f_ec);
        EC_KEY_free(eckey);
        BIO_free(bp_public);
    }
    
    if (SGX_WRAPPER_FILE f_btc = fopen("btc.pubkey", "r")){
        fclose(f_btc);
    }
    else{
        f_btc = fopen("btc.pubkey", "w");
        ECC_Start();
        CKey btckey = get_btc_privkey();
        CPubKey btc_pkey = btckey.GetPubKey();
        fwrite(HexStr(btc_pkey).c_str(), sizeof(uint8_t), HexStr(btc_pkey).length(), f_btc);
        ECC_Stop();
        fclose(f_btc);
    }
}

bool IsValidRedeemScript(CScript redeemScript, CScript scriptPubKey){
    std::vector<unsigned char> redeemScript_bytes = ToByteVector(redeemScript);
    unsigned char hash_redeemScript[20];
    hash160((unsigned char*)(&redeemScript_bytes[0]), redeemScript_bytes.size(), hash_redeemScript);
    std::vector<unsigned char> hash_redeemScript_bytes(hash_redeemScript, hash_redeemScript+20);
    // printf("Hash of redeemScript: %s\n", (HexStr(hash_redeemScript_bytes)).c_str());

    std::vector<unsigned char> data_bytes;
    scriptPubKey.IsPayToScriptHash(data_bytes);
    for (int i = 0; i < 20; i++){
        if (hash_redeemScript[i] != data_bytes[i]){
            return false;
        }
    }
    return true;
}

static CScript PushAll(const std::vector<valtype>& values)
{
    CScript result;
    //BOOST_FOREACH(const valtype& v, values) {
    for (int i = 0; i < values.size(); i++){
        const valtype v = values[i];
        if (v.size() == 0) {
            result << OP_0;
        } else if (v.size() == 1 && v[0] >= 1 && v[0] <= 16) {
            result << CScript::EncodeOP_N(v[0]);
        } else {
            result << v;
        }
    }
    return result;
}

CTransaction sign_raw_transaction(CMutableTransaction unsignedTx, std::vector<CTransaction> prevRawTxs, std::vector<CScript> redeemScripts){
    CKey btckey = get_btc_privkey();
    ECC_Start();
    ECCVerifyHandle* globalVerifyHandle = new ECCVerifyHandle();
    CBasicKeyStore tempKeystore;
    int nHashType = SIGHASH_ALL;
    tempKeystore.AddCScript(redeemScripts[0]);
    tempKeystore.AddKey(btckey);
    CKeyStore& keystore = tempKeystore;

    CMutableTransaction mergedTx(unsignedTx);
    ShuffleVector(mergedTx.vout);
    const CTransaction txConst(mergedTx);
    std::vector<SignatureData> sigs;
    for (int i = 0; i < mergedTx.vin.size(); i++) {
        CTxIn& txin = mergedTx.vin[i];
        const CScript& prevPubKey = prevRawTxs[i].vout[txin.prevout.n].scriptPubKey;
        const CAmount& amount = prevRawTxs[i].vout[txin.prevout.n].nValue;
        SignatureData sigdata;
        std::vector<valtype> ret;
        std::vector<unsigned char> vchSig;
        const BaseSignatureCreator& creator = MutableTransactionSignatureCreator(&keystore, &mergedTx, i, amount, nHashType);

        uint256 hash = SignatureHash(redeemScripts[i], mergedTx, i, nHashType, amount, SIGVERSION_BASE);
        btckey.Sign(hash, vchSig);
        vchSig.push_back((unsigned char)nHashType);
        ret.push_back(vchSig);
        CScript flow;
        flow << OP_TRUE;
        ret.push_back(std::vector<unsigned char>(flow.begin(), flow.end()));
        ret.push_back(std::vector<unsigned char>(redeemScripts[i].begin(), redeemScripts[i].end()));
        sigdata.scriptSig = PushAll(ret);
        sigs.push_back(sigdata);
    }
    for (int i = 0; i < mergedTx.vin.size(); i++){
        CTxIn& txin = mergedTx.vin[i];
        const CScript& prevPubKey = prevRawTxs[i].vout[txin.prevout.n].scriptPubKey;
        const CAmount& amount = prevRawTxs[i].vout[txin.prevout.n].nValue;
        UpdateTransaction(mergedTx, i, sigs[i]);
        ScriptError serror = SCRIPT_ERR_OK;
        if (!VerifyScript(txin.scriptSig, prevPubKey, NULL, STANDARD_SCRIPT_VERIFY_FLAGS, TransactionSignatureChecker(&txConst, i, amount), &serror)) {
            printf("Signing failed: %s\n", ScriptErrorString(serror));
            return mergedTx;
        }
    }
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << mergedTx;
    ECC_Stop();
    free(globalVerifyHandle);
    hexSignedRawTx = HexStr(ssTx.begin(), ssTx.end());
    printf("Mixed %d input : %s\n", nSize, hexSignedRawTx.c_str());
    return mergedTx;
}

bool scan_tx(CTransaction tx, CMutableTransaction &unsignedTx, std::vector<CTransaction> &prevRawTxs, std::vector<CScript> &redeemScripts){
    CScript script1 = tx.vout[0].scriptPubKey;
    // printf("Script %s\n\n", ScriptToAsmStr(script1).c_str());
    std::vector<unsigned char> op_return_data;
    if (!script1.IsMixingTx(op_return_data)){ // fast detection
        return false;
    }
    EC_KEY* eckey = get_ec_privkey();
    unsigned char hash_returning_script[20];
    if (ECIES_private_decrypt(&op_return_data[0], hash_returning_script, eckey) < 0){
        printf("Fail decrypt\n");
        return false;
    }
    std::vector<unsigned char> hash_returning_script_bytes(hash_returning_script, hash_returning_script+20);

    CKey btckey = get_btc_privkey();
    ECC_Start();
    CPubKey mixer_pubkey = btckey.GetPubKey();
    ECC_Stop();
    CPubKey sender_pkey = get_sender_pkey(tx);
    CScript redeemScript = generate_redeem_script(sender_pkey, mixer_pubkey, lock_time);

    CScript script2 = tx.vout[1].scriptPubKey;
    if (!IsValidRedeemScript(redeemScript, script2)){
        printf("not valid redeemScript\n");
        return false;
    }

    int nIndex = 1;
    CTxIn in(COutPoint(tx.GetHash(), nIndex), CScript(), 0);
    unsignedTx.vin.push_back(in);
    CScript scriptPubKey;
    scriptPubKey << OP_HASH160 << hash_returning_script_bytes << OP_EQUAL;
    CTxOut out(tx.vout[nIndex].nValue-txFee, scriptPubKey);
    unsignedTx.vout.push_back(out);
    prevRawTxs.push_back(tx);
    redeemScripts.push_back(redeemScript);

    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << tx;
    return true;
}

bool verify_block(CBlock block){
    CBlockHeader bh = block.GetBlockHeader();
    if (!CheckProofOfWork(block.GetHash(), block.nBits)){
        return false;
    }
    if ((bh.nVersion == genesis.nVersion) && (bh.hashMerkleRoot == genesis.hashMerkleRoot) && (bh.nTime == genesis.nTime)
        && (bh.nNonce == genesis.nNonce) && (bh.nBits == genesis.nBits) && (bh.hashPrevBlock == genesis.hashPrevBlock)){
        return true;
    }
    if(bh.nBits == GetNextWorkRequired(lastIndex, &bh)){
        CBlockIndex* pindexNew = new CBlockIndex(bh);
        pindexNew->pprev = lastIndex;
        pindexNew->nHeight = pindexNew->pprev->nHeight+1;
        pindexNew->BuildSkip();
        lastIndex = pindexNew;
        return true;
    }
    return false;
} 

bool verify_block_header(CBlockHeader blockheader){
    CBlockHeader bh = blockheader;
    if (!CheckProofOfWork(bh.GetHash(), bh.nBits)){
        return false;
    }
    if ((bh.nVersion == genesis.nVersion) && (bh.hashMerkleRoot == genesis.hashMerkleRoot) && (bh.nTime == genesis.nTime)
        && (bh.nNonce == genesis.nNonce) && (bh.nBits == genesis.nBits) && (bh.hashPrevBlock == genesis.hashPrevBlock)){
        return true;
    }
    if(bh.nBits == GetNextWorkRequired(lastIndex, &bh)){
        CBlockIndex* pindexNew = new CBlockIndex(bh);
        pindexNew->pprev = lastIndex;
        pindexNew->nHeight = pindexNew->pprev->nHeight+1;
        pindexNew->BuildSkip();
        lastIndex = pindexNew;
        return true;
    }
    return false;
}

void ecall_get_block(char* hexBlock){
    CBlock block;
    DecodeHexBlk(block, hexBlock);
    
    if (verify_block(block)){
        printf("OK\n");
        for (int i = 0; i < block.vtx.size(); i++){
            // printf("TX: %s\n", block.vtx[i].GetHash().GetHex().c_str());
            if (scan_tx(block.vtx[i], unsignedTx, prevRawTxs, redeemScripts)){
                // printf("Found transaction: %s\n", block.vtx[i].GetHash().GetHex().c_str());
                // printf("%d\n", unsignedTx.vin.size());
                if (unsignedTx.vin.size() >= nSize){
                    CTransaction signedTx = sign_raw_transaction(unsignedTx, prevRawTxs, redeemScripts);
                    unsignedTx.SetNull();
                    prevRawTxs.clear();
                    redeemScripts.clear();
                }
            }
        }
    }
    else{
        printf("Not OK\n");
    }
}