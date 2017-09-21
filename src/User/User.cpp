#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>
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

#include "script.h"
#include "pubkey.h"
#include "key.h"
#include "utilstrencodings.h"
#include "base58.h"
#include "streams.h"
#include "keystore.h"
#include "sign.h"
using namespace std;


typedef std::vector<unsigned char> valtype;

uint32_t lock_time = 1000; //
const CAmount txFee = 5000; 

void hash160(unsigned char *string, int len, unsigned char* dgst)
{
    unsigned char hashFinal[RIPEMD160_DIGEST_LENGTH];
    unsigned char hash256[SHA256_DIGEST_LENGTH];

    SHA256(string, len, hash256);
    RIPEMD160(hash256, SHA256_DIGEST_LENGTH, hashFinal);
    memcpy(dgst, hashFinal, RIPEMD160_DIGEST_LENGTH);
}

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
    // BN_free(r);
    // BN_free(n);
    // BN_free(Py);
    // EC_POINT_free(P);
    // EC_POINT_free(Rp);
    // BN_CTX_free(ctx);
    return ret;
}

int encipher(const EC_POINT *pkey, const unsigned char *m, size_t m_len, 
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

    PKCS5_PBKDF2_HMAC((const char*)password, S_len, NULL, 0, 0, md, ke_len+km_len, ke_km);

    EVP_CIPHER_CTX *ectx = EVP_CIPHER_CTX_new();

    EVP_EncryptInit_ex(ectx, cipher, NULL, ke_km, ke_km + EVP_CIPHER_key_length(cipher));
    EVP_EncryptUpdate(ectx, c_out + *c_len, &outl, m, 20);
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

    BN_free(R);
    BN_free(S);

    return 0;
}

int ECIES_public_encrypt(int len, const unsigned char *from, unsigned char *to, const EC_POINT *pub_key){
    //ciphertext: 70 bytes = 1 bytes identifier (0x00) + 33 bytes compressed EC point + 20 bytes encryption + 16 bytes hmac
    unsigned char R[512], D[512], c[512], salt[16];
    size_t R_len, D_len, c_len, m_len;
    unsigned char identifier = (unsigned char) strtol("0x00", NULL, 16);
    RAND_bytes(salt, sizeof(salt));
    m_len = 20;

    encipher(pub_key, from, m_len, R, &R_len, c, &c_len, D, &D_len, salt, sizeof(salt));
    unsigned char* ciphertext = (unsigned char*) malloc(1+R_len+D_len+c_len+1);
    // printf("%d %d %d\n", R_len, D_len, c_len);
    ciphertext[0] = identifier;
    memcpy(ciphertext+1, R, R_len);
    memcpy(ciphertext+1+R_len, D, D_len);
    memcpy(ciphertext+1+R_len+D_len, c, c_len);

    memcpy(to, ciphertext, len);
    ciphertext[70] = 0;
    // printf("ciphertext: %s\n", ciphertext);
    return 1;
}

CScript generate_redeem_script(const CPubKey user_pubkey, const CPubKey mixer_pubkey, const uint32_t lock_time){
    CScript redeemScript;
    redeemScript << OP_IF << ToByteVector(mixer_pubkey) << OP_CHECKSIG << OP_ELSE << lock_time << OP_CHECKLOCKTIMEVERIFY << OP_DROP << ToByteVector(user_pubkey) << OP_CHECKSIG << OP_ENDIF;
    // redeemScript << OP_IF << ToByteVector(mixer_pubkey) << OP_CHECKSIG << OP_ELSE << ToByteVector(user_pubkey) << OP_CHECKSIG << OP_ENDIF;
    return redeemScript;
}

CScript generate_returning_script(const CPubKey user_pubkey){
    CScript redeemScript;
    redeemScript << ToByteVector(user_pubkey) << OP_CHECKSIG;
    return redeemScript;
}

bool CScript::IsMixingTx(std::vector<unsigned char>& data) const
{
    // Extra-fast test for pay-to-script-hash CScripts:
    if ((*this)[0] == OP_RETURN && (*this)[1] == 0x36 && (*this)[2] == 0x00){
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

string ScriptToAsmStr(const CScript& script){
    string str;
    opcodetype opcode;
    vector<unsigned char> vch;
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
        } else {
            str += GetOpName(opcode);
        }
    }
    return str;
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

CTransaction sign_raw_transaction(CMutableTransaction unsignedTx, std::vector<CTransaction> prevRawTxs, std::vector<CScript> redeemScripts, CKey btckey){
    // Sign refund transaction
    ECC_Start();
    ECCVerifyHandle* globalVerifyHandle = new ECCVerifyHandle();
    CBasicKeyStore tempKeystore;
    int nHashType = SIGHASH_ALL;
    tempKeystore.AddCScript(redeemScripts[0]);
    tempKeystore.AddKey(btckey);
    CKeyStore& keystore = tempKeystore;

    CMutableTransaction mergedTx(unsignedTx);
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
        flow << OP_FALSE;
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
    }
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << mergedTx;
    ECC_Stop();
    free(globalVerifyHandle);
    std::string hexSignedRawTx = HexStr(ssTx.begin(), ssTx.end());
    printf("Signed Tx: %s\n", hexSignedRawTx.c_str());
    return mergedTx;
}

string craft_transaction(CTransaction prevTx, uint32_t nIndex, CKey user_key, CPubKey returning_pubkey, CPubKey mixer_pubkey, const EC_POINT* mixer_eckey){
    //Craft an unsigned rawtransaction
    // vin[0]: prevTx
    // vout[0]: op_return + encrypted returning P2SH address
    // vout[1]: Script hash of the agreed redeemScript

    CScript redeemScript = generate_redeem_script(user_key.GetPubKey(), mixer_pubkey, lock_time);
    vector<unsigned char> redeemScript_bytes = ToByteVector(redeemScript);
    unsigned char hash_redeemScript[20];
    hash160((unsigned char*)(&redeemScript_bytes[0]), redeemScript_bytes.size(), hash_redeemScript);
    vector<unsigned char> hash_redeemScript_bytes(hash_redeemScript, hash_redeemScript+20);
    // printf("RedeemScript: %s\n", ScriptToAsmStr(redeemScript).c_str());
    // printf("Hash of redeemScript: %s\n", (HexStr(hash_redeemScript_bytes)).c_str());
    
    CScript returning_script = generate_returning_script(returning_pubkey);
    vector<unsigned char> returning_script_bytes = ToByteVector(returning_script);
    unsigned char hash_returning_script[20];
    hash160((unsigned char*)(&returning_script_bytes[0]), returning_script_bytes.size(), hash_returning_script);
    unsigned char ciphertext[70];
    ECIES_public_encrypt(70, hash_returning_script, ciphertext, mixer_eckey);
    vector<unsigned char> ciphertext_bytes(ciphertext, ciphertext+70);

    vector<unsigned char> plainText(hash_returning_script, hash_returning_script+20);

    CMutableTransaction rawTx;
    CTxIn in(COutPoint(prevTx.GetHash(), nIndex), CScript(), 0);
    rawTx.vin.push_back(in);

    CScript script1, script2;
    script1 << OP_RETURN << ciphertext_bytes; 
    CTxOut vout1(0, script1);
    script2 << OP_HASH160 << hash_redeemScript_bytes << OP_EQUAL;
    CTxOut vout2(prevTx.vout[nIndex].nValue-txFee, script2);
    rawTx.vout.push_back(vout1);
    rawTx.vout.push_back(vout2);

    // rawTx.nLockTime = lock_time;

    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << rawTx;
    string hexRawTx = HexStr(ssTx.begin(), ssTx.end());
    return hexRawTx;
}

bool IsValidRedeemScript(CScript redeemScript, CScript scriptPubKey){
    std::vector<unsigned char> redeemScript_bytes = ToByteVector(redeemScript);
    unsigned char hash_redeemScript[20];
    hash160((unsigned char*)(&redeemScript_bytes[0]), redeemScript_bytes.size(), hash_redeemScript);
    std::vector<unsigned char> hash_redeemScript_bytes(hash_redeemScript, hash_redeemScript+20);

    std::vector<unsigned char> data_bytes;
    scriptPubKey.IsPayToScriptHash(data_bytes);
    for (int i = 0; i < 20; i++){
        if (hash_redeemScript[i] != data_bytes[i]){
            return false;
        }
    }
    return true;
}

bool craft_refund(CTransaction prevTx, CKey user_key, CPubKey mixer_pubkey, CMutableTransaction &unsignedTx, std::vector<CTransaction> &prevRawTxs, std::vector<CScript> &redeemScripts){
    CScript redeemScript = generate_redeem_script(user_key.GetPubKey(), mixer_pubkey, lock_time);
    // CMutableTransaction unsignedTx;
    CScript script2 = prevTx.vout[1].scriptPubKey;
    if (!IsValidRedeemScript(redeemScript, script2)){
        printf("Redeem Script hash does not match\n");
        return false;
    }
    CTxIn in(COutPoint(prevTx.GetHash(), 1), CScript(), 0);
    unsignedTx.vin.push_back(in);
    CScript script1;
    script1 << OP_DUP << OP_HASH160 << ToByteVector(user_key.GetPubKey().GetID()) << OP_EQUALVERIFY << OP_CHECKSIG;
    CTxOut vout(prevTx.vout[1].nValue-txFee, script1);

    unsignedTx.vout.push_back(vout);
    prevRawTxs.push_back(prevTx);
    redeemScripts.push_back(redeemScript);
    unsignedTx.nLockTime = lock_time;

    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << unsignedTx;
    string hexRawTx = HexStr(ssTx.begin(), ssTx.end());
    printf("Unsigned Refund  TX: %s\n", hexRawTx.c_str());
    return true;;
}

bool DecodeHexTx(CTransaction& tx, const std::string& strHexTx, bool fTryNoWitness){
    if (!IsHex(strHexTx))
        return false;
    vector<unsigned char> txData(ParseHex(strHexTx));
    if (fTryNoWitness) {
        CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS);
        try {
            ssData >> tx;
            if (ssData.eof()) {
                return true;
            }
        }
        catch (const std::exception&) {
            // Fall through.
        }
    }
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    try {
        ssData >> tx;
    }
    catch (const std::exception&) {
        return false;
    }
    return true;
}

CPubKey get_btc_pkey(char* filename){
    FILE* f = fopen(filename, "r");
    fseek (f , 0 , SEEK_END);
    int btc_pkey_length = ftell (f);
    rewind (f);
    char* buffer = (char*) malloc(btc_pkey_length+1);
    fread (buffer,sizeof(char),btc_pkey_length,f);
    fclose(f);
    
    string buffer_temp(buffer);
    std::vector<unsigned char> btc_pkey_data(ParseHex(buffer_temp));
    CPubKey btc_pkey(btc_pkey_data);
    return btc_pkey;
}

const EC_POINT* get_ec_pkey(char* filename){
    FILE* f = fopen(filename, "r");
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

void print_EC_POINT(const EC_POINT *point){
    const EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    printf("%s\n", EC_POINT_point2hex(group, point, POINT_CONVERSION_COMPRESSED, NULL));
}

// Params: 0 - Previous transaction in hex
//         1 - Private key to claim previous transaction
//         2 - Private key of the returning address
// Outputs: Create a new address for refund and returning coin. Return a (unsigned) transaction.

int main(int argc, char *argv[]){
    ECC_Start();

    string strHexTx(argv[1]);
    CTransaction prevTx;
    DecodeHexTx(prevTx, strHexTx, true);
    CPubKey mixer_pubkey = get_btc_pkey("..//btc.pubkey");
    const EC_POINT* mixer_eckey = get_ec_pkey("..//ec.pubkey");

    std::string hexPrivKey1(argv[2]);
    CBitcoinSecret key_secret1;
    key_secret1.SetString(hexPrivKey1);
    CKey user_key = key_secret1.GetKey(); // to create deposit transaction

    std::string hexPrivKey2(argv[3]);
    CBitcoinSecret key_secret2;
    key_secret2.SetString(hexPrivKey2);
    CPubKey user_pubkey = key_secret2.GetKey().GetPubKey(); //to create returning address

    int nIndex = -1;
    CScript sc;
    sc << OP_DUP << OP_HASH160 << ToByteVector(user_key.GetPubKey().GetID()) << OP_EQUALVERIFY << OP_CHECKSIG;
    for (int i = 0; i < prevTx.vout.size(); i++){
        CScript scriptPubKey = prevTx.vout[i].scriptPubKey;
        if (sc == scriptPubKey){
            nIndex = i;
            break;
        }
    }
    string craftTx = craft_transaction(prevTx, nIndex, user_key, user_pubkey, mixer_pubkey, mixer_eckey);
    printf("%s\n", craftTx.c_str());
    ECC_Stop();
    return 0;
}