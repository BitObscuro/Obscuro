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

int ElGamal_public_encrypt(int len, const unsigned char *from, unsigned char *to, const EC_POINT *pub_key){
    //ciphertext: 53 bytes = 1 bytes identifier (0x00) + 33 bytes compressed EC point + 20 bytes xor hash160
    unsigned char identifier = (unsigned char) strtol("0x00", NULL, 16);

    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *order = BN_new();
    BIGNUM *randomK = BN_new();
    EC_POINT *c1 = EC_POINT_new(group);

    EC_GROUP_get_order(group, order, ctx);
    BN_rand_range(randomK, order);
    EC_POINT_mul(group, c1, randomK, NULL, NULL, ctx);

    size_t compressed_length = 0;
    unsigned char *compressed_EC_POINT;
    compressed_length = EC_POINT_point2oct(group, c1, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    compressed_EC_POINT = (unsigned char*)malloc(compressed_length);
    EC_POINT_point2oct(group, c1, POINT_CONVERSION_COMPRESSED, compressed_EC_POINT, compressed_length, ctx);

    EC_POINT *temp = EC_POINT_new(group);
    EC_POINT_mul(group, temp, NULL, pub_key, randomK, ctx);

    size_t oct_temp_length = 0;
    unsigned char *oct_temp;
    oct_temp_length = EC_POINT_point2oct(group, temp, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    oct_temp = (unsigned char*)malloc(oct_temp_length);
    EC_POINT_point2oct(group, temp, POINT_CONVERSION_COMPRESSED, oct_temp, oct_temp_length, ctx);

    unsigned char hash_temp[20];
    hash160(oct_temp, oct_temp_length, hash_temp);

    size_t xor_length = RIPEMD160_DIGEST_LENGTH;
    unsigned char* c2 = (unsigned char*)malloc(xor_length);
    for (int i = 0; i < xor_length; i++){
        c2[i] = from[i] ^ hash_temp[i];
    }

    unsigned char* ciphertext = (unsigned char*) malloc(1 + compressed_length + xor_length + 1);
    ciphertext[0] = identifier;
    memcpy(ciphertext+1, compressed_EC_POINT, compressed_length);
    memcpy(ciphertext+1+compressed_length, c2, xor_length);

    memcpy(to, ciphertext, len);

    BN_CTX_free(ctx);
    EC_GROUP_free(group);
    BN_free(order);
    BN_free(randomK);
    EC_POINT_free(temp);
    EC_POINT_free(c1);
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
    unsigned char ciphertext[54];
    ElGamal_public_encrypt(54, hash_returning_script, ciphertext, mixer_eckey);
    vector<unsigned char> ciphertext_bytes(ciphertext, ciphertext+54);

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

const EC_POINT* get_elgamal_pkey(char* filename){
    FILE* f = fopen(filename, "r");
    fseek (f , 0 , SEEK_END);
    int pem_key_length = ftell (f);
    rewind (f);
    char* buffer = (char*) malloc(pem_key_length+1);
    fread (buffer,sizeof(char),pem_key_length,f);
    fclose(f);

    BIO *keybio = BIO_new_mem_buf(buffer, -1);
    const EC_KEY *eckey = (EC_KEY*)PEM_read_bio_EC_PUBKEY(keybio, NULL, NULL, NULL);
    const EC_POINT *elgamal_pkey = EC_KEY_get0_public_key(eckey);
    return elgamal_pkey;
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
    const EC_POINT* mixer_eckey = get_elgamal_pkey("..//elgamal.pubkey");

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