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

#include <stdio.h>
#include <assert.h>
#include <ctype.h>
#if HAVE_FORK
#include <sys/wait.h>
#endif
#include <signal.h>

#ifdef HAVE_READLINE
#include <readline/readline.h>
#include <readline/history.h>
#endif /* HAVE_READLINE */

#if HAVE_ERRNO_H
#include <errno.h>
#endif /* HAVE_ERRNO_H */

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif /* HAVE_STDLIB_H */

#if HAVE_STRING_H
#include <string.h>
#endif /* HAVE_STRING_H */

#if HAVE_UNISTD_H
# include <unistd.h>
#elif defined(_WIN32)
# include <io.h>
# undef isatty
# define isatty(fd) _isatty(fd)
#endif /* HAVE_UNISTD_H */

/* HP-UX require some constants defined by limits.h */
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif /* HAVE_LIMITS_H */

#if defined(__hpux__) && !defined(_POSIX_PATH_MAX)
#define _POSIX_PATH_MAX 255
#endif

#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif /* HAVE_LOCALE_H */

#ifdef HAVE_LANGINFO_H
#include <langinfo.h>
#endif /* HAVE_LANGINFO_H */

#ifdef HAVE_LOCALCHARSET_H
#include <localcharset.h>
#endif /* HAVE_LOCALCHARSET_H */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sstream> 
#include <vector>
#include <fstream>
#include <ctime>
#include <time.h>
#include <sys/time.h>

#ifdef _MSC_VER
# include <Shlobj.h>
#else
# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX
#endif

#include "sgx_urts.h"
#include "sgx_status.h"
#include "App.h"

#include <unistd.h>
#include <errno.h>
#include <map>

#include "MyEnclave_u.h"

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

int padding = RSA_PKCS1_PADDING;
const std::string base_cmd = "bitcoin-cli ";
const std::string mode = "-regtest ";

extern std::map<sgx_enclave_id_t, uint32_t>g_enclave_id_map;

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;
sgx_enclave_id_t vrfcert_eid = -1;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};



/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");

    printf("Ret error code: %x\n", ret);
}

/* Initialize the enclave:
 *   Step 1: retrive the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    
    /* Step 1: retrive the launch token saved by last transaction */
#ifdef _MSC_VER
    /* try to get the token saved in CSIDL_LOCAL_APPDATA */
    if (S_OK != SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, token_path)) {
        strncpy_s(token_path, _countof(token_path), TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    } else {
        strncat_s(token_path, _countof(token_path), "\\" TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+2);
    }

    /* open the token file */
    HANDLE token_handler = CreateFileA(token_path, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, NULL, NULL);
    if (token_handler == INVALID_HANDLE_VALUE) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    } else {
        /* read the token from saved file */
        DWORD read_num = 0;
        ReadFile(token_handler, token, sizeof(sgx_launch_token_t), &read_num, NULL);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
#else /* __GNUC__ */
    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    
    if (home_dir != NULL && 
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
#endif
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    uint32_t enclave_temp_no = 0;    

    int launch_token_updated;
    sgx_launch_token_t launch_token;
    ret = sgx_create_enclave(VRFCERT_ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &launch_token, &launch_token_updated, &vrfcert_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
#ifdef _MSC_VER
        if (token_handler != INVALID_HANDLE_VALUE)
            CloseHandle(token_handler);
#else
        if (fp != NULL) fclose(fp);
#endif
        return -1;
    }

    enclave_temp_no++;
    g_enclave_id_map.insert(std::pair<sgx_enclave_id_t, uint32_t>(vrfcert_eid, enclave_temp_no));

    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
#ifdef _MSC_VER
        if (token_handler != INVALID_HANDLE_VALUE)
            CloseHandle(token_handler);
#else
        if (fp != NULL) fclose(fp);
#endif
        return -1;
    }


    enclave_temp_no++;
    g_enclave_id_map.insert(std::pair<sgx_enclave_id_t, uint32_t>(global_eid, enclave_temp_no));

    /* Step 3: save the launch token if it is updated */
#ifdef _MSC_VER
    if (updated == FALSE || token_handler == INVALID_HANDLE_VALUE) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (token_handler != INVALID_HANDLE_VALUE)
            CloseHandle(token_handler);
        return 0;
    }
    
    /* flush the file cache */
    FlushFileBuffers(token_handler);
    /* set access offset to the begin of the file */
    SetFilePointer(token_handler, 0, NULL, FILE_BEGIN);

    /* write back the token */
    DWORD write_num = 0;
    WriteFile(token_handler, token, sizeof(sgx_launch_token_t), &write_num, NULL);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    CloseHandle(token_handler);
#else /* __GNUC__ */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
#endif
    return 0;
}

#if defined(_MSC_VER)
/* query and enable SGX device*/
int query_sgx_status()
{
    sgx_device_status_t sgx_device_status;
    sgx_status_t sgx_ret = sgx_enable_device(&sgx_device_status);
    if (sgx_ret != SGX_SUCCESS) {
        printf("Failed to get SGX device status.\n");
        return -1;
    }
    else {
        switch (sgx_device_status) {
        case SGX_ENABLED:
            return 0;
        case SGX_DISABLED_REBOOT_REQUIRED:
            printf("SGX device has been enabled. Please reboot your machine.\n");
            return -1;
        case SGX_DISABLED_LEGACY_OS:
            printf("SGX device can't be enabled on an OS that doesn't support EFI interface.\n");
            return -1;
        case SGX_DISABLED:
            printf("SGX device not found.\n");
            return -1;
        default:
            printf("Unexpected error.\n");
            return -1;
        }
    }
}
#endif

std::string exec(const char* cmd) {
    char buffer[128];
    std::string result = "";
    FILE* pipe = popen(cmd, "r");
    if (!pipe) throw std::runtime_error("popen() failed!");
    try {
        while (!feof(pipe)) {
            if (fgets(buffer, 128, pipe) != NULL){
                result += buffer;
            }
        }
    } catch (...) {
        pclose(pipe);
        throw;
    }
    pclose(pipe);
    return result;
}

std::string getbestblockhash(){
    std::string rpc("getbestblockhash ");
    rpc = base_cmd + mode + rpc;
    const char* cmd = rpc.c_str();
    std::string pout = exec(cmd);
    if (pout.find("error") != std::string::npos)
        throw std::runtime_error(pout);
    while (pout.find ("\n") != std::string::npos )
    {
        pout.erase (pout.find ("\n"), 1 );
    }
    return pout;
}

uint32_t get_block_count(){
    std::string rpc("getblockcount ");
    rpc = base_cmd + mode + rpc;
    const char* cmd = rpc.c_str();
    std::string pout = exec(cmd);
    if (pout.find("error") != std::string::npos)
        throw std::runtime_error(pout);
    return std::stoi(pout);
}

std::string get_block_hash(uint32_t index){
    std::string rpc("getblockhash ");
    rpc = base_cmd + mode + rpc + std::to_string(index);
    const char* cmd = rpc.c_str();
    std::string pout = exec(cmd);
    if (pout.find("error") != std::string::npos)
        throw std::runtime_error(pout);
    while (pout.find ("\n") != std::string::npos )
    {
        pout.erase (pout.find ("\n"), 1 );
    }
    return pout;
}

char* get_hexed_block(std::string hashval){
    std::string rpc("getblock ");
    std::string verbose(" false");
    rpc = base_cmd + mode + rpc + hashval + verbose;
    const char* cmd = rpc.c_str();
    std::string pout = exec(cmd);
    if (pout.find("error") != std::string::npos)
        throw std::runtime_error(pout);
    std::stringstream ss(pout);
    std::string line;
    ss >> line;
    char *res = new char[line.length() + 1];
    strcpy(res, line.c_str());
    return res;
}

char* send_raw_transaction(std::string rawTx){
    std::string rpc("sendrawtransaction ");
    rpc = base_cmd + mode + rpc + rawTx;
    const char* cmd = rpc.c_str();
    std::string pout = exec(cmd);
    if (pout.find("error") != std::string::npos)
        throw std::runtime_error(pout);
    std::stringstream ss(pout);
    std::string line;
    ss >> line;
    char *res = new char[line.length() + 1];
    strcpy(res, line.c_str());
    return res;
}

void bootstrapping(int block_count){
    MyEnclave_ecall_gen_new_pubkey(global_eid);
    for (int i = 0; i <= block_count; i++){
        char* hexedHeader = get_hexed_block(get_block_hash(i));
        printf("Block height: %d : ", i);
        MyEnclave_ecall_get_block(global_eid,hexedHeader);
    }
}

void scan_blockchain(){
    int block_count = get_block_count();
    bootstrapping(block_count);
    printf("Ctrl-C to escape\n");
    while (true){
        int best_block = get_block_count();
        for (int i = block_count+1; i <= best_block; i++){
            if (block_count != best_block){
                printf("Block height: %d : ", i);
            }
            char* hexedHeader = get_hexed_block(get_block_hash(i));
            MyEnclave_ecall_get_block(global_eid,hexedHeader);
        }
        block_count = best_block;
    }
}

void cmd_help(){
    std::cerr << "Usage in -regtest mode: " << std::endl;
    std::cerr << "Scan the transactions and mix the coins: ./app scan" << std::endl;
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[]){

#if defined(_MSC_VER)
    if (query_sgx_status() < 0) {
        /* either SGX is disabled, or a reboot is required to enable SGX */
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }
#endif 

    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }

    //printf("Create Enclave successfully !!! \n");
    int eret;
    sgx_status_t ret;
    ret = MyEnclave_ecall_set_communication_enclave_ids(global_eid, global_eid, vrfcert_eid);

    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }  

    ret = MyEnclave_ecall_set_enclave_id(global_eid, global_eid);

    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }
    switch(argc){
        case 2:
            if (strcmp(argv[1], "scan") == 0){
                scan_blockchain();
            }
            else{
                cmd_help();
            }
            break;
        default: cmd_help();
    }

    sgx_destroy_enclave(global_eid);
    return 0;
}