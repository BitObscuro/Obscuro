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

#ifndef _APP_H_
#define _APP_H_

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */

#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif

#ifndef STDIO_WRAPPER
// #define NULL 0
# define SGX_STDIN 1
# define SGX_STDOUT 2
# define SGX_STDERR 3
typedef int SGX_WRAPPER_FILE;
#endif

#if defined(_MSC_VER)
# define TOKEN_FILENAME   "Enclave.token"
# define ENCLAVE_FILENAME "Enclave.signed.dll"
#elif defined(__GNUC__)
# define TOKEN_FILENAME   "enclave.token"
# define ENCLAVE_FILENAME "MyEnclave.signed.so"
# define VRFCERT_ENCLAVE_FILENAME "vrfcert.signed.so"
#endif

extern sgx_enclave_id_t global_eid;    /* global enclave id */

#if defined(__cplusplus)
extern "C" {
#endif

void edger8r_array_attributes(void);
void edger8r_type_attributes(void);
void edger8r_pointer_attributes(void);
void edger8r_function_attributes(void);

void ecall_libc_functions(void);
void ecall_libcxx_functions(void);
void ecall_thread_functions(void);

#if defined(__cplusplus)
}
#endif

#endif /* !_APP_H_ */
