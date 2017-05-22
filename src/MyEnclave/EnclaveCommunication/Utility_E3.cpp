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
#include "sgx_eid.h"
#include "EnclaveMessageExchange.h"
#include "error_codes.h"
#include "Utility_E3.h"
#include "../MyEnclave.h"
#include "MyEnclave_t.h"
#include "../user_types.h"
#include "stdlib.h"
#include "string.h"

uint32_t marshal_input_parameters_e1_verfycert(uint32_t target_fn_id, uint32_t msg_type, verify_cert_param_struct_t *p_struct_var, size_t len_data, char** marshalled_buff, size_t* marshalled_buff_len)
{
    ms_in_msg_exchange_t *ms;
    size_t param_len, ms_len;
    char *temp_buff;
    uint8_t * addr;
    char* struct_data;   
    if(!p_struct_var || !marshalled_buff_len)
        return INVALID_PARAMETER_ERROR;  
    struct_data = (char*)p_struct_var;
    temp_buff = (char*)malloc(sizeof(uint32_t) + len_data);     
    if(!temp_buff)
        return MALLOC_ERROR;
    memcpy(temp_buff, struct_data, sizeof(uint32_t));
    addr = p_struct_var->data;
    memcpy(temp_buff + sizeof(uint32_t), addr, len_data);
    param_len = len_data + sizeof(uint32_t);
    ms_len = sizeof(ms_in_msg_exchange_t) + param_len;
    ms = (ms_in_msg_exchange_t *)malloc(ms_len);
    if(!ms)
    {
        SAFE_FREE(temp_buff);
        return MALLOC_ERROR;
    }
    ms->msg_type = msg_type;
    ms->target_fn_id = target_fn_id;
    ms->inparam_buff_len = (uint32_t)param_len;
    memcpy(&ms->inparam_buff, temp_buff, param_len);
    *marshalled_buff = (char*)ms;
    *marshalled_buff_len = ms_len;

    SAFE_FREE(temp_buff);
    return SUCCESS;
}

uint32_t marshal_input_parameters_e1_foo1(uint32_t target_fn_id, uint32_t msg_type, external_param_struct_t *p_struct_var, size_t len_data, size_t len_ptr_data, char** marshalled_buff, size_t* marshalled_buff_len)
{
    ms_in_msg_exchange_t *ms;
    size_t param_len, ms_len;
    char *temp_buff;
    int* addr;
    char* struct_data;
    if(!p_struct_var || !marshalled_buff_len)
        return INVALID_PARAMETER_ERROR;    
    struct_data = (char*)p_struct_var;
    temp_buff = (char*)malloc(len_data + len_ptr_data);
    if(!temp_buff)
        return MALLOC_ERROR;
    memcpy(temp_buff, struct_data, len_data);
    addr = *(int **)(struct_data + len_data);
    memcpy(temp_buff + len_data, addr, len_ptr_data); //can be optimized
    param_len = len_data + len_ptr_data;
    ms_len =  sizeof(ms_in_msg_exchange_t) + param_len;
    ms = (ms_in_msg_exchange_t *)malloc(ms_len);
    if(!ms)
    {
        SAFE_FREE(temp_buff);
        return MALLOC_ERROR;
    }
    ms->msg_type = msg_type;
    ms->target_fn_id = target_fn_id;
    ms->inparam_buff_len = (uint32_t)param_len;
    memcpy(&ms->inparam_buff, temp_buff, param_len);
    *marshalled_buff = (char*)ms;
    *marshalled_buff_len = ms_len;
        
    SAFE_FREE(temp_buff);
    return SUCCESS;
}

uint32_t marshal_retval_and_output_parameters_e3_verify(char** resp_buffer, size_t* resp_length, uint32_t retval, param_struct_t *p_struct_var)
{
    ms_out_msg_exchange_t *ms;
    size_t ret_param_len, ms_len;
    char *temp_buff;
    size_t retval_len;
    if(!resp_length || !p_struct_var)
        return INVALID_PARAMETER_ERROR;    
    retval_len = sizeof(retval);
    ret_param_len = sizeof(retval) + sizeof(param_struct_t);
    temp_buff = (char*)malloc(ret_param_len);
    if(!temp_buff)
        return MALLOC_ERROR;
    memcpy(temp_buff, &retval, sizeof(retval)); 
    memcpy(temp_buff + sizeof(retval), p_struct_var, sizeof(param_struct_t));
    ms_len = sizeof(ms_out_msg_exchange_t) + ret_param_len;
    ms = (ms_out_msg_exchange_t *)malloc(ms_len);
    if(!ms)
    {
        SAFE_FREE(temp_buff);
        return MALLOC_ERROR;
    }
    ms->retval_len = (uint32_t)retval_len;
    ms->ret_outparam_buff_len = (uint32_t)ret_param_len;
    memcpy(&ms->ret_outparam_buff, temp_buff, ret_param_len);
    *resp_buffer = (char*)ms;
    *resp_length = ms_len;
    SAFE_FREE(temp_buff);
    return SUCCESS;
}

uint32_t marshal_retval_and_output_parameters_e3_foo1(char** resp_buffer, size_t* resp_length, uint32_t retval, param_struct_t *p_struct_var)
{
    ms_out_msg_exchange_t *ms;
    size_t ret_param_len, ms_len;
    char *temp_buff;
    size_t retval_len;
    if(!resp_length || !p_struct_var)
        return INVALID_PARAMETER_ERROR;    
    retval_len = sizeof(retval);
    ret_param_len = sizeof(retval) + sizeof(param_struct_t);
    temp_buff = (char*)malloc(ret_param_len);
    if(!temp_buff)
        return MALLOC_ERROR;
    memcpy(temp_buff, &retval, sizeof(retval)); 
    memcpy(temp_buff + sizeof(retval), p_struct_var, sizeof(param_struct_t));
    ms_len = sizeof(ms_out_msg_exchange_t) + ret_param_len;
    ms = (ms_out_msg_exchange_t *)malloc(ms_len);
    if(!ms)
    {
        SAFE_FREE(temp_buff);
        return MALLOC_ERROR;
    }
    ms->retval_len = (uint32_t)retval_len;
    ms->ret_outparam_buff_len = (uint32_t)ret_param_len;
    memcpy(&ms->ret_outparam_buff, temp_buff, ret_param_len);
    *resp_buffer = (char*)ms;
    *resp_length = ms_len;
    SAFE_FREE(temp_buff);
    return SUCCESS;
}

uint32_t unmarshal_input_parameters_e3_foo1(param_struct_t *pstruct, ms_in_msg_exchange_t* ms)
{
    char* buff;
    size_t len;
    if(!pstruct || !ms)
        return INVALID_PARAMETER_ERROR;    
    buff = ms->inparam_buff;
    len = ms->inparam_buff_len;

    if(len != (sizeof(pstruct->var1) + sizeof(pstruct->var2)))
        return ATTESTATION_ERROR;

    memcpy(&pstruct->var1, buff, sizeof(pstruct->var1));
    memcpy(&pstruct->var2, buff + sizeof(pstruct->var1), sizeof(pstruct->var2)); 

    return SUCCESS;
}


uint32_t unmarshal_retval_and_output_parameters_e1_verify(char* out_buff, verify_cert_param_struct_t *p_struct_var, uint32_t* retval)
{
    size_t retval_len;
    ms_out_msg_exchange_t *ms;
    if(!out_buff || !p_struct_var)
        return INVALID_PARAMETER_ERROR;    
    ms = (ms_out_msg_exchange_t *)out_buff;
    retval_len = ms->retval_len;
    memcpy(retval, ms->ret_outparam_buff, retval_len);
    memcpy(&p_struct_var->len_data, (ms->ret_outparam_buff) + retval_len, sizeof(uint32_t));
    p_struct_var->data = (uint8_t*)malloc(p_struct_var->len_data);
    if(!p_struct_var->data)
    {
        return MALLOC_ERROR;
    }
    memcpy(p_struct_var->data, (ms->ret_outparam_buff) + retval_len + sizeof(p_struct_var->len_data), p_struct_var->len_data);
    return SUCCESS;
}


uint32_t unmarshal_retval_and_output_parameters_e1_foo1(char* out_buff, external_param_struct_t *p_struct_var, char** retval)
{
    size_t retval_len;
    ms_out_msg_exchange_t *ms;
    if(!out_buff || !p_struct_var)
        return INVALID_PARAMETER_ERROR;    
    ms = (ms_out_msg_exchange_t *)out_buff;
    retval_len = ms->retval_len;
    *retval = (char*)malloc(retval_len);
    if(!*retval)
    {
        return MALLOC_ERROR;
    }
    memcpy(*retval, ms->ret_outparam_buff, retval_len);
    memcpy(&p_struct_var->var1, (ms->ret_outparam_buff) + retval_len, sizeof(p_struct_var->var1));
    memcpy(&p_struct_var->var2, (ms->ret_outparam_buff) + retval_len + sizeof(p_struct_var->var1), sizeof(p_struct_var->var2));
    memcpy(&p_struct_var->p_internal_struct->ivar1, (ms->ret_outparam_buff) + retval_len + sizeof(p_struct_var->var1)+ sizeof(p_struct_var->var2), sizeof(p_struct_var->p_internal_struct->ivar1));
    memcpy(&p_struct_var->p_internal_struct->ivar2, (ms->ret_outparam_buff) + retval_len + sizeof(p_struct_var->var1)+ sizeof(p_struct_var->var2) + sizeof(p_struct_var->p_internal_struct->ivar1), sizeof(p_struct_var->p_internal_struct->ivar2));
    return SUCCESS;
}


uint32_t marshal_message_exchange_request(uint32_t target_fn_id, uint32_t msg_type, uint32_t secret_data, char** marshalled_buff, size_t* marshalled_buff_len)
{
    ms_in_msg_exchange_t *ms;
    size_t secret_data_len, ms_len;
    if(!marshalled_buff_len)
        return INVALID_PARAMETER_ERROR;            
    secret_data_len = sizeof(secret_data);
    ms_len = sizeof(ms_in_msg_exchange_t) + secret_data_len;
    ms = (ms_in_msg_exchange_t *)malloc(ms_len);
    if(!ms)
        return MALLOC_ERROR;

    ms->msg_type = msg_type;
    ms->target_fn_id = target_fn_id;
    ms->inparam_buff_len = (uint32_t)secret_data_len;
    memcpy(&ms->inparam_buff, &secret_data, secret_data_len);

    *marshalled_buff = (char*)ms;
    *marshalled_buff_len = ms_len;
    return SUCCESS;
}

uint32_t umarshal_message_exchange_request(uint32_t* inp_secret_data, ms_in_msg_exchange_t* ms)
{
    char* buff;
    size_t len;
    if(!inp_secret_data || !ms)
        return INVALID_PARAMETER_ERROR;    
    buff = ms->inparam_buff;
    len = ms->inparam_buff_len;

    if(len != sizeof(uint32_t))
        return ATTESTATION_ERROR;

    memcpy(inp_secret_data, buff, sizeof(uint32_t));

    return SUCCESS;
}

uint32_t marshal_message_exchange_response(char** resp_buffer, size_t* resp_length, uint32_t secret_response)
{
    ms_out_msg_exchange_t *ms;
    size_t secret_response_len, ms_len;
    size_t retval_len, ret_param_len;
    if(!resp_length)
        return INVALID_PARAMETER_ERROR;    
    secret_response_len = sizeof(secret_response);
    retval_len = secret_response_len;
    ret_param_len = secret_response_len;
    ms_len = sizeof(ms_out_msg_exchange_t) + ret_param_len;
    ms = (ms_out_msg_exchange_t *)malloc(ms_len);
    if(!ms)
        return MALLOC_ERROR;
    ms->retval_len = (uint32_t)retval_len;
    ms->ret_outparam_buff_len = (uint32_t)ret_param_len;
    memcpy(&ms->ret_outparam_buff, &secret_response, secret_response_len);
    *resp_buffer = (char*)ms;
    *resp_length = ms_len;
     return SUCCESS;
}

uint32_t umarshal_message_exchange_response(char* out_buff, char** secret_response)
{
    size_t retval_len;
    ms_out_msg_exchange_t *ms;
    if(!out_buff)
        return INVALID_PARAMETER_ERROR;    
    ms = (ms_out_msg_exchange_t *)out_buff;
    retval_len = ms->retval_len;
    *secret_response = (char*)malloc(retval_len);
    if(!*secret_response)
    {
        return MALLOC_ERROR;
    }
    memcpy(*secret_response, ms->ret_outparam_buff, retval_len);
    return SUCCESS;
}

