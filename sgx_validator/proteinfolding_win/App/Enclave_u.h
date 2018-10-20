#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "sgx_report.h"
#include "pouw_defs.h"
#include "blockchain.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif

sgx_status_t run(sgx_enclave_id_t eid, int* retval, pow_spec* work, difficulty_t* difficulty, block_hash_t* prev, sgx_target_info_t* quote_enc_info, sgx_report_t* report, output_t* output, char* enclave_ouput, int len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
