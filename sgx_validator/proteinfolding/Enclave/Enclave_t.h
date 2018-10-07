#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_report.h"
#include "pouw_defs.h"
#include "blockchain.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int run(pow_spec* work, difficulty_t* difficulty, block_hash_t* prev, sgx_target_info_t* quote_enc_info, sgx_report_t* report, output_t* output, char* enclave_ouput, int len);
void protain_folding(void);

sgx_status_t SGX_CDECL ocall_print_string(int* retval, const char* str);
sgx_status_t SGX_CDECL rdtsc(unsigned long long* retval);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
