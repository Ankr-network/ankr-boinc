#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_report.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int addOne(int* num, sgx_target_info_t* quote_enc_info, sgx_report_t* report, char* enclave_output, int len);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
