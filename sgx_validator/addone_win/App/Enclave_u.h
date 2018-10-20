#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "sgx_report.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


sgx_status_t addOne(sgx_enclave_id_t eid, int* retval, int* num, sgx_target_info_t* quote_enc_info, sgx_report_t* report, char* enclave_output, int len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
