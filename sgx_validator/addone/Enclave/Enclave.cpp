#include "sgx_eid.h"
#include "Enclave_t.h"
#include "sgx_thread.h"
#include "sgx_dh.h"
#include "sgx_utils.h"
#include "stdio.h"
#include <string.h>

int addOne(int* num, sgx_target_info_t* qe_info, sgx_report_t* report, char* enclave_output, int len) {
    int ret = 0;

    snprintf(enclave_output, len, "%d", (*num + 1));     
    sgx_report_data_t report_data;

    memset(report_data.d, 0, sizeof(report_data.d));
    sgx_sha256_hash_t hash;
    uint8_t *hinfo = report_data.d;
    ret= sgx_sha256_msg((const uint8_t *) enclave_output, strlen(enclave_output),
                (sgx_sha256_hash_t *) &hash);
    if(SGX_SUCCESS != ret) {
        return ret;
    }
    memset(hinfo, 0, SGX_REPORT_DATA_SIZE);
    memcpy(hinfo, &hash, SGX_HASH_SIZE);

    memset(qe_info->reserved1, 0, sizeof (qe_info->reserved1));
    memset(qe_info->reserved2, 0, sizeof (qe_info->reserved2));
    ret = sgx_create_report (qe_info, &report_data, report);
    if (ret != SGX_SUCCESS) {
        return ret;
    }

    return *num + 1;
}
