/*
 *   Copyright(C) 2011-2018 Intel Corporation All Rights Reserved.
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
 *
 */

#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */


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
	ret = sgx_sha256_msg((const uint8_t *)enclave_output, strlen(enclave_output),
		(sgx_sha256_hash_t *)&hash);
	if (SGX_SUCCESS != ret) {
		return ret;
	}
	memset(hinfo, 0, SGX_REPORT_DATA_SIZE);
	memcpy(hinfo, &hash, SGX_HASH_SIZE);

	memset(qe_info->reserved1, 0, sizeof(qe_info->reserved1));
	memset(qe_info->reserved2, 0, sizeof(qe_info->reserved2));
	ret = sgx_create_report(qe_info, &report_data, report);
	if (ret != SGX_SUCCESS) {
		return ret;
	}

	return *num + 1;
}
