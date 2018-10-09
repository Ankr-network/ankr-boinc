#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_addOne_t {
	int ms_retval;
	int* ms_num;
	sgx_target_info_t* ms_quote_enc_info;
	sgx_report_t* ms_report;
	char* ms_enclave_output;
	int ms_len;
} ms_addOne_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	0,
	{ NULL },
};
sgx_status_t addOne(sgx_enclave_id_t eid, int* retval, int* num, sgx_target_info_t* quote_enc_info, sgx_report_t* report, char* enclave_output, int len)
{
	sgx_status_t status;
	ms_addOne_t ms;
	ms.ms_num = num;
	ms.ms_quote_enc_info = quote_enc_info;
	ms.ms_report = report;
	ms.ms_enclave_output = enclave_output;
	ms.ms_len = len;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

