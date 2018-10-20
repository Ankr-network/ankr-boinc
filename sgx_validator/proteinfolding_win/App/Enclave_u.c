#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_run_t {
	int ms_retval;
	pow_spec* ms_work;
	difficulty_t* ms_difficulty;
	block_hash_t* ms_prev;
	sgx_target_info_t* ms_quote_enc_info;
	sgx_report_t* ms_report;
	output_t* ms_output;
	char* ms_enclave_ouput;
	int ms_len;
} ms_run_t;

typedef struct ms_ocall_print_string_t {
	int ms_retval;
	const char* ms_str;
} ms_ocall_print_string_t;

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ms->ms_retval = ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[1];
} ocall_table_Enclave = {
	1,
	{
		(void*)(uintptr_t)Enclave_ocall_print_string,
	}
};

sgx_status_t run(sgx_enclave_id_t eid, int* retval, pow_spec* work, difficulty_t* difficulty, block_hash_t* prev, sgx_target_info_t* quote_enc_info, sgx_report_t* report, output_t* output, char* enclave_ouput, int len)
{
	sgx_status_t status;
	ms_run_t ms;
	ms.ms_work = work;
	ms.ms_difficulty = difficulty;
	ms.ms_prev = prev;
	ms.ms_quote_enc_info = quote_enc_info;
	ms.ms_report = report;
	ms.ms_output = output;
	ms.ms_enclave_ouput = enclave_ouput;
	ms.ms_len = len;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

