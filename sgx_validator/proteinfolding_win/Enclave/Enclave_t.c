#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


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

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#pragma warning(disable: 4200)
#endif

static sgx_status_t SGX_CDECL sgx_run(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_run_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_run_t* ms = SGX_CAST(ms_run_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	pow_spec* _tmp_work = ms->ms_work;
	size_t _len_work = sizeof(pow_spec);
	pow_spec* _in_work = NULL;
	difficulty_t* _tmp_difficulty = ms->ms_difficulty;
	size_t _len_difficulty = sizeof(difficulty_t);
	difficulty_t* _in_difficulty = NULL;
	block_hash_t* _tmp_prev = ms->ms_prev;
	size_t _len_prev = sizeof(block_hash_t);
	block_hash_t* _in_prev = NULL;
	sgx_target_info_t* _tmp_quote_enc_info = ms->ms_quote_enc_info;
	size_t _len_quote_enc_info = sizeof(sgx_target_info_t);
	sgx_target_info_t* _in_quote_enc_info = NULL;
	sgx_report_t* _tmp_report = ms->ms_report;
	size_t _len_report = sizeof(sgx_report_t);
	sgx_report_t* _in_report = NULL;
	output_t* _tmp_output = ms->ms_output;
	size_t _len_output = sizeof(output_t);
	output_t* _in_output = NULL;
	char* _tmp_enclave_ouput = ms->ms_enclave_ouput;
	int _tmp_len = ms->ms_len;
	size_t _len_enclave_ouput = _tmp_len;
	char* _in_enclave_ouput = NULL;

	CHECK_UNIQUE_POINTER(_tmp_work, _len_work);
	CHECK_UNIQUE_POINTER(_tmp_difficulty, _len_difficulty);
	CHECK_UNIQUE_POINTER(_tmp_prev, _len_prev);
	CHECK_UNIQUE_POINTER(_tmp_quote_enc_info, _len_quote_enc_info);
	CHECK_UNIQUE_POINTER(_tmp_report, _len_report);
	CHECK_UNIQUE_POINTER(_tmp_output, _len_output);
	CHECK_UNIQUE_POINTER(_tmp_enclave_ouput, _len_enclave_ouput);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_work != NULL && _len_work != 0) {
		_in_work = (pow_spec*)malloc(_len_work);
		if (_in_work == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_work, _len_work, _tmp_work, _len_work)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_difficulty != NULL && _len_difficulty != 0) {
		_in_difficulty = (difficulty_t*)malloc(_len_difficulty);
		if (_in_difficulty == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_difficulty, _len_difficulty, _tmp_difficulty, _len_difficulty)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_prev != NULL && _len_prev != 0) {
		_in_prev = (block_hash_t*)malloc(_len_prev);
		if (_in_prev == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_prev, _len_prev, _tmp_prev, _len_prev)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_quote_enc_info != NULL && _len_quote_enc_info != 0) {
		_in_quote_enc_info = (sgx_target_info_t*)malloc(_len_quote_enc_info);
		if (_in_quote_enc_info == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_quote_enc_info, _len_quote_enc_info, _tmp_quote_enc_info, _len_quote_enc_info)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_report != NULL && _len_report != 0) {
		if ((_in_report = (sgx_report_t*)malloc(_len_report)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_report, 0, _len_report);
	}
	if (_tmp_output != NULL && _len_output != 0) {
		if ((_in_output = (output_t*)malloc(_len_output)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_output, 0, _len_output);
	}
	if (_tmp_enclave_ouput != NULL && _len_enclave_ouput != 0) {
		_in_enclave_ouput = (char*)malloc(_len_enclave_ouput);
		if (_in_enclave_ouput == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_enclave_ouput, _len_enclave_ouput, _tmp_enclave_ouput, _len_enclave_ouput)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = run(_in_work, _in_difficulty, _in_prev, _in_quote_enc_info, _in_report, _in_output, _in_enclave_ouput, _tmp_len);
err:
	if (_in_work) free(_in_work);
	if (_in_difficulty) free(_in_difficulty);
	if (_in_prev) free(_in_prev);
	if (_in_quote_enc_info) free(_in_quote_enc_info);
	if (_in_report) {
		if (memcpy_s(_tmp_report, _len_report, _in_report, _len_report)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_report);
	}
	if (_in_output) {
		if (memcpy_s(_tmp_output, _len_output, _in_output, _len_output)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_output);
	}
	if (_in_enclave_ouput) {
		if (memcpy_s(_tmp_enclave_ouput, _len_enclave_ouput, _in_enclave_ouput, _len_enclave_ouput)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_enclave_ouput);
	}

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv;} ecall_table[1];
} g_ecall_table = {
	1,
	{
		{(void*)(uintptr_t)sgx_run, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[1][1];
} g_dyn_entry_table = {
	1,
	{
		{0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(int* retval, const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	ocalloc_size += (str != NULL) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
