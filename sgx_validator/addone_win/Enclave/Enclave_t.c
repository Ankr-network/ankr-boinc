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


typedef struct ms_addOne_t {
	int ms_retval;
	int* ms_num;
	sgx_target_info_t* ms_quote_enc_info;
	sgx_report_t* ms_report;
	char* ms_enclave_output;
	int ms_len;
} ms_addOne_t;

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#pragma warning(disable: 4200)
#endif

static sgx_status_t SGX_CDECL sgx_addOne(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_addOne_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_addOne_t* ms = SGX_CAST(ms_addOne_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_num = ms->ms_num;
	size_t _len_num = sizeof(int);
	int* _in_num = NULL;
	sgx_target_info_t* _tmp_quote_enc_info = ms->ms_quote_enc_info;
	size_t _len_quote_enc_info = sizeof(sgx_target_info_t);
	sgx_target_info_t* _in_quote_enc_info = NULL;
	sgx_report_t* _tmp_report = ms->ms_report;
	size_t _len_report = sizeof(sgx_report_t);
	sgx_report_t* _in_report = NULL;
	char* _tmp_enclave_output = ms->ms_enclave_output;
	int _tmp_len = ms->ms_len;
	size_t _len_enclave_output = _tmp_len;
	char* _in_enclave_output = NULL;

	CHECK_UNIQUE_POINTER(_tmp_num, _len_num);
	CHECK_UNIQUE_POINTER(_tmp_quote_enc_info, _len_quote_enc_info);
	CHECK_UNIQUE_POINTER(_tmp_report, _len_report);
	CHECK_UNIQUE_POINTER(_tmp_enclave_output, _len_enclave_output);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_num != NULL && _len_num != 0) {
		_in_num = (int*)malloc(_len_num);
		if (_in_num == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_num, _len_num, _tmp_num, _len_num)) {
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
	if (_tmp_enclave_output != NULL && _len_enclave_output != 0) {
		_in_enclave_output = (char*)malloc(_len_enclave_output);
		if (_in_enclave_output == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_enclave_output, _len_enclave_output, _tmp_enclave_output, _len_enclave_output)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = addOne(_in_num, _in_quote_enc_info, _in_report, _in_enclave_output, _tmp_len);
err:
	if (_in_num) free(_in_num);
	if (_in_quote_enc_info) free(_in_quote_enc_info);
	if (_in_report) {
		if (memcpy_s(_tmp_report, _len_report, _in_report, _len_report)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_report);
	}
	if (_in_enclave_output) {
		if (memcpy_s(_tmp_enclave_output, _len_enclave_output, _in_enclave_output, _len_enclave_output)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_enclave_output);
	}

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv;} ecall_table[1];
} g_ecall_table = {
	1,
	{
		{(void*)(uintptr_t)sgx_addOne, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table = {
	0,
};


#ifdef _MSC_VER
#pragma warning(pop)
#endif
