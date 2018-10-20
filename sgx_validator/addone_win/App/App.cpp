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

#include <stdio.h>
#include <string.h>
#include <assert.h>

#ifdef _MSC_VER
# include <Shlobj.h>
#else
# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX
#endif

#include "sgx_urts.h"
#include "sgx_uae_service.h"
#include "App.h"
#include "Enclave_u.h"

#include <stdio.h>
#include <iostream>
#include "Enclave_u.h"
#include "sgx_urts.h"
#include "sgx_utils.h"
#include "sgx_uae_service.h"
#include <fstream>
#include "boinc_api.h"

using namespace std;
/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;
int initialize_enclave(const char* enclave_name, sgx_enclave_id_t* eid);
void print_error_message(sgx_status_t ret);

uint8_t SPID_FANZ[16] = {
		0x34, 0x15, 0xA2, 0x39,
		0xC3, 0xB6, 0x8E, 0xF6,
		0x6E, 0xAD, 0x98, 0xB1,
		0xA2, 0xD0, 0x1E, 0x2A,
};

static const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";
std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) {
	std::string ret;
	int i = 0;
	int j = 0;
	unsigned char char_array_3[3];
	unsigned char char_array_4[4];

	while (in_len--) {
		char_array_3[i++] = *(bytes_to_encode++);
		if (i == 3) {
			char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
			char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
			char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
			char_array_4[3] = char_array_3[2] & 0x3f;

			for (i = 0; (i < 4); i++)
				ret += base64_chars[char_array_4[i]];
			i = 0;
		}
	}

	if (i)
	{
		for (j = i; j < 3; j++)
			char_array_3[j] = '\0';

		char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
		char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
		char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
		char_array_4[3] = char_array_3[2] & 0x3f;

		for (j = 0; (j < i + 1); j++)
			ret += base64_chars[char_array_4[j]];

		while ((i++ < 3))
			ret += '=';

	}

	return ret;

}

//int exists(const char *fname)
//{
	//return 1;
	///
	///FILE *file;
	///if ((file = fopen(fname, "r")))
	///{
	///	fclose(file);
	///	return 1;
	///}
	//return 0;
//}


//int main(int argc, char const *argv[]) {
int SGX_CDECL main(int argc, char *argv[]) {
	
	string enclave_path;
	enclave_path = "Enclave.signed.dll"; 
	///if (!exists(enclave_path.c_str())) {
	///	std::cerr << enclave_path << " is not a file" << endl;
	///}

	boinc_init();
	char e_path[512];
	
	boinc_resolve_filename(enclave_path.c_str(), e_path, sizeof(e_path));
	///if (initialize_enclave(e_path, &global_eid) != 0) {
	if (initialize_enclave(enclave_path.c_str(), &global_eid) != 0) {
		std::cout << "Fail to initialize enclave." << std::endl;
		return 1;
	}
	
	int ret;
	sgx_target_info_t quote_enc_info;
	sgx_epid_group_id_t p_gid;
	sgx_report_t report;

	ret = sgx_init_quote(&quote_enc_info, &p_gid);
	if (ret != SGX_SUCCESS) {
		print_error_message((sgx_status_t)ret);
		return -1;
	}
	
	int num = 0;
	char enclave_output[4096] = { 0 };
	sgx_status_t status = addOne(global_eid, &ret, &num,
		&quote_enc_info, &report,
		enclave_output, 4096);
	if (status != SGX_SUCCESS) {
		std::cout << "FAILURE!!!" << status << std::endl;
	}
	
	sgx_spid_t spid;
	memcpy(spid.id, SPID_FANZ, 16);

	uint32_t quote_size;
	quote_size = 0;
	printf("size:%d\n", quote_size);
	ret = sgx_get_quote_size(NULL, &quote_size);
	printf("size:%d\n", quote_size);
	if (ret != SGX_SUCCESS) {
		return -1;
	}
	
	sgx_quote_t *quote = (sgx_quote_t *)malloc(quote_size);
	if (!quote) {
		return -1;
	}

	ret = sgx_get_quote(&report, SGX_UNLINKABLE_SIGNATURE, &spid, NULL, NULL, 0, NULL, quote, quote_size);
	if (ret != SGX_SUCCESS) {
		return -1;
	}
	
	std::string ostr;
    std::string base64_quote_str;
	base64_quote_str = base64_encode((const unsigned char*)quote, quote_size);
	ostr += (const char *)base64_quote_str.c_str();
	ostr += "\n";
	ostr += enclave_output;

	char output_path[512] = "out";
	ofstream outputfile;
	boinc_resolve_filename("out", output_path, sizeof(output_path));
	outputfile.open(output_path);
	///outputfile << ostr;
	outputfile.write(ostr.c_str(), strlen(ostr.c_str()));
	outputfile.close();
	
	printf("The quote and computing result is saved to out file.\n");
	boinc_finish(0);

	if (SGX_SUCCESS != sgx_destroy_enclave(global_eid))
		return -1;

	return 0;
}
