/*

Copyright 2018 Intel Corporation

This software and the related documents are Intel copyrighted materials,
and your use of them is governed by the express license under which they
were provided to you (License). Unless the License provides otherwise,
you may not use, modify, copy, publish, distribute, disclose or transmit
this software or the related documents without Intel's prior written
permission.

This software and the related documents are provided as is, with no
express or implied warranties, other than those that are expressly stated
in the License.

*/


using namespace std;

#ifdef _WIN32
#pragma comment(lib, "crypt32.lib")
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#else
#include "config.h"
#endif

#ifdef _WIN32
// *sigh*
# include "vs/client/Enclave_u.h"
#else
# include "Enclave_u.h"
#endif
#if !defined(SGX_HW_SIM)&&!defined(_WIN32)
#include "sgx_stub.h"
#endif
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <time.h>
#include <sgx_urts.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <intrin.h>
#include <wincrypt.h>
#include "win32/getopt.h"
#else
#include <openssl/evp.h>
#include <getopt.h>
#include <unistd.h>
#endif
#include <sgx_uae_service.h>
#include <sgx_ukey_exchange.h>
#include <string>
#include "common.h"
#include "protocol.h"
#include "sgx_detect.h"
#include "hexutil.h"
#include "fileio.h"
#include "base64.h"
#include "crypto.h"
#include "msgio.h"
#include "logfile.h"
#include "quote_size.h"

#define MAX_LEN 80

#ifdef _WIN32
# define strdup(x) _strdup(x)
#else
# define _rdrand64_step(x) ({ unsigned char err; asm volatile("rdrand %0; setc %1":"=r"(*x), "=qm"(err)); err; })
#endif

#ifdef __x86_64__
#define DEF_LIB_SEARCHPATH "/lib:/lib64:/usr/lib:/usr/lib64"
#else
#define DEF_LIB_SEARCHPATH "/lib:/usr/lib"
#endif

typedef struct config_struct {
	char mode;
	uint32_t flags;
	sgx_spid_t spid;
	sgx_ec256_public_t pubkey;
	sgx_quote_nonce_t nonce;
	char *server;
	char *port;
} config_t;

int file_in_searchpath (const char *file, const char *search, char *fullpath,
	size_t len);

sgx_status_t sgx_create_enclave_search (
	const char *filename,
	const int edebug,
	sgx_launch_token_t *token,
	int *updated,
	sgx_enclave_id_t *eid,
	sgx_misc_attribute_t *attr
);

char* do_quote(sgx_enclave_id_t eid, config_t *config);


char debug= 0;
char verbose= 0;

#define MODE_ATTEST 0x0
#define MODE_EPID 	0x1
#define MODE_QUOTE	0x2

#define OPT_PSE		0x01
#define OPT_NONCE	0x02
#define OPT_LINK	0x04
#define OPT_PUBKEY	0x08

/* Macros to set, clear, and get the mode and options */

#define SET_OPT(x,y)	x|=y
#define CLEAR_OPT(x,y)	x=x&~y
#define OPT_ISSET(x,y)	x&y

#ifdef _WIN32
# define ENCLAVE_NAME "Enclave.signed.dll"
#else
# define ENCLAVE_NAME "Enclave.signed.so"
#endif

char* get_quote (char* spid)
{
	config_t config;
	sgx_launch_token_t token= { 0 };
	sgx_status_t status;
	sgx_enclave_id_t eid= 0;
	int updated= 0;







	memset(&config, 0, sizeof(config));




 //char* spid = "3415A239C3B68EF66EAD98B1A2D01E2A";

			if ( ! from_hexstring((unsigned char *) &config.spid, spid, 16) ) {

				fprintf(stderr, "SPID must be 32-byte hex string\n");
				exit(1);
			}



	/* Can we run SGX? */


	/* Launch the enclave */
    status = sgx_create_enclave_search(ENCLAVE_NAME, SGX_DEBUG_FLAG, &token, &updated, &eid, 0);
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_create_enclave error");
	}

	/* Are we attesting, or just spitting out a quote? */

		return do_quote(eid, &config);

}

/*----------------------------------------------------------------------
 * do_quote()
 *
 * Generate a quote from the enclave.
 *----------------------------------------------------------------------
 * WARNING!
 *
 * DO NOT USE THIS SUBROUTINE AS A TEMPLATE FOR IMPLEMENTING REMOTE
 * ATTESTATION. do_quote() short-circuits the RA process in order
 * to generate an enclave quote directly!
 *
 * The high-level functions provided for remote attestation take
 * care of the low-level details of quote generation for you:
 *
 *   sgx_ra_init()
 *   sgx_ra_get_msg1
 *   sgx_ra_proc_msg2
 *
 * End developers should not normally be calling these functions
 * directly when doing remote attestation:
 *
 *    sgx_get_ps_sec_prop()
 *    sgx_get_quote()
 *    sgx_get_quote_size()
 *    sgx_calc_quote_size()
 *    sgx_get_report()
 *    sgx_init_quote()
 *
 *----------------------------------------------------------------------
 */

char* do_quote(sgx_enclave_id_t eid, config_t *config)
{
	sgx_status_t status, sgxrv;
	sgx_quote_t *quote;
	sgx_report_t report;
	sgx_report_t qe_report;
	sgx_target_info_t target_info;
	sgx_epid_group_id_t epid_gid;
	uint32_t sz= 0;
	uint32_t flags= config->flags;
	sgx_quote_sign_type_t linkable= SGX_UNLINKABLE_SIGNATURE;
	sgx_ps_cap_t ps_cap;
	char *pse_manifest = NULL;
	size_t pse_manifest_sz;
	char  *b64quote= NULL;
	char *b64manifest = NULL;


	/* Platform services info */
	if (OPT_ISSET(flags, OPT_PSE)) {
		status = sgx_get_ps_cap(&ps_cap);
		if (status != SGX_SUCCESS) {
			fprintf(stderr, "sgx_get_ps_cap: %08x\n", status);
			//return NULL;
		}

		status = get_pse_manifest_size(eid, &pse_manifest_sz);
		if (status != SGX_SUCCESS) {
			fprintf(stderr, "get_pse_manifest_size: %08x\n",
				status);
			//return 1;
		}

		pse_manifest = (char *) malloc(pse_manifest_sz);

		status = get_pse_manifest(eid, &sgxrv, pse_manifest, pse_manifest_sz);
		if (status != SGX_SUCCESS) {
			fprintf(stderr, "get_pse_manifest: %08x\n",
				status);
			//return 1;
		}
		if (sgxrv != SGX_SUCCESS) {
			fprintf(stderr, "get_sec_prop_desc_ex: %08x\n",
				sgxrv);
			//return 1;
		}
	}

	/* Get our quote */

	memset(&report, 0, sizeof(report));

	status= sgx_init_quote(&target_info, &epid_gid);
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_init_quote: %08x\n", status);
		//return 1;
	}



	status= get_report(eid, &sgxrv, &report, &target_info);
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "get_report: %08x\n", status);
		//return 1;
	}
	if ( sgxrv != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_create_report: %08x\n", sgxrv);
		//return 1;
	}

	// sgx_get_quote_size() has been deprecated, but our PSW may be too old
	// so use a wrapper function.

	if (! get_quote_size(&status, &sz)) {
		fprintf(stderr, "PSW missing sgx_get_quote_size() and sgx_calc_quote_size()\n");
		//return 1;
	}
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "SGX error while getting quote size: %08x\n", status);
		//return 1;
	}

	quote= (sgx_quote_t *) malloc(sz);
	if ( quote == NULL ) {
		fprintf(stderr, "out of memory\n");
		//return 1;
	}

	memset(quote, 0, sz);
	status= sgx_get_quote(&report, linkable, &config->spid,
		(OPT_ISSET(flags, OPT_NONCE)) ? &config->nonce : NULL,
		NULL, 0,
		(OPT_ISSET(flags, OPT_NONCE)) ? &qe_report : NULL,
		quote, sz);
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_get_quote: %08x\n", status);
		//return 1;
	}

	/* Print our quote */


	b64quote= base64_encode((char *) quote, sz);



	printf("{\n");
	printf("\"isvEnclaveQuote\":\"%s\"", b64quote);

	return b64quote;

}

/*
 * Search for the enclave file and then try and load it.
 */

sgx_status_t sgx_create_enclave_search (const char *filename, const int edebug,
	sgx_launch_token_t *token, int *updated, sgx_enclave_id_t *eid,
	sgx_misc_attribute_t *attr)
{
	struct stat sb;
	char epath[PATH_MAX];	/* includes NULL */

	/* Is filename an absolute path? */

	if ( filename[0] == '/' )
		return sgx_create_enclave(filename, edebug, token, updated, eid, attr);

	/* Is the enclave in the current working directory? */

	if ( stat(filename, &sb) == 0 )
		return sgx_create_enclave(filename, edebug, token, updated, eid, attr);

	/* Search the paths in LD_LBRARY_PATH */

	if ( file_in_searchpath(filename, getenv("LD_LIBRARY_PATH"), epath, PATH_MAX) )
		return sgx_create_enclave(epath, edebug, token, updated, eid, attr);

	/* Search the paths in DT_RUNPATH */

	if ( file_in_searchpath(filename, getenv("DT_RUNPATH"), epath, PATH_MAX) )
		return sgx_create_enclave(epath, edebug, token, updated, eid, attr);

	/* Standard system library paths */

	if ( file_in_searchpath(filename, DEF_LIB_SEARCHPATH, epath, PATH_MAX) )
		return sgx_create_enclave(epath, edebug, token, updated, eid, attr);

	/*
	 * If we've made it this far then we don't know where else to look.
	 * Just call sgx_create_enclave() which assumes the enclave is in
	 * the current working directory. This is almost guaranteed to fail,
	 * but it will insure we are consistent about the error codes that
	 * get reported to the calling function.
	 */

	return sgx_create_enclave(filename, edebug, token, updated, eid, attr);
}

int file_in_searchpath (const char *file, const char *search, char *fullpath,
	size_t len)
{
	char *p, *str;
	size_t rem;
	struct stat sb;

	if ( search == NULL ) return 0;
	if ( strlen(search) == 0 ) return 0;

	str= strdup(search);
	if ( str == NULL ) return 0;

	p= strtok(str, ":");
	while ( p != NULL) {
		size_t lp= strlen(p);

		if ( lp ) {

			strncpy(fullpath, p, len);
			rem= len-lp-1;

			strncat(fullpath, "/", rem);
			--rem;

			strncat(fullpath, file, rem);

			if ( stat(fullpath, &sb) == 0 ) {
				free(str);
				return 1;
			}
		}

		p= strtok(NULL, ":");
	}

	free(str);

	return 0;
}
