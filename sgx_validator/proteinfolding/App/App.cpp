#include <iostream>
#include <fstream>
#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>

#include "blockchain.h"
#include "App.h"
#include "sgx_urts.h"
#include "sgx_uae_service.h"
#include "Enclave_u.h"
#include "string.h"
#include "Debug.h"
#include "Log.h"
#include "Utils.h"
#include "boinc_api.h"
#include "util.h"


#include "base64.h"

#include "pouw_defs.h"

uint8_t SPID_FANZ[16] = {
        0x34, 0x15, 0xA2, 0x39,
        0xC3, 0xB6, 0x8E, 0xF6,
        0x6E, 0xAD, 0x98, 0xB1,
        0xA2, 0xD0, 0x1E, 0x2A,
};

namespace po = boost::program_options;
using namespace std;

#define ERR_NULL            -116

#if 0
#if !HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t size) {
    size_t ret = strlen(src);

    if (size) {
        size_t len = (ret >= size) ? size-1 : ret;
        memcpy(dst, src, len);
        dst[len] = '\0';
    }

    return ret;
}
#endif

void strip_whitespace(string& str) {
    while (1) {
        if (str.length() == 0) break;
        if (!isascii(str[0])) break;
        if (!isspace(str[0])) break;
        str.erase(0, 1);
    }

    int n = (int) str.length();
    while (n>0) {
        if (!isascii(str[n-1])) break;
        if (!isspace(str[n-1])) break;
        n--;
    }
    str.erase(n, str.length()-n);
}

void strip_whitespace(char *str) {
    string s = str;
    strip_whitespace(s);
    strcpy(str, s.c_str());
}

void xml_unescape(char* buf) {
    char* out = buf;
    char* in = buf;
    char* p;
    while (*in) {
        if (*in != '&') {       // avoid strncmp's if possible 
            *out++ = *in++;
        } else if (!strncmp(in, "&lt;", 4)) {
            *out++ = '<';
            in += 4;
        } else if (!strncmp(in, "&gt;", 4)) {
            *out++ = '>';
            in += 4;
        } else if (!strncmp(in, "&quot;", 4)) {
            *out++ = '"';
            in += 6;
        } else if (!strncmp(in, "&apos;", 4)) {
            *out++ = '\'';
            in += 6;
        } else if (!strncmp(in, "&amp;", 5)) {
            *out++ = '&';
            in += 5;
        } else if (!strncmp(in, "&#xD;", 5) || !strncmp(in, "&#xd;", 5)) {
            *out++ = '\r';
            in += 5;
        } else if (!strncmp(in, "&#xA;", 5) || !strncmp(in, "&#xa;", 5)) {
            *out++ = '\n';
            in += 5;
        } else if (!strncmp(in, "&#", 2)) {
            in += 2;
            char c = atoi(in);
            *out++ = c;
            p = strchr(in, ';');
            if (p) {
                in = p+1;
            } else {
                while (isdigit(*in)) in++;
            }
        } else {
            *out++ = *in++;
        }
    }
    *out = 0;
}

bool parse_str(const char* buf, const char* tag, char* dest, int destlen) {
    string str;
    const char* p;
    int len;
    
    p = strstr(buf, tag);
    if (!p) return false;
    p = strchr(p, '>');
    if (!p) return false;
    p++;
    const char* q = strchr(p, '<');
    if (!q) return false;
    len = (int)(q-p);
    if (len >= destlen) len = destlen-1;
    memcpy(dest, p, len);
    dest[len] = 0;
    strip_whitespace(dest);
    xml_unescape(dest);
    return true;
}

int boinc_resolve_filename(
    const char *virtual_name, char *physical_name, int len
) {     
    FILE *fp;
    char buf[512], *p;
        
    if (!virtual_name) return ERR_NULL;
    strlcpy(physical_name, virtual_name, len);
        
#ifndef _WIN32
    //if (is_symlink(virtual_name)) {
    //    return 0;
    //}
#endif
    
    // Open the link file and read the first line
    // 
    //fp = boinc_fopen(virtual_name, "r");
    fp = fopen(virtual_name, "r");
    if (!fp) return 0;
            
    // must initialize buf since fgets() on an empty file won't do anything
    //  
    buf[0] = 0;
    p = fgets(buf, sizeof(buf), fp);
    fclose(fp);
    
    // If it's the <soft_link> XML tag, return its value,
    // otherwise, return the original file name
    //
    // coverity[check_return]
    if (p) parse_str(buf, "<soft_link>", physical_name, len);
    return 0;
}
#endif
int main(int argc, const char *argv[]) {
    double difficulty;
    string block_hash;
    string enclave_path;
    ofstream outputfile;

    try {
        po::options_description desc("Allowed options");
        desc.add_options()
                ("help", "produce this message")
                ("difficulty", po::value(&difficulty)->required(), "current difficulty")
                ("enclave", po::value(&enclave_path)->required(), "path to the enclave image")
                ("hash", po::value(&block_hash)->required(), "block hash without nonce");

        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);

        if (vm.count("help")) {
            cerr << desc << endl;
            return -1;
        }

        po::notify(vm);
    }

    catch (po::required_option &e) {
        cerr << e.what() << endl;
        return -1;
    }
    catch (exception &e) {
        cerr << e.what() << endl;
        return -1;
    }
    catch (...) {
        cerr << "Unknown error!" << endl;
        return -1;
    }


    if (difficulty < 0 || difficulty > 1) {
        cerr << "difficulty is wrong: " << difficulty << endl;
        return -1;
    }

    if (block_hash.length() != 64) {
        cerr << "please supply SHA-256 (without 0x)" << endl;
        return -1;
    }

    uint32_t len;
    block_hash_t hash;
    if (BLOCK_HASH_LEN != fromHex(block_hash.c_str(), hash.h)) {
        LL_CRITICAL("Error in reading hash");
        return -1;
    }
    else
    {
        dump_buf("Hash: ", hash.h, sizeof hash.h);
    }

    if (!boost::filesystem::exists(enclave_path)) {
        cerr << enclave_path << " is not a file" << endl;
    }


    int ret;
    sgx_enclave_id_t eid;

    boinc_init();

    char e_path[512];
    boinc_resolve_filename(enclave_path.c_str(), e_path, sizeof(e_path));
    ret = initialize_enclave(e_path, &eid);
    if (ret != 0) {
        LL_CRITICAL("Exiting %d", ret);
        return ret;
    } else {
        LL_NOTICE("enclave %lu created", eid);
    }

    pow_spec prob;
    strcpy((char *) prob.prefix, "PREFIX@@PREFIX@@");
    memset(prob.target, 0xff, 32);

    // difficulty
    prob.target[0] = 0x11;
    prob.target[1] = 0x11;

    sgx_target_info_t quote_enc_info;
    sgx_epid_group_id_t p_gid;
    sgx_report_t report;

    ret = sgx_init_quote(&quote_enc_info, &p_gid);
    if (ret != SGX_SUCCESS) {
        print_error_message((sgx_status_t) ret);
        return -1;
    }

    output_t output;
    char enclave_output[4096] = {0};
    string ostr;

    difficulty_t diff;
    diff.difficulty = difficulty;
    run(eid, &ret,
        &prob, &diff, &hash,
        &quote_enc_info, &report,
        &output, enclave_output, 4096);
    if (ret != SGX_SUCCESS) {
        print_error_message((sgx_status_t) ret);
        return -1;
    }

    sgx_spid_t spid;
    memcpy(spid.id, SPID_FANZ, 16);

    uint32_t quote_size;
    sgx_get_quote_size(NULL, &quote_size);

    sgx_quote_t *quote = (sgx_quote_t *) malloc(quote_size);
    if (!quote) {
        LL_CRITICAL("%s", "failed to malloc");
        return -1;
    }
    ret = sgx_get_quote(&report, SGX_UNLINKABLE_SIGNATURE, &spid, NULL, NULL, 0, NULL, quote, quote_size);
    if (ret != SGX_SUCCESS) {
        print_error_message((sgx_status_t) ret);
        LL_CRITICAL("sgx_get_quote returned %d", ret);
        return -1;
    }

    dump_buf("measurement: ", quote->report_body.mr_enclave.m, sizeof(sgx_measurement_t));

    pouw_voucher *p_voucher = (pouw_voucher *) quote->report_body.report_data.d;
    LL_NOTICE("difficulty: %f", p_voucher->difficulty);
    LL_NOTICE("is_win: %d", p_voucher->is_win);
    dump_buf("block_hash", p_voucher->header_hash, 32);
    dump_buf("attestation: ", (const unsigned char *) quote, sizeof(sgx_quote_t));
    char attest_str[4096] = {0};
    hexdump_to_string("attestation: ", (const unsigned char *) quote, sizeof(sgx_quote_t), attest_str, 4096);

    char quote_str[4096] = {0};
    string base64_quote_str;
    char* start = quote_str;
    for (int i = 0; i < quote_size; i++)
    {
        fprintf(stdout, "%02x", ((const uint8_t*)quote)[i]);
        sprintf(start, "%02x", ((const uint8_t*)quote)[i]);
        start += 2;
    }

    base64_quote_str = base64_encode((const unsigned char*)quote, quote_size);
    //ostr += (const char *) quote_str;
    ostr += (const char *) base64_quote_str.c_str();

    ostr += "\n";
    ostr += enclave_output;

    char output_path[512];
    boinc_resolve_filename("out", output_path, sizeof(output_path));
    outputfile.open (output_path);
    outputfile << ostr;
    outputfile.close();

    printf("\nENCLAVE_OUTPUT:\n");
    printf("%s\n", enclave_output);
    printf("\nATTESTATION:\n");
    printf("%s\n", attest_str);
    printf("\nQUOTE:\n");
    printf("%s\n", quote_str);

    boinc_finish(0);
    boinc_sleep(30);

    exit:
    LL_NOTICE("%s", "all enclave closed successfully.");
    return ret;
}
