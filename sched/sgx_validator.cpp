// This file is part of BOINC.
// http://boinc.berkeley.edu
// Copyright (C) 2014 University of California
//
// BOINC is free software; you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// BOINC is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with BOINC.  If not, see <http://www.gnu.org/licenses/>.

// A sample validator that requires a majority of results to be
// bitwise identical.
// This is useful only if either
// 1) your application does no floating-point math, or
// 2) you use homogeneous redundancy
//
// if the --is_gzip option is used, all files are assumed to be gzipped.
// In this case, the 10-byte gzip header is skipped
// (it has stuff like a timestamp and OS code that can differ
// even if the archive contents are the same)

//#include "config.h"
#include "util.h"
#include "sched_util.h"
#include "sched_msgs.h"
#include "validate_util.h"
#include "validate_util2.h"
#include "validator.h"
#include "md5_file.h"
#include <openssl/sha.h>
#include "sgx_quote.h"
#include "base64.h"

using std::string;
using std::vector;

int sgx_boinc_sp_call_remote_attestation(char* spid, char* signing_cafile,  char* ias_cert, char *ias_cert_key, char* b64quote, char verbose_flag); // in static library

int sgx_remote_check(string file_path);

bool is_gzip = false;
int run_argc = 0;
char** run_argv = NULL;
    // if true, files are gzipped; skip header when comparing

struct FILE_CKSUM_LIST {
    vector<string> files;   // list of MD5s of files
    ~FILE_CKSUM_LIST(){}
};

int validate_handler_init(int argc, char** argv) {
    // handle project specific arguments here
    for (int i=1; i<argc; i++) {
        if (is_arg(argv[i], "is_gzip")) {
            is_gzip = true;
        }
    }
    return 0;
}

void validate_handler_usage() {
    // describe the project specific arguments here
    fprintf(stderr,
        "    Custom options:\n"
        "    [--is_gzip]  files are gzipped; skip header when comparing\n"
    );
}


bool files_match(FILE_CKSUM_LIST& f1, FILE_CKSUM_LIST& f2) {
    
    return false;
}

int init_result(RESULT& result, void*& data) {
    int retval;
    FILE_CKSUM_LIST* fcl = new FILE_CKSUM_LIST;
    vector<OUTPUT_FILE_INFO> files;
    char md5_buf[MD5_LEN];
    double nbytes;

    retval = get_output_file_infos(result, files);
    if (retval) {
        log_messages.printf(MSG_CRITICAL,
            "[RESULT#%lu %s] check_set: can't get output filenames\n",
            result.id, result.name
        );
        delete fcl;
        return retval;
    }

    if(files.size() == 0) return 1; // no output file, validataion failed anyway
 //   return 1;
    if(sgx_remote_check(files[0].path.c_str()) != 0) return 1; // sgx check error, validation failed anyway 

    for (unsigned int i=0; i<files.size(); i++) {
        OUTPUT_FILE_INFO& fi = files[i];
        if (fi.no_validate) continue;
        retval = md5_file(fi.path.c_str(), md5_buf, nbytes, is_gzip);
        if (retval) {
            if (fi.optional && retval == ERR_FOPEN) {
                strcpy(md5_buf, "");
                    // indicate file is missing; not the same as md5("")
            } else {
                log_messages.printf(MSG_CRITICAL,
                    "[RESULT#%lu %s] md5_file() failed for %s: %s\n",
                    result.id, result.name, fi.path.c_str(), boincerror(retval)
                );
                return retval;
            }
        }
        fcl->files.push_back(string(md5_buf));
    }
    data = (void*) fcl;
    return 0;
}

void sha256(char *string, int len, unsigned char outputBuffer[65])
{
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, len);
    SHA256_Final(outputBuffer, &sha256);
}

int sgx_remote_check(string file_path){
    int file_size = 0;
    char* b64quote = NULL;
    char* result_content = NULL;

    FILE* fp = fopen(file_path.c_str(), "r");
    if( fp == NULL )  {
         printf("fail to open file:%s\n", file_path.c_str());
         return 1;
    }

    fseek(fp, 0L, SEEK_END);
    file_size = ftell(fp);
    b64quote = new char[file_size + 1];
    memset(b64quote, 0, file_size + 1);

    fseek(fp, 0L, SEEK_SET);
    fread(b64quote, file_size, 1, fp); 
    result_content = strchr(b64quote, '\n');
    
    int len = result_content - b64quote;

    b64quote[file_size] = 0;
    *result_content = 0;
    result_content = result_content + 1;

    fclose(fp);

    unsigned char sha256hash[33];
    memset(sha256hash, 0, 33);
    sha256(result_content, file_size-len-1, sha256hash);

    string origquote = r_base64_decode(b64quote, len);
    if (strncmp((char*)sha256hash, (char*)((sgx_quote_t*)(origquote.c_str()))->report_body.report_data.d, 16) != 0) {
        printf("hashes do not match.\n");
        delete[] b64quote;
        return -1;
    }

    /* for test */
    //char* b64quote2= "AgAAAPoKAAAHAAYAAAAAADQVojnDto72bq2YsaLQHirmCGrHHUmt08LRyclZLFf4BQX///8CAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAANS16kwG2tk/a775pT+YR9M1jfxd7JqjZ6CsEnnxTndXAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC9ccY4Dvd8VBfostHOLUtlBLn0GOUEk0JEDP/yRD2VvQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABW9NIXvpRCgapTzL9gPMPLuYxzsRSEUILnCewQjBGaOQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqAIAAJqZc9uf1h8OXxrqr5PowV75nnZwscUgFZzLf9B3mUADpGICH2nYuXk3zd2TzKoSe6/XPRoKMQJh1YZ5n4tdNLPlJeKJwNz7l4CB/xvqdFFs03lqtgdc+eHTqvBjYmPX1XPhaVoxi2U3YoAYUPVp0hP+F1/pHiG8ItXnqKbkgpgRS5nCRCFfGE8M/ASHoJaY8PyHGBj6mqbbDTkEyRpAvSDcEntBcs5wOaWt/oTeQsg5yRdBg09v9hS1TNdfQnpUnsSXt4+0yvM5IE/XjUa32JwtKZ83I+yrcjn6+uy3w0dedptkbzvKh12Vfc35WI9NwCWaV7Ja/VHt8dthMrNvKo15h3VeiQbEJNOa/dAbSeQEuzCSn7/qMiG1C99lqIUv4Aa8JfolU1oX7KlNzGgBAACEw0iICzh7ABNYNpG7vj/B8QALxS0nnjTLkCzsgy+7aqHFAoYEI7VVDZvYYd+7Mw1NO1M6U+cpyGNhLg+Oaavt+EaOxfDQXmWm2yIfXXrzUjxQSCzVZ9AZaB0pe/oOjqFanUe8trVvTaHMm4krOduA18auzBZ3nk6CadyOgiouevBajfNkJaoafmbPTSuz+hFwpdyrYbANl9+QoR6WRKS/XFVUsYzi5th0z/Iy7FkQu7dmZKO1e4KXvdJn0C9FWtWNFrQdZf4qHChFZbXL8dCHBktIMQGyhycyg+qUm0O6XcsLZAhr5Hnxfj435DVBIoBFFQfkwOaUwZ24//qXqks+XWORKah34NR21aIBJsWyyFLixPR/sP1nAaxWnrdG50ycvK9mV4iYwB/Ay+H/nRfMKJN559FWT+pVLFXioMiqsl3KA1hE83dNQAENIFzX2y2sjt97vCVhZaDXumpVBKL9NXBm0IROwS7dbGr7afBgX09dfCuy7+Sm";
    //char* sign_file = "./AttestationReportSigningCACert.pem";
    //char* cert = "./client.crt";
    //char* key="./client.key";

    char* sign_file = "/home/ubuntu/projects/cplan/certs/AttestationReportSigningCACert.pem";
    char* cert = "/home/ubuntu/projects/cplan/certs/client.crt";
    char* key="/home/ubuntu/projects/cplan/certs/client.key";
    
     
    if(sgx_boinc_sp_call_remote_attestation("3415A239C3B68EF66EAD98B1A2D01E2A", sign_file, cert, key, b64quote, 0)== 0){
         printf("\n -------call_remote_attestation success\n\n");
    }else{
         printf("\n --------call_remote_attestation failed \n\n"); 
         delete[] b64quote;
         return 1;
    }
     
    delete[] b64quote;
    return 0;
}


int compare_results(
    RESULT & /*r1*/, void* data1,
    RESULT const& /*r2*/, void* data2,
    bool& match
) {
    FILE_CKSUM_LIST* f1 = (FILE_CKSUM_LIST*) data1;
    FILE_CKSUM_LIST* f2 = (FILE_CKSUM_LIST*) data2;

    match = files_match(*f1, *f2);
    return 0;
}

int cleanup_result(RESULT const& /*result*/, void* data) {
    delete (FILE_CKSUM_LIST*) data;
    return 0;
}

const char *BOINC_RCSID_7ab2b7189c = "$Id$";
