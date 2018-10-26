/* Compile & Run:
clang++ -std=c++11 -fsanitize=address `curl-config --cflags` -o libcurl_test libcurl_test.cpp `curl-config --libs` && ASAN_OPTIONS="detect_leaks=1" ./libcurl_test
*/

#include <map>
#include <string>
#include <cstdio>
#include <cstring>

#include <iostream>

#include <curl/curl.h>
using namespace std;


std::string getTargetString(std::string content, std::string beginer, std::string end){
  int offsize = beginer.size();

  // different member versions of find in the same order as above:
  std::size_t found = content.find(beginer);
  if (found == std::string::npos){
     std::cout << "error "<<beginer<<" is not found." << '\n';
     return "";
  }
  std::size_t found2 = content.find(end, found + offsize);
  std::string substr = content.substr(found + offsize , found2 - found - offsize);
  return substr;
}

struct PostData {
  const char *ptr;
  size_t size;
};
size_t read_data(void *ptr, size_t size, size_t nmemb, void *userp) {
  PostData *post_data = (PostData*)userp;

  size_t byte_len = size * nmemb;
  if (post_data->size < byte_len) {
    byte_len = post_data->size;
  }
  memcpy(ptr, post_data->ptr, byte_len);
  post_data->ptr += byte_len;
  post_data->size -= byte_len;
  return byte_len;
}


static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{     
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
} 

static size_t WriteHeaderCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

// return 0 if success
int sgx_remote_attestation(const char* ias_cert, const char *ias_cert_key, const char* b64quote, const char verbose_flag) 
{
 std::string body("{\"isvEnclaveQuote\":\"");
 body.append(std::string(b64quote));
 body.append("\"}"); 
  // Get a curl object
  CURL *curl = curl_easy_init();
  if (!curl) {
    printf("curl_easy_init() failed\n");
    return 1;
  }
  std::string httpbody, httpheader; 

  // Set url
  curl_easy_setopt(curl, CURLOPT_URL, "https://test-as.sgx.trustedservices.intel.com:443/attestation/sgx/v3/report");
  
  // Set HTTP method to POST
  if(verbose_flag)
      curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(curl, CURLOPT_POST, 1L);
  curl_easy_setopt(curl, CURLOPT_SSLCERT, ias_cert);
  //curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE,);
  curl_easy_setopt(curl, CURLOPT_SSLKEY, ias_cert_key);

  // Set callback on sending data
  const char *message = body.c_str();
  printf("post data: \n%s\n---post data end---\n\n", message);
  PostData post_data;
  post_data.ptr = message;
  post_data.size = strlen(message);
  curl_easy_setopt(curl, CURLOPT_READDATA, &post_data);
  curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_data);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(message));

  // Set callback on receiving data
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &httpbody);
  // header
  curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, WriteCallback);
  curl_easy_setopt(curl, CURLOPT_HEADERDATA, &httpheader);
   

  // Execute
  CURLcode res = curl_easy_perform(curl);
  long http_code = 0;
  curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &http_code);
  printf("http status %ld \n", http_code);
  if (res != CURLE_OK) {
    printf( "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    return 1;
  }

  if(http_code != 200){
    printf("http_code error : %ld \n", http_code);
    return 1;
  }
  
    std::cout<<"body:"<<httpbody<<std::endl;
    std::cout<<"header:"<<httpheader<<std::endl;
    std::string isvEnclaveQuoteStatus  ("isvEnclaveQuoteStatus\":\"");
    std::string status = getTargetString(httpbody, isvEnclaveQuoteStatus, "\"");  
    std::cout<<"isvEnclaveQuoteStatus:"<<status<<std::endl;

    std::string  signatureBeginer("x-iasreport-signature: ");
    std::string signature  = getTargetString(httpheader, signatureBeginer, "\n");
    std::cout<<"x-iasreport-signature:"<<signature<<std::endl;

    if(status.compare("OK") == 0 || status.compare("GROUP_OUT_OF_DATE")== 0){
       return 0;
    }else{
       return 1;
   }

}
/*
int main() {
  char * body="AgAAAPoKAAAHAAYAAAAAADQVojnDto72bq2YsaLQHir+RFMYMbHsrgY2vA+qYjVWBQX///8CAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAAAAAAAHAAAAAAAAAHRt3vddth7p9Ffs2NgTuodxz7FlkpweN/Nix/DwInKcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABLInd31N0fxhxviE9IZB0CtNEh0/0yjLCLVTH8rNq/igAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqAIAACq3YafQCbBd7v7bl1UQt/jrja+dUbP9rdI3pbWP/+LYmZTOen+LDVuKAMPPIc92G64wT+CbfTvvf4heazA+civyhX/UXFyGC3FuNIK6CzX7Gn7OJJomFqXLsZQl5a/mG7ZCsz6+kX4axfzCo6T6wQY3gwXPzJhLRI04h7KL8pedca6BgpTgmP1qQBxhuhqWcU6y9StG53nK4V15fBv+6K3JEUW8DwT40nsXXPFS2zdlaSzonS6vMXSVWLdKnsWSHFTWdS2FG9u6QdDdP63apLeocAQORTq950MytKc4r0xpyakIK8X5VOV41GtzZ6+DfymqVWWGw0PyKpjw3eTwBGs/eANzUW8q1E/3MPBE5QH/b7maWT4CL6PYN52mCVET66PbnIgBAobz3OtSd2gBAACzG9a+TQJN+mJxBCa1jILjwiJg4Z/3H6VRHkekUovAhPXB0dJXdaWbEDpgibZRMJUq66Q611b85urlFvkE9+S/cUFxRwrNX3+zUzz44X80gruH0uNSweUCDzjmdlIw0jjmqz+maCVRi0LxWxywffg9SOZBFyyfiQFv6r2eVAEx56OeO2QMT7adJ1WJLwc6Wg/SXjnGyDD0VznpGgKQclr2C6w6zbUWZEdsBj/2lmhjhFHvDVpBc5IDAdcis5rN7WH8AABBfeoPsqlimkKjL6xKCL9D/0VcowLkruzV+WmVF0naT1/cwBeGRY8jZwc3vdSgNuPN1gYJy+xSCcAsT42Uvi0s7Zrei9SEj+eYYrRpoPs2cf4+LEyAbzESIWReHQ9gvpGbcT5LAY7VA0NLuqltMhb1CItYyfCdq75JHxQuQSfII3g6xTM4qk/X/N/SVTFNVLMNcYevHymj0I4LAoYjEGBIASE3v6czPpFbdzcul/Abr8vliPwf";

  printf("%d\n",  strlen(body));
 sgx_remote_attestation("certs/client.crt", "certs/client.key" , body, 1); 
}
*/
