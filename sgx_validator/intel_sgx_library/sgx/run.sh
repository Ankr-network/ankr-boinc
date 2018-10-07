g++ -std=c++11  -g  -L/opt/intel/sgxsdk/lib64 -L/opt/openssl/1.1.0i/lib   -o zys  sgx_boinc_call_remote_attestation_test.cpp sgx_boinc_sp.a -lcrypto -lcurl  -I/opt/intel/sgxsdk/include
./zys -s 3415A239C3B68EF66EAD98B1A2D01E2A -A ./certs/AttestationReportSigningCACert.pem -C ./certs/client.crt --ias-cert-key=./certs/client.key -v 
