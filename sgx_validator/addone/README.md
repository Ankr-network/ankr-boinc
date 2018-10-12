# The Addone Example
This is a mini example for sgx application for boinc.
In this example it computes addone in sgx enclave.
If you don't know how to configure a sgx application for boinc, please read the README under proteinfolding folder.

## How to build?
just run 'make' to build the sgx application.
If there is something wrong, you should check your libraries are in correct folder. If you run at current folder under boinc, everything should be enough. If you move this example to other folder, you need to make sure the boinc headers and boinc libraries be correct.
Also, sgx sdk is assumed to install at /opt/intel/sgxsdk

## Build ouput
after running the 'make', you can get 3 files,
app 
enclave.signed.so  
enclave.so

You only need first two files for boinc.
you can run './app' locally for the testing. The app will find enclave.signed.so and run it.
After running './app', you will find an 'out' file. This 'out' file contains quote and computing result for validator.

## After Build
You can then add app and enclave.signed.so to your boinc server as an application and create workunits.
