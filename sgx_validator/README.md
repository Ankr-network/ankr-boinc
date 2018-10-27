# Build a boinc sgx app

This is a SGX application for boinc server. This document will focus on SGX task and and remote attestation. In current folder, it's a validator for sgx app, and in proteinfolding folder it's the sgx app which will be run in boinc client. The boinc client will report the computing result back to boinc server and sgx_validator will validate the result.
The sgx_validator will do two validations,
1. check the computing result sha256 hash to verify if it's as expected.
1. connect Intel ISA server to validator the computing from trusted enclave.

Therefore, this document is assuming you already have a working boinc server, and is assuming you already knew how to configure a traditional boinc server.

## source code describe  
all the new source code is in (boinc_root)/sgx_validator/ directory  
1. sgx_validator
source code for sgx_valibator
2. proteinfolding
example of boinc SGX application   

## How to build (Ubuntu)
1. To build validator,   
a. install  openssl-1.1.0i
$ wget https://www.openssl.org/source/openssl-1.1.0i.tar.gz
$ tar xf openssl-1.1.0i.tar.gz  
$ cd openssl-1.1.0i  
$ ./config --prefix=/opt/openssl/1.1.0i --openssldir=/opt/openssl/1.1.0i  
$ make  
$ sudo make install

 b. compile sgx_validator  
 $cd sgx_validator   
 $export LD_LIBRARY_PATH=/opt/openssl/1.1.0i/lib    
 $./run.sh    

2. To build proteinfolding,   

    $cd proteinfolding

    $cmake .

    $make

The executible pouw and protein.signed.so will be used in verison.xml and pouw is the main program.

## Configure boinc server
After compiling the SGX tasks, it should be added to boinc server side and follow the tradition of boinc server.  

1.add application to project.xml
  <app>
    <name>pouw</name>
    <user_friendly_name>pouw</user_friendly_name>
  </app>

2. add version application to boinc server
For example, it can be added to  

     myproject/apps/myapp/1.0/x86_64-pc-linux-gnu/  

The version.xml file should be added this directory as usual.

It will be something like this,

    <version>

    <file>

      <physical_name>pouw_1.0_x86_64-pc-linux-gnu</physical_name>

      <main_program/>

    </file>

    <file>

        <physical_name>protein.signed.so</physical_name>

    </file>

    <file>

        <physical_name>Enclave.config.xml</physical_name>

    </file>

    </version>



## Update the database
Then you can run './bin/xadd' and './bin/update_version' to save everything in your mysql database.

Lastly, you need to run './bin/stop' and './bin/start' to start your validator which is configured in config.xml as usual.

The validator will contact Intel Remote Attestation Service to do validation for boinc client computing result.


## Configure the validator

add openssl1.1.0i  ~/.bashrc
export LD_LIBRARY_PATH=/opt/openssl/1.1.0i/lib

add sgx_validator run parameters to config.xml
In config.xml, you need to add your own validator as below. This validator will validate the result and quote.

    <daemon>

        <cmd>sgx_validator --app myapp --spid --sign_file ./AttestationSigningCA.pem --cert client.crt --key client.key</cmd>

    </daemon>

Tips: to test the setting, run sgx_validator:
export LD_LIBRARY_PATH=/opt/openssl/1.1.0i/lib  
./bin/sgx_validator --app myapp --spid --sign_file ./AttestationSigningCA.pem --cert client.crt --key client.key    
 We provide test cert files in (boinc_root)/sgx_validator/intel_sgx_library/certs/certs   


## start the sgx_validator
export LD_LIBRARY_PATH=/opt/openssl/1.1.0i/lib
./bin/stop
./bin/start

## Configure the input and output file
you need to configure your input and outout file. In input file, you need to add your command parameters.
  <input_template>

    <file_info>

        <number>0</number>

    </file_info>

    <workunit>

        <file_ref>

            <file_number>0</file_number>

            <open_name>in</open_name>

            <copy_file/>

        </file_ref>

        <command_line>--difficulty 0.5 --enclave protein.signed.so --hash 1111111111222222222233333333335511111111112222222222333333333355</command_line>

    </workunit>

  </input_template>


In command_line, you can add your parameters. and copy_file tag can be added if you don't want to handle symbolic link in your app.

Tips:  the path of enclave should be specially assigned, for example  --enclave ../../projects/127.0.0.1_cplann/protein.signed.so
if the path sets improperly, the applicaiton will end unexpectedly, the absent of output file will show at boinc client.

## add workunit & test on boinc client
$./bin/stage_file --copy in
$./bin/create_work -appname ss  -wu_template  protein_in  -result_template templates/example_app_out in  -min_quorum 1  -target_nresults 1

boinc client loads the job(workunit), it takes around 30 seconds to finish the example sgx application.
After the output files submit to boinc server. sgx_validator will validate the result by call intel remote attesation.


## Write your own sgx app
This is an example for proteinfolding, and you can write your own sgx app.
The sgx app is similar with regular sgx apps, the following is the difference.

1. SGX MODE should be HW.
1. The quote should be generated after the workunit computing.
1. The quote should write to the beginning of the output file. As a result, the first line is the quote, and the rest lines are other output.

As usual, the sgx app should link boinc library and add boinc_init(), resolve_name(), boinc_finish() kind of functions. It follows the tradition of all old boinc applications.

The simple way is you can follow the sample application in boinc and compile the code under the boinc and use the same makefile(minor change for your file names). It will handle all the details for you, and then you can easily compile and link your sgx application.

For advanced developer, you can link the boinc libraries to your own app. You also need to include the all the header files of boinc.

You can add libboinc_api.a  and libboinc.a, and specify the header with -I${BOINC_ROOT}, -I${BOINC_ROOT}/api, -I${BOINC_ROOT}/lib

## RA certificates

For Remote attestation, the following info should be configured,

1. SPID
1. Service Provider private key
1. Service Provider certificate
1. Attestation Report Signing CA certificate
The user should register his certificate in Intel with following link,

     **https://software.intel.com/en-us/form/sgx-onboarding**

Then the user can get SPID, and Attestation Report Signing CA certificate. Please refer to Intel Remote Attestation document for details. The basic concepts about RA is not focus of this document.

1. For SGX app, it will need SPID in the software application.

1. In SGX app validator, SPID, Service Provider private key, Service Provider certificate,  Attestation Report Signing CA certificate are needed.
