Purpose of SampleEnclave:
=========
The project demonstrates several fundamental usages:
    1. Initializing and destroying an enclave
    2. Creating ECALLs or OCALLs
    3. Calling trusted libraries inside the enclave

How to build/execution:
=========
Windows:
	1. Make sure you have the Intel® Software Guard Extensions Windows SDK package installed.
	2. Open the Visual Studio solution file "SampleEnclave.sln". 
	3. Build and execute it directly.
Linux:
	1. Make sure you have the Intel® Software Guard Extensions Linux SDK package installed.
	2. Build the project with the prepared Makefile:
		a. Hardware Mode, Debug build:
		    $ make SGX_MODE=HW SGX_DEBUG=1
		b. Hardware Mode, Pre-release build:
		    $ make SGX_MODE=HW SGX_PRERELEASE=1
		c. Hardware Mode, Release build:
		    $ make SGX_MODE=HW
		d. Simulation Mode, Debug build:
		    $ make SGX_DEBUG=1
		e. Simulation Mode, Pre-release build:
		    $ make SGX_PRERELEASE=1
		f. Simulation Mode, Release build:
		    $ make
	3. Execute the binary directly:
		$ ./app

