# Implementation of Intrusion Detection Systems Using eBPF and Machine Learning: A Comparative Analysis of Different ML Approaches

```The original source code made by Maximilian Bachl et al. can be found on the following github repo:``` https://github.com/CN-TU/machine-learning-in-ebpf


Bachelor thesis
===============
This Bachelor thesis is a comparative analysis of different ML models to see how they perform on an eBPF based IDS. 
The IDS originally ran on Debian Buster, but during this project, we made sure it would work on Debian Bookworm.


Features
--------
This project aims to rework the source code to meet our needs, and we have therefore done some changes to the code. 

- Modified ebpf_wrapper.cc
	- Switched from simulated packets to real-time network traffic analysis. 
- New python script for testing
	- New python script removes the use of iperf for simulated packet transmission.
	- Uses Scapy for packet sniffing on port 9000 to sniff all TCP traffic on the device.
	- Sets a sleep timer for 10 seconds to allow the IDS some time to properly start. Earlier iterations of the script crashed due to a conflict between the subprocess for the IDS and the python script trying to send packets to the IDS before the subprocess was finished initializing.
- Included a bash script for sending packets to the IDS.
	- Although the script no longer relies on iperf to send simulated packets to the IDS, I still needed to be able to send a fair amount of packages to test the stability and general benchmark purposes. Therefore i made a simple bash script that makes a subprocess that generates packets and sends them to the IDS. This script sends between 20-30.000 packets in 10 seconds (which is the timer I set for the statistics report) using ncat, and will continue sending packets until the PID is killed.
- Removed code for running IDS in userspace
	- Running the IDS in userspace was out of scope for this project. I have therefore removed the code for it in order to clean it up and avoid confusion.
	- This affects ebpf_wrapper.cc
	- ids.c remains unchanged.


Installation
------------
1. This project has only been tested on Debian Bookworm. Other distros could be used, but I have not been able to test it.
2. Install dependencies:
	- sudo apt install bcc
	- sudo apt install libbpfcc-dev
	- sudo apt install linux-headers-$(uname -r)
	- pip install scapy

**NOTE**: After a system update on the Debian system, I experienced some issues running the IDS program. The error complained about missing headers. Running "sudo apt install linux-headers-$(uname -r)" again seemed to fix the issue. You might also try "sudo apt-get update && apt-get upgrade" while you're at it.

3. Compile the ebpf_wrapper
	- **g++ -fpermissive -I/usr/include/bcc ebpf_wrapper.cc -lbcc -o ebpf_wrapper**
4. Run the program:
	- sudo python3.7 newtest.py
NOTE: The python script has a line where you will manually have to type in the IP address of the device you are running the IDS on.
5. (Optional) Sending test-packets
	- The IDS is set to display a statistics report every 10 seconds. If there are no packets being sent in that period, it will display a message saying such. If you want to test the IDS by sending TCP packets, I have included a bash script that will create a subprocess, using ncat, that sends simulated packets to the designated IP-address.
In order to run this bash script, simply write:
		- sudo ncat_packet_tester.sh
NOTE: This script will create a subprocess. In order to stop the script from sending packets, you will need to kill the process running it. You can try closing the terminal window, or alternatively use the kill command followed by the process ID (PID):
	- kill [PID]
