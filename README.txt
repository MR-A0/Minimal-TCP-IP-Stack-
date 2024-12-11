1. USE LINUX THIS CODE WORK ON LINUX :

2. Compiling :

   [ gcc -Wall -g tcpip.c -o TCPIP -lpcap ]

3. Open Wireshark and Select your network interface :

   [Ex: ifconfig eth0]

4. Add Filter in Wireshark For Monitor Network Traffic :

   [ip.dst == IP-ADDRS]

5. Run the program with root privileges :

   [ sudo ./TCPIP ]

ENJOY ;)
