# Minimal-TCP-IP-Stack-
This is not a fully-fledged TCP/IP stack. I have created a minimal TCP/IP stack to understand the functionality of networking layers. It utilizes raw sockets, bypassing the embedded TCP/IP stack of the operating system.  The code builds custom layers such as the transport layer and network layer while bypassing the OS's networking stack.

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
