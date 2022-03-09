#!/usr/bin/python3
import socket, ssl, sys, pprint

hostname = sys.argv[1]
port = int(sys.argv[2])
# port = 443
cadir = '/etc/ssl/certs'
# Set up the TLS context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.load_verify_locations(capath=cadir)
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = True
print("Checking host name: ",context.check_hostname)
# print("List of all supported Ciphers:",context.get_ciphers())
# Create TCP connection
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((hostname, port))
print("TCP connection established.")
# Add the TLS
ssock = context.wrap_socket(sock, server_hostname=hostname,do_handshake_on_connect=False)
ssock.do_handshake() # Start the handshake
# print("Certificates to be copied to the folder are:",context.get_ca_certs()) #To get the information about certificates.
print("Handshake done.")
# print("Answers for Part 1:")
# print("\n1 The cipher being used is: ",ssock.cipher())
# print("\n2 The server certifcate: ")
# pprint.pprint(ssock.getpeercert())

file = "/wikipedia/commons/3/39/Awful_wreck_of_the_steam_packet_Home.jpg"

request = b"GET "+file.encode(encoding='utf-8')+b" HTTP/1.1\r\nHost: " + \
hostname.encode(encoding='utf-8') + b"\r\n\r\n"
ssock.sendall(request)

print("The request sent is: ",request)

# Read HTTP Response from Server
response = ssock.recv(2048)
print("\n\nImage retrieved. Printing some headers in the response: ",response.split(b"\r\n")[:10])
while response:
    response = ssock.recv(2048)

# Close the TLS Connection
ssock.shutdown(socket.SHUT_RDWR)
ssock.close()
print("\nConnection closed.\n")