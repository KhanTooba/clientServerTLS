import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, hmac
import socket	
import secrets
# from my_ttp import certificateClient
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from base64 import b64decode
from cryptography.hazmat.primitives.serialization import load_pem_public_key


def generateKey():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )  
    publicKey=key.public_key() 
    
    with open("ClientKey.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    return key, publicKey

def getCertificate(key, publicKey):
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"IN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"UttarPradesh"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Lucknow"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Clinet"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"client.com"),
        ])).sign(key, hashes.SHA256())

    with open("ClinetCsr.pem", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
        
    s = socket.socket()		
    port = 12423			
    s.connect(('127.0.0.1', port))
    s.send("Client".encode())
    s.recv(1024)
    s.send(csr.public_bytes(serialization.Encoding.PEM))
    certificateRCVD = s.recv(4096)
    cert1 = x509.load_pem_x509_certificate(certificateRCVD)
    s.send("Certificate received.".encode())
    publicKeyCA = load_pem_public_key(s.recv(4096))
    
    # publicKeyCA = cert1.public_key()
    s.close()
    # cert1, publicKeyCA = certificateClient(csr.public_bytes(serialization.Encoding.PEM),publicKey)

    return cert1, publicKeyCA

def VerifyCertificate(cert, publicKeyCA):
    return publicKeyCA.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,)

def updateHash(secret, n, seed):
    if n==0:
        return seed
    else:
        h = HMAC(secret, hashes.SHA256(), default_backend())
        h.update(updateHash(secret, n-1, seed))
        return h.finalize()

def prf(preMasterSecret):
    seed = "SEEDVALUE".encode()
    result = bytearray()
    i=1
    while len(result)<48:
        h = HMAC(preMasterSecret, hashes.SHA256(), default_backend())
        h.update(updateHash(preMasterSecret, i, seed))
        h.update(seed)
        result.extend(h.finalize())
        i = i + 1
    return str(result[:48])

def decrypting(key, encryptedData, tag, nonce):
    key=key[0:16]
    key=key.encode()
    encryptedData = b64decode(encryptedData)
    tag = b64decode(tag)
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(encryptedData)
    try:
        cipher.verify(tag)
        print("The message is authentic.")
    except ValueError:
        print("Key incorrect or message corrupted")
    return plaintext

def handshake(cert, private, public, CAKey):
    s = socket.socket()		
    port = 12413			
    s.connect(('127.0.0.1', port))
    #Beginning Handshake here:
    print(".........................Begining of Phase 1.....................\n")
    random = str(time.time())+str(secrets.token_hex(28))
    sessionID = str(secrets.token_hex(16))
    cipherSuite = "RSA,ECD"
    compression = ""
    phase1_request = "ClientHello\nVersion:V2\n"+random+"\n"+sessionID+"\n"+cipherSuite+"\n"+compression
    print("Hello message sent to server: ",phase1_request)
    s.send(phase1_request.encode())
    phase1_reply = s.recv(1024).decode()
    print ("Phase 1 reply from server: ", phase1_reply)
    print("............................End of Phase 1.......................\n\n")


    print(".........................Begining of Phase 2.....................\n")
    scert = s.recv(2048)
    print("Received certificate from Server: ", scert.decode())
    serverCertificate = x509.load_pem_x509_certificate(scert)
    if VerifyCertificate(serverCertificate, CAKey)==None:
        print("Server Certificate received is Valid.")
    else:
        print("Server Certificate received is invalid.")
    s.send("Got the certificate.".encode())

    phase2_message = s.recv(1024).decode()
    sendCert = -1
    if "certificate_request" in phase2_message:
        s.send("OK".encode())
        sendCert = 1
    
    phase2_message = s.recv(1024).decode()
    if "done" in phase2_message:
        print("Server has finished phase 2.")
    print("............................End of Phase 2.......................\n\n")


    print(".........................Begining of Phase 3.....................\n")
    if sendCert==1:
        s.send(cert.public_bytes(serialization.Encoding.PEM))
        print("Sent certificate to server.")
        s.recv(1024).decode()

    print("............................End of Phase 3.......................\n\n")


    print(".........................Begining of Phase 4.....................\n")
    pre_master_secret = secrets.token_hex(48).encode()
    encrypted_pre_master_secret = serverCertificate.public_key().encrypt(str(pre_master_secret).encode(),padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    s.send(encrypted_pre_master_secret)
    print("Pre-Master-secret sent.")
    masterSecret = prf(pre_master_secret)
    print("The calculated master Secret is: ")
    print("............................End of Phase 4.......................\n\n")

    print("............................End of Handshake.......................\n\n")
    print("......................Begining of Record Protocol.....................\n")

    encryptedData = s.recv(1024).decode()
    s.send("Data received. Send MAC.".encode())
    tag = s.recv(1024).decode()
    s.send("MAC received. Send nonce.".encode())
    nonce = s.recv(1024)
    dataReceived = decrypting(masterSecret, encryptedData, tag, nonce)
    print("The recieved data is:-",dataReceived.decode())
    s.close()	

def main():
    key , publicKey = generateKey()
    cert, publicKeyCA = getCertificate(key, publicKey)
    if VerifyCertificate(cert, publicKeyCA)==None:
        print("My Certificate is Valid.")
    else:
        print("My Certificate is Invalid.")
    handshake(cert, key, publicKey, publicKeyCA)

main()