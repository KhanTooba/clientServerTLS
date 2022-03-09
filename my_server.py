import secrets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
# from my_ttp import certificateServer
import socket
import time
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from base64 import b64encode
from cryptography.hazmat.primitives.serialization import load_pem_public_key

def generateKey():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )  
    publicKey=key.public_key() 
    
    with open("ServerKey.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    return key, publicKey

def getCertificate(key, publicKey):
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"IN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Delhi"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Delhi"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Server"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"server.com"),
        ])).sign(key, hashes.SHA256())

    with open("ServerCsr.pem", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    # cert1, publicKeyCA = certificateServer(csr.public_bytes(serialization.Encoding.PEM),publicKey)
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

def encrypting(key, data):
    key=key[0:16]
    key = key.encode()
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return b64encode(ciphertext).decode('utf-8'), b64encode(tag).decode('utf-8'), nonce

def handshake(certS, private, public, CAKey):
    s = socket.socket()        
    port = 12413              
    s.bind(('', port))        
    s.listen(5)
    msgRcvd = ""

    while True:
        c, addr = s.accept()   
        #Begin Handshake here:
        phase1_request = c.recv(1024).decode()
        if "Hello" in phase1_request:
            print("Client has initiated connection with a hello message.")
            print(".........................Begining of Phase 1.....................\n")
            print("Received Hello from Client: ", phase1_request)
            m1_split = phase1_request.split("\n")
            random = str(time.time())+str(secrets.token_hex(28))
            sessionID = m1_split[3] if m1_split[3]!="" else str(secrets.token_hex(16))
            cipherSuite = m1_split[4].split(",")[0] if m1_split[4]!="" else ""
            compression = m1_split[5].split(",")[0] if m1_split[5]!="" else ""
            phase1_reply = "ServerHello\nVersion:V2\n"+random+"\n"+sessionID+"\n"+cipherSuite+"\n"+compression
            c.send(phase1_reply.encode())
            print("Hello sent to client: ", phase1_reply)
            print("............................End of Phase 1.......................\n\n")


            print(".........................Begining of Phase 2.....................\n")
            phase2_request = certS.public_bytes(serialization.Encoding.PEM)
            c.send(phase2_request)
            c.recv(1024).decode()
            print("Sending request for certificate to client.")
            c.send("certificate_request".encode())
            ok = c.recv(1024).decode()
            # clientCertificate = c.recv(1024).decode()
            c.send("Server done.".encode())
            print("Certificate sent to client. Certificate requested from client. Server done sent.")
            # print("Received Certificate is: ", clientCertificate)
            print("............................End of Phase 2.......................\n\n")


            print(".........................Begining of Phase 3.....................\n")
            ccert = c.recv(2048)
            print("Received Certificate is: ", ccert.decode())
            clientCertificate = x509.load_pem_x509_certificate(ccert)
            if VerifyCertificate(clientCertificate, CAKey)==None:
                print("Client Certificate received is Valid.")
            else:
                print("Client Certificate received is invalid.")

            c.send("Certificate received. Begin phase 4 by sending premaster secret.".encode())
            print("............................End of Phase 3.......................\n\n")


            print(".........................Begining of Phase 4.....................\n")
            encrypted_pre_master_secret = c.recv(1024)
            pre_master_secret_temp = private.decrypt(encrypted_pre_master_secret,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
            pre_master_secret_temp = pre_master_secret_temp.decode() 
            #This is a string type but should have been byte because it starts with b'
            pre_master_secret = pre_master_secret_temp[2:len(pre_master_secret_temp)-1].encode()
            print("Pre-Master-secret received.")
            masterSecret = prf(pre_master_secret)
            print("The calculated master Secret is: ")
            print("............................End of Phase 4.......................\n\n")

            print("............................End of Handshake.......................\n\n")
            print("......................Begining of Record Protocol.....................\n")

            dataToSend = "The OTP for transferring Rs 1,00,000 to your friend's account is 256345."
            encryptedDataToSend, tag, nonce = encrypting(masterSecret, dataToSend.encode())
            c.send(encryptedDataToSend.encode())
            c.recv(1024).decode()
            c.send(tag.encode())
            c.recv(1024).decode()
            c.send(nonce)
            print("Message has been sent.")
        c.close()
        break

def main():
    key , publicKey = generateKey()
    cert, publicKeyCA = getCertificate(key, publicKey)
    if VerifyCertificate(cert, publicKeyCA)==None:
        print("My certificate is Valid.")
    else:
        print("My certificate is Invalid.")
    #keys generated
    #Certificate created and verified.
    #Now begin the handshake with client
    handshake(cert, key, publicKey, publicKeyCA)
main()