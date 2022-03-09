from distutils import extension
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID
import datetime
from OpenSSL import crypto
from rsa import PublicKey

def certificateServer(private_key_CA, csr, keyClient):
    req = x509.load_pem_x509_csr(csr)

    publicKeyCA = private_key_CA.public_key()

    one_day = datetime.timedelta(1, 0, 0)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(req.subject)
    builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'TTP'),]))

    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))
    builder = builder.serial_number(x509.random_serial_number())

    builder = builder.public_key(keyClient)
    builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True,)
    cert = builder.sign(private_key=private_key_CA, algorithm=hashes.SHA256(),)
    return cert, publicKeyCA


def certificateClient(private_key_CA, csr, keyClient):
    req = x509.load_pem_x509_csr(csr)
    
    publicKeyCA = private_key_CA.public_key()

    one_day = datetime.timedelta(1, 0, 0)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(req.subject)
    builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'TTP'),]))

    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))
    builder = builder.serial_number(x509.random_serial_number())

    builder = builder.public_key(keyClient)
    builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True,)
    cert = builder.sign(private_key=private_key_CA, algorithm=hashes.SHA384(),)
    return cert, publicKeyCA


def ttp():
    private_key_CA = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    s = socket.socket()        
    port = 12423              
    s.bind(('', port))        
    s.listen(5)
    c, addr = s.accept()   
    name = c.recv(1024).decode()
    if "Client" in name:
        c.send("I am listening to you.".encode())
        # cert, publicKeyCA = certificateClient()
        csr = c.recv(1024)
        request = x509.load_pem_x509_csr(csr)
        publicKey = request.public_key()
        print(csr)
        print(publicKey)
        cert, publicKeyCA = certificateClient(private_key_CA, csr, publicKey)
        # c.send(cert.public_bytes(serialization.Encoding.PEM))
        c.send(cert.public_bytes(serialization.Encoding.PEM))
        c.recv(1024)
        c.send(publicKeyCA.public_bytes(serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo))
        c.close()
    elif "Server" in name:
        c.send("I am listening to you.".encode())
        # cert, publicKeyCA = certificateClient()
        csr = c.recv(1024)
        request = x509.load_pem_x509_csr(csr)
        publicKey = request.public_key()
        print(csr)
        print(publicKey)
        cert, publicKeyCA = certificateServer(private_key_CA, csr, publicKey)
        # c.send(cert.public_bytes(serialization.Encoding.PEM))
        c.send(cert.public_bytes(serialization.Encoding.PEM))
        c.recv(1024)
        c.send(publicKeyCA.public_bytes(serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo))
        c.close()
    
    c, addr = s.accept()   
    name = c.recv(1024).decode()
    if "Client" in name:
        c.send("I am listening to you.".encode())
        # cert, publicKeyCA = certificateClient()
        csr = c.recv(1024)
        request = x509.load_pem_x509_csr(csr)
        publicKey = request.public_key()
        print(csr)
        print(publicKey)
        cert, publicKeyCA = certificateClient(private_key_CA, csr, publicKey)
        # c.send(cert.public_bytes(serialization.Encoding.PEM))
        c.send(cert.public_bytes(serialization.Encoding.PEM))
        c.recv(1024)
        c.send(publicKeyCA.public_bytes(serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo))
        c.close()
    elif "Server" in name:
        c.send("I am listening to you.".encode())
        # cert, publicKeyCA = certificateClient()
        csr = c.recv(1024)
        request = x509.load_pem_x509_csr(csr)
        publicKey = request.public_key()
        print(csr)
        print(publicKey)
        cert, publicKeyCA = certificateServer(private_key_CA, csr, publicKey)
        # c.send(cert.public_bytes(serialization.Encoding.PEM))
        c.send(cert.public_bytes(serialization.Encoding.PEM))
        c.recv(1024)
        c.send(publicKeyCA.public_bytes(serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo))
        c.close()
    
    s.close()
    
    return 0

ttp()