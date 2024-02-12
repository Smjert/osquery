import socket
import ssl
import argparse
import pprint

print("ASD1")

argsParser = argparse.ArgumentParser("mtls_server")

print("ASD2")

argsParser.add_argument(
    "--cert",
    metavar="CERT_FILE",
    default=None,
    help="TLS server cert.")
argsParser.add_argument(
    "--key",
    metavar="PRIVATE_KEY_FILE",
    default=None,
    help="TLS server cert private key.")
argsParser.add_argument(
    "--ca",
    metavar="CA_FILE",
    default=None,
    help="TLS server CA list for client-auth.")
argsParser.add_argument(
    "--cn",
    default=None,
    help="Expected common name")

print("ASD3")

args = argsParser.parse_args()

print("ASD4")

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind(("localhost", 5000))
server_socket.listen(10)

print("ASD5")

client, fromaddr = server_socket.accept()

print("ASD6")
secure_sock = ssl.wrap_socket(client, server_side=True, ca_certs = args.ca, certfile=args.cert, keyfile=args.key, cert_reqs=ssl.CERT_REQUIRED,
                           ssl_version=ssl.PROTOCOL_SSLv23)

print(repr(secure_sock.getpeername()))
print(secure_sock.cipher())
print(pprint.pformat(secure_sock.getpeercert()))
cert = secure_sock.getpeercert()
print(cert)

# verify client
if not cert or ('commonName', args.cn) not in cert['subject'][3]: raise Exception("ERROR")

try:
    data = secure_sock.read(1024)
    secure_sock.write(data)
finally:
    secure_sock.close()
    server_socket.close()
