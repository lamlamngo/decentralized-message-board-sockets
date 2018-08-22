from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from binascii import *
from socket import *
from blockchain_constants import *
import sys, time

# Load a index num key from a pem file.
def load_key(file_name, num, private):

    with open(file_name, "rb") as key_file:

        text = key_file.read()

        if private:
            end_delim = b"-----END PRIVATE KEY-----\n"
        else:
            end_delim = b"-----END PUBLIC KEY-----\n"
        
        start_ix = 0
        end_ix = -1
    
        for i in range(num+1):
            
            ix = text.find(end_delim, start_ix)
            if ix < 0:
                print("Error: Invalid key number")
                exit()

            end_ix = ix + len(end_delim)
            key_str = text[start_ix:end_ix]
            start_ix = end_ix

            if i == num:

                try:
                    if private:
                        key = serialization.load_pem_private_key(
                            key_str,
                            password=None,
                            backend=default_backend()
                        )
                    else:
                        key = serialization.load_pem_public_key(
                            key_str,
                            backend=default_backend()
                        )
                    return key
                except:
                    print("Error: Invalid key file format")
                    exit()
                    
    print("Error: Invalid key file format")
    exit()
                    

private_file_name = "private_keys.pem"
public_file_name = "public_keys.pem"

# Process commandline arguments.
if len(sys.argv) < 2 or len(sys.argv) > 4:
    print("Usage: python3 send_message.py <message> <from_num> [to_num]")
    exit()

    
msg = sys.argv[1].encode()
if len(sys.argv) >= 3:
    from_num = int(sys.argv[2])
else:
    from_num = 0

if len(sys.argv) == 4:
    to_num = int(sys.argv[3])
    public = False
else:
    to_num = -1
    public = True

# Load keys
private_key = load_key(private_file_name, from_num, True)

if not public:
    public_key = load_key(public_file_name, to_num, False)


'''
Message format:

<msg> = hex(<from_key>)&<msg_body>&hex(<signature>)
<msg_body> = <timestamp>:hex(<public_msg>)
           | <timestamp>:hex(<encrypted_msg>):hex(<to_key>)
   
''' 

# Form message
timestamp = str(time.time()).encode()
if public:

    # Public message
    msg = timestamp + b":" + hexlify(msg)
    
else:
    
    # Private message
    ciphertext = public_key.encrypt(
        msg,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    msg = timestamp + b":" + hexlify(ciphertext) + b":" + hexlify(public_key_pem)
   

# Generate signature
signature = private_key.sign(
    msg,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

sender_key_pem = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)


# Construct full message
full_msg = hexlify(sender_key_pem) + b"&" + msg + b"&" + hexlify(signature) 

# Send message on local server.
sock = socket(AF_INET, SOCK_STREAM)
try:
    host = "localhost"
    sock = create_connection((host, DEFAULT_PORT),1)
    f_in = sock.makefile('r')
    f_out = sock.makefile('w')
    f_out.write("MESSAGE_BROADCAST\n")
    f_out.flush()
    f_out.write((full_msg + b"\n").decode())
    f_out.flush()
    print("Server response: ", f_in.readline())
    sock.close()
except:
    print("Error: Failed to connect to server.")
    
    
