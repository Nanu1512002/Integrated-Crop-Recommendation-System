import sys
from Crypto.Cipher import AES
from Crypto.Cipher import DES3
from Crypto.Cipher import CAST
from os import urandom
import blowfish
from base64 import b64encode
from base64 import b64decode
from Crypto import Random
from Crypto.Util.Padding import pad
import csv
import socket
from flask import Flask, jsonify, request

app = Flask(__name__)

sys.path.append("D:\\aryan\\Vit_temp\\Python\\capstone_project_12\\.venv\\Lib\\site-packages")

# Create a socket object

# receive data from the server and decoding to get the string.

# close the connection
# s.close()


# Assigning Algorithms Numbers :-
# 1 -> AES
# 2 -> TDES
# 3 -> BLOWFISH
# 4 -> CAST

def encrypt_data(algonumber, key, data, s):
    # Use your existing encryption methods
    # For example:
    # cipher_text = my_encryption_method(data)
    # return cipher_text
    if algonumber == '1':
        key = b64decode(key)
        print("KEY :", key)
        AESEncrypt(key, data, s)
    elif algonumber == '2':
        key = b64decode(key)
        print("KEY :", key)
        tripledesencrypt(key, data, s)
    elif algonumber == '4':
        key = b64decode(key)
        print("KEY :", key)
        CASTEncrypt(key, data, s)
    elif algonumber == '3':
        key = b64decode(key)
        print("KEY :", key)
        BlowfishEncrypt(key, data, s)
    pass


def BlowfishEncrypt(key, data, s):
    cipher = blowfish.Cipher(key)
    iv = urandom(8)  # initialization vector
    while (len(data) % 8) != 0:
        data = data + " "
    res = data.encode('utf-8')
    print("Data to encrypt", data)
    ciphertext = b"".join(cipher.encrypt_cbc(res, iv))
    print("encrypted data", ciphertext)
    s.send(ciphertext)
    cipher = [b64encode(ciphertext).decode('utf-8'), b64encode(iv).decode('utf-8')]

    with open('ciphertext.csv', 'w', encoding='UTF8') as f:
        writer = csv.writer(f)
        # write the data(cipher,iv)
        writer.writerow(cipher)
        f.close()


def CASTEncrypt(key, plaintext, s):
    cipher = CAST.new(key, CAST.MODE_OPENPGP)
    plaintext = plaintext.encode()
    msg = cipher.encrypt(plaintext)
    eiv = msg[:CAST.block_size+2]
    ciphertext = msg[CAST.block_size+2:]
    print("The encrypted data is:", b64encode(ciphertext).decode('utf-8'))
    print("The iv is:", b64encode(eiv).decode('utf-8'))
    cipher = [b64encode(ciphertext).decode('utf-8'), b64encode(eiv).decode('utf-8')]
    s.send((b64encode(eiv).decode('utf-8')).encode())
    with open('ciphertext.csv', 'w', encoding='UTF8') as f:
        writer = csv.writer(f)

        # write the data(cipher,iv)
        writer.writerow(cipher)
        f.close()


def AESEncrypt(key, plain_text, s):
    plain_text = plain_text.encode()
    # Generate a non-repeatable key vector with a length
    # equal to the size of the AES block
    iv = Random.new().read(AES.block_size)
    # Use key and iv to initialize AES object, use MODE_CBC mode
    mycipher = AES.new(key, AES.MODE_CBC, iv)

    ciphertext = mycipher.encrypt(pad(plain_text, AES.block_size))
    print("The encrypted data is:", b64encode(ciphertext).decode('utf-8'))
    print("The iv is:", b64encode(iv).decode('utf-8'))
    cipher = [b64encode(ciphertext).decode('utf-8'), b64encode(iv).decode('utf-8')]
    s.send((b64encode(iv).decode('utf-8')).encode())

    with open('ciphertext.csv', 'w', encoding='UTF8') as f:
        writer = csv.writer(f)

        # write the data(cipher,iv)
        writer.writerow(cipher)

        f.close()


def tripledesencrypt(bkey, msg, s):
    key = pad(bkey, 24)
    tdes_key = DES3.adjust_key_parity(key)
    cipher = DES3.new(tdes_key, DES3.MODE_EAX, nonce=b'0')
    ciphertext = cipher.encrypt(msg.encode('utf-8'))
    print("Encrypted text :-", ciphertext)
    s.send(ciphertext)
    cipher = [b64encode(ciphertext).decode('utf-8')]
    with open('ciphertext.csv', 'w', encoding='UTF8') as f:
        writer = csv.writer(f)
        writer.writerow(cipher)
        f.close()


def send_data(nitrogen, phosphorous, potassium, temperature, humidity, ph, rainfall): # send key to receiver
    s = socket.socket()

    # Define the port on which you want to connect
    port = 12345

    # connect to the server on local computer
    s.connect(('127.0.0.1', port))

    # Construct data dictionary
    data = f"{nitrogen},{phosphorous},{potassium},{temperature},{humidity},{ph},{rainfall}"

    keyreceived = s.recv(1024).decode()
    print("The received key is ", keyreceived)
    print("Algo Number : ", keyreceived[0])
    with open("D:\\aryan\\Vit_temp\\Python\\capstone_project_12\\key.csv") as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        for row in csv_reader:
            if len(row) == 0:
                break
            keyreceived = row[0]
        csv_file.close()

    # keyrecieved = input("Enter the key received by the receiver side : ")
    algonumber = keyreceived[0]
    key = keyreceived[1:]
    print(algonumber)
    print(key)
    encrypt_data(algonumber, key, data, s)

    # Send the encrypted data

    # Receive response from receiver
    response = s.recv(1024).decode()

    # Display response
    print("Response from receiver:", response)
    return response


@app.route('/getdata', methods=['POST'])
def getdata():
    request_data = request.json
    nitrogen = request_data.get("Nitrogen")
    phosphorous = request_data.get("Phosphorous")
    potassium = request_data.get("Potassium")
    temperature = request_data.get("Temperature")
    humidity = request_data.get("Humidity")
    ph = request_data.get("pH")
    rainfall = request_data.get("Rainfall")
    data = send_data(nitrogen, phosphorous, potassium, temperature, humidity, ph, rainfall)
    response = {
        "status": 200,
        "message": "Response Received",
        "crop_to_grow": data,
    }
    return jsonify(response)


if __name__ == '__main__':
    app.run(debug=True)
