import random
import sys, os
from Crypto.Cipher import AES
from Crypto.Cipher import DES3
from Crypto.Cipher import CAST
from Crypto.Util.Padding import unpad

from base64 import b64decode
import blowfish
from base64 import b64encode
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import csv
import socket
import numpy as np
import pickle
import warnings
warnings.filterwarnings('ignore')
sys.path.append("D:\\aryan\\Vit_temp\\Python\\capstone_project_12\\venv\\Lib\\site-packages")
# next create a socket object
s = socket.socket()
print("Socket successfully created")

# reserve a port on your computer in our
# case it is 12345, but it can be anything
port = 12345

# Next bind to the port
# we have not typed any ip in the ip field
# instead we have inputted an empty string
# this makes the server listen to requests
# coming from other computers on the network
s.bind(('', port))
print("socket binded to %s" % port)

# put the socket into listening mode
s.listen(5)
print("socket is listening")


# a forever loop until we interrupt it or
# an error occurs

# Assigning Algorithms Numbers :-
# 1 -> AES
# 2 -> TDES
# 3 -> BLOWFISH
# 4 -> CAST


def CASTdecryption(key, ciphertext, eiv):
    ciphertext = b64decode(ciphertext)
    eiv = b64decode(eiv)

    print("Decoded ciphertext : ", ciphertext, len(ciphertext))
    print("Decoded iv : ", eiv, len(eiv))
    cipher = CAST.new(key, CAST.MODE_OPENPGP, eiv)
    decryptedText = cipher.decrypt(ciphertext)

    print("Decrypted data is : ", decryptedText)
    print("Text is: ", decryptedText[0:])
    return decryptedText[0:]


def AESdecryption(key, ciphertext, iv):
    ciphertext = b64decode(ciphertext)
    iv = b64decode(iv)

    print("Decoded ciphertext : ", ciphertext, len(ciphertext))
    print("Decoded iv : ", iv, len(iv))
    # To decrypt, use key and iv to generate a new AES object
    mydecrypt = AES.new(key, AES.MODE_CBC, iv)

    # Use the newly generated AES object to decrypt the encrypted ciphertext
    decrypttext = unpad(mydecrypt.decrypt(ciphertext), AES.block_size)
    # decrypttext = mydecrypt.decrypt(ciphertext)
    print("The decrypted data is: ")
    print("Text is: ", decrypttext[0:])
    return decrypttext[0:]


def blowfishdecrypt(key, ciphertext, iv):
    ciphertext = b64decode(ciphertext)
    iv = b64decode(iv)

    print("Decoded ciphertext : ", ciphertext, len(ciphertext))
    print("Decoded iv : ", iv, len(iv))
    cipher = blowfish.Cipher(key)
    data_decrypted = b"".join(cipher.decrypt_cbc(ciphertext, iv))
    decrypttext = data_decrypted.decode()
    print("The decrypted data is : ")
    print("Text is: ", decrypttext[0:])
    return decrypttext[0:]


def tripledesdecrypt(ciphertext, bkey):
    key = pad(bkey, 24)
    tdes_key = DES3.adjust_key_parity(key)
    cipher = DES3.new(tdes_key, DES3.MODE_EAX, nonce=b'0')
    ciphertext = b64decode(ciphertext)
    plaintext = cipher.decrypt(ciphertext)
    decrypttext = plaintext.decode('utf-8')
    print("Decrypted Text : ")
    print("Text is: ", decrypttext)
    return decrypttext


def randomize():
    rand = random.randint(40, 4000)
    return rand % 5


def load_models_from_directory(directory):
    models = []
    for filename in os.listdir(directory):
        if filename.endswith(".pkl"):
            model_path = os.path.join(directory, filename)
            model = pickle.load(open(model_path, 'rb'))
            models.append(model)
    return models


def make_crop_recommendations(models, N, P, K, temperature, humidity, ph, rainfall):
    predictions = []
    for model in models:
        data = np.array([[N, P, K, temperature, humidity, ph, rainfall]])
        prediction = model.predict(data)
        predictions.append(prediction[0])
    print(predictions)
    return predictions


def process_data(data_str, models_directory):
    # Perform processing on the received data
    N, P, K, temperature, humidity, ph, rainfall = map(float, data_str.split(','))
    models = load_models_from_directory(models_directory)
    predictions = make_crop_recommendations(models, N, P, K, temperature, humidity, ph, rainfall)
    majority_prediction = max(set(predictions), key=predictions.count)  # Get the majority prediction
    return majority_prediction

def rec_data():

    algonumber = randomize()
    if algonumber == 0:
        pass
    else:
        bkey = get_random_bytes(16)
        key = str(algonumber)
        bkey1 = b64encode(bkey).decode('utf-8')
        key += bkey1

        keys = [key]
        with open('key.csv', 'w', encoding='UTF8') as f:
            writer = csv.writer(f)

            # write the data(cipher,iv)
            writer.writerow(keys)

            f.close()
        print("Symmetric Key : ", key)
        print("AlgoNumber : ", algonumber)
        while True:
            # Establish connection with client.
            c, addr = s.accept()
            # send a thank you message to the client. encoding to send byte type.
            c.send(key.encode())

            # Close the connection with the client
            #c.close()

            # Breaking once connection closed
            break

        if algonumber == 2 or algonumber == 3:
            input(c.recv(1024))
        else:
            input(c.recv(1024).decode())
        with open("D:\\aryan\\Vit_temp\\Python\\capstone_project_12\\ciphertext.csv") as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=',')
            for row in csv_reader:
                if len(row) == 0:
                    break
                ciphertext = row[0]
                if algonumber != 2:
                    iv = row[1]
            csv_file.close()
        #c.close()

        if algonumber == 1:  # AES
            result = AESdecryption(bkey, ciphertext, iv)
            result = result.decode('utf-8')
        elif algonumber == 2:  # TDES
            result = tripledesdecrypt(ciphertext, bkey)
        elif algonumber == 4:  # CAST
            result = CASTdecryption(bkey, ciphertext, iv)
            result = result.decode('utf-8')
        elif algonumber == 3:  # Blowfish
            result = blowfishdecrypt(bkey, ciphertext, iv)
    processed_data = process_data(result, "D:\\aryan\\Vit_temp\\Python\\capstone_project_12")
    print("Processed data:", processed_data)

        # Send response back to the sender
    c.sendall(processed_data.encode())


rec_data()
