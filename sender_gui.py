import sys
import tkinter as tk
import datetime
import time
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

sys.path.append("D:\\aryan\\Vit_temp\\Python\\capstone_project_12\\.venv\\Lib\\site-packages")

# Create a socket object
s = socket.socket()

# Define the port on which you want to connect
port = 12345

# connect to the server on local computer
s.connect(('127.0.0.1', port))

# receive data from the server and decoding to get the string.

# close the connection
# s.close()


# Assigning Algorithms Numbers :-
# 1 -> AES
# 2 -> TDES
# 3 -> BLOWFISH
# 4 -> CAST

def encrypt_data(algonumber, key, data):
    # Use your existing encryption methods
    # For example:
    # cipher_text = my_encryption_method(data)
    # return cipher_text
    if algonumber == '1':
        key = b64decode(key)
        print("KEY :", key)
        AESEncrypt(key, data)
    elif algonumber == '2':
        key = b64decode(key)
        print("KEY :", key)
        tripledesencrypt(key, data)
    elif algonumber == '4':
        key = b64decode(key)
        print("KEY :", key)
        CASTEncrypt(key, data)
    elif algonumber == '3':
        key = b64decode(key)
        print("KEY :", key)
        BlowfishEncrypt(key, data)
    pass


def BlowfishEncrypt(key, data):
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


def CASTEncrypt(key, plaintext):
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


def AESEncrypt(key, plain_text):
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


def tripledesencrypt(bkey, msg):
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


def show_message_box(response):
    top = tk.Toplevel(window)
    top.title("Success")
    label = tk.Label(top, text="The crop which can \n be grown is "+response, font=("Helvetica", 12, "bold"))
    label.pack(padx=30, pady=10)
    button_ok = tk.Button(top, text="OK", command=top.destroy)
    button_ok.pack(pady=10)


def send_data():  # send key to receiver
    nitrogen = (txt1.get())
    phosphorous = (txt2.get())
    potassium = (txt3.get())
    temperature = (txt4.get())
    humidity = (txt5.get())
    ph = (txt6.get())
    rainfall = (txt7.get())

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
    encrypt_data(algonumber, key, data)

    # Send the encrypted data

    # Receive response from receiver
    response = s.recv(1024).decode()

    # Display response
    print("Response from receiver:", response)
    show_message_box(response)

##################################################################################


def tick():
    time_string = time.strftime('%H:%M:%S')
    clock.config(text=time_string)
    clock.after(200, tick)


###################################################################################

ts = time.time()
date = datetime.datetime.fromtimestamp(ts).strftime('%d-%m-%Y')
day, month, year = date.split("-")

mont = {'01': 'January',
        '02': 'February',
        '03': 'March',
        '04': 'April',
        '05': 'May',
        '06': 'June',
        '07': 'July',
        '08': 'August',
        '09': 'September',
        '10': 'October',
        '11': 'November',
        '12': 'December'}

######################################## GUI FRONT-END ###########################################

window = tk.Tk()
window.geometry("1280x600")
window.resizable(True, True)
window.title("crop")
window.configure(background='#262523')

frame2 = tk.Frame(window, bg="#00aeff")
frame2.place(relx=0.25, rely=0.17, relwidth=0.48, relheight=0.80)

message3 = tk.Label(window, text="Crop Recommendation System", fg="white", bg="#262523", width=55,
                    height=1, font=('times', 29, ' bold '))
message3.place(x=10, y=10)

frame3 = tk.Frame(window, bg="#c4c6ce")
frame3.place(relx=0.52, rely=0.09, relwidth=0.09, relheight=0.07)

frame4 = tk.Frame(window, bg="#c4c6ce")
frame4.place(relx=0.36, rely=0.09, relwidth=0.16, relheight=0.07)

datef = tk.Label(frame4, text=day + "-" + mont[month] + "-" + year + "  |  ", fg="orange", bg="#262523", width=55, height=1, font=('times', 22, ' bold '))
datef.pack(fill='both', expand=1)

clock = tk.Label(frame3, fg="orange", bg="#262523", width=55, height=1, font=('times', 22, ' bold '))
clock.pack(fill='both', expand=1)
tick()

lbl1 = tk.Label(frame2, text="Nitrogen", width=15, fg="black", bg="#00aeff", font=('times', 17, ' bold '))
lbl1.place(x=100, y=20)
txt1 = tk.Entry(frame2, width=15, fg="black", font=('times', 15, ' bold '))
txt1.place(x=350, y=20)

lbl2 = tk.Label(frame2, text="Phosphorous", width=15, fg="black", bg="#00aeff", font=('times', 17, ' bold '))
lbl2.place(x=100, y=70)
txt2 = tk.Entry(frame2, width=15, fg="black", font=('times', 15, ' bold '))
txt2.place(x=350, y=70)

lbl3 = tk.Label(frame2, text="Potassium", width=15, fg="black", bg="#00aeff", font=('times', 17, ' bold '))
lbl3.place(x=100, y=120)
txt3 = tk.Entry(frame2, width=15, fg="black", font=('times', 15, ' bold '))
txt3.place(x=350, y=120)

lbl4 = tk.Label(frame2, text="Temperature", width=15, fg="black", bg="#00aeff", font=('times', 17, ' bold '))
lbl4.place(x=100, y=170)
txt4 = tk.Entry(frame2, width=15, fg="black", font=('times', 15, ' bold '))
txt4.place(x=350, y=170)

lbl5 = tk.Label(frame2, text="Humidity", width=15, fg="black", bg="#00aeff", font=('times', 17, ' bold '))
lbl5.place(x=100, y=220)
txt5 = tk.Entry(frame2, width=15, fg="black", font=('times', 15, ' bold '))
txt5.place(x=350, y=220)

lbl6 = tk.Label(frame2, text="pH", width=15, fg="black", bg="#00aeff", font=('times', 17, ' bold '))
lbl6.place(x=100, y=270)
txt6 = tk.Entry(frame2, width=15, fg="black", font=('times', 15, ' bold '))
txt6.place(x=350, y=270)

lbl7 = tk.Label(frame2, text="Rainfall", width=15, fg="black", bg="#00aeff", font=('times', 17, ' bold '))
lbl7.place(x=100, y=320)
txt7 = tk.Entry(frame2, width=15, fg="black", font=('times', 15, ' bold '))
txt7.place(x=350, y=320)

message = tk.Label(frame2, text="", bg="#00aeff", fg="black", width=39, height=1, activebackground="yellow",
                   font=('times', 16, ' bold '))
message.place(x=7, y=450)

##################### MENUBAR #################################

menubar = tk.Menu(window, relief='ridge')
filemenu = tk.Menu(menubar, tearoff=0)
filemenu.add_command(label='Exit', command=window.destroy)
menubar.add_cascade(label='Help', font=('times', 29, ' bold '), menu=filemenu)

###################### BUTTONS ##################################

send = tk.Button(frame2, text="Suggest", command=send_data, fg="black", bg="yellow", width=11,
                         activebackground="white", font=('times', 11, ' bold '))
send.place(x=267, y=390)

window.configure(menu=menubar)
window.mainloop()
