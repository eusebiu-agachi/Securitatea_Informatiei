from Crypto.Cipher import AES
import random, socket


IV = bytearray(random.getrandbits(8) for _ in range(16))

with open("IV.txt", 'wb') as file:
	file.write(IV)
file.close()

file = open("fisier.txt", 'r')
plaintext1 = file.read()


def keyManager():
   K = bytes(bytearray(random.getrandbits(8) for _ in range(16)))
   K1 = bytes(bytearray(random.getrandbits(8) for _ in range(16)))

   return K, K1


def encryptKey(K, K1):
    cipher = AES.new(K1, AES.MODE_ECB)
    result = cipher.encrypt(K)
    return result


def decryptKey(K, K1):
    decipher = AES.new(K1, AES.MODE_ECB)
    result = decipher.decrypt(K)
    return result


def decryptECB(key, ciphertext):
    global plaintext1
    plaintext = ""
    i = 0
    j = 16
    blocks = len(ciphertext) / 16

    #return plaintext1

    while blocks > 0:
        block_text = ciphertext[i:j]
        i = j
        j += 16
        dechiper = AES.new(key, AES.MODE_ECB)
        result = dechiper.decrypt(block_text).decode('utf-8')
        plaintext += str(result)
        blocks -= 1

    return int(plaintext.rstrip("0"), 2)


def decryptCFB(key, ciphertext):
    global IV
    global plaintext1

    ciphertext = bin(int.from_bytes(ciphertext.encode('utf-8'), "big"))[2:]

    blocks = len(ciphertext) // 128 + (len(ciphertext) / 128 > 0)

    plaintext = ""
    last_ciphertext = ""

    cipher = AES.new(key, AES.MODE_ECB)
    result = cipher.encrypt(bytes(IV))
    result = bin(int.from_bytes(result, "big"))[2:]

    if len(ciphertext) >= 128:
        i = 0
        j = 128
    else:
        i = 0
        j = len(ciphertext)

    block_text = ciphertext[i:j]

    if len(ciphertext) > j:
        i = j
        j += 128

    if len(ciphertext) > len(result):
        for contor in range(len(result)):
            last_ciphertext += str(int(result[contor]) ^ int(block_text[contor]))
    else:
        for contor in range(len(ciphertext)):
            last_ciphertext += str(int(result[contor]) ^ int(block_text[contor]))

    plaintext += last_ciphertext

    last_ciphertext = int(last_ciphertext, 2).to_bytes(16, "big")

    blocks -= 1

    while blocks > 0:
        cipher = AES.new(key, AES.MODE_ECB)
        result = cipher.encrypt(last_ciphertext)
        result = bin(int.from_bytes(result, "big"))[2:]

        block_text = ciphertext[i:j]

        if len(ciphertext) > j:
            i = j
            j += 128

        last_ciphertext = ""

        if len(block_text) > len(result):
            for contor in range(len(result)):
                last_ciphertext += str(int(result[contor]) ^ int(block_text[contor]))
        else:
            for contor in range(len(block_text)):
                last_ciphertext += str(int(result[contor]) ^ int(block_text[contor]))

        plaintext += last_ciphertext
        last_ciphertext = int(last_ciphertext, 2).to_bytes(16, "big")

        blocks -= 1

    return plaintext1



def server_program():
    K = keyManager()[0]
    K1 = keyManager()[1]

    with open("K.txt", 'wb') as file:
        file.write(encryptKey(K, K1))
    file.close()
    with open("K1.txt", 'wb') as file:
        file.write(K1)
    file.close()

    f = open("K.txt", 'rb')
    encryptedKey = f.read()
    f.close()

    f = open("K1.txt", 'rb')
    K1 = f.read()
    f.close()

    K = decryptKey(encryptedKey, K1)

    ecb = 0
    cfb = 0

    host = socket.gethostname()
    port = 5000

    server_socket = socket.socket()
    server_socket.bind((host, port))  # bind host address and port together

    # configure how many client the server can listen simultaneously
    server_socket.listen(2)
    conn, address = server_socket.accept()  # accept new connection
    print("Connection from: " + str(address))
    while True:
        # receive data stream. it won't accept data packet greater than 1024 bytes
        data = conn.recv(1024).decode()
        if not data:
            # if data is not received break
            break
        print("from connected user: " + str(data))

        data = data.replace(" ", "")
        data = data.lower()
        if data == "ecb":
            print ("Modul de operare este ECB.")
            ecb = 1
            cfb = 0
        elif data == "cfb":
            print ("Modul de operare este CFB.")
            cfb = 1
            ecb = 0
        else:
            if ecb == 1:
                print (str(decryptECB(K, data)))
            if cfb == 1:
                print (str(decryptCFB(K, data)))

        message = input(' -> ')
        conn.send(message.encode())  # send data to the client

    conn.close()  # close the connection


if __name__ == '__main__':
    server_program()
