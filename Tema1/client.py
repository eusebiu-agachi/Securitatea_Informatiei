from Crypto.Cipher import AES
import random, socket


def decryptKey(K, K1):
    decipher = AES.new(K1, AES.MODE_ECB)
    result = decipher.decrypt(K)
    return result


def encryptECB(key, plaintext):
    plaintext = int(plaintext)
    plaintext = bin(plaintext)

    contor = 128
    while contor < len(plaintext):
        contor += 128

    plaintext = plaintext + (contor - len(plaintext)) * '0'
    blocks = len(plaintext) / 128

    i = 0
    j = 128
    ciphertext = b''

    while blocks > 0:
        block_text = plaintext[i:j]
        i = j
        j += 128
        chiper = AES.new(key, AES.MODE_ECB)
        result = chiper.encrypt(block_text.encode('utf-8'))
        ciphertext = b''.join([ciphertext, result])
        blocks -= 1

    return ciphertext



def encryptCFB(key, plaintext):
    f = open("IV.txt", 'rb')
    IV = f.read()
    f.close()

    plaintext = int(plaintext)
    plaintext = bin(plaintext)[2:]

    contor = 128
    while contor < len(plaintext):
        contor += 128
    plaintext = plaintext + (contor - len(plaintext)) * '0'
    blocks = len(plaintext) / 128

    i = 0
    j = 128
    ciphertext = ""
    last_ciphertext = ""

    cipher = AES.new(key, AES.MODE_ECB)
    result = cipher.encrypt(IV)
    result = bin(int.from_bytes(result, "big"))[2:]

    block_text = plaintext[i:j]
    i = j
    j += 128

    for contor in range(len(result)):
        last_ciphertext += str(int(result[contor]) ^ int(block_text[contor]))

    ciphertext += last_ciphertext
    last_ciphertext = int(last_ciphertext, 2).to_bytes(16, "big")

    blocks -= 1

    while blocks > 0:

        cipher = AES.new(key, AES.MODE_ECB)
        result = cipher.encrypt(last_ciphertext)
        result = bin(int.from_bytes(result, "big"))[2:]

        block_text = plaintext[i:j]
        last_ciphertext = ""

        for contor in range(len(result)):
            last_ciphertext += str(int(result[contor]) ^ int(block_text[contor]))
        ciphertext += last_ciphertext

        i = j
        j += 128
        blocks -= 1

    return int(ciphertext, 2).to_bytes(len(plaintext) // 8, "big")


def client_program():
    f = open("K.txt", 'rb')
    encryptedKey = f.read()
    f.close()

    f = open("K1.txt", 'rb')
    K1 = f.read()
    f.close()

    K = decryptKey(encryptedKey, K1)

    f = open("fisier.txt", 'r')
    plaintext = f.read()
    f.close()

    ecb = 0
    cfb = 0


    host = socket.gethostname()  # as both code is running on same pc
    port = 5000  # socket server port number

    client_socket = socket.socket()  # instantiate
    client_socket.connect((host, port))  # connect to the server

    message = input(" -> ")  # take input

    message = message.replace(" ", "")
    message = message.lower()

    while message.lower().strip() != 'exit':
        if message == "ecb":
            ecb = 1
            cfb = 0
            #client_socket.send(encryptECB(K, plaintext))
            #print (str(encryptECB(K, plaintext)))
            client_socket.send(message.encode())
        elif message == "cfb":
            cfb = 1
            ecb = 0
            client_socket.send(message.encode())
            #client_socket.send(encryptCFB(K, plaintext).encode())

        else:
            if ecb == 1:
                client_socket.send(str(encryptECB(K, plaintext)).encode())
            if cfb == 1:
                client_socket.send(str(encryptCFB(K, plaintext)).encode())
        data = client_socket.recv(1024).decode()  # receive response

        print('Received from server: ' + data)  # show in terminal

        message = input(" -> ")  # again take input

    client_socket.close()  # close the connection


if __name__ == '__main__':
    client_program()
