from Crypto.Cipher import AES, DES3, PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint
from Crypto.Hash import SHA3_224, SHA3_256, SHA3_384, SHA3_512
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
import time


# symmetric encryption using AES or 3-DES algorithms in OFB or CFB mode of operation
def symmetric_encryption(msg, key, mode, encryption_mode, iv):
    if mode == "AES":
        msg = pad(msg, AES.block_size)
        if encryption_mode == "OFB":
            cipher = AES.new(key, AES.MODE_OFB, iv)
        elif encryption_mode == "CFB":
            cipher = AES.new(key, AES.MODE_CFB, iv)
    elif mode == "DES3":
        msg = pad(msg, DES3.block_size)
        if encryption_mode == "OFB":
            cipher = DES3.new(key, DES3.MODE_OFB, iv)
        elif encryption_mode == "CFB":
            cipher = DES3.new(key, DES3.MODE_CFB, iv)
    encrypted = cipher.encrypt(msg)
    return encrypted


# symmetric decryption using AES or 3-DES algorithms in OFB or CFB mode of operation
def symmetric_decryption(encrypted, key, mode, encryption_mode, iv):
    if mode == "AES":
        if encryption_mode == "OFB":
            cipher = AES.new(key, AES.MODE_OFB, iv)
        elif encryption_mode == "CFB":
            cipher = AES.new(key, AES.MODE_CFB, iv)
        decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
    elif mode == "DES3":
        if encryption_mode == "OFB":
            cipher = DES3.new(key, DES3.MODE_OFB, iv)
        elif encryption_mode == "CFB":
            cipher = DES3.new(key, DES3.MODE_CFB, iv)
        decrypted = unpad(cipher.decrypt(encrypted), DES3.block_size)
    return decrypted


# calculating message hash using SHA3 algorithm of size: 224, 256 or 512 bits
def get_hash(msg, hash_size):
    if hash_size == "224":
        hash = SHA3_224.new(msg)
    if hash_size == "256":
        hash = SHA3_256.new(msg)
    if hash_size == "384":
        hash = SHA3_384.new(msg)
    if hash_size == "512":
        hash = SHA3_512.new(msg)
    return hash


# calculating digital signature
def get_signature(private_key, hash_size, msg):
    print()
    hashed_msg = get_hash(msg, hash_size)
    key = RSA.import_key(private_key)
    signature = PKCS1_v1_5.new(key).sign(hashed_msg)
    return signature


# digital signature verification
def verify_signature(public_key, signature, hash_mode, msg):
    hashed_msg = get_hash(msg, hash_mode)
    key = RSA.import_key(public_key)
    try:
        PKCS1_v1_5.new(key).verify(hashed_msg, signature)
        return True
    except:
        return False


# RSA encryption
def rsa_encryption(public_key, to_encrypt):
    encryptor = PKCS1_OAEP.new(public_key)
    encrypted = encryptor.encrypt(to_encrypt)
    return encrypted


# RSA decryption
def rsa_decryption(key, to_decrypt):
    decryptor = PKCS1_OAEP.new(key)
    decrypted = decryptor.decrypt(to_decrypt)
    return decrypted


# creating initialization vector
def initialize_vector(mode):
    if mode == "AES":
        iv_size = 16
    elif mode == "DES3":
        iv_size = 8
    vector = [randint(0, 1) for _ in range(iv_size)]
    return bytes(vector)


# class representing message sender
class Sender:

    def __init__(self, hash_mode, encryption_mode, mode, rec_public_key, own_private_key, symmetrical_key_size):
        self.hash_mode = hash_mode
        self.mode = mode
        self.encryption_mode = encryption_mode
        self.rec_public_key = rec_public_key
        self.symmetrical_key_size = symmetrical_key_size
        self.iv = initialize_vector(self.mode)
        self.private_key = own_private_key

    def send_message(self, message):
        # symmetric key creation and message encryption with said key
        _key = get_random_bytes(self.symmetrical_key_size)
        encrypted_msg = symmetric_encryption(message, _key, self.mode, self.encryption_mode, self.iv)

        # symmetric key encryption using reciever's public key
        encrypted_key = rsa_encryption(self.rec_public_key, _key)

        # writing encrypted message and key in appropriately named files
        with open("message.txt", "wb") as file:
            file.write(encrypted_msg)
        with open("key.txt", "wb") as file:
            file.write(encrypted_key)

        # digital envelope (consisted of encrypted message and encrypted key)
        envelope = encrypted_key + encrypted_msg

        # digital seal
        signature = get_signature(self.private_key.export_key(), self.hash_mode, envelope)

        # writing digital seal in appropriately named file "seal.txt"
        with open("seal.txt", "wb") as file:
            file.write(signature)

        print("Sender: Message sent!")


# class representing message recipient (reciever)
class Reciever:

    def __init__(self, hash_mode, encryption_mode, mode, private_key, s_public_key, iv):
        self.hash_mode = hash_mode
        self.mode = mode
        self.encryption_mode = encryption_mode
        self.private_key = private_key
        self.s_public_key = s_public_key
        self.iv = iv


    def read_message(self):
        # reading recieved message
        with open("message.txt", "rb") as file:
            enc_msg = file.read()

        # reading recieved key
        with open("key.txt", "rb") as file:
            enc_key = file.read()

        # key decryption using own private key
        _decrypted_key = rsa_decryption(self.private_key, enc_key)

        # message decryption using previously decrpypted key
        _decrypted_msg = symmetric_decryption(enc_msg, _decrypted_key, self.mode, self.encryption_mode, self.iv)

        # reading signature
        with open("seal.txt", "rb") as file:
            _signature = file.read()

        # signature verification
        if verify_signature(self.s_public_key.export_key(), _signature, self.hash_mode, _decrypted_msg):
            print("\nReciever: Signature verified!")
            # original message print
            print("Reciever:\n  Decrypted message: " + str(_decrypted_msg.decode()))
        else:
            print("Reciever: Signature unverified!")


if __name__ == '__main__':
    print("NOTE: During program run, message.txt, key.txt and seal.txt files will be created on your device.")
    print("Data corresponding their names will be written in them.")
    print()
    print("Insert:")
    print("Symmetric encryption algorithm(AES or DES3): ")
    mode = input().upper()
    print("Insert:")
    print("Mode of operation for symmetric encryption algorithm(OFB or CFB)")
    encryption_mode = input().upper()
    print("Key size(AES): 16, 24 or 32 bits")
    print("Key size(3-DES): 16 ili 24 bits")
    print("Insert:")
    print("Key size in bits: ")
    symmetrical_key_size = int(input())
    print("Insert:")
    print("Asymmetric algorithm encryption(RSA) key size in bits(1024, 2048 or 3072): ")
    rsa_key_size = int(input())
    print("Insert:")
    print("SHA3 hash size(224, 256, 384 ili 512): ")
    hash_mode = input()
    print("Insert:")
    print("Message: ")
    message = bytes(input(), encoding='utf8')

    # reciever private and public key creation
    reciever_private_key = RSA.generate(rsa_key_size)       # not visible to sender
    reciever_public_key = reciever_private_key.publickey()  # visible to sender

    # sender private and public key creation
    sender_private_key = RSA.generate(rsa_key_size)         # not visible to reciever
    sender_public_key = sender_private_key.publickey()      # visible to reciever

    sender = Sender(hash_mode, encryption_mode, mode, reciever_public_key, sender_private_key, symmetrical_key_size)
    reciever = Reciever(hash_mode, encryption_mode, mode, reciever_private_key, sender_public_key, sender.iv)

    sender.send_message(message)
    time.sleep(1)
    reciever.read_message()

