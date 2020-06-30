from Crypto.Cipher import AES, DES3, PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint
from Crypto.Hash import SHA3_224, SHA3_256, SHA3_384, SHA3_512
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
import time


# simetricna enkripcija AES ili 3-DES algoritmom u 2 nacina rada: OFB ili CFB
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


# simetricna dekripcija AES ili 3-DES algoritmom u 2 nacina rada: OFB ili CFB
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


# racunanje sazetka poruke SHA3 algoritmom velicine: 224, 256, 384 ili 512 bitova
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


# racunanje digitalnog potpisa
def get_signature(private_key, hash_size, msg):
    print()
    hashed_msg = get_hash(msg, hash_size)
    key = RSA.import_key(private_key)
    signature = PKCS1_v1_5.new(key).sign(hashed_msg)
    return signature


# verificiranje digitalnog potpisa
def verify_signature(public_key, signature, hash_mode, msg):
    hashed_msg = get_hash(msg, hash_mode)
    key = RSA.import_key(public_key)
    try:
        PKCS1_v1_5.new(key).verify(hashed_msg, signature)
        return True
    except:
        return False


# RSA enkripcija
def rsa_encryption(public_key, to_encrypt):
    encryptor = PKCS1_OAEP.new(public_key)
    encrypted = encryptor.encrypt(to_encrypt)
    return encrypted


# RSA dekripcija
def rsa_decryption(key, to_decrypt):
    decryptor = PKCS1_OAEP.new(key)
    decrypted = decryptor.decrypt(to_decrypt)
    return decrypted


# stvaranje inicijalizacijskog vektora
def initialize_vector(mode):
    if mode == "AES":
        iv_size = 16
    elif mode == "DES3":
        iv_size = 8
    vector = [randint(0, 1) for _ in range(iv_size)]
    return bytes(vector)


# klasa koja predstavlja posiljatelja poruke
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
        # stvaranje simetricnog kljuca i kriptiranje poruke istim
        _key = get_random_bytes(self.symmetrical_key_size)
        encrypted_msg = symmetric_encryption(message, _key, self.mode, self.encryption_mode, self.iv)

        # kriptiranje simetricnog kljuca javnim kljucem primatelja
        encrypted_key = rsa_encryption(self.rec_public_key, _key)

        # zapisivanje kriptirane poruke i kljuca u datoteke
        with open("message.txt", "wb") as file:
            file.write(encrypted_msg)
        with open("key.txt", "wb") as file:
            file.write(encrypted_key)

        # digitalna omotnica - cine ju enkriptirana poruka i enkriptirani kljuc
        envelope = encrypted_key + encrypted_msg

        # digitalni pecat
        signature = get_signature(self.private_key.export_key(), self.hash_mode, envelope)

        # zapisivanje digitalnog pecata u "seal.txt"
        with open("seal.txt", "wb") as file:
            file.write(signature)

        print("Posiljatelj: Poruka je poslana!")


# klasa koja predstavlja primatelja poruke
class Reciever:

    def __init__(self, hash_mode, encryption_mode, mode, private_key, s_public_key, iv):
        self.hash_mode = hash_mode
        self.mode = mode
        self.encryption_mode = encryption_mode
        self.private_key = private_key
        self.s_public_key = s_public_key
        self.iv = iv


    def read_message(self):
        # citanje primljene poruke
        with open("message.txt", "rb") as file:
            enc_msg = file.read()

        # citanje primljenog kljuca
        with open("key.txt", "rb") as file:
            enc_key = file.read()

        # dekriptiranje kljuca vlastititm privatnim kljucem
        _decrypted_key = rsa_decryption(self.private_key, enc_key)

        # dekriptiranje poruke prethodno dekriptiranim kljucem
        _decrypted_msg = symmetric_decryption(enc_msg, _decrypted_key, self.mode, self.encryption_mode, self.iv)

        # citanje potpisa
        with open("seal.txt", "rb") as file:
            _signature = file.read()

        # verificiranje potpisa
        if verify_signature(self.s_public_key.export_key(), _signature, self.hash_mode, _decrypted_msg):
            print("\nPrimatelj: Potpis je verificiran!")
            # ispis originalno poslane poruke
            print("Primatelj:\n  Dekriptirana poruka: " + str(_decrypted_msg.decode()))
        else:
            print("Primatelj: Potpis nije verificiran!")


if __name__ == '__main__':
    print("Prilikom izvodenja programa stvoriti ce se: message.txt, key.txt i seal.txt datoteke.")
    print("U njima ce biti zapisani njima odgovarajuci podaci.")
    print()
    print("Unesite:")
    print("Algoritam simetricnog kriptiranja(AES ili DES3): ")
    mode = input().upper()
    print("Unesite:")
    print("Nacin rada algoritma simetricnog kriptiranja(OFB ili CFB): ")
    encryption_mode = input().upper()
    print("Velicina kljuca(AES): 16, 24 ili 32 bita")
    print("Velicina kljuca(3-DES): 16 ili 24 bita")
    print("Unesite:")
    print("Velicinu kljuca u bitovima: ")
    symmetrical_key_size = int(input())
    print("Unesite:")
    print("Velicinu kljuca za algoritam asimetricnog kriptiranja(RSA) u bitovima(1024, 2048 ili 3072): ")
    rsa_key_size = int(input())
    print("Unesite:")
    print("Velicinu sazetka SHA3(224, 256, 384 ili 512): ")
    hash_mode = input()
    print("Unesite:")
    print("Poruku: ")
    message = bytes(input(), encoding='utf8')

    # stvaranje privatnog i javnog kljuca primatelja
    reciever_private_key = RSA.generate(rsa_key_size)       # nije vidljiv posiljatelju
    reciever_public_key = reciever_private_key.publickey()  # vidljiv posiljatelju

    # stvaranje privatnog i javnog kljuca posiljatelja
    sender_private_key = RSA.generate(rsa_key_size)         # nije vidljiv primatelju
    sender_public_key = sender_private_key.publickey()      # vidljiv primatelju

    posiljatelj = Sender(hash_mode, encryption_mode, mode, reciever_public_key, sender_private_key, symmetrical_key_size)
    primatelj = Reciever(hash_mode, encryption_mode, mode, reciever_private_key, sender_public_key, posiljatelj.iv)

    posiljatelj.send_message(message)
    time.sleep(1)
    primatelj.read_message()

