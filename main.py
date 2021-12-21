import os
import pickle
import argparse
from cryptography.hazmat.primitives import padding as pad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.padding import PaddingContext


def key_generation(sym_key_dir: str, public_key_path: str, private_key_path: str, _size: int):
    a = int(_size/8)
    sym_key = algorithms.AES(os.urandom(a))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key = key
    public_key = key.public_key()
    f = open(public_key_path + "\\public.pem", "wb")
    f.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo))
    f.close()
    f = open(private_key_path + '\\private.pem', "wb")
    f.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                      format=serialization.PrivateFormat.TraditionalOpenSSL,
                                      encryption_algorithm=serialization.NoEncryption()))
    f.close()
    encrypt_sym_key = public_key.encrypt(sym_key.key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                   algorithm=hashes.SHA256(), label=None))
    f = open(sym_key_dir + '\\encrypted.txt', "wb")
    f.write(encrypt_sym_key)
    f.close()


def encrypt_text(path_to_text: str, private_key_path: str, sym_key_path: str, path_to_save: str):
    f = open(sym_key_path, "rb")
    encrypted_sym_key = f.read()
    f.close()
    f = open(private_key_path, "rb")
    private_key = serialization.load_pem_private_key(f.read(), password=None)
    f.close()
    sym_key = private_key.decrypt(encrypted_sym_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                  algorithm=hashes.SHA256(), label=None))
    f = open(path_to_text, "r")
    output_text = f.read()
    f.close()
    padder: PaddingContext = pad.ANSIX923(8).padder()
    t_text = bytes(output_text, 'UTF-8')
    padded_text = padder.update(t_text) + padder.finalize()
    iv = os.urandom(8)
    cipher = Cipher(algorithms.Blowfish(sym_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    c_text = encryptor.update(padded_text)
    setting = {'text': c_text, 'iv': iv}
    f = open(path_to_save, "wb")
    pickle.dump(setting, f)
    f.close()


def decrypt_text(path_to_text: str, private_key_path: str, sym_key_path: str, path_to_save: str):
    f = open(sym_key_path, "rb")
    encrypted_sym_key = f.read()
    f.close()
    f = open(private_key_path, "rb")
    private_key = serialization.load_pem_private_key(f.read(), password=None)
    f.close()
    sym_key = private_key.decrypt(encrypted_sym_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                  algorithm=hashes.SHA256(), label=None))
    f = open(path_to_text, "rb")
    data = pickle.load(f)
    f.close()
    text_to_decrypt = data['text']
    iv = data["iv"]
    cipher = Cipher(algorithms.Blowfish(sym_key), modes.CBC(iv))
    decrypter = cipher.decryptor()
    dc_text = decrypter.update(text_to_decrypt) + decrypter.finalize()
    under = pad.ANSIX923(8).unpadder()
    under_dc_text = under.update(dc_text)
    f = open(path_to_save, "w")
    f.write(str(under_dc_text)[2:-1])
    f.close()


def check_size():
    length = input()
    while int(length) != 128 and int(length) != 192 and int(length) != 256:
        print("Некорректная длина ключа(128||192||256)")
        length = input()
    return int(length)


parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-gen', '--generation', help='Генерация ключей')
group.add_argument('-enc', '--encryption', help='Шифрование')
group.add_argument('-dec', '--decryption', help='Дешифрование')
args = parser.parse_args()
if args.generation is not None:
    print("Введите путь, по которому будут сохранены ключи: ")
    d_dir = input()
    print("Введите длину ключа: ")
    size = check_size()
    key_generation(d_dir, d_dir, d_dir, size)
    print("Ключи успешно созданы")
else:
    if args.encryption is not None:
        print("Введите путь к тексту, который нужно зашифровать: ")
        text = input()
        print("\nВведите путь к приватному ключу: ")
        private = input()
        print("\nВведите путь к симметричному ключу: ")
        sym = input()
        print("\nВведите путь, в который хотите сохранить зашифрованный текст: ")
        res = input()
        encrypt_text(text, private, sym, res)
        print("Текст успешно сохранен")
    else:
        print("Введите путь к тексту, который нужно расшифровать: ")
        text = input()
        print("\nВведите путь к приватному ключу: ")
        private = input()
        print("\nВведите путь к симметричному ключу: ")
        sym = input()
        print("\nВведите путь, по которому будет сохранен расшифрованный текст: ")
        res = input()
        decrypt_text(text, private, sym, res)
        print("Текст успешно сохранен")
