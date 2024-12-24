from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
from getpass import getpass

# Генерация ключа на основе пароля
def generate_key(password: str):
    # Используем PBKDF2 для генерации ключа из пароля
    kdf = hashes.Hash(hashes.SHA256(), backend=default_backend())
    kdf.update(password.encode())
    key = kdf.finalize()
    return key[:32]  # AES-256 требует 32 байта для ключа

# Шифрование файла
def encrypt_file(file_path: str, password: str):
    # Генерация ключа из пароля
    key = generate_key(password)
    
    # Инициализация случайного IV
    iv = os.urandom(16)
    
    # Чтение данных из файла
    with open(file_path, 'rb') as file:
        data = file.read()
    
    # Добавление padding для того, чтобы размер данных был кратен блоку (128 бит, 16 байт)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    # Создание шифратора AES в режиме CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Шифрование данных
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Запись зашифрованных данных в новый файл
    encrypted_file_path = file_path + '.enc'
    with open(encrypted_file_path, 'wb') as enc_file:
        enc_file.write(iv + encrypted_data)  # IV идет в начале файла
    print(f'Файл зашифрован и сохранен как {encrypted_file_path}')

# Расшифровка файла
def decrypt_file(file_path: str, password: str):
    # Генерация ключа из пароля
    key = generate_key(password)
    
    # Чтение зашифрованных данных из файла
    with open(file_path, 'rb') as file:
        iv = file.read(16)  # Первые 16 байт - это IV
        encrypted_data = file.read()
    
    # Создание дешифратора AES в режиме CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Расшифровка данных
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    # Удаление padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    original_data = unpadder.update(decrypted_data) + unpadder.finalize()
    
    # Сохранение расшифрованного файла
    decrypted_file_path = file_path.replace('.enc', '.dec')
    with open(decrypted_file_path, 'wb') as dec_file:
        dec_file.write(original_data)
    print(f'Файл расшифрован и сохранен как {decrypted_file_path}')

# Главная функция
def main():
    # Запросить пользователя о действии
    action = input('Введите действие (encrypt/decrypt)(1/2): ').strip().lower()
    
    # Запросить путь к файлу
    file_path = input('Введите путь к файлу: ').strip()
    
    # Запросить пароль
    password = getpass('Введите пароль: ')
    
    if action == '1':
        encrypt_file(file_path, password)
    elif action == '2':
        decrypt_file(file_path, password)
    else:
        print('Неверное действие!')

if __name__ == '__main__':
    main()

