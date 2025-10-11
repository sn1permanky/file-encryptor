import os
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

# Создаем "ленивый" класс
class CryptoManager:
    _instance = None
    _initialized = False
    MAGIC_MARKER = b'ENCRYPTED'  # Маркер зашифрованного файла

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not CryptoManager._initialized:
            CryptoManager._initialized = True
            self.script_path = os.path.abspath(sys.argv[0])

    # Функция создания пароля. Используется совместно с salt (солью). 
    def _get_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    # Проверка, является ли файл самим скриптом
    def _is_script(self, filepath: str) -> bool:
        return os.path.abspath(filepath) == self.script_path

    # Проверка, зашифрован ли уже файл
    def _is_encrypted(self, filepath: str) -> bool:
        try:
            with open(filepath, 'rb') as f:
                header = f.read(len(self.MAGIC_MARKER))
                return header == self.MAGIC_MARKER
        except:
            return False

    # Функция шифрования файла, также стараемся учитывать принцип единой ответственности
    def encrypt_file(self, filepath: str, password: str): 
        try:
            if self._is_script(filepath):
                print(f"Пропущен (скрипт): {filepath}")
                return None
            
            if self._is_encrypted(filepath):
                print(f"Пропущен (уже зашифрован): {filepath}")
                return None
            
            salt = os.urandom(16)
            key = self._get_key(password, salt)
            
            with open(filepath, 'rb') as f:
                data = f.read()
            
            encrypted = Fernet(key).encrypt(data)
            
            with open(filepath, 'wb') as f:
                f.write(self.MAGIC_MARKER + salt + encrypted)
            
            return True
        except Exception as e:
            print(f"Ошибка: {filepath} - {e}")
            return False

    # Функция расшифровки
    def decrypt_file(self, filepath: str, password: str):
        try:
            if self._is_script(filepath):
                print(f"Пропущен (скрипт): {filepath}")
                return None
            
            with open(filepath, 'rb') as f:
                data = f.read()
            
            marker_len = len(self.MAGIC_MARKER)
            if data[:marker_len] != self.MAGIC_MARKER:
                print(f"Пропущен (не зашифрован): {filepath}")
                return None
            
            salt = data[marker_len:marker_len+16]
            encrypted = data[marker_len+16:]
            key = self._get_key(password, salt)
            
            decrypted = Fernet(key).decrypt(encrypted)
            
            with open(filepath, 'wb') as f:
                f.write(decrypted)
            
            return True
        except Exception as e:
            print(f"Ошибка: {filepath} - {e}")
            return False

    # Функция для работы скрипта внутри папки
    def process_folder(self, folder: str, password: str, encrypt=True):
        action = "Шифрование" if encrypt else "Дешифрование"
        print(f"\n{action}: {folder}\n")
        
        success = 0
        failed = 0
        skipped = 0
        
        for root, _, files in os.walk(folder):
            for file in files:
                filepath = os.path.join(root, file)
                
                if encrypt:
                    result = self.encrypt_file(filepath, password)
                else:
                    result = self.decrypt_file(filepath, password)
                
                if result is True:
                    success += 1
                elif result is False:
                    failed += 1
                else:
                    skipped += 1
        
        print(f"\nГотово: {success} успешно, {failed} ошибок, {skipped} пропущено")


def main():
    crypto = CryptoManager()
    
    print("ШИФРОВАНИЕ ФАЙЛОВ\n")
    
    while True:
        print("1. Зашифровать папку")
        print("2. Расшифровать папку")
        print("3. Выход")
        
        choice = input("\nВыбор (1-3): ").strip()
        
        if choice == '3':
            print("Выход...")
            break
        
        if choice not in ['1', '2']:
            print("Неверный выбор!")
            continue
        
        folder = input("Путь к папке: ").strip()
        if not os.path.isdir(folder):
            print("Папка не найдена!")
            continue
        
        password = input("Пароль: ").strip()
        if len(password) < 12:
            print("Пароль слишком короткий!")
            continue
        
        encrypt = (choice == '1')
        crypto.process_folder(folder, password, encrypt)


if __name__ == "__main__":
    main()
