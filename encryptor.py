import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

# Создаем "ленивый" класс
class CryptoManager:
    _instance = None
    _initialized = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not CryptoManager._initialized:
            CryptoManager._initialized = True
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
# Функция шифрования файла, также стараемся учитывать принцип единой ответственности
    def encrypt_file(self, filepath: str, password: str): 
        try:
            salt = os.urandom(16)
            key = self._get_key(password, salt)
            
            with open(filepath, 'rb') as f:
                data = f.read()
            
            encrypted = Fernet(key).encrypt(data)
            
            with open(filepath, 'wb') as f:
                f.write(salt + encrypted)
            
            return True
        except Exception as e:
            print(f"Ошибка: {filepath} - {e}")
            return False
# Функция расшифровки
    def decrypt_file(self, filepath: str, password: str):
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            
            salt = data[:16]
            encrypted = data[16:]
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
        print(f"\n{action}: {folder}")
        
        success = 0
        failed = 0
        
        for root, _, files in os.walk(folder):
            for file in files:
                if file.endswith('.py'):  # Пропускаем Python-файлы
                    continue
                
                filepath = os.path.join(root, file)
                print(f"  {filepath}")
                
                if encrypt:
                    result = self.encrypt_file(filepath, password)
                else:
                    result = self.decrypt_file(filepath, password)
                
                if result:
                    success += 1
                else:
                    failed += 1
        
        print(f"\nГотово: {success} успешно, {failed} ошибок")


def main():
    crypto = CryptoManager()
    
    print("=" * 50)
    print("ШИФРОВАНИЕ ФАЙЛОВ")
    print("=" * 50)
    
    while True:
        print("\n1. Зашифровать папку")
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
        if len(password) < 4:
            print("Пароль слишком короткий!")
            continue
        
        encrypt = (choice == '1')
        crypto.process_folder(folder, password, encrypt)


if __name__ == "__main__":
    main()
