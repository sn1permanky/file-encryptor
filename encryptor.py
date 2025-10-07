import os
import base64

#Необходимо реализовать Singletone класс, то есть паттерн одиночку, который может встречаться только один раз
#есть несколько способов инициализации - ленивый и мгновенный
# Мы используем ленивую инициализацию, бещ создания 
# создаем такой класс
class Cryptos
  _instance = None # отдельно кладем объект
  _initialized = False # проверка вызова инициализации

  def __new__(cls):
        #Создаёт единственный экземпляр класса 
        if cls._instance is None:
            cls._instance = super(CryptoManager, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        """Инициализация выполняется только один раз"""
        if not CryptoManager._initialized:
            CryptoManager._initialized = True

# Функция для генерации
  def _generate_key_from_password(self, password: str, salt: bytes) -> bytes:
#Генерируем ключ из пароля, как хорошую практику, с использованием PBKDF
#Плюс добавляем соль и хэш функции SHA256, без соли можно подобрать через радужные таблицы
      
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 бит для AES-256
            salt=salt,
            iterations=100000,  # Количество итераций для усложнения подбора
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
  # функция для шифрования файла  
  def encrypt_file(self, file_path: str, password: str) -> bool:
       
