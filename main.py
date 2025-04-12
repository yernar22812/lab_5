from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature
import base64
import os

#Генерация ключей два ключа публичный(для шифрования) и приватный(для расшифровки)
def generate_keys():
    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537, # стандартные числа для безопасности
            key_size=2048 # размер стандартный для скорости
        )
        public_key = private_key.public_key() # генерирует уже

        # Save private key
        with open("private_key.pem", "wb") as f:
            f.write(private_key.private_bytes( # сохораняет в байт чтобы потом норм сохранить
                encoding=serialization.Encoding.PEM, # в pem файле сохнраиться обчно ключи именно в таком формате хранятся
                format=serialization.PrivateFormat.TraditionalOpenSSL, # в традиционном формате сохраняется есть новее но не везде использовать можно                encryption_algorithm=serialization.NoEncryption()
            ))

        # Save public key
        with open("public_key.pem", "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo #тоже стандарт использует
            ))

        print("✅ Ключи успешно сгенерированы и сохранены в файлы .pem")
    except Exception as e:
        print(f"❌ Ошибка при генерации ключей: {e}")

#Шифрование шифрует введеный текст с использованием публичного ключа выводит и сохраняет в файле
def encrypt_message(message):
    try:
        with open("public_key.pem", "rb") as f: # открывает тот pem файл
            public_key = serialization.load_pem_public_key(f.read())

        encrypted = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()), # паддинг добавляет случайность  MGF1 делает маску для большей безопасности
                algorithm=hashes.SHA256(), # хэширует для целостности данных и для защиты
                label=None
            )
        )

        encoded = base64.b64encode(encrypted).decode() # расшифровывает и выводит уже в нормальном виде сообщение
        print("🔒 Зашифрованное сообщение:\n" + encoded)

        with open("encrypted_message.txt", "w") as f: # открывает файл в режиме WWWW если файла нет он создаст если есть то перезапишет блок with гарантирует закрывание файла
            f.write(encoded)

    except Exception as e:
        print("❌ Ошибка при шифровании:", e)

#Дешифрование получает в себя строку base 64 декодирует её и расшифровывает при помощи уже приватного ключа и выводит исходное сообщение
def decrypt_message(encoded):
    try:
        with open("private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        encrypted = base64.b64decode(encoded.encode())

        decrypted = private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        print("🔓 Расшифрованное сообщение:\n" + decrypted.decode())

    except Exception as e:
        print("❌ Ошибка при расшифровке:", e)

#Подпись
def sign_message(message):
    try:
        with open("private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        signature = private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        encoded_sig = base64.b64encode(signature).decode()
        print("✍️ Цифровая подпись:\n" + encoded_sig)

        with open("signature.txt", "w") as f:
            f.write(encoded_sig)

    except Exception as e:
        print("❌ Ошибка при создании подписи:", e)

#Проверка подписи
def verify_signature(message, encoded_signature):
    try:
        with open("public_key.pem", "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())

        signature = base64.b64decode(encoded_signature.encode())

        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        print("✅ Подпись действительна (сообщение подлинное).")

    except InvalidSignature:
        print("❌ Подпись недействительна (сообщение подделано).")
    except Exception as e:
        print("❌ Ошибка при проверке подписи:", e)

# простая менюшка
def main():
    while True:
        print("\n📬 RSA Secure Message App - Меню:")
        print("1. Сгенерировать ключи")
        print("2. Зашифровать сообщение")
        print("3. Расшифровать сообщение")
        print("4. Загрузить зашифрованное сообщение из файла")
        print("5. Подписать сообщение")
        print("6. Проверить подпись")
        print("7. Выход")
        choice = input("> ")

        if choice == "1":
            generate_keys()
        elif choice == "2":
            message = input("Введите сообщение для шифрования: ")
            encrypt_message(message)
        elif choice == "3":
            encoded = input("Вставьте зашифрованное сообщение (base64): ")
            decrypt_message(encoded)
        elif choice == "4":
            if os.path.exists("encrypted_message.txt"):
                with open("encrypted_message.txt", "r") as f:
                    encoded = f.read()
                    decrypt_message(encoded)
            else:
                print("Файл encrypted_message.txt не найден.")
        elif choice == "5":
            msg = input("Введите сообщение для подписи: ")
            sign_message(msg)
        elif choice == "6":
            msg = input("Введите оригинальное сообщение: ")
            sig = input("Вставьте цифровую подпись (base64): ")
            verify_signature(msg, sig)
        elif choice == "7":
            break
        else:
            print("❗ Неверный выбор. Попробуйте снова.")

if __name__ == "__main__":
    main()
