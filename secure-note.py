

import os
import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import shutil

class SecureNote:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.notebook = Notebook()
        self.storage_directory = "secure_notes"
        os.makedirs(self.storage_directory, exist_ok=True)

    def generate_keys(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def save_keys(self, private_key_path, public_key_path):
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(private_key_path, "wb") as private_file:
            private_file.write(private_pem)

        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(public_key_path, "wb") as public_file:
            public_file.write(public_pem)

    def load_keys(self, private_key_path, public_key_path):
        with open(private_key_path, "rb") as private_file:
            private_pem = private_file.read()
            self.private_key = serialization.load_pem_private_key(private_pem, password=None, backend=default_backend())

        with open(public_key_path, "rb") as public_file:
            public_pem = public_file.read()
            self.public_key = serialization.load_pem_public_key(public_pem, backend=default_backend())

    def encrypt(self, plaintext):
        ciphertext = self.public_key.encrypt(
            plaintext.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    def decrypt(self, ciphertext):
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode()

    def add_note(self, message):
        ciphertext = self.encrypt(message)
        self.notebook.add_note(ciphertext)

    def delete_note(self, index):
        self.notebook.delete_note(index)

    def get_notes(self):
        notes = self.notebook.get_notes()
        decrypted_notes = [self.decrypt(note) for note in notes]
        return decrypted_notes

    def save_to_file(self, filename, content):
        file_path = os.path.join(self.storage_directory, filename)
        with open(file_path, "wb") as file:
            file.write(content)

    def load_from_file(self, filename):
        file_path = os.path.join(self.storage_directory, filename)
        with open(file_path, "rb") as file:
            content = file.read()
        return content

    def list_files(self):
        files = os.listdir(self.storage_directory)
        return files

    def export_file(self, filename, destination):
        file_path = os.path.join(self.storage_directory, filename)
        shutil.copy(file_path, destination)

    def delete_file(self, filename):
        file_path = os.path.join(self.storage_directory, filename)
        os.remove(file_path)

    def export_notes(self, with_password=False, password=None):
        notes = self.get_notes()
        if with_password:
            decrypted_notes = []
            for note in notes:
                try:
                    decrypted_note = self.decrypt(note)
                    decrypted_notes.append(decrypted_note)
                except cryptography.exceptions.InvalidKey:
                    print("پسورد نادرست. رمزگشایی ناموفق.")
                    return None
            return decrypted_notes
        else:
            return notes

class Notebook:
    def __init__(self):
        self.notes = []

    def add_note(self, note):
        self.notes.append(note)

    def delete_note(self, index):
        if index >= 0 and index < len(self.notes):
            del self.notes[index]

    def get_notes(self):
        return self.notes

note_app = SecureNote()
note_app.generate_keys()
note_app.save_keys("private_key.pem", "public_key.pem")
note_app.load_keys("private_key.pem", "public_key.pem")

while True:
    print("1. اضافه کردن یادداشت")
    print("2. حذف یادداشت")
    print("3. نمایش یادداشت‌ها")
    print("4. گرفتن یادداشت‌ها (با پسورد)")
    print("5. گرفتن یادداشت‌ها (بدون پسورد)")
    print("6. خروج")

    choice = input("لطفاً شماره گزینه را وارد کنید: ")

    if choice == "1":
        message = input("لطفا متن یادداشت خود را وارد کنید: ")
        note_app.add_note(message)
        print("یادداشت اضافه شد.")
    elif choice == "2":
        index = int(input("لطفاً شماره یادداشت مورد نظر برای حذف را وارد کنید: "))
        note_app.delete_note(index - 1)
        print("یادداشت حذف شد.")
    elif choice == "3":
        notes = note_app.get_notes()
        print("لیست یادداشت‌ها:")
        for i, message in enumerate(notes):
            print(f"{i + 1}. {message}")
    elif choice == "4":
        password = input("لطفاً پسورد را وارد کنید: ")
        notes = note_app.export_notes(with_password=True, password=password)
        if notes is not None:
            print("یادداشت‌ها (رمزگشایی با پسورد):")
            for i, message in enumerate(notes):
                print(f"{i + 1}. {message}")
    elif choice == "5":
        notes = note_app.export_notes(with_password=False)
        if notes is not None:
            print("یادداشت‌ها (بدون رمزگشایی):")
            for i, message in enumerate(notes):
                print(f"{i + 1}. {message}")
    elif choice == "6":
        break
    else:
        print("گزینه نامعتبر. لطفاً دوباره وارد کنید.")
