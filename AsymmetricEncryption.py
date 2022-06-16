from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import *
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64 as BASE64


class Tools:
    
    def Bytes_To_String(Bytes):
        return Bytes.decode("utf-8")
    
    def String_To_Bytes(String):
        return String.encode('utf-8')

class Main:
    
    def Generate_Private_Key():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        return {
            'Private Key': private_key
        }
    
    def Get_Public_Key(Private_Key):
        return {
            'Public Key': Private_Key.public_key()
        }
    
    def Generate_Private_Pem(Private_Key):
        private_pem = Private_Key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return {
            'Private Pem': Tools.Bytes_To_String(private_pem)
        }
    
    def Generate_Public_Pem(Public_Key):
        public_pem = Public_Key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return {
            'Public Pem': Tools.Bytes_To_String(public_pem)
        }
    def Get_Private_Key_From_Private_Pem(Private_Pem):
        Private_Pem = Tools.String_To_Bytes(Private_Pem)
        private_key = serialization.load_pem_private_key(
            Private_Pem,
            password=None,
            backend=default_backend()
        )
        return {
            'Private Key': private_key
        }
    
    def Get_Public_Key_From_Public_Pem(Public_Pem):
        Public_Pem = Tools.String_To_Bytes(Public_Pem)
        public_key = serialization.load_pem_public_key(
            Public_Pem,
            backend=default_backend()
        )
        return {
            'Public Key': public_key
        }
        
class Base64:
    
    def Encode(Message):
        message = Message
        message_bytes = message.encode('utf-8')
        base64_bytes = BASE64.b64encode(message_bytes)
        base64_message = base64_bytes.decode('utf-8')
        return base64_message
    
    def Decode(Base64):
        base64_message = Base64
        base64_bytes = base64_message.encode('utf-8')
        message_bytes = BASE64.b64decode(base64_bytes)
        message = message_bytes.decode('utf-8')
        return message

class Encrypt:
    
    def Encrypt_With_Private_Key(PrivateKey, Message):
        PublicKey = Main.Get_Public_Key(PrivateKey)['Public Key']
        message = Base64.Encode(Message)
        message = Tools.String_To_Bytes(message)
        encrypted = PublicKey.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted = BASE64.b64encode(encrypted)
        encrypted = encrypted.decode('utf-8')
        return {
            'Encrypted Message': encrypted
        }
        
    def Encrypt_With_Public_Key(PublicKey, Message):
        PublicKey = PublicKey
        message = Base64.Encode(Message)
        message = Tools.String_To_Bytes(message)
        encrypted = PublicKey.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted = BASE64.b64encode(encrypted)
        encrypted = encrypted.decode('utf-8')
        return {
            'Encrypted Message': encrypted
        }

class Decrypt:
    
    def Decrypt_With_Private_Key(PrivateKey, EncryptedMessage):
        encrypted = BASE64.b64decode(Tools.String_To_Bytes(EncryptedMessage))
        original_message = PrivateKey.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        original_message = Base64.Decode(original_message.decode('utf-8'))
        return {
            'Decrypted Message': original_message
        }
    
    def Decrypt_With_Private_Pem(PrivatePem, EncryptedMessage):
        PrivateKey = Main.Get_Private_Key_From_Private_Pem(PrivatePem)['Private Key']
        encrypted = BASE64.b64decode(Tools.String_To_Bytes(EncryptedMessage))
        original_message = PrivateKey.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        original_message = Base64.Decode(original_message.decode('utf-8'))
        return {
            'Decrypted Message': original_message
        }
        
        
