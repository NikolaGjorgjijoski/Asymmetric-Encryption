import AsymmetricEncryption

PrivateKey = AsymmetricEncryption.Main.Generate_Private_Key()['Private Key'] ## This is a Cryptography Object
PrivatePem = AsymmetricEncryption.Main.Generate_Private_Pem(PrivateKey)['Private Pem'] ## This is a string


PublicKey = AsymmetricEncryption.Main.Get_Public_Key(PrivateKey)['Public Key'] ## This is a Cryptography Object
PublicPem = AsymmetricEncryption.Main.Generate_Public_Pem(PublicKey)['Public Pem'] ## This is a string

## Convert PublicPem (String) to Public Key (Cryptography Object)
Conversion_1 = AsymmetricEncryption.Main.Get_Public_Key_From_Public_Pem(PublicPem)['Public Key']

## Convert Private Pem (String) to Private Key (Cryptography Object)
Conversion_2 = AsymmetricEncryption.Main.Get_Private_Key_From_Private_Pem(PrivatePem)['Private Key']

## This is the message we will encrypting and decrypting
Message = "This is a top secret message"

## Encrypt Using Public Key
Encrypted_Message_Using_Public_Key = AsymmetricEncryption.Encrypt.Encrypt_With_Public_Key(PublicKey, Message)['Encrypted Message']

## Encrypt Using Private Key
Encrypted_Message_Using_Private_Key = AsymmetricEncryption.Encrypt.Encrypt_With_Private_Key(PrivateKey, Message)['Encrypted Message']

## Encrypted_Message_Using_Private_Key is the same as Encrypted_Message_Using_Public_Key
Encrypted_Message = Encrypted_Message_Using_Private_Key # or Encrypted_Message_Using_Private_Key does not matter

## Decrypt Using Private Key
Decrypt_Message_Using_Private_Key = AsymmetricEncryption.Decrypt.Decrypt_With_Private_Key(PrivateKey, Encrypted_Message)['Decrypted Message']

## Decrypt Using Private Pem

Decrypt_Message_Using_Private_Pem = AsymmetricEncryption.Decrypt.Decrypt_With_Private_Pem(PrivatePem, Encrypted_Message)['Decrypted Message']
