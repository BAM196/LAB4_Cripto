#No se utiliza pycrypto por estar obsoleta
#pip uninstall pycrypto
#pip install pycryptodome


from Crypto.Cipher import AES
from Crypto.Cipher import DES
from Crypto.Cipher import DES3

from Crypto.Random import get_random_bytes

from Crypto.Util.Padding import pad, unpad

#para texto legible
from base64 import b64encode

#keys
DesKey = input("DesKey: ").encode('utf-8')#8 bytes
#12345678
AesKey = input("AesKey: ").encode('utf-8') #32 bytes
#12345678901234567890123456789012
Des3Key = input("3DesKey: ").encode('utf-8')#16 o 24 bytes
#1234567890123456
#123456789012345678901234
#vector de inicialización
Desvector = input("Desvector de inicialización: ")#8 bytes
#12345678
Aesvector = input("Aesvector de inicialización: ")#16 bytes
#ejemplo: 1234567890123456
Des3vector = input("3Desvector de inicialización: ")#8 bytes
#12345678
texto = input("Texto a cifrar: ").encode('utf-8')
#texto: b'12345678abcdefgh' #16 bytes   
#DES
def Des_Cifrado(DesKey):
    print(f"DesKey original: {DesKey}")
    if len(DesKey) < 8:
        print("La clave DES debe tener 8 bytes de longitud.")
        DesKey += get_random_bytes(8 - len(DesKey))    
        print(f"DesKey a trabajar: {DesKey}")


    if len(DesKey) > 8:
        print("La clave DES debe tener 8 bytes de longitud.")
        DesKey = DesKey[:8]
        print(f"DesKey a trabajar: {DesKey}")


    cipher = DES.new(DesKey,DES.MODE_CBC, iv = Desvector.encode('utf-8'))
    #msgDES =  cipher.encrypt(texto) 
    #msgDES_texto = b64encode(msgDES).decode('utf-8')
    msgDES  = cipher.encrypt(pad(texto, DES.block_size))
    msgDES_texto = b64encode(msgDES).decode('utf-8')
    print(f"mensaje cifrado bytes [DES]: {msgDES}")
    #print(f"mensaje cifrado [DES]: {msgDES_texto}")
    print(f"mensaje cifrado pad [DES]: {msgDES_texto}")
    #print(f"mensaje cifrado [DES]: {msgDES}")
    return msgDES

def Des_Descifrado(msjen, DesKey):
    decipher = DES.new(DesKey, DES.MODE_CBC, iv=Desvector.encode('utf-8'))
    msgDescifrado = unpad(decipher.decrypt(msjen), DES.block_size)
    print(f"mensaje descifrado [DES]: {msgDescifrado}")

#AES
def Aes_Cifrado(AesKey):
    print(f"AesKey original: {AesKey}")
    if len(AesKey) <24:
        print("La clave Aes debe tener 32 bytes de longitud.")
        AesKey += get_random_bytes(32 - len(AesKey))    
        print(f"AesKey a trabajar: {AesKey}")
    
    if len(AesKey) > 32:
        print("La clave Aes debe tener 32 bytes de longitud.")
        AesKey = AesKey[:32]
        print(f"AesKey a trabajar: {AesKey}")

    cipher = AES.new(AesKey,AES.MODE_CBC, iv= Aesvector.encode('utf-8'))
    msgAES = cipher.encrypt(pad(texto, AES.block_size)) 
    msgAES_texto = b64encode(msgAES).decode('utf-8')
    print(f"mensaje cifrado [AES]: {msgAES}")
    print(f"mensaje cifrado pad [AES]: {msgAES_texto}")
    return msgAES

def Aes_Descifrado(msjen, AesKey):
    decipher = AES.new(AesKey, AES.MODE_CBC, iv=Aesvector.encode('utf-8'))
    msgDescifrado = unpad(decipher.decrypt(msjen), AES.block_size)
    print(f"mensaje descifrado [AES]: {msgDescifrado}")



#DES3
def Des3_Cifrado(Des3Key):
    print(f"Des3Key original: {Des3Key}")
    if len(Des3Key) < 24:
        print("La clave DES3 debe tener 24 bytes de longitud.")
        Des3Key += get_random_bytes(24 - len(Des3Key))    
        print(f"Des3Key a trabajar: {Des3Key}")
    
    if len(Des3Key) > 24:
        print("La clave DES3 debe tener 24 bytes de longitud.")
        Des3Key = Des3Key[:24]
        print(f"Des3Key a trabajar: {Des3Key}")

    cipher = DES3.new(Des3Key,DES3.MODE_CBC, iv= Des3vector.encode('utf-8'))
    msgDES3 = cipher.encrypt(pad(texto, DES3.block_size)) 
    msgDES3_texto = b64encode(msgDES3).decode('utf-8')
    print(f"mensaje cifrado [DES3]: {msgDES3}")
    print(f"mensaje cifrado pad [DES3]: {msgDES3_texto}")
    return msgDES3

def Des3_Descifrado(msjen, Des3Key):
    decipher = DES3.new(Des3Key, DES3.MODE_CBC, iv=Des3vector.encode('utf-8'))
    msgDescifrado = unpad(decipher.decrypt(msjen), DES3.block_size)
    print(f"mensaje descifrado [DES3]: {msgDescifrado}")



BytesDES = Des_Cifrado(DesKey)
#Des_Descifrado(b'\x9e\x1c\x8f\x1e\x9e\xbb\x0c\x9c\x9e\x1c\x8f\x1e\x9e\xbb\x0c\x9c', DesKey)
Des_Descifrado(BytesDES, DesKey)
#Des_Descifrado(b'PXWVqYv/gJ1F6qgMfDtZJUqcjewBWdI4', DesKey)


BytesAES = Aes_Cifrado(AesKey)
Aes_Descifrado(BytesAES, AesKey)


BytesDES3 = Des3_Cifrado(Des3Key)
Des3_Descifrado(BytesDES3, Des3Key)