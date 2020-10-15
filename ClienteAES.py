import socket
import random
import struct
import binascii
import time
from FuncionDH import FuncionDH #Archivo con la funcion Diffie-Hellman
from Cryptodome.Cipher import DES
from Cryptodome.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from Cryptodome.Cipher import AES

key = "1234"
key = key.encode("UTF-8)")
key = pad(key, AES.block_size)#Contraseña de 8 bytes para desencriptar el mensaje
Cliente_Datos = {}

Numeros_Primos = [109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463]
Primo = random.choice(Numeros_Primos) #Numero primo (Cliente y Servidor)
g = random.randrange(1, 100) #Numero g (Cliente y Servidor)

a = random.randrange(1, Primo-1)#Numero secreto del Cliente

Cliente_Datos['a'] = a
Cliente_Datos['A'] = FuncionDH(g, Cliente_Datos['a'], Primo) #Se obtiene A del cliente

#Conexion con el Servidor
Cliente_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
Cliente_socket.connect(("localhost", 8000))

Datos_Publicos = (g, Primo, Cliente_Datos['A']) #Datos publicos para el Cliente y el Servidor
packer_client = struct.Struct('I I I')
packed_data_client = packer_client.pack(*Datos_Publicos)

unpacker_client = struct.Struct('I I')
try:
    #Enviar los datos
    print("Enviando los valores de g, p y A")
    Cliente_socket.sendall(packed_data_client)
    Datos_Servidor = Cliente_socket.recv(unpacker_client.size)
    time.sleep(3)
    print("Los datos fueron enviados correctamente")
    unpacked_data_server = unpacker_client.unpack(Datos_Servidor)
    Cliente_Datos['k'] = FuncionDH(Datos_Servidor[0], Cliente_Datos['a'], Primo) #Se obtiene la key del Cliente
    print("Recibiendo mensaje encriptado...")
    if (Cliente_Datos['k'] == unpacked_data_server[1]): #Se comparan la llave del servidor con la del cliente
        Leyendo = True
        Nuevo_Archivo = open("mensajerecibido.txt","wb")
        while Leyendo:
            msj_encriptado = Cliente_socket.recv(1024)                              
            desencriptar= AES.new(key, AES.MODE_ECB)
            msj_desencriptado = desencriptar.decrypt(msj_encriptado)
            Nuevo_Archivo.write(msj_desencriptado)
            if len(msj_encriptado) < 1:
                Leyendo = False
                Nuevo_Archivo.close()
    else:
                print("Las claves no coinciden, el mensaje no puede ser leido")
        
        
finally:
    print("Cerrando sesion")
    Cliente_socket.close()
