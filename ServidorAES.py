import socket
import struct
import binascii
import random
import time
from FuncionDH import FuncionDH #Archivo con la funcion Diffie-Hellman
from Cryptodome.Cipher import DES
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

def PAD(Texto):
    while len(Texto) % 8 != 0:
        Texto += " "

    return Texto

key = "1234"
key = key.encode("UTF-8)")
key = pad(key, AES.block_size)
Servidor = {}

Servidor_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
Servidor_socket.bind(("localhost", 8000))
Servidor_socket.listen(1)

unpacker_Server = struct.Struct('I I I')
packer_Server = struct.Struct('I I')
Encendido = True
while Encendido:
    print("Esperando la conexion del cliente...")
    conexion, address = Servidor_socket.accept()
    try:
        Datos_Cliente = conexion.recv(unpacker_Server.size)

        unpacked_data_client = unpacker_Server.unpack(Datos_Cliente)
        print("Los datos fueron recibidos correctamente")
        Servidor["b"] = random.randrange(1, unpacked_data_client[1] - 1) #Numero secreto "b" del servidor
        Servidor["B"] = FuncionDH(unpacked_data_client[0], Servidor["b"], unpacked_data_client[1])
        Servidor["k"] = FuncionDH(unpacked_data_client[2], Servidor["b"], unpacked_data_client[1]) #Key del servidor
        Datos_Servidor = (Servidor["B"], Servidor["k"])
        
        packed_data_Server = packer_Server.pack(*Datos_Servidor)
        conexion.sendall(packed_data_Server)
        print("Leyendo y encriptando mensaje...")
        time.sleep(3)
        Archivo = open("mensajeentrada.txt","rb")
        Leyendo = True
        while Leyendo:
            texto = Archivo.readline()
            encriptar = AES.new(key, AES.MODE_ECB)
            texto_encriptado = encriptar.encrypt(pad(texto,AES.block_size))
            conexion.sendall(texto_encriptado)
            if not texto:
                print("El texto se ha encriptado con éxito.")
                Leyendo = False
    finally:
        print("Terminando conexión")
        Encendido = False
        conexion.close()

     
