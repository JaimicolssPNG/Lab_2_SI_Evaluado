import socket
import struct
import binascii
import random
import time
from FuncionDH import FuncionDH #Archivo con la funcion Diffie-Hellman
from AES import *
from Cryptodome.Cipher import DES

def PAD(Texto): #Padding para el texto a encriptar
    while len(Texto) % 8 != 0:
        Texto += " "

    return Texto

#Key para DES y DES3
Key = ("Secretos".encode('utf-8')) #Contraseña de 8 bytes para encriptar el mensaje
Key2 = ("8bytesKy".encode('utf-8'))
Key3 = ("Password".encode('utf-8'))

#Datos del cliente para generar la B y la key con Diffie-Hellman
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
        time.sleep(3)
        print("Los datos fueron recibidos correctamente")
        Servidor["b"] = random.randrange(1, unpacked_data_client[1] - 1) #Numero secreto "b" del servidor
        Servidor["B"] = FuncionDH(unpacked_data_client[0], Servidor["b"], unpacked_data_client[1])
        Servidor["k"] = FuncionDH(unpacked_data_client[2], Servidor["b"], unpacked_data_client[1]) #Key del servidor
        Datos_Servidor = (Servidor["B"], Servidor["k"])
        
        packed_data_Server = packer_Server.pack(*Datos_Servidor)
        conexion.sendall(packed_data_Server)
        print("Leyendo y encriptando mensaje...")
        time.sleep(3)
        Archivo = open("mensajeentrada.txt")
        Leyendo = True
        while Leyendo:
            Texto = Archivo.readline()
            desE = DES.new(Key, DES.MODE_ECB)
            #Descomentar para usar 3DES
            #desE2 = DES.new(Key2,DES.MODE_ECB)
            #desE3 = DES.new(Key3,DES.MODE_ECB)
            Padded_Texto = PAD(Texto)
            Mensaje_Final = Padded_Texto.encode('utf-8')
            #Descomentar para usar 3DES
            #Mensaje_Encriptado = desE3.encrypt(Mensaje_Final)
            #Mensaje_Encriptado_2 = desE2.encrypt(Mensaje_Encriptado)
            #Mensaje_Encriptado_Final = desE.encrypt(Mensaje_Encriptado_2)
            Mensaje_Encriptado_Final = desE.encrypt(Mensaje_Final) #Comentar para usar 3DES
            print("Enviando mensaje encriptado...")
            conexion.sendall(Mensaje_Encriptado_Final)
            time.sleep(3)
            if not Texto:
                Leyendo = False
                Archivo.close()
    finally:
        print("Terminando conexion")
        Encendido = False
        conexion.close()

     
