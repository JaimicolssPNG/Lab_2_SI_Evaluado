import socket
import random
import struct
import binascii
import time
from FuncionDH import FuncionDH #Archivo con la funcion Diffie-Hellman
from AES import * #Importa la funcion AES (Todas las funciones)
from Cryptodome.Cipher import DES

#Key para DES y DES3
Key = ("Secretos".encode('utf-8')) #Contraseña de 8 bytes para desencriptar el mensaje
Key2 = ("8bytesKy".encode('utf-8'))
Key3 = ("Password".encode('utf-8'))

#Datos del cliente para generar la A y la key con Diffie-Hellman
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
    print("Los datos fueron enviados correctamente")
    unpacked_data_server = unpacker_client.unpack(Datos_Servidor)
    Cliente_Datos['k'] = FuncionDH(Datos_Servidor[0], Cliente_Datos['a'], Primo)#Se obtiene la key del Cliente
    print("Recibiendo mensaje encriptado...")
    
    if (Cliente_Datos['k'] == unpacked_data_server[1]): #Se comparan la llave del servidor con la del cliente
        Leyendo = True
        Nuevo_Archivo = open("mensajerecibido.txt","wb")
        while Leyendo:
            Mensaje_Encriptado = Cliente_socket.recv(1024)
            desD = DES.new(Key,DES.MODE_ECB)
            #Descomentar para usar 3DES
            #desD2 = DES.new(Key2,DES.MODE_ECB)
            #desD3 = DES.new(Key3,DES.MODE_ECB)
            print("Desencriptando el mensaje...")
            time.sleep(3)
            Mensaje_Desencriptado = desD.decrypt(Mensaje_Encriptado)
            #Descomentar para usar 3DES
            #Mensaje_Desencriptado_2 = desD2.decrypt(Mensaje_Desencriptado)
            #Mensaje_Desencriptado_Final = desD3.decrypt(Mensaje_Desencriptado_2)
            Nuevo_Archivo.write (Mensaje_Desencriptado)#Comentar para usar 3DES
            #Descomentar para usar 3DES
            #Nuevo_Archivo.write (Mensaje_Desencriptado_Final)

        
            if len(Mensaje_Encriptado) < 1:
                print("El archivo fue desencriptado con exito")
                time.sleep(3)
                Leyendo = False
                Nuevo_Archivo.close()
            
                
    else:
        print("Las claves no coinciden, el mensaje no puede ser leido")
        
        
finally:
    print("Cerrando sesion")
    Cliente_socket.close()
