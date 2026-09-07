<p align="center">
<img src="assets/1.png" width="1000">
</p>

La intrusión se desarrolla sobre un entorno Windows de elevada complejidad, articulado en torno a una
aplicación web corporativa que expone un servicio vulnerable a inyección SQL, vector que permite obtener
acceso  inicial  al  servidor  y  enumerar  información  sensible  del  backend.  La  inspección  del  sistema
comprometido revela la presencia de una versión vulnerable de Visual Studio Code, cuyos procesos se
encuentran activos y cuya funcionalidad de depuración remota habilita la ejecución arbitraria de código. La
explotación de este subsistema permite obtener una sesión interactiva bajo la identidad del usuario cyork,
consolidando así un primer movimiento lateral dentro del host.

El  análisis  del  código  fuente de  la  aplicación,  tras  la  exfiltración  de  la  biblioteca  MultimasterAPI.dll,
revela  credenciales  embebidas  en  una  cadena  de  conexión.  La  reutilización  de  esta  contraseña  en  otros
servicios del dominio permite acceder mediante WinRM como sbauer, identidad que dispone de permisos
GenericWrite  sobre  el  objeto  de  usuario  jorden.  Este  privilegio  habilita  la  manipulación  de  atributos
críticos  del  directorio,  entre  ellos  la  configuración  de  pre-autenticación  Kerberos,  cuya  desactivación
posibilita la ejecución de un ataque de AS-REP Roasting y la obtención del hash Kerberos del usuario.

El descifrado del hash proporciona acceso directo a la cuenta jorden, miembro del grupo Server Operators,
cuyas capacidades permiten modificar la ruta de ejecución de servicios que operan en contexto SYSTEM.
La explotación de este privilegio culmina en la obtención de una sesión con privilegios máximos sobre el
sistema,  habilitando  la  ejecución  de  ataques  de  replicación  como  DCSync  y,  en  última  instancia,  el
compromiso total del dominio.

<p align="center"><strong><u>Enumeración</u></strong></p>

La dirección IP de la máquina víctima es 10.129.95.200. Por tanto, envié 5 trazas ICMP para verificar que existe conectividad entre las dos máquinas.

<img src="assets/2.jpg">

Una vez que identificada la dirección IP de la máquina objetivo, utilicé el comando nmap -p- -sS -sC -sV --min-rate 5000 -vvv -Pn 10.129.95.200 -oN scanner_multimaster para descubrir los puertos abiertos y sus versiones:

- (-p-): realiza un escaneo de todos los puertos abiertos.
- (-sS): utilizado para realizar un escaneo TCP SYN, siendo este tipo de escaneo el más común y rápido, además de ser relativamente sigiloso ya que no llega a completar las conexiones TCP. Habitualmente se conoce esta técnica como sondeo de medio abierto (half open). Este sondeo consiste en enviar un paquete SYN, si recibe un paquete SYN/ACK indica que el puerto está abierto, en caso contrario, si recibe un paquete RST (reset), indica que el puerto está cerrado y si no recibe respuesta, se marca como filtrado.
- (-sC): utiliza los scripts por defecto para descubrir información adicional y posibles vulnerabilidades. Esta opción es equivalente a --script=default. Es necesario tener en cuenta que algunos de estos scripts se consideran intrusivos ya que podría ser detectado por sistemas de detección de intrusiones, por lo que no se deben ejecutar en una red sin permiso.
- (-sV): Activa la detección de versiones. Esto es muy útil para identificar posibles vectores de ataque si la versión de algún servicio disponible es vulnerable. 
- (--min-rate 5000): ajusta la velocidad de envío a 5000 paquetes por segundo.
- (-Pn): asume que la máquina a analizar está activa y omite la fase de descubrimiento de hosts.

<img src="assets/3.jpg">

El reconocimiento inicial mediante Nmap evidenció una superficie de exposición significativamente amplia,
con  múltiples  servicios  accesibles  desde  el  exterior.  Entre  ellos  destacaban  los  puertos  53/TCP  (DNS),
389/TCP (LDAP) y 445/TCP (SMB), cuya concurrencia funcional constituye un indicador inequívoco de
que  el  activo  analizado  desempeña  el  rol  de  controlador  de  dominio  dentro  de  la  infraestructura
corporativa. La propia herramienta identificó el dominio asociado como MEGACORP.LOCAL, lo que
permitió inferir desde el inicio la presencia de un entorno Windows con servicios de directorio plenamente
operativos.

<img src="assets/4.jpg"> 

<p align="center"><strong><u>IIS</u></strong></p>

El  acceso  al  servicio  HTTP  en  el  puerto  80  reveló  un  portal  corporativo  orientado  a  empleados,
presumiblemente utilizado como interfaz de interacción interna. La navegación inicial permitió identificar
un mecanismo de autenticación accesible desde el botón LOGIN.

<img src="assets/5.jpg"> 

Sin  embargo,  la  funcionalidad  se  encontraba  temporalmente  inhabilitada,  devolviendo  un  mensaje  que
informaba de tareas de mantenimiento en curso.

<img src="assets/6.jpg"> 

Este comportamiento sugiere que el componente de autenticación no estaba expuesto en su totalidad o que
el backend asociado se encontraba parcialmente deshabilitado.

<img src="assets/7.jpg"> 

La sección Gallery del portal resultó ser estática y carente de elementos interactivos relevantes, limitándose
a la exposición de imágenes sin metadatos ni funcionalidades adicionales.

<img src="assets/8.jpg"> 

En contraste, la sección Colleague Finder sí presentaba un vector de interés: un campo de búsqueda que,
incluso cuando se enviaba vacío, devolvía un conjunto de resultados con atributos asociados a empleados,
incluyendo nombre, rol profesional y dirección de correo electrónico.

<img src="assets/9.jpg"> 

Este comportamiento indicaba la existencia de un backend accesible y potencialmente manipulable, por lo
que  se  procedió  a  interceptar la  solicitud  mediante  Burp  Suite,  reenviándola  posteriormente  al  módulo
Repeater para su análisis exhaustivo.

<img src="assets/10.jpg"> 

La inspección de la petición reveló un POST dirigido al endpoint /api/getColleagues, con un parámetro
name encapsulado en un cuerpo JSON. La respuesta del servidor, igualmente en formato JSON, incluía los
campos id, name, position, email y src, lo que confirmaba la existencia de un servicio de enumeración de
empleados expuesto sin restricciones aparentes.

Para validar la consistencia del endpoint y facilitar la extracción masiva de datos, se procedió a replicar la
solicitud  mediante  cURL,  procesando  la  salida  con  jq  para  obtener  una  representación  estructurada  y
manipulable de la información devuelta por el servidor.

<img src="assets/11.jpg"> 

Del mismo modo que en el caso de los nombres, la extracción de direcciones de correo electrónico resultó
igualmente trivial, permitiendo consolidar ambos conjuntos de datos en archivos independientes (names.txt
y emails.txt) para su posterior explotación en fases avanzadas de enumeración.

<img src="assets/12.jpg"> 

El comportamiento del endpoint sugiere de manera inequívoca que la consulta está siendo delegada a un
motor de base de datos, lo que convierte a este vector en un candidato idóneo para evaluar la presencia de
vulnerabilidades  de  inyección  SQL.  Como  aproximación  inicial,  se  procedió  a  introducir  un  apóstrofo
aislado en el parámetro de búsqueda con el fin de observar la reacción del backend.

<img src="assets/13.jpg"> 

La  respuesta  del  servidor  consistió  en  un  403  Forbidden,  lo  que  constituye  un  indicio  razonable  de  la
existencia de mecanismos de filtrado de entrada, ya sea implementados en la propia lógica de la aplicación
o mediante un Web Application Firewall. Ante este tipo de restricciones, una estrategia habitual consiste
en explorar variantes de codificación alternativas que puedan ser aceptadas por el parser JSON antes de
alcanzar la capa de filtrado.

<img src="assets/14.jpg"> 

El  análisis  de  la  especificación  RFC  correspondiente  revela  que,  aunque  la  codificación  por  defecto  es
UTF-8, el estándar contempla también UTF-16 y UTF-32, lo que abre la posibilidad de introducir cargas
útiles en formatos no previstos por los controles de seguridad.

```python
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
```

La inyección de un apóstrofo codificado en UTF-16 no generó ningún error, lo que justificó profundizar en
esta vía de explotación. Para ello, se recurrió a un conversor en línea y, posteriormente, a un script en Python
que permitiera automatizar la codificación de cargas útiles arbitrarias. Se procedió entonces a transformar
la  cadena  '  or  1=1--  -  a  su  representación  en  UTF-16,  obteniendo  un  payload  apto  para  ser  enviado  al
endpoint sin activar los mecanismos de bloqueo previamente observados.

<img src="assets/15.png"> 

La ejecución de la solicitud con la carga útil codificada resultó exitosa, confirmando de manera concluyente
la existencia de una vulnerabilidad de inyección SQL en el servicio.

<img src="assets/16.jpg"> 

A  partir  de  este  punto,  el  siguiente  paso  metodológico  consistió  en  determinar  el  número  de  columnas
devueltas  por  la  consulta  subyacente,  requisito  indispensable  para  construir  payloads  más  complejos  y
avanzar hacia técnicas de extracción de información estructurada del motor de base de datos comprometido.

<img src="assets/17.jpg"> 

La  inyección  del  payload  previamente  construido  devolvió  resultados  válidos,  lo  que  confirmó  que  la
consulta subyacente aceptaba la manipulación del parámetro y que la carga útil era procesada sin activar
mecanismos de filtrado adicionales.

<img src="assets/18.jpg"> 

A  partir  de  este  punto,  resultaba  imprescindible  determinar  la  estructura  exacta  de  la  tabla  afectada,  en
particular el número de columnas, para poder avanzar hacia técnicas de extracción más sofisticadas.

<img src="assets/19.jpg"> 

La prueba destinada a verificar si la tabla contenía más de cinco columnas devolvió un valor nulo, lo que
permitió concluir que la estructura estaba compuesta exactamente por cinco columnas, en consonancia con
los campos observados en las respuestas JSON del endpoint.

<img src="assets/20.jpg"> 

La correlación con los resultados del reconocimiento inicial evidenció que el motor de base de datos en uso
era  Microsoft  SQL  Server,  lo  que  condicionó  tanto  la  sintaxis  de  los  payloads  como  las  técnicas  de
enumeración posteriores.

<img src="assets/21.jpg"> 

Se procedió entonces a identificar la versión del motor y el nombre de la base de datos activa, obteniéndose
como resultado Hub_DB, que se convirtió en el punto focal de la fase de descubrimiento de objetos internos.

<img src="assets/22.jpg"> 

La enumeración de las tablas presentes en la base de datos reveló únicamente dos entidades: Colleagues y
Logins.

<img src="assets/23.jpg"> 

Mientras  que  la  primera  correspondía  al  conjunto  de  datos  ya  expuesto  por  el  portal  web,  la  segunda
constituía un vector de interés crítico, dado que su denominación sugería la presencia de credenciales o
artefactos relacionados con autenticación.

<img src="assets/24.jpg"> 

La  inspección  de  su  estructura  confirmó  esta  hipótesis:  la  tabla  Logins  contenía  exclusivamente  dos
columnas,  username  y  password,  lo  que  indicaba  que  almacenaba  pares  de  credenciales  en  formato
persistente.

<img src="assets/25.jpg"> 

La extracción de los valores contenidos en ambas columnas se completó sin restricciones, proporcionando
un conjunto de nombres de usuario y contraseñas en formato hash. La longitud de los hashes, 96 bytes,
constituye  un  indicador  relevante  para  la  identificación  del  algoritmo  empleado,  y  su  análisis  posterior
permitiría determinar la viabilidad de un ataque de cracking offline o la necesidad de recurrir a técnicas de
descifrado más avanzadas.

<img src="assets/26.jpg"> 

Para identificar el algoritmo de hashing empleado en las credenciales extraídas, se procedió a realizar una
correlación entre la longitud observada —96 bytes— y los modos soportados por Hashcat, utilizando un
filtrado previo en Bash para localizar todos los algoritmos cuya salida coincide con dicho tamaño.

<img src="assets/27.jpg"> 

El  análisis  reveló  que  los  candidatos  plausibles  eran  SHA2-384,  SHA3-384  y  Keccak-384,  todos  ellos
pertenecientes a  la familia de funciones criptográficas  de 384  bits. La tabla  contenía  únicamente cuatro
hashes  únicos,  por  lo  que  se  consolidaron  en  un  archivo  destinado  a  un  ataque  de  fuerza  bruta  offline,
empleando los modos 10800, 17500 y 17900 de Hashcat, correspondientes a los algoritmos identificados.

<img src="assets/28.jpg"> 

La ejecución del ataque utilizando el modo Keccak-384 permitió descifrar tres de los cuatro hashes, lo que
proporcionó  un  conjunto  inicial  de  contraseñas  en  texto  claro.  Dado  que  la  enumeración  previa  había
permitido  obtener  una  lista  exhaustiva  de  direcciones  de  correo  electrónico  corporativas,  se  procedió  a
derivar de ellas un conjunto ampliado de posibles nombres de usuario, asumiendo la práctica habitual en
entornos empresariales de utilizar el prefijo del correo como identificador de autenticación.

<img src="assets/29.jpg"> 

Con ambos conjuntos —las contraseñas descifradas y la lista de posibles usuarios— se llevó a cabo una
campaña  de  password  spraying  contra  los  servicios  expuestos  externamente,  concretamente  SMB  y
WinRM, utilizando la herramienta netexec para automatizar la interacción y registrar de forma precisa los
resultados.

<img src="assets/30.jpg"> 

Ninguna de las combinaciones probadas resultó válida, lo que indica que las credenciales descifradas no
pertenecen a los usuarios enumerados previamente o que su ámbito de validez se restringe a otros servicios
internos no expuestos en la superficie de ataque inicial.

<p align="center"><strong><u>Domain User Enumeration</u></strong></p>

En  entornos  Active  Directory,  cada  entidad  de  seguridad  —usuarios,  grupos  y  equipos—  posee  un
identificador  único  denominado  RID  (Relative  Identifier),  que  constituye  el  segmento  final  del  SID
(Security  Identifier).  Este  mecanismo  es  conceptualmente  análogo  al  principal_id  de  SQL  Server:  un
contador incremental que asigna valores consecutivos a los objetos del dominio. La obtención del RID de
un usuario concreto permite inferir la estructura del SID y, por extensión, iterar sobre rangos completos de
RIDs para identificar otros objetos del dominio mediante técnicas de enumeración lateral.

<img src="assets/31.jpg"> 

SQL Server proporciona la función SUSER_SID(), que devuelve el SID asociado a un usuario determinado.
Se  empleó  esta  función  para recuperar  el  SID del  administrador  primario  del  dominio.  Sin  embargo,  la
salida se presentó en formato VARBINARY, y la conversión implícita realizada por la cláusula UNION
generó una representación ilegible.

<img src="assets/32.jpg"> 

Para solventar esta limitación, se optó por exfiltrar el SID carácter por carácter, utilizando la columna id
como  canal  de  retorno  y  determinando  previamente  la  longitud  total  del  SID  mediante  la  función
DATALENGTH().

<img src="assets/33.jpg"> 

La función SUBSTRING() permitió extraer cada byte de forma individual. La primera consulta devolvió
el valor 1, lo que implica que los dos primeros dígitos del SID son 01, un comportamiento coherente con la
estructura estándar de los identificadores de seguridad en Windows.

<img src="assets/33.jpg"> 

A  partir  de  este  punto,  se  automatizó  el  proceso  mediante  un  script  que  incrementaba  la  posición  del
substring para enumerar secuencialmente todos los bytes del SID. Durante la ejecución se observó que el
servidor comenzaba a bloquear solicitudes tras varios intentos consecutivos, lo que sugiere la intervención
de un WAF.

<img src="assets/34.jpg"> 

Para  evitar  su  detección,  se  introdujo  un  retardo  de  dos  segundos  entre  cada  petición,  lo  que  permitió
completar la exfiltración sin interrupciones. Una vez reconstruido el SID completo, se utilizó la función
SUSER_SNAME() para realizar una resolución inversa y validar la identidad asociada.

<img src="assets/35.jpg"> 

La  consulta  devolvió  correctamente  MEGACORP\Administrator,  lo  que  confirmó  la  integridad  del
proceso de exfiltración.

<img src="assets/36.jpg"> 

El SID obtenido tenía una longitud total de 56 bytes, de los cuales los primeros 48 bytes correspondían al
SID del dominio, es decir, el identificador raíz a partir del cual se construyen todos los RIDs de objetos
del bosque. Con esta información, fue posible comenzar a generar RIDs arbitrarios para enumerar usuarios
del dominio de forma secuencial.

<img src="assets/37.jpg"> 

En Active Directory, cualquier objeto creado por administradores —y no por el propio sistema operativo—
recibe un RID igual o superior a 1000. El análisis de los últimos ocho bytes del SID exfiltrado reveló el
valor f401, que, tras invertir el orden y convertirlo a entero, produce 500, el RID reservado para la cuenta
Administrator por defecto. Este hallazgo confirmó la validez del método y permitió establecer el punto de
partida para la enumeración sistemática de usuarios.

Con la estructura del SID del dominio plenamente reconstruida y el RID base identificado, se automatizó
el proceso de bruteforce de RIDs a partir del valor 1000, con el objetivo de identificar usuarios adicionales
del dominio mediante consultas sucesivas al motor SQL.

```python
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
```

Este  procedimiento  constituye  una  técnica  avanzada  de  enumeración  lateral  que  permite  reconstruir  la
topología de identidades del dominio incluso en ausencia de privilegios directos sobre Active Directory.

<img src="assets/38.jpg"> 

Foothold

El proceso de enumeración automatizada permitió identificar cuatro usuarios adicionales en el dominio.
Con  este  nuevo  conjunto  de  identidades,  se  procedió  a  realizar  un  password  spraying  sistemático
utilizando netexec, orientado a los servicios expuestos externamente, concretamente SMB y WinRM.

La prueba reveló que las credenciales tushikikatomo / finance1 eran válidas para WinRM, lo que habilitó
un vector de acceso remoto mediante el protocolo nativo de administración de Windows en el puerto 5985.

Se  estableció  una  sesión  interactiva  utilizando  Evil-WinRM,  confirmando  la  autenticidad  de  las
credenciales y la capacidad de ejecutar comandos en el sistema comprometido.

WinRM

La inspección inicial del entorno reveló que el usuario carecía de privilegios elevados y no disponía de
acceso al directorio C:\inetpub, lo que sugiere un perfil operativo limitado.

19 de agosto de 2026

18

Lateral Movement (cyork)

Se continuó con la fase de enumeración del host para identificar posibles vectores de movimiento lateral.
El  análisis  del  directorio  Program  Files  evidenció  la  presencia  de  Visual  Studio  Code  (VSCode),  un
hallazgo relevante dado que ciertas versiones del editor incorporan funcionalidades de depuración remota
susceptibles de abuso.

La  enumeración  de  procesos  mediante  Get-Process  confirmó  que  múltiples  instancias  de  VSCode  se
encontraban activas. La verificación de la versión instalada reveló que correspondía a una iteración afectada
por una vulnerabilidad de ejecución remota de comandos, documentada públicamente en un análisis técnico
que  incluye  un  aviso  de  seguridad  emitido  por  Tavis  Ormandy.  Dicho  aviso  detalla  que  el  VSCode
Remote  Debugger  permanece  habilitado  por  defecto,  exponiendo  un  canal  de  depuración  basado  en
tecnologías Electron, Chromium y CEF.

En  este  contexto,  resulta  pertinente  describir  brevemente  el  funcionamiento  del  CEF  debugger.  El
Chromium  Embedded  Framework  (CEF)  es  una  arquitectura  que  permite  integrar  componentes  del
navegador Chromium dentro de aplicaciones nativas.  Su debugger expone  un  conjunto de  interfaces de
inspección y control diseñadas para desarrolladores, incluyendo la capacidad de evaluar código JavaScript
en tiempo real, manipular el DOM y ejecutar comandos dentro del contexto del proceso que aloja el motor.

Cuando  estas  interfaces  se  encuentran  habilitadas  sin  restricciones,  pueden  ser  instrumentalizadas  para
obtener  ejecución  arbitraria  de  código  en  el host,  convirtiéndose  en  un  vector  de  explotación  altamente
eficaz.

19 de agosto de 2026

19

La  búsqueda  de  recursos  relacionados  con  el  aviso  de  Ormandy  condujo  al  repositorio  cefdebug,  que
proporciona binarios compilados para interactuar con depuradores de Electron, CEF y Chromium.

Tras descargar y descomprimir la versión correspondiente, el binario fue transferido al servidor mediante
el comando upload de Evil-WinRM.

Su  ejecución  permitió  identificar  los  sockets  de  depuración  activos,  confirmando  la  presencia  de  dos
instancias de CEF debugger escuchando en el sistema.

Se  procedió  a  validar  la  vulnerabilidad  mediante  la  ejecución  de  código  de  prueba,  lo  que  confirmó  la
capacidad de interactuar con el servicio y ejecutar instrucciones dentro del contexto del proceso.

Con la interacción establecida, el siguiente objetivo consistió en obtener una reverse shell. Para ello, se
levantó un servidor web en el puerto 80 y se emitieron las instrucciones necesarias para descargar un binario
de Netcat en el host comprometido, preparando así el entorno para establecer un canal de retorno hacia la
infraestructura del auditor.

Con el binario de Netcat ya transferido al host comprometido, se procedió a habilitar un listener en el puerto
9001,  estableciendo  así  el  canal  de  retorno  necesario  para  obtener  una  reverse  shell  desde  el  proceso
vulnerable.

19 de agosto de 2026

20

La ejecución del payload a través del depurador confirmó la capacidad de invocar instrucciones arbitrarias
en el contexto del proceso de VSCode, lo que permitió materializar la conexión inversa y obtener una sesión
interactiva plenamente operativa.

Lateral Movement (sbauer)

La inspección del entorno de ejecución reveló que la cuenta cyork pertenecía al grupo Developers, una
pertenencia especialmente relevante dado que este grupo dispone de permisos de acceso sobre el directorio
C:\inetpub,  un  enclave  habitual  para  aplicaciones  web  y  servicios  expuestos.  Este  hallazgo  abrió  la
posibilidad  de  identificar  artefactos  sensibles,  configuraciones  internas  o  componentes  susceptibles  de
abuso para escalar privilegios o pivotar hacia otros servicios.

El  análisis  preliminar  del  contenido  de  C:\inetpub  evidenció  la  presencia  de  archivos  y  directorios  de
interés,  cuya  estructura  y  función  sugerían  la  existencia  de  componentes  web  activos  o  residuales.  La
enumeración detallada de estos elementos constituiría el siguiente paso lógico en la fase de movimiento
lateral,  dado  que  los  directorios  de  publicación  web  suelen  albergar  configuraciones,  credenciales
embebidas,  scripts  ejecutables  o  binarios  auxiliares  que  pueden  ser  instrumentalizados  para  obtener
persistencia o elevar privilegios dentro del sistema comprometido.

19 de agosto de 2026

21

Reverse Engineering

El directorio bin dentro de C:\inetpub resultó particularmente sugestivo desde una perspectiva ofensiva. Su
inspección  minuciosa  reveló  la  presencia  de  la  biblioteca  MultimasterAPI.dll,  un  componente
potencialmente crítico al tratarse de una pieza ensamblada para la lógica interna de la aplicación web. Con
el fin de proceder a un análisis estático y dinámico más exhaustivo, se habilitó un servidor SMB mediante
el módulo smbserver.py de Impacket, lo que permitió transferir la DLL hacia el entorno del auditor de forma
controlada.

La operación de copia se realizó tras mapear la unidad remota mediante el comando net use, estableciendo
así un canal de comunicación persistente entre el host comprometido y la infraestructura del auditor.

Una vez transferido el archivo, la herramienta file confirmó que se trataba de un ensamblado .NET, lo que
habilitó  su  apertura  directa  en  ILSpy,  un  editor  y  depurador  especializado  en  ingeniería  inversa  de
assemblies .NET.

revisión  del  código

La
fuente  descompilado,  concretamente  en  el  espacio  de  nombres
MultimasterAPI.Controllers y dentro del controlador ColleagueController, reveló un hallazgo crítico: una
cadena de conexión embebida que incluía la contraseña D3veL0pM3nT!.

19 de agosto de 2026

22

La  presencia  de  credenciales  en  código  fuente  constituye  una  mala  praxis  recurrente  en  entornos
corporativos  y,  en  muchos  casos,  estas  contraseñas  siguen  patrones  reutilizados  o  coherentes  con
convenciones internas de la organización.

Por ello, antes de proceder a un password spraying indiscriminado, se verificó la política de contraseñas
del dominio.

El análisis de la política reveló que no existían mecanismos de bloqueo de cuentas, lo que eliminaba el
riesgo de denegación de servicio por intentos fallidos y habilitaba la posibilidad de realizar un password
spraying  seguro.  Con  esta  información,  se  procedió  a  probar  la  contraseña  obtenida  contra  el  servicio
WinRM, utilizando la lista de usuarios enumerados previamente.

19 de agosto de 2026

23

El resultado confirmó la hipótesis inicial: la contraseña había sido reutilizada. El servicio WinRM aceptó
las credenciales sbauer / D3veL0pM3nT!, proporcionando acceso remoto al sistema bajo la identidad de
este usuario. Este hallazgo constituye un vector de escalada lateral significativo, derivado directamente de
una mala gestión de credenciales en el entorno de desarrollo.

Privilege Escalation

Para  avanzar  en  la  fase  de  escalada  de  privilegios  dentro  del  dominio,  se  empleó  BloodHound  como
plataforma  de  enumeración  y  correlación  relacional  de  objetos  de  Active  Directory.  El  ingestor
bloodhound-python  permitió  recopilar  de  forma  remota  la  totalidad  de  los  metadatos  relevantes  del
dominio, incluyendo relaciones de control, delegaciones implícitas, ACLs, pertenencias a grupos y rutas de
privilegio potenciales.

19 de agosto de 2026

24

Una vez procesados los datos, la interfaz gráfica de BloodHound facilitó la visualización de las cadenas de
ataque disponibles, permitiendo identificar vectores de escalada que no serían evidentes mediante técnicas
manuales.

En la pestaña Search, se marcó el usuario SBAUER@MEGACORP.LOCAL como owned, habilitando
así  el  análisis  de  rutas  ascendentes  desde  su  posición  actual.  La  sección  Reachable  High  Value  Targets
reveló  un  hallazgo  crítico:  el  usuario  sbauer  disponía  de  permisos  GenericWrite  sobre  el  objeto
JORDEN@MEGACORP.LOCAL, considerado de alto valor debido a su pertenencia al grupo Server
Operators, uno de los grupos privilegiados del dominio con capacidad para gestionar servicios críticos del
sistema.

El permiso GenericWrite otorga la facultad de modificar cualquier atributo no protegido del objeto destino,
incluyendo  propiedades  sensibles  como  servicePrincipalNames,  logon  scripts,  o  configuraciones  de
seguridad  específicas.  Entre  estas,  destaca  la  capacidad  de  modificar  el  atributo  que  controla  la
pre-autenticación Kerberos, una medida de seguridad diseñada para impedir ataques de adivinación de
contraseñas.

Cuando la pre-autenticación está habilitada, el cliente debe enviar un timestamp cifrado con la clave del
usuario antes de recibir un Ticket Granting Ticket (TGT). Si se deshabilita, el atacante puede enviar una
solicitud AS-REQ vacía y el KDC devolverá un TGT cifrado directamente con el hash NTLM del usuario,
exponiendo así un material criptográfico susceptible de ser sometido a un ataque offline.

Partiendo  de  la  hipótesis  de  que  el  usuario  Jorden  podría  tener  una  contraseña  débil  o  predecible,  se
procedió a deshabilitar la pre-autenticación Kerberos mediante el cmdlet Get-ADUser, aprovechando el
permiso GenericWrite previamente identificado.

Con la configuración modificada, se utilizó la herramienta GetNPUser de Impacket para ejecutar un ataque
de  AS-REP  Roasting,  orientado  a  extraer  el  TGT  cifrado  del  usuario  sin  necesidad  de  conocer  su
contraseña.

19 de agosto de 2026

25

Hashcat

El hash obtenido mediante AS-REP Roasting fue sometido a un ataque de fuerza bruta offline utilizando
Hashcat. Para ello, se almacenó el material criptográfico en un archivo denominado hash y se procedió a
identificar el modo adecuado para su descifrado. Dado que el hash correspondía a un Kerberos 5 AS-REP
etype 23, se seleccionó el modo 18200, ejecutando posteriormente Hashcat con el diccionario rockyou.txt
como fuente de candidatos.

El ataque resultó exitoso, revelando la contraseña rainforest786 asociada al usuario jorden, lo que permitió
establecer una sesión remota mediante WinRM bajo dicha identidad.

19 de agosto de 2026

26

La  pertenencia  de  jorden  al  grupo  Server  Operators  constituye  un  vector  de  escalada  de  privilegios
especialmente crítico. Este grupo dispone de la capacidad de iniciar, detener y modificar las propiedades
de múltiples servicios del sistema, incluyendo el servicio Computer Browser, que se ejecuta en el contexto
de SYSTEM. La posibilidad de alterar la ruta del binario asociado a un servicio de este tipo convierte a
Server  Operators  en  un  grupo  de  alto  riesgo,  cuya  membresía  debería  estar  estrictamente  controlada  y
monitorizada,  especialmente porque  también permite  el  inicio  de  sesión  interactivo  en  controladores  de
dominio.

Se procedió a modificar la ruta del binario del servicio vulnerable y se verificó que el cambio había sido
aplicado correctamente.

Tras detener y reiniciar el servicio, la ejecución del payload configurado permitió obtener una reverse shell
con privilegios elevados.

19 de agosto de 2026

27

Sin embargo, la sesión resultó inestable, por lo que se optó por una estrategia más robusta: crear un nuevo
usuario y añadirlo al grupo Administrators, garantizando así un acceso persistente y estable al sistema
comprometido.

Con privilegios administrativos, se ejecutó un ataque DCSync, obteniendo las credenciales del dominio
directamente desde el controlador de dominio. Este ataque, basado en la capacidad de replicación de Active
Directory, permite extraer hashes NTLM y Kerberos de cualquier cuenta, incluyendo la del administrador
del dominio, siempre que el atacante disponga de privilegios equivalentes a los de un Domain Controller o
de un objeto con delegaciones de replicación.

19 de agosto de 2026

28

Una  vez  obtenidas  las  credenciales  del  administrador,  se  estableció  una  sesión  mediante  WinRM,
consolidando el control total sobre el dominio.

Durante  la  enumeración  previa  también  se  identificó  que  el  usuario  jorden  disponía  de  los  privilegios
SeBackupPrivilege y SeRestorePrivilege, dos permisos de alto impacto que permiten realizar copias y
restauraciones de archivos protegidos.

Estos privilegios habilitan técnicas como la copia de archivos sensibles mediante robocopy, incluyendo
bases de datos del sistema, hives del registro o componentes críticos del controlador de dominio, lo que
constituye otro vector viable para la obtención de credenciales o la escalada de privilegios.

19 de agosto de 2026

29


