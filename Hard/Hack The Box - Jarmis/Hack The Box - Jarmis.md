<p align="center">
<img src="assets/1.png" width="1000">
</p>

El análisis del sistema revela un servicio Linux que expone únicamente dos superficies iniciales: un servidor SSH y una aplicación web que implementa una API dedicada a la obtención y clasificación de firmas JARM. Esta API consulta la configuración TLS del servidor indicado, genera su huella criptográfica y la contrasta con una base de datos interna. Cuando la firma coincide con un registro catalogado como malicioso, el servicio activa una fase adicional de inspección que consiste en establecer una conexión suplementaria para obtener metadatos del servidor remoto.

La presencia de esta conexión adicional permite identificar un comportamiento susceptible de explotación: la API realiza solicitudes salientes hacia destinos arbitrarios, lo que habilita un vector de Server Side Request Forgery (SSRF). Mediante este SSRF es posible enumerar los puertos internos del sistema, revelando la presencia del servicio Open Management Infrastructure (OMI) en uno de ellos. OMI es vulnerable a OMIGod, una vulnerabilidad crítica que permite la ejecución remota de código con privilegios de root mediante una única petición POST con un cuerpo SOAP XML especialmente construido.

La explotación completa se articula encadenando la solicitud suplementaria generada por la API con un mecanismo de redirección controlado por el analista. Este comportamiento puede reproducirse mediante un servidor Flask que recibe la conexión de metadatos y la transforma en una petición POST encapsulada en un esquema Gopher, permitiendo enviar el payload SOAP hacia el puerto interno donde reside OMI y obtener una reverse shell con privilegios elevados.

Como vía alternativa, también es posible interceptar y redirigir la conexión suplementaria manipulando la capa de red del sistema mediante reglas selectivas en el firewall. Esta aproximación, basada en NAT y selección estadística de paquetes, permite capturar exclusivamente el flujo TLS adicional sin interferir con las diez conexiones del fingerprinting JARM, desviándolo hacia un servicio de escucha controlado por el analista. Esta variante ofrece una solución minimalista y transparente que reproduce el comportamiento necesario para desencadenar el vector SSRF sin depender de herramientas externas.

<center><strong><u>Enumeración</u></strong></center>

La dirección IP de la máquina víctima es 10.129.95.238. Por tanto, envié 5 trazas ICMP para verificar que existe conectividad entre las dos máquinas.

<img src="assets/2.png">

Una vez que identificada la dirección IP de la máquina objetivo, utilicé el comando nmap -p- -sS -sC -sV --min-rate 5000 -vvv -Pn 10.129.95.238 -oN scanner_jarmis para descubrir los puertos abiertos y sus versiones:

- (-p-): realiza un escaneo de todos los puertos abiertos.
- (-sS): utilizado para realizar un escaneo TCP SYN, siendo este tipo de escaneo el más común y rápido, además de ser relativamente sigiloso ya que no llega a completar las conexiones TCP. Habitualmente se conoce esta técnica como sondeo de medio abierto (half open). Este sondeo consiste en enviar un paquete SYN, si recibe un paquete SYN/ACK indica que el puerto está abierto, en caso contrario, si recibe un paquete RST (reset), indica que el puerto está cerrado y si no recibe respuesta, se marca como filtrado.
- (-sC): utiliza los scripts por defecto para descubrir información adicional y posibles vulnerabilidades. Esta opción es equivalente a --script=default. Es necesario tener en cuenta que algunos de estos scripts se consideran intrusivos ya que podría ser detectado por sistemas de detección de intrusiones, por lo que no se deben ejecutar en una red sin permiso.
- (-sV): Activa la detección de versiones. Esto es muy útil para identificar posibles vectores de ataque si la versión de algún servicio disponible es vulnerable. 
- (--min-rate 5000): ajusta la velocidad de envío a 5000 paquetes por segundo.
- (-Pn): asume que la máquina a analizar está activa y omite la fase de descubrimiento de hosts.

<center><strong><u>Web Enumeration</u></strong></center>

Tras el acceso inicial a la superficie web expuesta por el activo, la interfaz permanecía indefinidamente anclada en un estado de Loading…, lo que sugería una dependencia de recursos externos o una resolución incompleta del dominio. 

<img src="assets/3.png"> 

Ante esta anomalía, se procedió a un análisis más granular del tráfico generado por el navegador, inspeccionando las peticiones consignadas en la pestaña Network. Allí se identificó una solicitud GET dirigida al endpoint http://jarmis.htb, lo que evidenciaba que el servicio web delegaba parte de su funcionalidad en dicho dominio.

<img src="assets/4.png"> 

Con el fin de normalizar la resolución DNS y garantizar la correcta interacción con el servicio, se incorporó una entrada específica para jarmis.htb en el archivo /etc/hosts. 

<img src="assets/5.png"> 

Tras esta modificación, el acceso al dominio reveló una plataforma que se autodenominaba Jarmis, presentada como un motor de búsqueda sustentado en mecanismos de identificación criptográfica.

<img src="assets/6.png"> 

En este punto resultó pertinente contextualizar el concepto de JARM, dado que la nomenclatura del servicio parecía aludir directamente a esta tecnología. JARM constituye una técnica de fingerprinting activo orientada a la caracterización de servidores que implementan Transport Layer Security (TLS). Su funcionamiento se basa en la emisión de un conjunto de diez paquetes Client Hello especialmente diseñados, cada uno con variaciones en parámetros críticos del protocolo. 

El servidor objetivo responde con sus correspondientes Server Hello, cuyas propiedades —versiones soportadas, suites criptográficas negociadas, extensiones, comportamiento ante anomalías sintácticas— son agregadas y posteriormente sometidas a un proceso de hashing determinista. El resultado es una huella criptográfica única que permite discriminar implementaciones TLS, identificar configuraciones heterogéneas, detectar infraestructuras correlacionadas y, en determinados escenarios, inferir la presencia de dispositivos intermedios o comportamientos anómalos.

La aparición de un servicio web que se autodefine como “Search Engine” pero que opera sobre la semántica de JARM constituye un indicio preliminar de que la máquina podría estar instrumentalizando esta tecnología como vector funcional o como superficie de ataque. En consecuencia, la interacción con Jarmis no solo se convierte en un paso necesario para la enumeración, sino también en un potencial punto de entrada para la explotación, especialmente si la implementación del fingerprinting presenta desviaciones respecto al estándar o expone mecanismos internos no previstos para su consumo público.

Una vez cargada la interfaz de Jarmis, el menú desplegable del motor de búsqueda reveló tres modalidades de consulta, cada una aparentemente vinculada a un mecanismo interno distinto de interacción con el backend. Con el objetivo de caracterizar su comportamiento, se procedió a enumerar sistemáticamente cada opción.

<img src="assets/7.png">  

La primera modalidad, basada en la búsqueda por ID, aceptaba valores enteros y devolvía un objeto JSON que contenía la huella JARM asociada al identificador solicitado. Este comportamiento evidenciaba que el servicio mantenía un repositorio interno de firmas previamente generadas, accesible sin autenticación y susceptible de enumeración exhaustiva. La estructura del JSON, junto con la ausencia de restricciones en la entrada, sugería que el backend operaba como un agregador de fingerprints, probablemente almacenados tras ejecuciones previas del motor.

<img src="assets/8.png">

La segunda modalidad, denominada Fetch Jarm, presentaba una interfaz significativamente más simple: un único campo destinado a recibir una cadena de texto. La simplicidad del parámetro, unida a la semántica del servicio, permitía inferir que el backend esperaba un endpoint remoto sobre el cual ejecutar la lógica de fingerprinting. Dado que JARM es intrínsecamente un mecanismo de identificación activa de servidores TLS, resultaba razonable concluir que el campo debía aceptar un URL o, al menos, un host accesible mediante el protocolo TLS.

<img src="assets/9.png"> 

Para validar esta hipótesis y determinar si el servicio realizaba conexiones salientes hacia el recurso proporcionado, se introdujo la dirección IP del atacante en el campo de entrada. Con el fin de monitorizar cualquier intento de conexión desde el host objetivo, se habilitó un listener en el puerto 443/TCP, empleando ncat en modo SSL para emular un servidor TLS mínimo y capturar cualquier interacción entrante.

<img src="assets/10.png">  

El resultado confirmó la sospecha inicial: inmediatamente después de enviar la solicitud, el servidor de Jarmis estableció una conexión hacia la dirección indicada, evidenciando que el backend ejecutaba de forma activa el proceso de fingerprinting sobre el host proporcionado. 

<img src="assets/11.png"> 

El análisis de las conexiones entrantes reveló un comportamiento característico del algoritmo JARM. Este mecanismo, en su implementación estándar, genera la huella criptográfica a partir de diez intentos de negociación TLS, cada uno con variaciones específicas en los parámetros del Client Hello. 

<img src="assets/12.png">  

Sin embargo, al emplear ncat en modo SSL sin configuración adicional, únicamente se registró una única conexión en nuestro listener. Esta discrepancia se explica por la naturaleza pasiva de ncat: al no emitir respuestas válidas para las sucesivas negociaciones, el servidor objetivo interpreta los intentos como fallidos y los marca con el código 000, lo que justifica la presencia de nueve tríadas de ceros en la firma JARM devuelta por el servicio.

Para obtener una visión más completa del comportamiento del backend, se habilitó el parámetro -k en ncat, permitiendo la aceptación de múltiples conexiones consecutivas. Bajo esta configuración, el listener capturó los diez intentos de conexión correspondientes al proceso completo de fingerprinting. Este resultado confirmó que el servicio Jarmis ejecuta la lógica JARM de manera íntegra, replicando fielmente la secuencia de negociaciones TLS que define la huella criptográfica.

<img src="assets/13.png">  

Un aspecto llamativo emergió al comparar los objetos JSON generados en ambas pruebas. En la segunda ejecución —aquella en la que se capturaron los diez intentos— el JSON devuelto por el servicio resultó notablemente más breve, omitiendo campos como ismalicious y server. Esta ausencia sugiere que el backend aplica una lógica condicional en función de la calidad o completitud de las respuestas obtenidas durante el fingerprinting. 

En otras palabras, cuando la interacción con el host remoto no produce un conjunto de atributos suficientemente rico, el servicio complementa la firma con metadatos adicionales; mientras que, ante una secuencia completa de negociaciones, se limita a devolver la huella estricta sin anotaciones auxiliares.

<img src="assets/14.png">  

La divergencia entre ambas firmas permitió realizar una comprobación adicional: al consultar la base de datos interna mediante la opción de búsqueda por ID, la firma correspondiente a la primera interacción —la incompleta, con nueve tríadas de ceros— sí se encontraba registrada, mientras que la segunda, derivada de la secuencia completa de diez conexiones, no figuraba en el repositorio. 

Este comportamiento sugiere que el backend almacena únicamente aquellas firmas que cumplen ciertos criterios de clasificación o que han sido generadas en contextos específicos, lo que abre la puerta a hipótesis sobre mecanismos internos de validación, categorización o incluso detección de comportamientos anómalos.

<img src="assets/15.png"> 
