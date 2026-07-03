# DMVPN Fase 3 Hub and Spoke sobre IPsec con IKEv2

**Asignatura:** Seguridad de Redes
**Estudiante:** Manuel Alejandro Cruz Messon
**Matrícula:** 2025-0689
**Docente:** Jonathan Rondón
**Fecha:** 2 de julio de 2026

> **Nota:** el direccionamiento no se realizó en base a la matrícula del estudiante; este requerimiento se recordó demasiado tarde y no fue posible rehacer las topologías y videos.

---

## Tabla de Contenidos

- [1. Resumen y Objetivos](#1-resumen-y-objetivos)
- [2. Topología de Red y Direccionamiento](#2-topología-de-red-y-direccionamiento)
- [3. Especificación de Políticas y Parámetros de Seguridad (IKEv2)](#3-especificación-de-políticas-y-parámetros-de-seguridad-ikev2)
- [4. Configuración de la Nube DMVPN Fase 3 (mGRE + NHRP Redirect/Shortcut)](#4-configuración-de-la-nube-dmvpn-fase-3-mgre--nhrp-redirectshortcut)
- [5. Puntos Críticos Analizados](#5-puntos-críticos-analizados)
- [6. Protocolo de Verificación y Diagnóstico Técnico](#6-protocolo-de-verificación-y-diagnóstico-técnico)

---

## 1. Resumen y Objetivos

Este documento describe la evolución del laboratorio DMVPN hacia su **Fase 3**, manteniendo la misma topología física de tres sedes (PEER A como Hub/NHS, PEER B y PEER C como Spokes). La diferencia central respecto a la Fase 2 radica en dos aspectos: primero, la Fase 1 de negociación (IKE) migra del modelo ISAKMP heredado hacia la suite modular de **IKEv2** con un keyring comodín (`peer ALL`, `address 0.0.0.0 0.0.0.0`); segundo, se habilitan los comandos `ip nhrp redirect` en el Hub y `ip nhrp shortcut` en los Spokes, lo cual permite el establecimiento de túneles IPsec/GRE dinámicos y directos entre spokes (spoke-to-spoke) sin que el tráfico de datos deba atravesar permanentemente el Hub, característica distintiva de DMVPN Fase 3. Se mantiene NAT dinámico con sobrecarga (PAT) y EIGRP como protocolo de enrutamiento dinámico, ahora bajo el proceso EIGRP 100.

### Objetivos del Proyecto

- **Migración de ISAKMP a IKEv2 con Autenticación Comodín:** reemplazar la política ISAKMP (IKEv1) por la suite modular IKEv2 (proposal, policy, keyring y profile), utilizando un keyring comodín capaz de autenticar a cualquier peer remoto sin declaraciones individuales por IP, condición necesaria para escalar el número de spokes.
- **Comunicación Directa Spoke-to-Spoke (DMVPN Fase 3):** habilitar `ip nhrp redirect` en el Hub y `ip nhrp shortcut` en cada Spoke, permitiendo que, ante tráfico spoke-to-spoke, el Hub notifique al spoke origen la ruta óptima directa hacia el spoke destino, estableciéndose un túnel dinámico temporal entre ambos sin depender del Hub para el reenvío continuo de datos.
- **Enrutamiento Dinámico entre Sedes:** mantener la propagación automática de las rutas `172.16.1.0/24`, `172.16.2.0/24` y `172.16.3.0/24` mediante el proceso EIGRP 100 sobre la nube mGRE, ahora compatible con los túneles dinámicos de Fase 3.
- **Confidencialidad e Integridad del Túnel:** garantizar la protección del tráfico inter-sede, tanto hub-spoke como spoke-spoke, mediante IKEv2 con AES-256/SHA-256 y un transform-set IPsec en modo transporte.

---

## 2. Topología de Red y Direccionamiento

Tres sedes interconectadas mediante un gateway WAN que emula un proveedor de servicios de Internet (R-ISP). PEER A continúa como Hub (NHS) de la nube DMVPN; PEER B y PEER C se registran como Spokes, con la diferencia de que en Fase 3 estos últimos podrán negociar túneles directos entre sí bajo demanda.

| Dispositivo / Sede | Interfaz | Dirección IP | Máscara de Subred | Propósito / Rol |
|---|---|---|---|---|
| PEER A (HUB) | Gi0/0 | 10.0.0.60 | 255.255.255.0 | Enlace WAN (IP Pública) / NAT Outside |
| PEER A (HUB) | Gi0/1 | 172.16.1.1 | 255.255.255.0 | Gateway LAN A / NAT Inside |
| PEER A (HUB) | Tunnel0 | 192.168.100.1 | 255.255.255.0 | NHS DMVPN / Hub mGRE (redirect) |
| PEER B (SPOKE) | Gi0/0 | 10.0.0.70 | 255.255.255.0 | Enlace WAN (IP Pública) / NAT Outside |
| PEER B (SPOKE) | Gi0/1 | 172.16.2.1 | 255.255.255.0 | Gateway LAN B / NAT Inside |
| PEER B (SPOKE) | Tunnel0 | 192.168.100.2 | 255.255.255.0 | Spoke DMVPN (shortcut) |
| PEER C (SPOKE) | Gi0/0 | 10.0.0.80 | 255.255.255.0 | Enlace WAN (IP Pública) / NAT Outside |
| PEER C (SPOKE) | Gi0/1 | 172.16.3.1 | 255.255.255.0 | Gateway LAN C / NAT Inside |
| PEER C (SPOKE) | Tunnel0 | 192.168.100.3 | 255.255.255.0 | Spoke DMVPN (shortcut) |
| R-ISP (Gateway) | N/A | 10.0.0.1 | 255.255.255.0 | Puerta de enlace predeterminada WAN |

---

## 3. Especificación de Políticas y Parámetros de Seguridad (IKEv2)

A diferencia de la Fase 2 (basada en `crypto isakmp key ... address 0.0.0.0`), esta implementación adopta la suite modular de IKEv2, declarando un keyring con un peer genérico (`peer ALL`) cuya dirección comodín (`0.0.0.0 0.0.0.0`) permite la autenticación de cualquier origen remoto.

### Configuración NAT y ACL de Salida a Internet — PEER A

> Configuración equivalente en PEER B y PEER C, sustituyendo las direcciones WAN `10.0.0.70`/`10.0.0.80` y las redes LAN `172.16.2.0/24` y `172.16.3.0/24` respectivamente.

### Fase 1: IKEv2 Proposal, Policy, Keyring Comodín y Profile

| Parámetro | Valor |
|---|---|
| Algoritmo de Cifrado | AES-CBC-256 (Advanced Encryption Standard con encadenamiento de bloques de cifrado de 256 bits) |
| Integridad y Hash | SHA-256 (Secure Hash Algorithm de 256 bits para procesos de autenticación e intercambio seguro) |
| Grupo Diffie-Hellman | Grupo 14 (Exponenciación modular de 2048 bits para la generación segura de claves efímeras) |
| Autenticación | Peer comodín `ALL` con dirección/máscara `0.0.0.0 0.0.0.0` dentro del keyring `DMVPN_KEY`, y perfil IKEv2 con `match identity remote address 0.0.0.0`, permitiendo la autenticación de cualquier peer remoto (Hub o Spoke) bajo la misma clave, condición indispensable para escalar el número de spokes sin reconfigurar el Hub |
| Pre-Shared Key | `cisco123` |

### Fase 2: IPsec Transform Set en Modo Transporte

| Parámetro | Valor |
|---|---|
| Nombre del Set | `TS` |
| Encapsulación Criptográfica | ESP con AES de 256 bits (esp-aes 256) |
| Autenticación/Hashing de Datos | ESP bajo código de autenticación de mensajes cifrados (esp-sha256-hmac) |
| Modo de Operación | Modo Transporte (mode transport), requerido en DMVPN dado que la cabecera de enrutamiento externa ya es provista por el encapsulamiento mGRE |
| Perfil IPsec | `DMVPN_IPS_PROF`, el cual vincula el transform-set `TS` con el perfil IKEv2 `DMVPN_PROF` y se aplica sobre la interfaz `Tunnel0` de cada peer mediante `tunnel protection` |

---

## 4. Configuración de la Nube DMVPN Fase 3 (mGRE + NHRP Redirect/Shortcut)

La interfaz `Tunnel0` incorpora los comandos NHRP distintivos de la Fase 3: `ip nhrp redirect` en el Hub, e `ip nhrp shortcut` en cada Spoke. Estos comandos habilitan el mecanismo de optimización de rutas propio de esta fase, en el cual el Hub detecta tráfico subóptimo (spoke-hub-spoke) y notifica al spoke origen para que negocie un túnel directo hacia el spoke destino.

### PEER A — Hub (NHS) — Interfaz Tunnel0 y EIGRP 100

`ip nhrp redirect` habilita al Hub para enviar mensajes NHRP Traffic Indication a un spoke cuando detecta que su tráfico de retorno está siendo reenviado de forma subóptima a través del propio Hub, iniciando así el proceso de resolución de un atajo (shortcut) spoke-to-spoke.

A diferencia de la Fase 2, en este Hub no se deshabilita `ip next-hop-self eigrp`, dado que en Fase 3 el mecanismo de redirección NHRP —y no el next-hop de EIGRP— es el responsable de optimizar la ruta de datos entre spokes; se recomienda validar en laboratorio si esta omisión afecta la resolución de next-hop en el plano de control de EIGRP.

### PEER B — Spoke — Interfaz Tunnel0 y EIGRP 100

### PEER C — Spoke — Interfaz Tunnel0 y EIGRP 100

```
interface Tunnel0
 ip address 192.168.100.3 255.255.255.0
 ip nhrp network-id 1
 ip nhrp shortcut
 ip nhrp map 192.168.100.1 10.0.0.60
 ip nhrp map multicast 10.0.0.60
 ip nhrp nhs 192.168.100.1
 tunnel source GigabitEthernet0/0
 tunnel mode gre multipoint
 tunnel protection ipsec profile DMVPN_IPS_PROF
exit
!
router eigrp 100
 network 192.168.100.0 0.0.0.255
 network 172.16.3.0 0.0.0.255
exit
```

---

## 5. Puntos Críticos Analizados

### A. Diferencia entre DMVPN Fase 2 y Fase 3: Redirect y Shortcut

En la Fase 2, todo el tráfico spoke-to-spoke debía transitar obligatoriamente por el Hub, incluso después de establecida la comunicación. En Fase 3, gracias a `ip nhrp redirect` (Hub) e `ip nhrp shortcut` (Spokes), el primer paquete de una conversación spoke-to-spoke aún atraviesa el Hub, pero este notifica al spoke origen mediante un mensaje de redirección para que negocie un túnel IPsec/GRE dinámico directo con el spoke destino, optimizando la latencia y liberando carga de procesamiento del Hub en flujos posteriores.

### B. Migración de Autenticación ISAKMP Wildcard a Keyring IKEv2 Comodín

El concepto de clave comodín se mantiene respecto a la Fase 2 (donde se usaba `crypto isakmp key DMVPN_KEY address 0.0.0.0`), pero ahora se expresa mediante un peer nombrado `ALL` con máscara comodín `0.0.0.0 0.0.0.0` dentro de un keyring IKEv2, y un profile con `match identity remote address 0.0.0.0`. Esta estructura modular permite, de ser necesario, declarar perfiles adicionales más específicos sin afectar la política general.

### C. Convivencia de NAT Overload con Túneles Dinámicos Spoke-to-Spoke

Al igual que en Fase 2, el NAT dinámico con sobrecarga se aplica sobre toda la LAN local sin exclusión explícita del tráfico inter-sede, dado que el tráfico hacia redes remotas (incluyendo los nuevos túneles spoke-to-spoke resueltos dinámicamente) es dirigido por la tabla de enrutamiento EIGRP hacia `Tunnel0` antes de evaluarse contra la política de NAT de la interfaz física Gi0/0.

---

## 6. Protocolo de Verificación y Diagnóstico Técnico

### Paso 1: Verificación del Registro NHRP de los Spokes en el Hub

Se confirma que los spokes se hayan registrado exitosamente ante el NHS. Este comando se ejecuta en PEER A (Hub):

```
PEER_A# show ip nhrp
```

**Criterio de Aceptación:** deben listarse las entradas dinámicas correspondientes a `192.168.100.2` (PEER B) y `192.168.100.3` (PEER C), cada una asociada a su dirección NBMA real.

### Paso 2: Validación del Canal de Control en Fase 1 (IKEv2 SA)

Para examinar el estado del intercambio de llaves entre el Hub y cada spoke (y, tras la redirección, entre los propios spokes), se emplea el comando de diagnóstico avanzado para IKEv2:

```
Router# show crypto ikev2 sa
```

**Criterio de Aceptación:** el resultado en consola debe declarar de forma explícita el parámetro **READY** por cada asociación activa. En PEER B, además de la SA hacia el Hub, debe observarse una nueva SA READY hacia PEER C tras el establecimiento del túnel directo.

### Paso 3: Validación del Canal de Datos en Fase 2 (IPsec SA)

Una vez establecido el enlace de control, es indispensable auditar que los flujos de datos GRE multipunto sean procesados por los algoritmos de encriptación simétrica ESP en modo transporte:

```
Router# show crypto ipsec sa | include pkts
```

Los registros y contadores del sistema para `#pkts encaps` (paquetes cifrados salientes) y `#pkts decaps` (paquetes descifrados entrantes) deben mostrar valores enteros mayores a cero e incrementar en tiempo real conforme persista el envío de ráfagas de datos.

### Paso 4: Validación de la Tabla de Enrutamiento EIGRP

Se debe confirmar que cada peer haya aprendido dinámicamente, vía EIGRP 100, las redes LAN remotas a través de la interfaz Tunnel0.

```
Router# show ip route eigrp
```
