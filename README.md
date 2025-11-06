# Librería de Protocolo HTTP

Una librería Python para el manejo de peticiones HTTP CGI con enfoque en seguridad y facilidad de uso.

## 🔒 Características de Seguridad

- **Rate Limiting**: Control de límite de peticiones por IP con persistencia en archivos
- **Input Sanitization**: Sanitización automática de datos de entrada para prevenir inyecciones
- **Header Injection Protection**: Limpieza automática de cabeceras HTTP
- **Content-Type Validation**: Validación estricta de tipos de contenido permitidos
- **Timeout Protection**: Protección contra ataques DoS con timeouts configurables
- **Security Headers**: Cabeceras de seguridad modernas incluidas por defecto
- **JSON Depth Limiting**: Protección contra JSON bombs con límites de profundidad
- **Content-Length Validation**: Validación estricta del tamaño de contenido
- **XSS Protection**: Escapado automático de datos en plantillas HTML
- **Path Traversal Prevention**: Validación segura de rutas de archivos

## ⚡ Características Principales

- ✅ Soporte completo para métodos HTTP (GET, POST, PUT, DELETE, OPTIONS, HEAD)
- ✅ Parsing seguro de JSON y form-urlencoded
- ✅ CORS configurable con preflight automático
- ✅ Logging estructurado y configurable
- ✅ Manejo de proxies de confianza para IP real del cliente
- ✅ Routing con paths dinámicos y parámetros de ruta
- ✅ Gestión automática de Content-Length y encoding UTF-8
- ✅ **Servidor de archivos HTML con comunicación bidireccional segura**
- ✅ **Sistema de plantillas con inyección segura de datos**

## 📦 Instalación

Descarga `http_lib.py` para luego importarlo en tu código. No requiere dependencias externas más allá de las bibliotecas estándar de Python.

## 🚀 Uso Básico

### Ejemplo Mínimo (API JSON)

```python
#!/usr/bin/env python3
from http import HTTP

# Crear instancia del handler
endpoint = HTTP()

# Definir un handler para GET
def handle_get(data, params, headers, path_params):
    response = {
        "message": "¡Hola mundo!",
        "params": params,
        "method": "GET"
    }
    endpoint.send_response(200, 'application/json', response)

# Registrar el handler
endpoint.register_handler("GET", handle_get, path="/saludo")

# Procesar la petición
if __name__ == "__main__":
    endpoint.handle_request()
```

### Ejemplo con Parámetros de Ruta

```python
#!/usr/bin/env python3
from http import HTTP

endpoint = HTTP()

def get_user(data, params, headers, path_params):
    """GET /users/{id} - Obtiene un usuario específico"""
    user_id = path_params.get('id')
    response = {
        "user": {
            "id": user_id,
            "name": f"User {user_id}",
            "email": f"user{user_id}@example.com"
        }
    }
    endpoint.send_response(200, 'application/json', response)

def get_comment(data, params, headers, path_params):
    """GET /posts/{post_id}/comments/{comment_id}"""
    post_id = path_params.get('post_id')
    comment_id = path_params.get('comment_id')
    response = {
        "post_id": post_id,
        "comment": {
            "id": comment_id,
            "text": f"Comentario {comment_id} del post {post_id}"
        }
    }
    endpoint.send_response(200, 'application/json', response)

# Registrar handlers con paths dinámicos
endpoint.register_handler("GET", get_user, "/users/{id}")
endpoint.register_handler("GET", get_comment, "/posts/{post_id}/comments/{comment_id}")

if __name__ == "__main__":
    endpoint.handle_request()
```

## ⚙️ Configuración

### Parámetros del Constructor HTTP

| Parámetro | Tipo | Defecto | Descripción |
|-----------|------|---------|-------------|
| `max_content_length` | int | 1048576 | Tamaño máximo del cuerpo de la petición (bytes) |
| `max_query_string_length` | int | 2048 | Longitud máxima del query string |
| `max_header_length` | int | 8192 | Longitud máxima por cabecera HTTP |
| `timeout_seconds` | int | 30 | Timeout de ejecución en segundos |
| `rate_limit_requests` | int | 100 | Número de peticiones permitidas por ventana |
| `rate_limit_window` | int | 60 | Ventana de tiempo para rate limiting (segundos) |
| `log_file` | str | None | Archivo de log (None = stderr) |
| `log_level` | int | logging.INFO | Nivel de logging |
| `allowed_methods` | List[str] | ['GET','POST','PUT','DELETE','OPTIONS','HEAD'] | Métodos HTTP permitidos |
| `allowed_content_types` | List[str] | ['application/json', 'application/x-www-form-urlencoded', 'text/plain'] | Content-Types permitidos |
| `cors_origins` | str | "*" | Orígenes permitidos para CORS |
| `security_headers` | Dict[str,str] | {...} | Cabeceras de seguridad personalizadas |
| `enable_rate_limiting` | bool | True | Habilitar/deshabilitar rate limiting |
| `enable_timeout` | bool | True | Habilitar/deshabilitar timeout |
| `max_json_depth` | int | 10 | Profundidad máxima para JSON |
| `max_dict_items` | int | 100 | Máximo número de items en diccionarios |
| `max_array_items` | int | 1000 | Máximo número de items en arrays |
| `trusted_proxies` | List[str] | [] | IPs de proxies de confianza |

### Cabeceras de Seguridad por Defecto

```python
{
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Cross-Origin-Resource-Policy': 'same-site',
    'Cache-Control': 'no-store'
}
```

## 📝 Estructura de Datos

### Handlers

Los handlers reciben 4 parámetros:

```python
def mi_handler(data, params, headers, path_params):
    """
    data: Dict - Datos del cuerpo de la petición (POST/PUT)
    params: Dict[str, List[str]] - Query string parameters
    headers: Dict[str, str] - Cabeceras HTTP sanitizadas
    path_params: Dict[str, str] - Parámetros extraídos de la ruta
    """
    pass
```

### Objeto Request Actual

```python
request_info = endpoint.get_current_request()
# Contiene:
{
    'request_id': 'abc12345',          # ID único de la petición
    'method': 'POST',                  # Método HTTP
    'path': '/users/123',              # Path de la petición
    'query_params': {...},             # Parámetros de query string
    'data': {...},                     # Datos del cuerpo de la petición
    'headers': {...},                  # Cabeceras HTTP sanitizadas
    'timestamp': '2024-01-15T10:30:00', # Timestamp ISO
    'client_ip': '192.168.1.100',      # IP real del cliente
    'user_agent': 'Mozilla/5.0...',    # User-Agent del cliente
    'path_params': {...}               # Parámetros de ruta (si aplica)
}
```

### Formato de Query Parameters

```python
# URL: /api?name=John&tags=python&tags=web&age=30
params = {
    'name': ['John'],
    'tags': ['python', 'web'],
    'age': ['30']
}
```

## 🛡️ Mejores Prácticas de Seguridad

### 1. Validación de Entrada

```python
def handle_post(data, params, headers, path_params):
    # Siempre validar datos de entrada
    if not isinstance(data.get('email'), str):
        endpoint.send_response(400, 'application/json', {
            "error": "Email debe ser una cadena"
        })
        return
    
    # Validar formato de email
    import re
    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', data['email']):
        endpoint.send_response(400, 'application/json', {
            "error": "Formato de email inválido"
        })
        return
```

### 2. Rate Limiting Personalizado

```python
# Para APIs públicas
endpoint = HTTP(
    rate_limit_requests=10,    # Muy restrictivo
    rate_limit_window=60
)

# Para APIs internas
endpoint = HTTP(
    rate_limit_requests=1000,  # Más permisivo
    rate_limit_window=60
)
```

### 3. Configuración CORS

```python
# Producción - dominios específicos
endpoint = HTTP(
    cors_origins="https://miapp.com"
)

# Desarrollo - más permisivo
endpoint = HTTP(
    cors_origins="*"
)
```

## 🔧 Configuración del Servidor Web

### Apache (.htaccess)

```apache
# Habilitar CGI
Options +ExecCGI
AddHandler cgi-script .py

# Redirigir todas las peticiones al script
RewriteEngine On
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^(.*)$ /api.py/$1 [L,QSA]

# Headers de seguridad adicionales
Header always set X-Content-Type-Options nosniff
Header always set X-Frame-Options DENY
```

### Nginx (configuración CGI)

```nginx
location /api/ {
    fastcgi_pass unix:/var/run/fcgiwrap.socket;
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME /path/to/api.py;
    fastcgi_param PATH_INFO $uri;
}
```

## 📊 Logging y Monitoreo

### Configuración de Logs

```python
import logging

endpoint = HTTP(
    log_file="/var/log/api.log",
    log_level=logging.DEBUG  # Para desarrollo
    # log_level=logging.INFO  # Para producción
)
```

### Formato de Logs

```
2024-01-15 10:30:15,123 - SecureCGI_140234 - INFO - Registrado handler para GET /users/{id}
2024-01-15 10:30:15,456 - SecureCGI_140234 - INFO - Dispatch GET /users/123 (pattern: /users/{id}) - rid=abc12345 - ip=192.168.1.100
2024-01-15 10:30:16,789 - SecureCGI_140234 - WARNING - Rate limit excedido para IP: 192.168.1.100
2024-01-15 10:30:17,012 - SecureCGI_140234 - ERROR - Error en handler POST /users: KeyError('required_field') - rid=def67890
```

## 🚨 Manejo de Errores

### Errores HTTP Automáticos

La librería maneja automáticamente:

- **400 Bad Request**: Datos malformados, campos requeridos faltantes
- **404 Not Found**: Path no encontrado
- **405 Method Not Allowed**: Método HTTP no permitido para el path
- **408 Request Timeout**: Timeout de ejecución excedido
- **413 Payload Too Large**: Contenido demasiado grande
- **415 Unsupported Media Type**: Content-Type no soportado
- **429 Too Many Requests**: Rate limit excedido
- **500 Internal Server Error**: Errores de ejecución

### Respuestas de Error Personalizadas

```python
def handle_get(data, params, headers, path_params):
    user_id = params.get('user_id', [''])[0]
    
    if not user_id:
        endpoint.send_response(400, 'application/json', {
            "error": True,
            "code": "MISSING_USER_ID",
            "message": "El parámetro user_id es requerido",
            "documentation": "https://api.midominio.com/docs#user-id"
        })
        return
```

## 🧪 Testing

### Pruebas con cURL (API JSON)

```bash
# GET simple
curl -X GET "http://localhost/api.py/health"

# GET con parámetros de ruta
curl -X GET "http://localhost/api.py/users/123"

# POST con JSON
curl -X POST "http://localhost/api.py/users" \
     -H "Content-Type: application/json" \
     -d '{"name":"John","email":"john@example.com"}'

# PUT con parámetros de ruta
curl -X PUT "http://localhost/api.py/users/123" \
     -H "Content-Type: application/json" \
     -d '{"name":"Jane","email":"jane@example.com"}'

# DELETE
curl -X DELETE "http://localhost/api.py/users/123"
```

### Pruebas con Python requests

```python
import requests

base_url = "http://localhost/api.py"

# GET con parámetros de ruta
response = requests.get(f"{base_url}/users/123")
print(response.json())

# POST JSON
response = requests.post(
    f"{base_url}/users",
    json={"name": "John", "email": "john@example.com"}
)
print(response.json())

# POST formulario HTML
response = requests.post(
    f"{base_url}/contact",
    data={"name": "John", "email": "john@example.com", "message": "Hello"}
)
print(response.text)  # HTML response
```

## 🎯 Routing

### Registro de Handlers

```python
# Path estático
endpoint.register_handler("GET", handler_func, "/users")

# Path con parámetro simple
endpoint.register_handler("GET", handler_func, "/users/{id}")

# Path con múltiples parámetros
endpoint.register_handler("GET", handler_func, "/posts/{post_id}/comments/{comment_id}")

# Handler por defecto (sin path específico)
endpoint.register_handler("GET", handler_func)
```

### Acceso a Parámetros de Ruta

```python
def get_user(data, params, headers, path_params):
    # path_params contiene los valores extraídos de la ruta
    user_id = path_params.get('id')  # De /users/{id}
    
    response = {"user_id": user_id}
    endpoint.send_response(200, 'application/json', response)
```

Para reportar problemas o solicitar nuevas características, abre un issue en el repositorio del proyecto.
