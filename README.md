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

Clona los archivos `http.py` y `html_handler.py` para luego importarlos en tu código. No requiere dependencias externas más allá de las bibliotecas estándar de Python.

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

### Ejemplo Mínimo (Servidor HTML)

```python
#!/usr/bin/env python3
from http import HTTP
from html_handler import HTMLHandler

endpoint = HTTP()
html = HTMLHandler(templates_dir='templates')

def show_page(data, params, headers, path_params):
    html.serve_html(
        endpoint,
        'home.html',
        initial_data={'title': 'Mi Sitio', 'message': 'Bienvenido'}
    )

endpoint.register_handler('GET', show_page, '/home')

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

## 🌐 HTMLHandler - Servidor de Páginas HTML

El `HTMLHandler` permite servir archivos HTML con comunicación bidireccional **sin necesidad de APIs REST ni JavaScript complejo**. Los datos se intercambian mediante formularios HTML estándar de forma totalmente segura.

### Características del HTMLHandler

- ✅ Servir archivos HTML estáticos de forma segura
- ✅ Sistema de plantillas con placeholders seguros
- ✅ Inyección automática de datos con protección anti-XSS
- ✅ Procesamiento de formularios HTML sin APIs
- ✅ Validación de path para prevenir path traversal
- ✅ Cache opcional con ETags
- ✅ Comunicación natural sin AJAX ni fetch

### Ejemplo Completo: Formulario de Contacto

**Script Python (`contact.py`):**

```python
#!/usr/bin/env python3
from http import HTTP
from html_handler import HTMLHandler

endpoint = HTTP()
html = HTMLHandler(templates_dir='templates')

# Procesador de datos del formulario
def process_contact(form_data, query_params):
    """Procesa el formulario de contacto"""
    
    if form_data:
        name = form_data.get('name', '').strip()
        email = form_data.get('email', '').strip()
        message = form_data.get('message', '').strip()
        
        # Validar datos
        if not all([name, email, message]):
            return {
                'error': True,
                'error_message': 'Por favor completa todos los campos',
                'form_data': form_data
            }
        
        # Aquí procesarías el formulario (enviar email, guardar en BD, etc.)
        # ...
        
        return {
            'success': True,
            'success_message': f'Gracias {name}, tu mensaje ha sido enviado.'
        }
    
    # Primera carga sin datos
    return {'title': 'Contacto'}

# Registrar procesador
html.register_data_processor('contact', process_contact)

# Handlers GET y POST para la misma ruta
def show_contact(data, params, headers, path_params):
    html.serve_html(endpoint, 'contact.html', request_data=data, query_params=params)

endpoint.register_handler('GET', show_contact, '/contact')
endpoint.register_handler('POST', show_contact, '/contact')

if __name__ == "__main__":
    endpoint.handle_request()
```

**Plantilla HTML (`templates/contact.html`):**

```html
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>{{title}}</title>
    <style>
        .success { color: green; padding: 10px; background: #e8f5e9; }
        .error { color: red; padding: 10px; background: #ffebee; }
    </style>
</head>
<body>
    <h1>Formulario de Contacto</h1>
    
    <!-- Los mensajes se inyectan de forma segura -->
    {{raw:success_message}}
    {{raw:error_message}}
    
    <form method="POST" action="/contact">
        <div>
            <label>Nombre:</label>
            <input type="text" name="name" required>
        </div>
        <div>
            <label>Email:</label>
            <input type="email" name="email" required>
        </div>
        <div>
            <label>Mensaje:</label>
            <textarea name="message" rows="5" required></textarea>
        </div>
        <button type="submit">Enviar</button>
    </form>
</body>
</html>
```

### Sistema de Placeholders Seguros

El HTMLHandler usa tres tipos de placeholders para inyectar datos:

```html
<!-- 1. Texto escapado (previene XSS automáticamente) -->
<h1>Hola {{username}}</h1>
<p>Email: {{user_email}}</p>

<!-- 2. Datos JSON para JavaScript (escapado para seguridad) -->
<script>
    const userData = JSON.parse('{{json:user_data}}');
    const items = JSON.parse('{{json:items_list}}');
</script>

<!-- 3. HTML confiable del servidor (usar solo para mensajes generados por tu código) -->
<div class="message">{{raw:success_message}}</div>
```

**⚠️ Importante**: Nunca uses `{{raw:}}` con datos que vengan directamente del usuario. Solo para HTML generado por tu servidor.

### Ejemplo: CRUD Completo

**Script Python:**

```python
#!/usr/bin/env python3
from http import HTTP
from html_handler import HTMLHandler

endpoint = HTTP()
html = HTMLHandler(templates_dir='templates')

# Base de datos simulada
items_db = [
    {'id': 1, 'name': 'Item 1', 'description': 'Primer item'},
    {'id': 2, 'name': 'Item 2', 'description': 'Segundo item'}
]

def process_items(form_data, query_params):
    """Procesa operaciones CRUD"""
    action = form_data.get('action', '')
    
    if action == 'add':
        name = form_data.get('name', '').strip()
        description = form_data.get('description', '').strip()
        
        if name:
            new_id = max([item['id'] for item in items_db], default=0) + 1
            items_db.append({
                'id': new_id,
                'name': name,
                'description': description
            })
            return {
                'items': items_db,
                'success_message': '<div class="success">Item agregado</div>'
            }
    
    elif action == 'delete':
        item_id = int(form_data.get('id', 0))
        items_db[:] = [item for item in items_db if item['id'] != item_id]
        return {
            'items': items_db,
            'success_message': '<div class="success">Item eliminado</div>'
        }
    
    return {'items': items_db}

html.register_data_processor('items', process_items)

def serve_items(data, params, headers, path_params):
    html.serve_html(endpoint, 'items.html', request_data=data)

endpoint.register_handler('GET', serve_items, '/items')
endpoint.register_handler('POST', serve_items, '/items')

if __name__ == "__main__":
    endpoint.handle_request()
```

**Plantilla HTML:**

```html
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Gestión de Items</title>
</head>
<body>
    <h1>Lista de Items</h1>
    
    {{raw:success_message}}
    
    <!-- Formulario para agregar -->
    <h2>Agregar Nuevo</h2>
    <form method="POST">
        <input type="hidden" name="action" value="add">
        <input type="text" name="name" placeholder="Nombre" required>
        <input type="text" name="description" placeholder="Descripción">
        <button type="submit">Agregar</button>
    </form>
    
    <!-- Lista con JavaScript -->
    <h2>Items Existentes</h2>
    <div id="items-list"></div>
    
    <script>
        const items = JSON.parse('{{json:items}}');
        const listDiv = document.getElementById('items-list');
        
        items.forEach(item => {
            const div = document.createElement('div');
            div.innerHTML = `
                <h3>${item.name}</h3>
                <p>${item.description}</p>
                <form method="POST" style="display:inline">
                    <input type="hidden" name="action" value="delete">
                    <input type="hidden" name="id" value="${item.id}">
                    <button type="submit">Eliminar</button>
                </form>
                <hr>
            `;
            listDiv.appendChild(div);
        });
    </script>
</body>
</html>
```

### Configuración del HTMLHandler

```python
html = HTMLHandler(
    templates_dir='templates',           # Directorio de plantillas
    allowed_extensions=('.html', '.htm'), # Extensiones permitidas
    max_file_size=1024 * 1024,           # Tamaño máximo (1MB)
    enable_caching=True                   # Habilitar cache con ETags
)
```

### API del HTMLHandler

#### `register_data_processor(page_name, processor_func)`

Registra un procesador de datos para una página específica.

```python
def my_processor(form_data, query_params):
    """
    form_data: Dict con datos del formulario (POST/PUT)
    query_params: Dict con parámetros de query string
    
    Returns: Dict con datos para inyectar en la plantilla
    """
    return {'key': 'value'}

html.register_data_processor('page_name', my_processor)
```

#### `serve_html(http_instance, page_name, **kwargs)`

Sirve una página HTML con datos inyectados.

```python
html.serve_html(
    endpoint,                    # Instancia HTTP
    'contact.html',              # Archivo HTML
    request_data=data,           # Datos del POST/PUT (opcional)
    query_params=params,         # Query string (opcional)
    initial_data={'key': 'val'}, # Datos iniciales (opcional)
    status_code=200              # Código HTTP (opcional)
)
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

### 2. Seguridad en Plantillas HTML

```python
# ✅ CORRECTO: Escapar datos de usuario
html_content = """<h1>Hola {{username}}</h1>"""

# ✅ CORRECTO: JSON para JavaScript
html_content = """
<script>
    const data = JSON.parse('{{json:user_data}}');
</script>
"""

# ❌ INCORRECTO: Nunca uses raw con datos de usuario
# html_content = """<div>{{raw:user_input}}</div>"""  # ¡PELIGROSO!

# ✅ CORRECTO: raw solo para HTML generado por el servidor
def my_processor(form_data, query_params):
    return {
        'success_message': '<div class="success">Operación exitosa</div>'
    }
```

### 3. Rate Limiting Personalizado

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

### 4. Configuración CORS

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

### Pruebas con cURL (Páginas HTML)

```bash
# GET página HTML
curl -X GET "http://localhost/app.py/home"

# POST formulario
curl -X POST "http://localhost/app.py/contact" \
     -d "name=John&email=john@example.com&message=Hello"

# POST con action específica
curl -X POST "http://localhost/app.py/items" \
     -d "action=add&name=NewItem&description=Test"
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

## 📚 Estructura de Proyecto Recomendada

```
mi_proyecto/
├── http.py              # Librería HTTP principal
├── html_handler.py      # Handler para páginas HTML
├── api.py              # Script CGI para API JSON
├── app.py              # Script CGI para páginas HTML
├── templates/          # Plantillas HTML
│   ├── home.html
│   ├── contact.html
│   ├── items.html
│   └── dashboard.html
├── static/             # Archivos estáticos (CSS, JS, imágenes)
│   ├── css/
│   ├── js/
│   └── images/
└── logs/
    └── app.log
```


Para reportar problemas o solicitar nuevas características, abre un issue en el repositorio del proyecto.
