#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import urllib.parse
import hashlib
import time
import re
import logging
import tempfile
import signal
import secrets
from datetime import datetime
from typing import Dict, Any, Optional, Callable, List, Union, Tuple

try:
    import fcntl
    _HAVE_FCNTL = True
except Exception:
    _HAVE_FCNTL = False

# --- Utilidades de saneo básico de cabeceras/valores --- #
_CONTROL_CHARS_RE = re.compile(r'[\x00-\x1F\x7F]')

def _clean_header_value(value: str, max_len: int = 8192) -> str:
    """Elimina CRLF y chars de control para prevenir inyección de cabeceras"""
    if not isinstance(value, str):
        value = str(value)
    value = value.replace('\r', '').replace('\n', '')
    value = _CONTROL_CHARS_RE.sub('', value)
    return value[:max_len]

def _gen_request_id() -> str:
    return secrets.token_hex(8)

class HTTP:
    """
    Librería segura para manejo de peticiones HTTP (cgi) con configuración flexible
    y soporte para múltiples paths
    """

    def __init__(self,
                 max_content_length: int = 1024 * 1024,
                 max_query_string_length: int = 2048,
                 max_header_length: int = 8192,
                 timeout_seconds: int = 30,
                 rate_limit_requests: int = 100,
                 rate_limit_window: int = 60,
                 log_file: Optional[str] = None,
                 log_level: int = logging.INFO,
                 allowed_methods: List[str] = None,
                 allowed_content_types: List[str] = None,
                 cors_origins: str = "*",
                 security_headers: Optional[Dict[str, str]] = None,
                 enable_rate_limiting: bool = True,
                 enable_timeout: bool = True,
                 max_json_depth: int = 10,
                 max_dict_items: int = 100,
                 max_array_items: int = 1000,
                 trusted_proxies: Optional[List[str]] = None):
        """
        Inicializa el protocolo HTTP con la configuración dada.
        """
        self.max_content_length = max_content_length
        self.max_query_string_length = max_query_string_length
        self.max_header_length = max_header_length
        self.timeout_seconds = timeout_seconds
        self.rate_limit_requests = rate_limit_requests
        self.rate_limit_window = rate_limit_window
        self.enable_rate_limiting = enable_rate_limiting
        self.enable_timeout = enable_timeout
        self.max_json_depth = max_json_depth
        self.max_dict_items = max_dict_items
        self.max_array_items = max_array_items
        self.trusted_proxies = trusted_proxies or []

        # Métodos y tipos permitidos
        self.allowed_methods = (allowed_methods or
                                ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD'])
        self.allowed_content_types = allowed_content_types or [
            'application/json',
            'application/x-www-form-urlencoded',
            'text/plain'
        ]

        # CORS
        self.cors_origins = cors_origins

        # Headers de seguridad por defecto (afinados para API)
        default_security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Cross-Origin-Resource-Policy': 'same-site',
            'Cache-Control': 'no-store'
        }
        if security_headers:
            default_security_headers.update(security_headers)
        self.security_headers = default_security_headers

        # Logging
        self._setup_logging(log_file, log_level)

        # Handlers por path y método: {path: {method: handler}}
        self.handlers: Dict[str, Dict[str, Callable]] = {}
        
        # Handler por defecto (sin path específico)
        self.default_handlers: Dict[str, Callable] = {}

        # Estado de la petición actual
        self.current_request: Dict[str, Any] = {}

    def _setup_logging(self, log_file: Optional[str], log_level: int):
        """Configura el sistema de logging"""
        self.logger = logging.getLogger(f"SecureCGI_{id(self)}")
        self.logger.setLevel(log_level)
        if not self.logger.handlers:
            if log_file and (os.path.dirname(log_file) == '' or os.path.exists(os.path.dirname(log_file))):
                handler = logging.FileHandler(log_file)
            else:
                handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def register_handler(self, method: str, handler_func: Callable, path: Optional[str] = None):
        """
        Registra un handler para un método HTTP específico y opcionalmente un path.
        
        Args:
            method: Método HTTP (GET, POST, PUT, DELETE, etc.)
            handler_func: Función handler que recibirá (data, params, headers, path_params)
            path: Path opcional. Si es None, se usa como handler por defecto.
                  Soporta parámetros: /users/{id} o /posts/{post_id}/comments/{comment_id}
        
        Ejemplos:
            endpoint.register_handler("GET", get_users, "/users")
            endpoint.register_handler("GET", get_user, "/users/{id}")
            endpoint.register_handler("POST", create_post, "/posts")
            endpoint.register_handler("GET", fallback_get)  # Handler por defecto sin path
        """
        method = method.upper()
        
        if path is None:
            # Handler por defecto (sin path específico)
            self.default_handlers[method] = handler_func
            self.logger.info(f"Registrado handler por defecto para {method}")
        else:
            # Normalizar path (quitar trailing slash excepto root)
            path = path.rstrip('/') or '/'
            
            if path not in self.handlers:
                self.handlers[path] = {}
            
            self.handlers[path][method] = handler_func
            self.logger.info(f"Registrado handler para {method} {path}")

    def _get_request_path(self) -> str:
        """Obtiene el path de la petición actual"""
        # PATH_INFO es el path después del script CGI
        path = os.environ.get('PATH_INFO', '/') or '/'
        # Normalizar (quitar trailing slash excepto root)
        path = path.rstrip('/') or '/'
        return path

    def _match_path(self, request_path: str) -> Optional[Tuple[str, Dict[str, str]]]:
        """
        Intenta hacer match del request_path con los paths registrados.
        Soporta parámetros dinámicos: /users/{id}
        
        Returns:
            Tuple de (path_pattern, path_params) si hay match, None si no
        """
        # Primero intenta match exacto
        if request_path in self.handlers:
            return (request_path, {})
        
        # Luego intenta match con parámetros
        for pattern in self.handlers.keys():
            # Convertir pattern a regex
            # /users/{id} -> /users/(?P<id>[^/]+)
            # /posts/{post_id}/comments/{comment_id} -> /posts/(?P<post_id>[^/]+)/comments/(?P<comment_id>[^/]+)
            
            regex_pattern = pattern
            param_names = re.findall(r'\{(\w+)\}', pattern)
            
            for param_name in param_names:
                regex_pattern = regex_pattern.replace(
                    f'{{{param_name}}}',
                    f'(?P<{param_name}>[^/]+)'
                )
            
            # Anclar al inicio y final
            regex_pattern = f'^{regex_pattern}$'
            
            match = re.match(regex_pattern, request_path)
            if match:
                path_params = match.groupdict()
                # Sanitizar los parámetros extraídos
                sanitized_params = {
                    k: self._sanitize_input(v, 200) 
                    for k, v in path_params.items()
                }
                return (pattern, sanitized_params)
        
        return None

    def _setup_timeout(self):
        """Configura timeout para prevenir ataques DoS (Unix)."""
        if not self.enable_timeout:
            return
        if hasattr(signal, 'SIGALRM'):
            def timeout_handler(signum, frame):
                self.logger.error("Timeout: Script execution exceeded time limit")
                self._send_error_response(408, "Request Timeout")
                try:
                    sys.stdout.flush()
                finally:
                    os._exit(1)
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(self.timeout_seconds)
        else:
            self.logger.warning("Timeout no soportado en esta plataforma; deshabilitado.")

    def _validate_environment(self) -> bool:
        """Valida variables de entorno críticas"""
        required_vars = ['REQUEST_METHOD']
        for var in required_vars:
            if var not in os.environ:
                self.logger.error(f"Falta variable de entorno requerida: {var}")
                return False
        return True

    def _sanitize_input(self, data: Any, max_length: int = 1000) -> str:
        """
        Valida/limita longitud sin escapar HTML (no romper JSON).
        Si en el futuro sirves HTML, escapa allí, no aquí.
        """
        if not isinstance(data, str):
            data = str(data)
        data = data.strip()
        if len(data) > max_length:
            data = data[:max_length]
            self.logger.warning(f"Input truncado a {max_length} caracteres")
        return data

    def _validate_content_type(self, content_type: Optional[str]) -> bool:
        """Valida el Content-Type básico (solo tipo principal)"""
        if not content_type:
            return True
        main_type = content_type.split(';')[0].strip().lower()
        return main_type in self.allowed_content_types

    def _get_client_ip(self) -> str:
        """Resuelve IP del cliente respetando proxies de confianza."""
        client_ip = os.environ.get('REMOTE_ADDR', '') or ''
        xff = os.environ.get('HTTP_X_FORWARDED_FOR')
        if xff and client_ip in self.trusted_proxies:
            first = xff.split(',')[0].strip()
            if first:
                client_ip = first
        return client_ip or 'unknown'

    def _rate_limit_file(self, client_ip: str) -> str:
        ip_hash = hashlib.md5(client_ip.encode()).hexdigest()
        return os.path.join(tempfile.gettempdir(), f"rate_limit_{ip_hash}")

    def _check_rate_limit(self) -> bool:
        """Implementa rate limiting con archivo y locking (Unix)."""
        if not self.enable_rate_limiting or self.rate_limit_requests <= 0:
            return True
        try:
            client_ip = self._get_client_ip()
            current_time = int(time.time())
            temp_file = self._rate_limit_file(client_ip)

            requests: List[int] = []
            fd = os.open(temp_file, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                with os.fdopen(fd, 'r+', encoding='utf-8') as f:
                    if _HAVE_FCNTL:
                        try:
                            fcntl.flock(f, fcntl.LOCK_EX)
                        except Exception:
                            pass
                    try:
                        lines = f.read().splitlines()
                        requests = [int(x) for x in lines if x.isdigit()]
                    except Exception:
                        requests = []
                    win = self.rate_limit_window
                    requests = [t for t in requests if current_time - t < win]
                    if len(requests) >= self.rate_limit_requests:
                        self.logger.warning(f"Rate limit excedido para IP: {client_ip}")
                        return False
                    requests.append(current_time)
                    f.seek(0)
                    f.truncate(0)
                    f.write("\n".join(str(t) for t in requests) + "\n")
                    if _HAVE_FCNTL:
                        try:
                            fcntl.flock(f, fcntl.LOCK_UN)
                        except Exception:
                            pass
            except Exception:
                try:
                    os.close(fd)
                except Exception:
                    pass
            return True
        except Exception as e:
            self.logger.error(f"Fallo en rate limit: {e}")
            return True

    def _get_request_method(self) -> Optional[str]:
        """Obtiene y valida el método HTTP"""
        method = os.environ.get('REQUEST_METHOD', 'GET').upper()
        if method not in self.allowed_methods:
            self.logger.warning(f"Método HTTP no permitido: {method}")
            return None
        return method

    def _get_query_string(self) -> Dict[str, List[str]]:
        """Obtiene y valida parámetros de query string"""
        query_string = os.environ.get('QUERY_STRING', '') or ''
        if len(query_string) > self.max_query_string_length:
            self.logger.warning("Query string demasiado larga; truncando")
            query_string = query_string[:self.max_query_string_length]
        if query_string:
            try:
                parsed = urllib.parse.parse_qs(query_string, keep_blank_values=False)
                sanitized: Dict[str, List[str]] = {}
                for key, values in parsed.items():
                    clean_key = self._sanitize_input(key, 200)
                    clean_values = [self._sanitize_input(v, 2000) for v in values]
                    sanitized[clean_key] = clean_values
                return sanitized
            except Exception as e:
                self.logger.error(f"Error parseando query string: {e}")
                return {}
        return {}

    def _sanitize_json_data(self, data: Any, current_depth: int = 0) -> Any:
        """Sanitiza datos JSON recursivamente (hasta la profundidad indicada)"""
        if current_depth > self.max_json_depth:
            self.logger.warning("Límite de profundidad JSON superado")
            return "DEPTH_LIMIT_EXCEEDED"
        if isinstance(data, dict):
            sanitized: Dict[str, Any] = {}
            for i, (key, value) in enumerate(data.items()):
                if i >= self.max_dict_items:
                    self.logger.warning("Diccionario truncado por max_dict_items")
                    break
                clean_key = self._sanitize_input(str(key), 200)
                sanitized[clean_key] = self._sanitize_json_data(value, current_depth + 1)
            return sanitized
        if isinstance(data, list):
            if len(data) > self.max_array_items:
                self.logger.warning("Array truncado por max_array_items")
                data = data[:self.max_array_items]
            return [self._sanitize_json_data(v, current_depth + 1) for v in data]
        if isinstance(data, str):
            return self._sanitize_input(data, 10000)
        if isinstance(data, (int, float, bool)) or data is None:
            return data
        return self._sanitize_input(str(data), 10000)

    def _get_request_data(self) -> Dict[str, Any]:
        """Obtiene datos del cuerpo (POST/PUT)"""
        try:
            content_length_str = os.environ.get('CONTENT_LENGTH', '0') or '0'
            try:
                content_length = int(content_length_str)
            except Exception:
                self.logger.error(f"CONTENT_LENGTH inválido: {content_length_str!r}")
                return {}

            if content_length < 0:
                self.logger.error("Content-Length negativo")
                return {}
            if content_length > self.max_content_length:
                self.logger.error(f"Content-Length demasiado grande: {content_length}")
                return {}

            if content_length == 0:
                return {}

            raw = sys.stdin.read(content_length)
            content_type = (os.environ.get('CONTENT_TYPE', '') or '').lower()

            if not self._validate_content_type(content_type):
                self.logger.warning(f"Content-Type no permitido: {content_type}")
                return {}

            if 'application/json' in content_type:
                try:
                    data = json.loads(raw)
                    return self._sanitize_json_data(data)
                except json.JSONDecodeError as e:
                    self.logger.error(f"JSON inválido: {e}")
                    return {}

            if 'application/x-www-form-urlencoded' in content_type:
                try:
                    parsed = urllib.parse.parse_qs(raw, keep_blank_values=True)
                    sanitized: Dict[str, List[str]] = {}
                    for key, values in parsed.items():
                        clean_key = self._sanitize_input(key, 200)
                        clean_values = [self._sanitize_input(v, 2000) for v in values]
                        sanitized[clean_key] = clean_values
                    return sanitized
                except Exception as e:
                    self.logger.error(f"Error parseando form-urlencoded: {e}")
                    return {}

            if 'multipart/form-data' in content_type:
                self.logger.warning("multipart/form-data no soportado")
                return {}

            return {"data": self._sanitize_input(raw, self.max_content_length)}

        except Exception as e:
            self.logger.error(f"Error leyendo cuerpo: {e}")
            return {}

    def _get_safe_headers(self) -> Dict[str, str]:
        """Obtiene cabeceras HTTP de forma segura"""
        safe_headers: Dict[str, str] = {}
        for key, value in os.environ.items():
            if key.startswith('HTTP_'):
                header_name = key[5:].replace('_', '-').title()
                clean_value = _clean_header_value(value, self.max_header_length)
                safe_headers[header_name] = clean_value
            elif key in ['CONTENT_TYPE', 'CONTENT_LENGTH']:
                header_name = key.replace('_', '-').title()
                safe_headers[header_name] = _clean_header_value(str(value), 200)
        return safe_headers

    def send_response(self,
                      status_code: int = 200,
                      content_type: str = 'application/json',
                      body: Union[Dict, List, str, bytes] = b'',
                      extra_headers: Optional[Dict[str, str]] = None):
        """Envía respuesta HTTP segura con Content-Length y control de cuerpo."""

        status_messages = {
            200: 'OK', 201: 'Created', 202: 'Accepted',
            204: 'No Content', 304: 'Not Modified',
            400: 'Bad Request', 401: 'Unauthorized',
            403: 'Forbidden', 404: 'Not Found', 405: 'Method Not Allowed',
            408: 'Request Timeout', 413: 'Payload Too Large',
            415: 'Unsupported Media Type', 429: 'Too Many Requests',
            500: 'Internal Server Error'
        }
        status_message = status_messages.get(status_code, 'Unknown')

        no_body = (status_code in (204, 304)) or (self.current_request.get('method') == 'HEAD')
        body_bytes: bytes = b""

        if not no_body:
            if isinstance(body, (dict, list)):
                try:
                    json_output = json.dumps(body, ensure_ascii=False, separators=(',', ':'))
                    body_bytes = json_output.encode('utf-8')
                    if content_type.startswith('application/json') and 'charset=' not in content_type.lower():
                        content_type = content_type + '; charset=utf-8'
                except TypeError as e:
                    self.logger.error(f"Error serializando JSON: {e}")
                    fallback = '{"error":"Internal serialization error"}'
                    body_bytes = fallback.encode('utf-8')
                    content_type = 'application/json; charset=utf-8'
            elif isinstance(body, bytes):
                body_bytes = body
            else:
                body_str = '' if body is None else str(body)
                if content_type.startswith('application/json') and 'charset=' not in content_type.lower():
                    content_type = content_type + '; charset=utf-8'
                if content_type.startswith('text/') and 'charset=' not in content_type.lower():
                    content_type = content_type + '; charset=utf-8'
                body_bytes = body_str.encode('utf-8')

        print(f"Status: {status_code} {status_message}")

        content_type = content_type or 'application/octet-stream'
        print(f"Content-Type: {_clean_header_value(content_type, 200)}")

        for header, value in self.security_headers.items():
            print(f"{header}: {_clean_header_value(value, 200)}")

        print(f"Access-Control-Allow-Origin: {_clean_header_value(self.cors_origins, 200)}")
        print("Access-Control-Allow-Methods: " + ", ".join(self.allowed_methods))
        print("Access-Control-Allow-Headers: Content-Type, Authorization")
        print("Access-Control-Max-Age: 86400")
        print("Vary: Origin, Access-Control-Request-Method, Access-Control-Request-Headers")

        if extra_headers:
            for header, value in extra_headers.items():
                print(f"{header}: {_clean_header_value(str(value), 400)}")

        if not no_body:
            print(f"Content-Length: {len(body_bytes)}")

        print()

        if not no_body and body_bytes:
            sys.stdout.flush()
            try:
                sys.stdout.buffer.write(body_bytes)
            except Exception:
                sys.stdout.write(body_bytes.decode('utf-8', errors='replace'))
            sys.stdout.flush()

    def _send_error_response(self, status_code: int, message: str, extra_headers: Optional[Dict[str, str]] = None):
        """Envía respuesta de error segura"""
        error_data = {
            "error": True,
            "status": status_code,
            "message": self._sanitize_input(message, 1000),
            "timestamp": datetime.now().isoformat(),
            "request_id": self.current_request.get('request_id')
        }
        self.logger.warning(f"Error response: {status_code} - {message} - rid={self.current_request.get('request_id')}")
        self.send_response(status_code, 'application/json', error_data, extra_headers=extra_headers)

    def handle_request(self):
        """Maneja la petición HTTP principal"""
        request_id = _gen_request_id()
        try:
            self._setup_timeout()

            if not self._validate_environment():
                self.current_request = {'request_id': request_id, 'method': os.environ.get('REQUEST_METHOD', 'UNKNOWN')}
                self._send_error_response(500, "Server configuration error")
                return

            method = os.environ.get('REQUEST_METHOD', 'GET').upper()
            request_path = self._get_request_path()

            headers = self._get_safe_headers()
            query_params = self._get_query_string()
            request_data: Dict[str, Any] = {}

            client_ip = self._get_client_ip()
            user_agent = headers.get('User-Agent', 'unknown')

            self.current_request = {
                'request_id': request_id,
                'method': method,
                'path': request_path,
                'query_params': query_params,
                'data': {},
                'headers': headers,
                'timestamp': datetime.now().isoformat(),
                'client_ip': client_ip,
                'user_agent': user_agent
            }

            if not self._check_rate_limit():
                self._send_error_response(429, "Too many requests")
                return

            if method == 'OPTIONS':
                acrm = headers.get('Access-Control-Request-Method')
                acrh = headers.get('Access-Control-Request-Headers')
                extra = {}
                if acrm:
                    extra["Access-Control-Allow-Methods"] = _clean_header_value(acrm)
                if acrh:
                    extra["Access-Control-Allow-Headers"] = _clean_header_value(acrh)
                self.logger.info(f"OPTIONS preflight - rid={request_id}")
                self.send_response(204, body=b'', extra_headers=extra)
                return

            if method not in self.allowed_methods:
                self._send_error_response(405, "Method not allowed",
                                          extra_headers={"Allow": ", ".join(self.allowed_methods)})
                return

            if method in ['POST', 'PUT', 'PATCH', 'DELETE']:
                content_length_str = os.environ.get('CONTENT_LENGTH', '0') or '0'
                try:
                    content_length = int(content_length_str)
                except Exception:
                    self._send_error_response(400, "Invalid Content-Length")
                    return
                if content_length > self.max_content_length:
                    self._send_error_response(413, "Payload too large")
                    return
                content_type = os.environ.get('CONTENT_TYPE', '')
                if not self._validate_content_type(content_type):
                    self._send_error_response(415, "Unsupported media type")
                    return
                request_data = self._get_request_data()

            self.current_request['data'] = request_data

            # Buscar handler para el path
            path_match = self._match_path(request_path)
            
            if path_match:
                pattern, path_params = path_match
                self.current_request['path_params'] = path_params
                
                if method in self.handlers[pattern]:
                    try:
                        self.logger.info(f"Dispatch {method} {request_path} (pattern: {pattern}) - rid={request_id} - ip={client_ip}")
                        self.handlers[pattern][method](request_data, query_params, headers, path_params)
                    except Exception as e:
                        self.logger.error(f"Error en handler {method} {pattern}: {e} - rid={request_id}")
                        self._send_error_response(500, "Handler execution error")
                else:
                    # Path existe pero método no permitido para ese path
                    allowed = list(self.handlers[pattern].keys())
                    self._send_error_response(405, f"Method not allowed for {request_path}",
                                            extra_headers={"Allow": ", ".join(allowed)})
            elif method in self.default_handlers:
                # Usar handler por defecto si existe
                try:
                    self.logger.info(f"Dispatch {method} (default handler) - rid={request_id} - ip={client_ip}")
                    self.default_handlers[method](request_data, query_params, headers, {})
                except Exception as e:
                    self.logger.error(f"Error en default handler {method}: {e} - rid={request_id}")
                    self._send_error_response(500, "Handler execution error")
            else:
                # No se encontró handler
                self._send_error_response(404, f"Path not found: {request_path}")

        except Exception as e:
            self.logger.error(f"Excepción no controlada: {e} - rid={request_id}")
            self._send_error_response(500, "Internal server error")
        finally:
            if self.enable_timeout and hasattr(signal, 'alarm'):
                try:
                    signal.alarm(0)
                except Exception:
                    pass

    def get_current_request(self) -> Dict[str, Any]:
        """Obtiene información de la petición actual"""
        return self.current_request.copy()
