import asyncio
import subprocess
import threading
import queue
import re
import os
import sys
import time
import platform
import glob
from typing import Optional, List
from mcp.server.fastmcp import FastMCP

# --- Auto-Detection & Cross-Platform Logic ---

def get_os_type():
    return platform.system()

def find_proxmark3_exe():
    """Finds the proxmark3 executable based on the OS."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    os_type = get_os_type()
    
    executable_name = "proxmark3.exe" if os_type == "Windows" else "proxmark3"
    
    # 1. Check current directory
    local_path = os.path.join(base_dir, executable_name)
    if os.path.exists(local_path):
        return local_path
        
    # 2. Check build directory (common in dev setups)
    build_path = os.path.join(base_dir, "build", executable_name)
    if os.path.exists(build_path):
        return build_path
        
    # 3. Fallback to just the name (hope it's in PATH)
    return executable_name

def detect_port() -> Optional[str]:
    """Auto-detects the Proxmark3 port based on OS."""
    os_type = get_os_type()
    print(f"Detecting port for {os_type}...")
    
    if os_type == "Windows":
        return _detect_port_windows()
    elif os_type == "Linux":
        return _detect_port_linux()
    elif os_type == "Darwin": # macOS
        return _detect_port_macos()
    return None

def _detect_port_windows() -> Optional[str]:
    """Uses PowerShell to find Proxmark3 devices."""
    # Logic extracted from the official pm3 shell script
    ps_cmd = (
        "Get-CimInstance -ClassName Win32_serialport | "
        "Where-Object {$_.PNPDeviceID -like '*VID_9AC4&PID_4B8F*' -or $_.PNPDeviceID -like '*VID_2D2D&PID_504D*'} | "
        "Select -expandproperty DeviceID"
    )
    
    try:
        # We use a wrapper to run PS command
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True
        )
        
        ports = result.stdout.strip().splitlines()
        ports = [p.strip() for p in ports if p.strip()]
        
        if ports:
            print(f"Found Windows Ports: {ports}")
            return ports[0] # Return first found
        
        # Check for Bluetooth Dongle (optional, based on pm3 script)
        ps_cmd_bt = (
            "Get-CimInstance -ClassName Win32_serialport | "
            "Where-Object {$_.PNPDeviceID -like '*VID_10C4&PID_EA60*'} | "
            "Select -expandproperty DeviceID"
        )
        result_bt = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd_bt],
            capture_output=True, text=True
        )
        bt_ports = [p.strip() for p in result_bt.stdout.strip().splitlines() if p.strip()]
        if bt_ports:
            print(f"Found BT Dongle: {bt_ports[0]}")
            return bt_ports[0]

    except Exception as e:
        print(f"Error detecting Windows port: {e}")
        
    return None

def _detect_port_linux() -> Optional[str]:
    """Scans /dev/ttyACM* and checks UDEV info."""
    devices = glob.glob("/dev/ttyACM*")
    for dev in devices:
        try:
            # Check properties using udevadm
            cmd = ["udevadm", "info", "-q", "property", "-n", dev]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if "ID_VENDOR=proxmark.org" in result.stdout:
                return dev
        except:
            continue
            
    # Simple Fallback if udevadm fails but ttyACM0 exists (often correct for PM3)
    if devices:
        return devices[0]
        
    return None

def _detect_port_macos() -> Optional[str]:
    """Scans /dev/tty.usbmodem*."""
    devices = glob.glob("/dev/tty.usbmodem*")
    if devices:
        return devices[0]
    return None

# --- Session Management ---

class Proxmark3Session:
    def __init__(self, port: Optional[str] = None):
        self.process: Optional[subprocess.Popen] = None
        self.output_queue = queue.Queue()
        self.is_running = False
        self.requested_port = port
        self.thread: Optional[threading.Thread] = None

    def start(self):
        if self.is_running:
            return "Session already running"

        exe_path = find_proxmark3_exe()
        cmd = [exe_path]
        
        # Port Resolution
        port_to_use = self.requested_port
        if not port_to_use or port_to_use == "auto":
            detected = detect_port()
            if detected:
                print(f"Auto-detected port: {detected}")
                port_to_use = detected
                # Append detected port to command
                cmd.append(port_to_use)
            else:
                print("No port detected. Starting in offline/default mode.")
                # Don't append any port arg, let PM3 decide (likely offline)
        else:
            cmd.append(port_to_use)

        
        cwd = os.path.dirname(exe_path) if os.path.exists(exe_path) else os.getcwd()
        
        # Environment Setup
        env = os.environ.copy()
        
        # Windows ProxSpace DLL injection
        if get_os_type() == "Windows":
            # Heuristic: Check relative to the script location if we are in a ProxSpace tree
            # Script: .../pm3/proxmark3/client/proxmark3_mcp.py
            # Expected: .../msys2/mingw64/bin
            
            script_dir = os.path.dirname(os.path.abspath(__file__))
            # Go up 3 levels from client/ -> proxmark3/ -> pm3/ -> ProxSpace
            possible_roots = [
               os.path.abspath(os.path.join(script_dir, "../../../msys2/mingw64/bin")), # Standard ProxSpace
               r"g:\Proxmark3\ProxSpace\msys2\mingw64\bin", # Hardcoded fallback from previous fix
            ]
            
            for dll_path in possible_roots:
                if os.path.exists(dll_path):
                    print(f"Injecting DLL path: {dll_path}")
                    env["PATH"] = dll_path + os.pathsep + env["PATH"]
                    break

        print(f"Starting Process: {' '.join(cmd)}")
        
        try:
            self.process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, 
                cwd=cwd,
                env=env,
                text=True,
                bufsize=0, # Unbuffered
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
            )
            self.is_running = True
            
            self.thread = threading.Thread(target=self._read_output, daemon=True)
            self.thread.start()
            
            return self._read_until_prompt()
            
        except Exception as e:
            self.is_running = False
            return f"Failed to start proxmark3: {e}"

    def _read_output(self):
        while self.is_running and self.process:
            try:
                char = self.process.stdout.read(1)
                if not char:
                    break
                self.output_queue.put(char)
            except Exception:
                break
        self.is_running = False

    def _read_until_prompt(self, timeout: float = 10.0) -> str:
        buffer = ""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            if not self.is_running:
                return buffer + "\n[Process Terminated]"
            
            try:
                char = self.output_queue.get(timeout=0.1)
                buffer += char
                if buffer.endswith("pm3 > "): 
                    return self._clean_output(buffer)
            except queue.Empty:
                continue
                
        return self._clean_output(buffer) + "\n[Timeout waiting for prompt]"

    def _clean_output(self, text: str) -> str:
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        text = ansi_escape.sub('', text)
        return text.strip()

    def execute(self, command: str) -> str:
        if not self.is_running or not self.process:
            return "Error: Session not running. Call connect() first."

        while not self.output_queue.empty():
            self.output_queue.get()

        try:
            print(f"Sending command: {command}")
            # Ensure command ends with newline
            cmd_str = command.strip() + "\n"
            self.process.stdin.write(cmd_str)
            self.process.stdin.flush()
        except OSError:
            self.is_running = False
            return "Error: Process terminated unexpectedly"

        return self._read_until_prompt()

    def disconnect(self):
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
        self.is_running = False
        self.process = None

# --- MCP Server Setup ---

mcp = FastMCP("Proxmark3")
pm3_session = Proxmark3Session()

@mcp.tool()
def connect(port: str = "auto") -> str:
    """
    Connect to the Proxmark3 device.
    Args:
        port: COM port (e.g., 'COM3') or 'auto' to attempt auto-detection.
    """
    p = None if port == "auto" else port
    global pm3_session
    if pm3_session.is_running:
        pm3_session.disconnect()
    
    pm3_session = Proxmark3Session(p)
    return pm3_session.start()

@mcp.tool()
def execute_command(command: str) -> str:
    """
    Execute a Proxmark3 command.
    Args:
        command: The command to run (e.g., 'hf search', 'hw status').
    """
    return pm3_session.execute(command)

@mcp.tool()
def disconnect() -> str:
    """Disconnect from the Proxmark3 device."""
    pm3_session.disconnect()
    return "Disconnected"

if __name__ == "__main__":
    mcp.run()
