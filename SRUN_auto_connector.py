import subprocess
import time
import socket
from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait, Select
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.edge.service import Service
from selenium.webdriver.edge.options import Options
import re
from flask import Flask, render_template_string
import logging
import os
from ping3 import ping

LOG_DIR = r"LOG_DIR"
LOG_FILE = os.path.join(LOG_DIR, "network_check.log")
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')
options = Options()
options.add_argument("--headless")
options.add_argument("--disable-gpu")
browser = webdriver.Edge(options=options)

# Flask 应用
app = Flask(__name__)

@app.route('/')
def index():
    """主页，显示日志内容"""
    try:
        with open(LOG_FILE, 'r', encoding='latin-1') as f:
            log_content = f.readlines()
        return render_template_string('''
        <html>
            <head><title>auto network connector log</title></head>
            <body>
                <h1>auto network connector log</h1>
                <pre>{{ logs }}</pre>
                <meta http-equiv="refresh" content="5">
            </body>
        </html>
        ''', logs=''.join(log_content))
    except Exception as e:
        logging.error(f"Error occurred : {e}")
        return "Error reading log file.", 500


username_ = 'username'
password_ = 'password'
kinds = {1:'@ydyx',2:'@dx',3:'@tch',4:'@stu'}
kind_index=1
def encrypt_username(username,kind):
    res = '{SRUN2}'
    for char in username:
        res += chr(ord(char) + 4)
    return res+kind

def logout():
    try:
        browser.get("http://172.16.245.50/")
        time.sleep(1)
        login_btn = browser.find_element(By.XPATH, '//*[@id="logout"]')
        login_btn.click()
        logging.info(f"Successfully logout.")
        ptint(f"Successfully logout.")
    except Exception as e:
        logging.error(f"Failed to logout: {e}")
        print (f"Failed to logout: {e}")
        return False
def login():
    available_networks = scan_networks()
    print(f"available_networks: {available_networks}")
    logging.info(f"available_networks: {available_networks}")
    # 自动连接到 CMCC-EDU 或 SWPU-EDU
    for ssid in ["CMCC-EDU", "SWPU-EDU"]:
        if ssid in available_networks:
            connect_to_wifi(ssid)
            ssid_=ssid
            break
    else:
        print("cannot find available_networks")
        logging.error("cannot find available_networks")
        return 0  # 如果没有找到网络，则退出程序
    # 进行 ping 测试
    if not ping("baidu.com"):
        print("auto logining")
        logging.info("auto logining")
        '''# 打印本机 IP 地址
        ip_address = get_ip_address()
        if ip_address:
            print(f"IP ADDR: {ip_address}")
            logging.info(f"IP ADDR: {ip_address}")'''
        try:
            if ssid_ == "CMCC-EDU":
                browser.get("http://172.16.245.50/srun_portal_pc?ac_id=2&theme=basic")
            else:
                browser.get("http://172.16.245.50/srun_portal_pc?ac_id=1&theme=basic")
            # 输入用户名和密码
            username = browser.find_element(By.XPATH, '//*[@id="username"]')
            password = browser.find_element(By.XPATH, '//*[@id="password"]')

            username.clear()
            username.send_keys(username_)
            password.clear()
            password.send_keys(password_)

            # 选择下拉菜单中的“移动有线”
            domain_select = Select(browser.find_element(By.ID, 'domain'))
            domain_select.select_by_value(kinds[kind_index])

            # 点击登录按钮
            login_btn = browser.find_element(By.XPATH, '//*[@id="login"]')
            login_btn.click()
        except Exception as e:
            logging.error(f"Failed to login: {e}")
def scan_networks():
    """扫描可用的无线网络并返回一个列表"""
    try:
        result = subprocess.run(['netsh', 'wlan', 'show', 'network'], capture_output=True, text=True, encoding='latin-1', creationflags=subprocess.CREATE_NO_WINDOW)
        networks = []
        for line in result.stdout.splitlines():
            if 'SSID' in line:
                ssid = line.split(':')[1].strip()
                networks.append(ssid)
        return networks
    except Exception as e:
        print(f"failed to scan the network: {e}")
        logging.error(f"failed to scan the networ: {e}")
        return []

def connect_to_wifi(ssid):
    """连接到指定的无线网络"""
    try:
        subprocess.run(['netsh', 'wlan', 'connect', ssid], check=True, encoding='utf-8', creationflags=subprocess.CREATE_NO_WINDOW)
        print(f"connected to {ssid} ")
        logging.info(f"connected to {ssid} ")
    except subprocess.CalledProcessError as e:
        print(f"failed to connected to {ssid}: {e}")
        logging.error(f"failed to connected to {ssid}: {e}")

def get_ip_address():
    
    """获取本机的 IP 地址"""
    try:
        result = subprocess.run(['ipconfig'], capture_output=True, text=True, encoding='gbk', creationflags=subprocess.CREATE_NO_WINDOW)
        ip_pattern = re.compile(r'IPv4 地址.*?: (\d+\.\d+\.\d+\.\d+)')
        for line in result.stdout.splitlines():
            match = ip_pattern.search(line)
            if match:
                return match.group(1)
    except Exception as e:
        print(f"failed to get IP ADDR: {e}")
        logging.error(f"failed to get IP ADDR: {e}")
        return
'''
def ping(host):
    """Ping a host and return True if it's reachable."""
    try:
        subprocess.run(["ping", "-n", "2", host], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        logging.info("network accessible")
        return True
    except subprocess.CalledProcessError:
        logging.info("network not accessible")
        return False'''

def check_interface(interface_name):
    """Check if a specific network interface is connected."""
    result = subprocess.run(["netsh", "interface", "show", "interface", interface_name], stdout=subprocess.PIPE, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    return "已连接" in result.stdout

def rasdial(connection_name, username, password):
    """Dial a connection using rasdial."""
    try:
        print("rasdial", connection_name, username, password)
        subprocess.run(["rasdial", connection_name, username, password], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        return True
    except subprocess.CalledProcessError:
        return False

def main():
    while True:
        if not ping("baidu.com"):
            print("The network is disconnected,check interface")
            logging.info("The network is disconnected,check interface")
            if not check_interface("以太网"):
                print("Ethernet adapter is not connected")
                logging.info("Ethernet adapter is not connected")
                login()
            else:
                print("Ethernet adapter is not connected,try dial")
                logging.info("Ethernet adapter is not connected,try dial")
                if not rasdial("宽带连接", encrypt_username(username_,kinds[kind_index]) , password_):
                    print("dialing failed")
                    logging.error("dialing failed")
                else:
                    print("dialing success")
                    logging.info("dialing success")
        else:
            print("The network is connected,check interface")
            logging.info("The network is disconnected,check interface")
            if not check_interface("以太网"):
                print("wireless network is connected,but ethernet adapter is not connected")
                logging.info("wireless network is connected,but ethernet adapter is not connected")
            else:
                print("Ethernet adapter is connected,cheak dial status")
                logging.info("Ethernet adapter is connected,cheak dial status")
                if not check_interface("WLAN"):
                    print("the broadband is connected,nothing to do")
                    logging.info("the broadband is connected,nothing to do")
                else:
                    print("the broadband is not connected,try dial")
                    logging.info("the broadband is not connected,try dial")
                    logout()
                    subprocess.run(["netsh", "wlan", "disconnect"], creationflags=subprocess.CREATE_NO_WINDOW)
                    if not rasdial("宽带连接", encrypt_username(username_,kinds[kind_index]) , password_):
                        print("dialing failed")
                        logging.error("dialing failed")
                    else:
                        print("dialing success")
                        logging.info("dialing success")

        time.sleep(6)

if __name__ == "__main__":
    import threading
    threading.Thread(target=main, daemon=True).start()
    app.run(host='0.0.0.0', port=5010)
