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
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--disable-gpu")
    browser = webdriver.Edge(options=options)
    browser.get("http://172.16.245.50/")
    time.sleep(1)
    login_btn = browser.find_element(By.XPATH, '//*[@id="logout"]')
    login_btn.click()

def login():
    available_networks = scan_networks()
    print(f"可用的网络: {available_networks}")

    # 自动连接到 CMCC-EDU 或 SWPU-EDU
    for ssid in ["CMCC-EDU", "SWPU-EDU"]:
        if ssid in available_networks:
            connect_to_wifi(ssid)
            break
    else:
        print("未找到可连接的网络。")
        return 0  # 如果没有找到网络，则退出程序
    time.sleep(3)
    # 进行 ping 测试
    if not ping("baidu.com"):
        print("进行登录操作...")

        # 打印本机 IP 地址
        ip_address = get_ip_address()
        if ip_address:
            print(f"本机 IP 地址: {ip_address}")
        options = Options()
        options.add_argument("--headless")
        options.add_argument("--disable-gpu")

        # 启动浏览器
        browser = webdriver.Edge(options=options)
        browser.get("http://www.baidu.com/")
        

        # 输入用户名和密码
        username = browser.find_element(By.XPATH, '//*[@id="username"]')
        password = browser.find_element(By.XPATH, '//*[@id="password"]')

        username.clear()
        username.send_keys(username_)
        password.clear()
        password.send_keys(password_)

        # 选择下拉菜单中的“移动有线”
        domain_select = Select(browser.find_element(By.ID, 'domain'))
        domain_select.select_by_value('@ydyx')

        # 点击登录按钮
        login_btn = browser.find_element(By.XPATH, '//*[@id="login"]')
        login_btn.click()
        time.sleep(3)
        browser.quit()

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
        print(f"扫描网络时出错: {e}")
        return []

def connect_to_wifi(ssid):
    """连接到指定的无线网络"""
    try:
        subprocess.run(['netsh', 'wlan', 'connect', ssid], check=True, encoding='utf-8', creationflags=subprocess.CREATE_NO_WINDOW)
        print(f"已连接到 {ssid} 无线网络")
    except subprocess.CalledProcessError as e:
        print(f"连接到 {ssid} 失败: {e}")

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
        print(f"获取IP地址时出错: {e}")
        return None


def ping(host):
    """Ping a host and return True if it's reachable."""
    try:
        subprocess.run(["ping", "-n", "2", host], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        return True
    except subprocess.CalledProcessError:
        return False

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
            print("网络断开，检查以太网适配器状态...")
            if not check_interface("以太网"):
                print("没有连接以太网适配器。")
                login()
            else:
                print("以太网适配器已连接，尝试拨号...")
            
                if not rasdial("宽带连接", encrypt_username(username_,kinds[kind_index]) , password_):
                    print("拨号失败。")
                else:
                    print("拨号成功。")
        else:
            print("网络正常，检查无线网络和以太网适配器状态...")
            if not check_interface("以太网"):
                print("无线网络已连接，但以太网适配器未连接。")
            else:
                print("以太网适配器已连接，检查宽带连接状态...")
                if not check_interface("WLAN"):
                    print("宽带已连接，无需拨号。")
                else:
                    print("宽带未连接，尝试拨号...")
                    logout()
                    subprocess.run(["netsh", "wlan", "disconnect"], creationflags=subprocess.CREATE_NO_WINDOW)
                    if not rasdial("宽带连接", encrypt_username(username_,kinds[kind_index]) , password_):
                        print("拨号失败。")
                    else:
                        print("拨号成功。")

        time.sleep(6)

if __name__ == "__main__":
    main()
