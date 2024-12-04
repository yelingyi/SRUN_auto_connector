import subprocess
import time
import socket
import re
from flask import Flask, render_template_string
import logging
import os
from ping3 import ping
import requests
import urllib.request

if bytes is str: input = raw_input

try:

    def get_func(url, *args, **kwargs):
        resp = requests.get(url, *args, **kwargs)
        return resp.text


    def post_func(url, data, *args, **kwargs):
        resp = requests.post(url, data=data, *args, **kwargs)
        return resp.text

except ImportError:

    def get_func(url, *args, **kwargs):
        req = urllib.request.Request(url, *args, **kwargs)
        resp = urllib.request.urlopen(req)
        return resp.read().decode("utf-8")


    def post_func(url, data, *args, **kwargs):
        data_bytes = bytes(urllib.parse.urlencode(data), encoding='utf-8')
        req = urllib.request.Request(url, data=data_bytes, *args, **kwargs)
        resp = urllib.request.urlopen(req)
        return resp.read().decode("utf-8")


class SrunClient:
    name = 'SWPU'
    srun_ip = '172.16.245.50' # 自己学校认证ip，格式为#.#.#.# 例如123.123.123.123

    login_url = 'http://{}/cgi-bin/srun_portal'.format(srun_ip)
    online_url = 'http://{}/cgi-bin/rad_user_info'.format(srun_ip)
    # headers = {'User-Agent': 'SrunClient {}'.format(name)}
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36'}

    def __init__(self, username=None, passwd=None, print_log=True):
        self.username = username
        self.passwd = passwd
        self.print_log = print_log
        self.check_status = 0
        self.online_info = dict()
        #self.check_online()

    def _encrypt(self, passwd):
        column_key = [0, 0, 'd', 'c', 'j', 'i', 'h', 'g']
        row_key = [
            ['6', '7', '8', '9', ':', ';', '<', '=', '>', '?', '@', 'A', 'B', 'C', 'D', 'E'],
            ['?', '>', 'A', '@', 'C', 'B', 'E', 'D', '7', '6', '9', '8', ';', ':', '=', '<'],
            ['>', '?', '@', 'A', 'B', 'C', 'D', 'E', '6', '7', '8', '9', ':', ';', '<', '='],
            ['=', '<', ';', ':', '9', '8', '7', '6', 'E', 'D', 'C', 'B', 'A', '@', '?', '>'],
            ['<', '=', ':', ';', '8', '9', '6', '7', 'D', 'E', 'B', 'C', '@', 'A', '>', '?'],
            [';', ':', '=', '<', '7', '6', '9', '8', 'C', 'B', 'E', 'D', '?', '>', 'A', '@'],
            [':', ';', '<', '=', '6', '7', '8', '9', 'B', 'C', 'D', 'E', '>', '?', '@', 'A'],
            ['9', '8', '7', '6', '=', '<', ';', ':', 'A', '@', '?', '>', 'E', 'D', 'B', 'C'],
            ['8', '9', '6', '7', '<', '=', ':', ';', '@', 'A', '>', '?', 'D', 'E', 'B', 'C'],
            ['7', '6', '8', '9', ';', ':', '=', '<', '?', '>', 'A', '@', 'C', 'B', 'D', 'E'],
        ]
        encrypt_passwd = ''
        for idx, c in enumerate(passwd):
            char_c = column_key[ord(c) >> 4]
            char_r = row_key[idx % 10][ord(c) & 0xf]
            if idx % 2:
                encrypt_passwd += char_c + char_r
            else:
                encrypt_passwd += char_r + char_c
        return encrypt_passwd

    def _log(self, msg):
        if self.print_log:
            print('[SrunClient {}] {}'.format(self.name, msg))

    def check_online(self):
        resp_text = get_func(self.online_url, headers=self.headers)
        if 'not_online' in resp_text:
            self._log('###*** NOT ONLINE! ***###')
            return False
        try:
            items = resp_text.split(',')
            self.online_info = {
                'online': True, 'username': items[0],
                'login_time': items[1], 'now_time': items[2],
                'used_bytes': items[6], 'used_second': items[7],
                'ip': items[8], 'balance': items[11],
                'auth_server_version': items[21]
            }
            return True
        except Exception as e:
            print(resp_text)
            print('Catch `Status Internal Server Error`? The request is frequent!')
            print(e)

    def show_online(self):
        if not self.check_online(): return
        self._log('###*** ONLINE INFORMATION! ***###')
        header = '================== ONLIN INFORMATION =================='

        print(header)
        print('Username: {}'.format(self.online_info['username']))
        print('Login time: {}'.format(self.time2date(self.online_info['login_time'])))
        print('Now time: {}'.format(self.time2date(self.online_info['now_time'])))
        print('Used data: {}'.format(self.humanable_bytes(self.online_info['used_bytes'])))
        print('Ip: {}'.format(self.online_info['ip']))
        print('Balance: {}'.format(self.online_info['balance']))
        print('=' * len(header))

    def login(self,ac_id):
        if self.check_online():
            self._log('###*** ALREADY ONLINE! ***###')
            return True
        if not self.username or not self.passwd:
            self._log('###*** LOGIN FAILED! (username or passwd is None) ***###')
            self._log('username and passwd are required! (check username and passwd)')
            return False
        encrypt_passwd = self._encrypt(self.passwd)
        payload = {
            'action': 'login',
            'username': self.username,
            'password': encrypt_passwd,
            'type': 2, 'n': 117,
            'drop': 0, 'pop': 0,
            'mbytes': 0, 'minutes': 0,
            'ac_id': ac_id
        }
        resp_text = post_func(self.login_url, data=payload, headers=self.headers)
        if 'login_ok' in resp_text:
            self._log('###*** LOGIN SUCCESS! ***###')
            self._log(resp_text)
            self.show_online()
            return True
        elif 'login_error' in resp_text:
            self._log('###*** LOGIN FAILED! (login error)***###')
            self._log(resp_text)
            return False
        else:
            self._log('###*** LOGIN FAILED! (unknown error) ***###')
            self._log(resp_text)
            return False

    def logout(self,ac_id):
        if not self.check_online(): return True
        payload = {
            'action': 'logout',
            'ac_id': ac_id,
            'username': self.online_info['username'],
            'type': 1
        }
        resp_text = post_func(self.login_url, data=payload, headers=self.headers)
        if 'logout_ok' in resp_text:
            self._log('###*** LOGOUT SUCCESS! ***###')
            return True
        elif 'login_error' in resp_text:
            self._log('###*** LOGOUT FAILED! (login error) ***###')
            self._log(resp_text)
            return False
        else:
            self._log('###*** LOGOUT FAILED! (unknown error) ***###')
            self._log(resp_text)
            return False

    def thread_check_online(self):
        resp_text = get_func(self.online_url, headers=self.headers)
        if 'not_online' in resp_text:
            self._log('###*** NOT ONLINE! ***###')
            self._log("NOT ONLINE, TRY TO LOGIN!")
            self.login()
            self.check_status += 1
        print('\r', '当前已自动重连{:d}次'.format(self.check_status), end='')
    def time2date(self,timestamp):
        time_arry = time.localtime(int(timestamp))
        return time.strftime('%Y-%m-%d %H:%M:%S', time_arry)

    def humanable_bytes(self,num_byte):
        num_byte = float(num_byte)
        num_GB, num_MB, num_KB = 0, 0, 0
        if num_byte >= 1024 ** 3:
            num_GB = num_byte // (1024 ** 3)
            num_byte -= num_GB * (1024 ** 3)
        if num_byte >= 1024 ** 2:
            num_MB = num_byte // (1024 ** 2)
            num_byte -= num_MB * (1024 ** 2)
        if num_byte >= 1024:
            num_KB = num_byte // 1024
            num_byte -= num_KB * 1024
        return '{} GB {} MB {} KB {} B'.format(num_GB, num_MB, num_KB, num_byte)

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



def encrypt_username(username,kind):
    res = '{SRUN2}'
    for char in username:
        res += chr(ord(char) + 4)
    return res+kind

def wifi_logout():
    try:
        connected_ssid= subprocess.run("netsh wlan show interfaces | findstr /C:&quot;SSID&quot;", capture_output=True, text=True)
        #ac_id 的设置按实际情况而定
        if "CMCC-EDU" in str(connected_ssid):
            srun_client.logout(2)
        else:
            srun_client.logout(1)
    except Exception as e:
        logging.error(f"Failed to logout: {e}")
        print (f"Failed to logout: {e}")
        return False
def wifi_login():
    
    # 进行 ping 测试
    if not ping("baidu.com"):
        if not ping("172.16.245.50"):
            available_networks = scan_networks()
            print(f"available_networks: {available_networks}")
            logging.info(f"available_networks: {available_networks}")
            # 自动连接到 CMCC-EDU 或 SWPU-EDU
            for ssid in ["CMCC-EDU", "SWPU-EDU"]:
                if ssid in available_networks:
                    connect_to_wifi(ssid)
                    connected_ssid=ssid
                    break
            else:
                print("cannot find available_networks")
                logging.error("cannot find available_networks")
                return 0  # 如果没有找到网络，则退出程序\
            time.sleep(5)
        
        connected_ssid= subprocess.run("netsh wlan show interfaces | findstr /C:&quot;SSID&quot;", capture_output=True, text=True)
        #ac_id 的设置按实际情况而定
        wifi_logout()
        if "CMCC-EDU" in str(connected_ssid):
            print(2)
            srun_client.login(ac_id=2)
        else:
            srun_client.login(ac_id=1)
        srun_client.show_online()
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
                wifi_login()
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
                    wifi_logout()
                    subprocess.run(["netsh", "wlan", "disconnect"], creationflags=subprocess.CREATE_NO_WINDOW)
                    if not rasdial("宽带连接", encrypt_username(username_,kinds[kind_index]) , password_):
                        print("dialing failed")
                        logging.error("dialing failed")
                    else:
                        print("dialing success")
                        logging.info("dialing success")

        time.sleep(6)

if __name__ == "__main__":
    username_ = 'username'
    password_ = 'password'
    kinds = {1:'@ydyx',2:'@dx',3:'@tch',4:'@stu'}
    kind_index=1
    srun_client = SrunClient()
    srun_client.username = encrypt_username(username_,kinds[kind_index]) # 修改自己深澜账号
    srun_client.passwd = password_ #深澜密码
    LOG_DIR = r"LOG_DIR"
    LOG_FILE = os.path.join(LOG_DIR, "network_check.log")
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)

    logging.basicConfig(filename=LOG_FILE, level=logging.ERROR,
                        format='%(asctime)s - %(levelname)s - %(message)s')
    import threading
    threading.Thread(target=main, daemon=True).start()
    app.run(host='0.0.0.0', port=5010)
