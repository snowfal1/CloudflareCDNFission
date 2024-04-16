# 标准库
import os
import re
import random
import ipaddress
import subprocess
import concurrent.futures

# 第三方库
import requests
from lxml import etree
from fake_useragent import UserAgent
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 文件配置
ips = "Fission_ip.txt"
domains = "Fission_domain.txt"
dns_result = "dns_result.txt"


# 并发数配置
max_workers_request = 20   # 并发请求数量
max_workers_dns = 50       # 并发DNS查询数量

# 生成随机User-Agent
ua = UserAgent()

# 网站配置
sites_config = {
    "site_ip138": {
        "url": "https://site.ip138.com/",
        "xpath": '//ul[@id="list"]/li/a'
    },
    "dnsdblookup": {
        "url": "https://dnsdblookup.com/",
        "xpath": '//ul[@id="list"]/li/a'
    },
    "ipchaxun": {
        "url": "https://ipchaxun.com/",
        "xpath": '//div[@id="J_domain"]/p/a'
    }
}

# 设置会话
def setup_session():
    session = requests.Session()
    retries = Retry(total=5, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

# 生成请求头
def get_headers():
    return {
        'User-Agent': ua.random,
        'Accept': '*/*',
        'Connection': 'keep-alive',
    }

# 查询域名的函数，自动重试和切换网站
def fetch_domains_for_ip(ip_address, session, attempts=0, used_sites=None):
    print(f"Fetching domains for {ip_address}...")
    if used_sites is None:
        used_sites = []
    if attempts >= 3:  # 如果已经尝试了3次，终止重试
        return []

    # 选择一个未使用的网站进行查询
    available_sites = {key: value for key, value in sites_config.items() if key not in used_sites}
    if not available_sites:
        return []  # 如果所有网站都尝试过，返回空结果

    site_key = random.choice(list(available_sites.keys()))
    site_info = available_sites[site_key]
    used_sites.append(site_key)

    try:
        url = f"{site_info['url']}{ip_address}/"
        headers = get_headers()
        response = session.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        html_content = response.text

        parser = etree.HTMLParser()
        tree = etree.fromstring(html_content, parser)
        a_elements = tree.xpath(site_info['xpath'])
        domains = [a.text for a in a_elements if a.text]

        if domains:
            print(f"succeed to fetch domains for {ip_address} from {site_info['url']}")
            return domains
        else:
            raise Exception("No domains found")

    except Exception as e:
        print(f"Error fetching domains for {ip_address} from {site_info['url']}: {e}")
        return fetch_domains_for_ip(ip_address, session, attempts + 1, used_sites)

# 并发处理所有IP地址
def fetch_domains_concurrently(ip_addresses):
    session = setup_session()
    domains = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers_request) as executor:
        future_to_ip = {executor.submit(fetch_domains_for_ip, ip, session): ip for ip in ip_addresses}
        for future in concurrent.futures.as_completed(future_to_ip):
            domains.extend(future.result())

    return list(set(domains))

# DNS查询函数
def dns_lookup(domain):
    print(f"Performing DNS lookup for {domain}...")
    result = subprocess.run(["nslookup", domain], capture_output=True, text=True)
    return domain, result.stdout

# 通过域名列表获取绑定过的所有ip
def perform_dns_lookups(domain_filename, result_filename, unique_ipv4_filename):
    try:
        # 读取域名列表
        with open(domain_filename, 'r') as file:
            domains = file.read().splitlines()

        # 创建一个线程池并执行DNS查询
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers_dns) as executor:
            results = list(executor.map(dns_lookup, domains))

        # 写入查询结果到文件
        with open(result_filename, 'w') as output_file:
            for domain, output in results:
                output_file.write(output)

        # 从结果文件中提取所有IPv4地址
        ipv4_addresses = set()
        for _, output in results:
            ipv4_addresses.update(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', output))

        with open(unique_ipv4_filename, 'r') as file:
            exist_list = {ip.strip() for ip in file}

        # 检查IP地址是否为公网IP
        filtered_ipv4_addresses = set()
        for ip in ipv4_addresses:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.is_global:
                    filtered_ipv4_addresses.add(ip)
            except ValueError:
                # 忽略无效IP地址
                continue
        
        filtered_ipv4_addresses.update(exist_list)

        # 保存IPv4地址
        with open(unique_ipv4_filename, 'w') as output_file:
            for address in filtered_ipv4_addresses:
                output_file.write(address + '\n')

    except Exception as e:
        print(f"Error performing DNS lookups: {e}")

# 主函数
def main():
    # 判断是否存在IP文件
    if not os.path.exists(ips):
        with open(ips, 'w') as file:
            file.write("")
    
    # 判断是否存在域名文件
    if not os.path.exists(domains):
        with open(domains, 'w') as file:
            file.write("")

    # IP反查域名
    with open(ips, 'r') as ips_txt:
        ip_list = [ip.strip() for ip in ips_txt]

    domain_list = fetch_domains_concurrently(ip_list)
    print("域名列表为")
    print(domain_list)
    with open("Fission_domain.txt", "r") as file:
        exist_list = [domain.strip() for domain in file]

    domain_list = list(set(domain_list + exist_list))

    with open("Fission_domain.txt", "w") as output:
        for domain in domain_list:
            output.write(domain + "\n")
    print("IP -> 域名 已完成")

    # 域名解析IP
    perform_dns_lookups(domains, dns_result, ips)
    print("域名 -> IP 已完成")

# 程序入口
if __name__ == '__main__':
    main()
