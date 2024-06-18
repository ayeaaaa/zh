import base64
import json
from urllib.parse import urlparse, parse_qs
from colorama import init, Fore, Style

# 初始化 colorama 库，使其在 Windows 上也能正常工作
init(autoreset=True)

def print_copyright_info():
    print(Fore.YELLOW + "本程序由ayeaaaa编写，用于本地解析和转换 VMess, VLESS, 和 Hysteria2 链接。" + Style.RESET_ALL)

def decode_vmess_link(vmess_link):
    vmess_link = vmess_link[8:]  # Remove "vmess://"
    decoded_data = base64.b64decode(vmess_link).decode('utf-8')
    return json.loads(decoded_data)

def decode_vless_link(vless_link):
    parsed_url = urlparse(vless_link)
    params = parse_qs(parsed_url.query)
    proxy = {
        'type': 'vless',
        'server': parsed_url.hostname,
        'port': int(parsed_url.port),
        'uuid': parsed_url.username,
        'encryption': params.get('encryption', ['none'])[0],
        'security': params.get('security', ['none'])[0],
        'network': params.get('type', ['tcp'])[0],
        'ws-opts': {
            'path': params.get('path', [''])[0],
            'headers': {
                'Host': params.get('host', [''])[0]
            }
        },
        'name': parsed_url.fragment  # 使用URL的fragment部分作为名称
    }
    return proxy

def decode_hysteria2_link(hy2_link):
    parsed_url = urlparse(hy2_link)
    params = parse_qs(parsed_url.query)
    proxy = {
        'type': 'hysteria2',
        'server': parsed_url.hostname,
        'port': int(parsed_url.port),
        'password': parsed_url.username,
        'sni': params.get('sni', [''])[0],
        'skip-cert-verify': params.get('insecure', ['0'])[0] == '1',
        'name': parsed_url.fragment  # 使用URL的fragment部分作为名称
    }
    return proxy

def save_to_yaml(proxy):
    clash_config = f"""
port: 7890
socks-port: 7891
allow-lan: true
mode: Rule
log-level: info
external-controller: :9090
cfw-latency-timeout: 5000
dns:
  enabled: true
  nameserver:
    - 119.29.29.29
    - 223.5.5.5
  fallback:
    - 8.8.8.8
    - 8.8.4.4
    - tls://1.0.0.1:853
    - tls://dns.google:853
proxies:
  - name: {proxy['name']}
    type: {proxy['type']}
    server: {proxy['server']}
    port: {proxy['port']}
"""
    
    if proxy['type'] == 'vmess':
        clash_config += f"""
    uuid: {proxy['uuid']}
    alterId: {proxy['alterId']}
    cipher: {proxy['cipher']}
    network: {proxy['network']}
    tls: {proxy['tls']}
    ws-opts:
      path: {proxy['ws-opts']['path']}
      headers:
        Host: {proxy['ws-opts']['headers']['Host']}
"""
    elif proxy['type'] == 'vless':
        clash_config += f"""
    uuid: {proxy['uuid']}
    encryption: {proxy['encryption']}
    security: {proxy['security']}
    network: {proxy['network']}
    ws-opts:
      path: {proxy['ws-opts']['path']}
      headers:
        Host: {proxy['ws-opts']['headers']['Host']}
"""
    elif proxy['type'] == 'hysteria2':
        clash_config += f"""
    password: {proxy['password']}
    sni: {proxy['sni']}
    skip-cert-verify: {str(proxy['skip-cert-verify']).lower()}
"""

    clash_config += """
proxy-groups:
  - name: ProxyGroup1
    type: select
    proxies:
      - {name}
rules:
  - DOMAIN-SUFFIX,google.com,ProxyGroup1
  - DOMAIN-SUFFIX,facebook.com,ProxyGroup1
  - DOMAIN-KEYWORD,youtube,ProxyGroup1
  - GEOIP,CN,DIRECT
  - MATCH,ProxyGroup1
""".format(name=proxy['name'])

    with open('config.yaml', 'w') as file:
        file.write(clash_config)
    print(Fore.GREEN + "Configuration saved to 'config.yaml'.")

def main():
    print_copyright_info()
    
    while True:
        link = input(Fore.GREEN + "请输入 VMess, VLESS 或 HY2 链接: " + Style.RESET_ALL)
        if link.startswith('vmess://'):
            proxy_info = decode_vmess_link(link)
            proxy = {
                'name': proxy_info.get('ps', 'Proxy1'),  # 从ps字段获取节点名称
                'type': 'vmess',
                'server': proxy_info['add'],
                'port': int(proxy_info['port']),
                'uuid': proxy_info['id'],
                'alterId': int(proxy_info['aid']),
                'cipher': 'auto',
                'network': proxy_info['net'],
                'tls': proxy_info['tls'],
                'ws-opts': {
                    'path': proxy_info['path'],
                    'headers': {
                        'Host': proxy_info['host']
                    }
                }
            }
            break
        elif link.startswith('vless://'):
            proxy = decode_vless_link(link)
            break
        elif link.startswith('hysteria2://'):
            proxy = decode_hysteria2_link(link)
            break
        else:
            print(Fore.RED + "链接格式不正确，请输入有效的 VMess, VLESS 或 HY2 链接。")

    # 打印节点信息
    print(Fore.GREEN + "节点信息:" + Style.RESET_ALL)
    print(Fore.GREEN + "===================" + Style.RESET_ALL)
    print(f"- name: {proxy['name']}")
    print(f"  network: {proxy.get('network', 'N/A')}")
    print(f"  port: {proxy['port']}")
    print(f"  server: {proxy['server']}")
    print(f"  tls: {proxy.get('tls', 'N/A')}")
    print(f"  type: {proxy['type']}")
    if 'uuid' in proxy:
        print(f"  uuid: {proxy['uuid']}")
    if 'ws-opts' in proxy:
        print(f"  ws-opts:")
        print(f"    headers:")
        print(f"      Host: {proxy['ws-opts']['headers']['Host']}")
        print(f"    path: {proxy['ws-opts']['path']}")
    if 'encryption' in proxy:
        print(f"  encryption: {proxy['encryption']}")
    if 'headerType' in proxy:
        print(f"  headerType: {proxy['headerType']}")
    if 'password' in proxy:
        print(f"  password: {proxy['password']}")
    if 'skip-cert-verify' in proxy:
        print(f"  skip-cert-verify: {proxy['skip-cert-verify']}")
    if 'sni' in proxy:
        print(f"  sni: {proxy['sni']}")
    print(Fore.GREEN + "===================" + Style.RESET_ALL)

    # 询问用户是否要保存为 YAML 文件，默认为 'Y'
    save_yaml = input(Fore.GREEN + "是否保存为 YAML 文件？ (Y/n): " + Style.RESET_ALL).strip().lower() or 'y'
    if save_yaml == 'y':
        save_to_yaml(proxy)

    # 保持窗口打开
    input(Fore.GREEN + "按任意键退出..." + Style.RESET_ALL)

if __name__ == "__main__":
    main()
