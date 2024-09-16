from mnemonic import Mnemonic
import nacl.signing
import hashlib
import ecdsa
import base58
import requests
import webbrowser
import time
import threading
import os
import sys

# Solana RPC 节点 URL
solana_rpc_urls = [
    "https://api.mainnet-beta.solana.com",  # 默认的 Solana 主网节点
    "https://solana-api.projectserum.com",  # Project Serum 的 RPC 节点
    "https://api.rpcpool.com"               # 另一个公共 RPC 节点
]

# Bitcoin RPC 节点 URL 或其他 API 服务
btc_rpc_urls = [
    "https://blockchain.info/q/addressbalance",
    "https://api.blockchair.com/bitcoin/dashboards/address",
    "https://api.blockcypher.com/v1/btc/main/addrs"
]

# 设置超时时间
timeout = 10  # 设置 10 秒的超时时间
watchdog_timeout = 12  # Watchdog 超时时间为 60 秒

# 文件路径：桌面上的文件，用于存储生成的助记词
desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
mnemonic_file_path = os.path.join(desktop_path, "generated_mnemonics.txt")

# 初始化文件（如果文件不存在则创建）
if not os.path.exists(mnemonic_file_path):
    with open(mnemonic_file_path, 'w') as f:
        pass

# Watchdog 重启函数
def restart_script():
    print("程序超时没有活动，正在重启...")
    python = sys.executable
    os.execl(python, python, *sys.argv)  # 重新启动当前脚本

# Watchdog 定时器
def start_watchdog():
    global last_activity_time
    while True:
        if time.time() - last_activity_time > watchdog_timeout:
            restart_script()  # 如果超时，重启程序
        time.sleep(1)

# 更新 Watchdog 活动时间
def reset_watchdog():
    global last_activity_time
    last_activity_time = time.time()

# 检查 Solana 地址余额
def get_solana_balance(address):
    reset_watchdog()
    headers = {
        "Content-Type": "application/json"
    }
    data = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getBalance",
        "params": [address]
    }
    for rpc_url in solana_rpc_urls:
        try:
            response = requests.post(rpc_url, headers=headers, json=data, timeout=timeout)
            if response.status_code == 200:
                balance = response.json()["result"]["value"]
                return balance
            else:
                print(f"Error fetching balance from {rpc_url}: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"Request to {rpc_url} failed: {e}")
    return 0

# 检查 Bitcoin 地址余额
def get_btc_balance(address):
    reset_watchdog()
    for url in btc_rpc_urls:
        try:
            if "blockchain.info" in url:
                response = requests.get(f"{url}/{address}")
                if response.status_code == 200:
                    return int(response.text)
            elif "blockchair.com" in url:
                response = requests.get(f"{url}/{address}")
                if response.status_code == 200:
                    return response.json()['data']['address']['balance']
            elif "blockcypher.com" in url:
                response = requests.get(f"{url}/{address}/balance")
                if response.status_code == 200:
                    return response.json()['balance']
        except requests.RequestException as e:
            print(f"Error fetching balance from {url}: {e}")
    return 0

# 读取已生成的助记词
def load_generated_mnemonics():
    with open(mnemonic_file_path, 'r') as f:
        return set(line.strip() for line in f)

# 保存生成的助记词
def save_mnemonic(mnemonic):
    with open(mnemonic_file_path, 'a') as f:
        f.write(mnemonic + '\n')

# 初始化助记词生成器
mnemo = Mnemonic("english")
generation_count = 0  # 初始化生成次数
last_activity_time = time.time()  # 初始化 Watchdog 时间
generated_mnemonics = load_generated_mnemonics()  # 加载已生成的助记词

# 启动 Watchdog 线程
watchdog_thread = threading.Thread(target=start_watchdog, daemon=True)
watchdog_thread.start()

while True:
    reset_watchdog()  # 重置 Watchdog 计时器
    generation_count += 1  # 增加生成次数

    # 生成随机的 BIP-0039 助记词，直到生成未使用的助记词
    while True:
        mnemonic = mnemo.generate(strength=128)  # 128 位强度生成 12 个词的助记词
        if mnemonic not in generated_mnemonics:
            generated_mnemonics.add(mnemonic)  # 添加到已生成的集合中
            save_mnemonic(mnemonic)  # 保存到文件中
            break

    # 使用助记词生成种子
    seed = Mnemonic.to_seed(mnemonic)

    # 使用种子生成 Ed25519 密钥对（Solana 地址）
    signing_key = nacl.signing.SigningKey(seed[:32])
    public_key = signing_key.verify_key

    # 将公钥编码为 Solana 地址
    sol_address = base58.b58encode(public_key.encode()).decode('utf-8')

    # 使用种子生成私钥（Bitcoin 地址）
    private_key = hashlib.sha256(seed).digest()
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    public_key = b'\x04' + vk.to_string()

    # 生成 Bitcoin 地址
    sha256_1 = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_1)
    hashed_public_key = ripemd160.digest()
    network_byte = b'\x00'  # 主网前缀
    network_hashed_public_key = network_byte + hashed_public_key
    sha256_2 = hashlib.sha256(network_hashed_public_key).digest()
    sha256_3 = hashlib.sha256(sha256_2).digest()
    checksum = sha256_3[:4]
    btc_address = base58.b58encode(network_hashed_public_key + checksum).decode('utf-8')

    # 格式化助记词为 4*3 的显示格式
    mnemonic_list = mnemonic.split()  # 将助记词拆分为列表
    formatted_mnemonic = [mnemonic_list[i:i + 3] for i in range(0, len(mnemonic_list), 3)]  # 每 3 个词一组
    formatted_mnemonic_str = '\n'.join([' '.join(group) for group in formatted_mnemonic])  # 将每组词拼接为字符串并换行

    # 输出生成的助记词和地址
    print(f"第 {generation_count} 次生成：")
    print(f"隨機生成的註記詞:\n{formatted_mnemonic_str}")  # 以 4*3 格式输出助记词
    print()
    print(f"Solana地址: {sol_address}")
    print(f"Bitcoin地址: {btc_address}")

    # 检查 Solana 地址的余额
    sol_balance = get_solana_balance(sol_address)
    print(f"Solana地址餘額: {sol_balance} sol")

    # 检查 Bitcoin 地址的余额
    btc_balance = get_btc_balance(btc_address)
    print(f"Bitcoin地址餘額: {btc_balance} btc")
    print("\n")

    # 如果其中任何一个地址的余额不为零，则打开浏览器并退出循环
    if sol_balance > 0:
        print("找到餘額不為零的 Solana 地址！")
        webbrowser.open(f"https://solscan.io/account/{sol_address}")
        break
    elif btc_balance > 0:
        print("找到餘額不為零的 Bitcoin 地址！")
        webbrowser.open(f"https://www.blockchain.com/explorer/addresses/btc/{btc_address}")
        break

    # 等待一段时间再生成下一个地址
    time.sleep(3)  # 避免频繁请求，增加等待时间
