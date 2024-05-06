import hashlib
import ecdsa
from concurrent.futures import ThreadPoolExecutor

def generate_trc20_address(num_consecutive_digits=None):
    while True:
        # 生成随机私钥
        private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

        # 获取公钥
        public_key = private_key.verifying_key.to_string()

        # 计算公钥的 SHA-256 哈希值
        public_key_hash = hashlib.sha256(public_key).digest()

        # 计算 RIPEMD-160 哈希值
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(public_key_hash)
        public_key_hash_ripemd160 = ripemd160.digest()

        # 添加 TRC20 地址前缀
        trc20_address = b"\x41" + public_key_hash_ripemd160

        # 计算地址校验和
        checksum = hashlib.sha256(hashlib.sha256(trc20_address).digest()).digest()[:4]

        # 添加地址校验和
        trc20_address += checksum

        # 将地址编码为 Base58
        trc20_address_base58 = base58_encode(trc20_address)

        # 如果设定了筛选尾号相同的条件，并且地址的尾号不符合条件，则继续生成下一个地址
        if num_consecutive_digits is not None and not has_consecutive_digits(trc20_address_base58.decode(), num_consecutive_digits):
            continue
        
        return private_key.to_string().hex(), trc20_address_base58.decode()

def base58_encode(input_bytes):
    alphabet = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    base_count = len(alphabet)
    encode = b""
    # Convert big-endian bytes to integer
    input_int = int.from_bytes(input_bytes, 'big')
    # Append digits to the start of string
    while input_int > 0:
        input_int, remainder = divmod(input_int, base_count)
        encode = alphabet[remainder:remainder+1] + encode
    return encode

def has_consecutive_digits(address, num_consecutive_digits):
    return len(set(address[-num_consecutive_digits:])) == 1

if __name__ == "__main__":
    num_consecutive_digits = input("请输入要筛选的尾号相同字符的数量（例如：3）：")
    while not num_consecutive_digits.isdigit():
        print("请重新输入数字作为尾号相同字符的数量。")
        num_consecutive_digits = input("请输入要筛选的尾号相同字符的数量（例如：3）：")

    num_threads = input("请输入线程数量：")
    while not num_threads.isdigit():
        print("请重新输入数字作为线程数量。")
        num_threads = input("请输入线程数量：")
    num_threads = int(num_threads)

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        for _ in range(num_threads):
            future = executor.submit(generate_trc20_address, int(num_consecutive_digits))
            private_key, address = future.result()
            print("私钥:", private_key)
            print("TRC20 地址:", address)
