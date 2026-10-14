import os
from pyrlp import encode as rlp_encode
from pykeccak import Keccak256
from pyecdsa import _scalar_mult, _point_add, G, N, P, _is_on_curve, _inverse_mod

def private_key_to_address(priv_key_hex):
    priv_int = int(priv_key_hex, 16) if priv_key_hex.startswith("0x") else int(priv_key_hex, 16)
    pub_pt = _scalar_mult(priv_int, G)
    pub_x = pub_pt[0]
    pub_y = pub_pt[1]
    pubkey_bytes = b'\x04' + pub_x.to_bytes(32, 'big') + pub_y.to_bytes(32, 'big')
    hasher = Keccak256()
    hasher.update(pubkey_bytes[1:])  # Skip the 0x04 prefix
    addr = '0x' + hasher.digest()[-20:].hex()
    return addr

def ecdsa_sign(priv_key_hex, msg_hash_hex):
    priv_key = int(priv_key_hex, 16)
    z = int(msg_hash_hex, 16)
    k = 1  # Simplified: use fixed k for demo; in production use secure random
    r_point = _scalar_mult(k, G)
    r = r_point[0] % N
    if r == 0:
        raise ValueError("r is 0")
    k_inv = _inverse_mod(k, N)
    s = (z + r * priv_key) * k_inv % N
    if s == 0:
        raise ValueError("s is 0")
    # Calculate recovery_id from r_point's y coordinate (not from public key!)
    recovery_id = r_point[1] % 2
    return r, s, recovery_id

def sign_transaction(priv_key_hex, nonce, gas_price, gas_limit, to, value, data, chain_id):
    to_bytes = bytes.fromhex(to[2:]) if isinstance(to, str) else to
    tx = [nonce, gas_price, gas_limit, to_bytes, value, data, chain_id, 0, 0]
    tx_rlp = rlp_encode(tx)
    tx_hash = Keccak256()
    tx_hash.update(tx_rlp)
    msg_hash = tx_hash.digest()
    msg_hash_hex = '0x' + msg_hash.hex()
    r, s, recovery_id = ecdsa_sign(priv_key_hex, msg_hash_hex)
    # recovery_id is now correctly calculated from r_point (k*G) in ecdsa_sign
    v = 35 + chain_id * 2 + recovery_id
    signed_tx = [nonce, gas_price, gas_limit, to_bytes, value, data, v, r, s]
    signed_rlp = rlp_encode(signed_tx)
    return '0x' + signed_rlp.hex()

def create_transfer_data(recipient):
    selector = Keccak256()
    selector.update(b"transfer(address)")
    sel = selector.digest()[:4]
    addr_bytes = bytes.fromhex(recipient[2:])
    padded_addr = b'\x00' * (32 - len(addr_bytes)) + addr_bytes
    data = sel + padded_addr
    return data

def transfer(priv_key, contract_addr, recipient, nonce, gas_price, gas_limit, chain_id):
    data = create_transfer_data(recipient)
    signed_tx = sign_transaction(priv_key, nonce, gas_price, gas_limit, contract_addr, 0, data, chain_id)
    return signed_tx

if __name__ == '__main__':
    # Example usage
    priv_key = "0x0000000000000000000000000000000000000000000000000000000000000001"
    contract_addr = "0x1234567890123456789012345678901234567890"
    recipient = "0x0987654321098765432109876543210987654321"
    nonce = 0
    gas_price = 20000000000
    gas_limit = 21000
    chain_id = 1
    signed_tx = transfer(priv_key, contract_addr, recipient, nonce, gas_price, gas_limit, chain_id)
    print(signed_tx)