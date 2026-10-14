import eth_abi

from eth_account import Account
from eth_account.messages import encode_defunct, defunct_hash_message
from eth_keys.main import PublicKey, Signature
from eth_utils import keccak


# Elliptic Curve parameters for secp256k1
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A = 0
B = 7
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
G = (Gx, Gy)
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
K = 10**18

def _inverse_mod(k, p):
    if k == 0:
        raise
    return pow(k, p - 2, p)

def _is_on_curve(point):
    if point is None:
        return True
    x, y = point
    return (y * y - (x * x * x + A * x + B)) % P == 0

def _point_add(point1, point2):
    if point1 is None:
        return point2
    if point2 is None:
        return point1
    x1, y1 = point1
    x2, y2 = point2
    if x1 == x2 and y1 != y2:
        return None
    if x1 == x2:
        m = (3 * x1 * x1 + A) * _inverse_mod(2 * y1, P)
    else:
        m = (y2 - y1) * _inverse_mod(x2 - x1, P)
    m %= P
    x3 = (m * m - x1 - x2) % P
    y3 = (m * (x1 - x3) - y1) % P
    return (x3, y3)

def _scalar_mult(k, point):
    result = None
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result

def _ecdsa_verify(msg_hash_hex, signature_hex, public_key_hex):
    assert msg_hash_hex.startswith('0x')
    assert signature_hex.startswith('0x')
    assert public_key_hex.startswith('0x')
    r = int(signature_hex[2:66], 16)
    s = int(signature_hex[66:130], 16)
    if not (1 <= r < N and 1 <= s < N):
        return False
    point = (int(public_key_hex[2:66], 16), int(public_key_hex[66:], 16))
    # print(type(msg_hash_hex), msg_hash_hex)
    e = int(msg_hash_hex[2:], 16)
    w = _inverse_mod(s, N)
    u1 = (e * w) % N
    u2 = (r * w) % N
    q = _point_add(_scalar_mult(u1, G), _scalar_mult(u2, point))
    if q is None:
        return False
    x, y = q
    return r == x % N

def _ecdsa_recover(msg_hash_hex, signature_hex):
    assert msg_hash_hex.startswith('0x')
    assert signature_hex.startswith('0x')
    r = int(signature_hex[2:66], 16)
    s = int(signature_hex[66:130], 16)
    z = int(msg_hash_hex[2:], 16)

    if len(signature_hex[2:]) == 130:
        v = int(signature_hex[130:], 16)
        if v >= 27:
            recovery_id = v - 27
        else:
            recovery_id = v
        recovery_ids = [recovery_id]
    else:
        recovery_ids = [0, 1]

    for recovery_id in recovery_ids:
        for j in range(2):
            x = r + j * N
            if x >= P:
                continue

            y_squared = (pow(x, 3, P) + A * x + B) % P
            y = pow(y_squared, (P + 1) // 4, P)

            if y % 2 != recovery_id:
                y = P - y

            point = (x, y)
            if not _is_on_curve(point):
                continue

            r_inv = _inverse_mod(r, N)
            u1 = (-z * r_inv) % N
            u2 = (s * r_inv) % N

            q = _point_add(_scalar_mult(u1, G), _scalar_mult(u2, point))

            if q is None:
                continue

            public_key_hex = f"0x{q[0]:064x}{q[1]:064x}"
            if _ecdsa_verify(msg_hash_hex, signature_hex, public_key_hex):
                return public_key_hex

    return None


def _encode_uint256(value):
    return value.to_bytes(32, 'big')

def _encode_address(address_str):
    address_bytes = bytes.fromhex(address_str[2:])
    return b'\x00' * (32 - len(address_bytes)) + address_bytes

def _encode_dynamic_bytes(data_hex):
    data_bytes = bytes.fromhex(data_hex)
    length = len(data_bytes)
    padded_length = (length + 31) // 32 * 32 # Calculate padded length for data
    return length.to_bytes(32, 'big') + data_bytes + b'\x00' * (padded_length - length)

# '{"a": [845300000000000000000000002, 8453, 43114, "0x51055892893c17ae7db48a0c0f760145bfe9f1e5", "0x09ace2d19b0273a762b0fe22b9e5199505c778de", 0, "000000000000000000000000490537058bdddaae99dd4da8b5db5675936bfedf0000000000000000000000000000000000000000000000008ac7230489e80000", "0000000000000000000000000000000000000000000000000000000000000000", "034da1308a53b6586fed90af2bd4e48cc863913551cc41d6148f43441691e4fd1ea27a1e3daf2b4c1386d0426cc37a4423729204177740768970937c93d648961c"], "f": "bridge_incoming_process", "p": "zentest"}'
def bridge_incoming_process(info, args):
    #assert args['f'] == 'bridge_incoming_process'
    #sender = info['sender']
    #addr = handle_lookup(sender)
    print('bridge_incoming_process')

    txid = args['a'][0]
    source_chain_id = args['a'][1]
    dest_chain_id = args['a'][2]
    source_chain_sender = args['a'][3]
    dest_chain_recipient = args['a'][4]
    gas = args['a'][5]
    user_payload = args['a'][6]
    exsig = args['a'][7]
    signature = args['a'][8]

    encoded_txid = _encode_uint256(txid)
    encoded_source_chain_id = _encode_uint256(source_chain_id)
    encoded_dest_chain_id = _encode_uint256(dest_chain_id)
    encoded_source_chain_sender = _encode_address(source_chain_sender)
    encoded_dest_chain_recipient = _encode_address(dest_chain_recipient)
    offset_user_payload = 6 * 32
    encoded_offset_user_payload = _encode_uint256(offset_user_payload)

    header = b''.join([
        encoded_txid,
        encoded_source_chain_id,
        encoded_dest_chain_id,
        encoded_source_chain_sender,
        encoded_dest_chain_recipient,
        encoded_offset_user_payload,
    ])
    encoded_user_payload_data = _encode_dynamic_bytes(user_payload)

    encoded_data = b''.join([
        header,
        encoded_user_payload_data,
    ])
    print(f"ABI Encoded Data (Pure Python): 0x{encoded_data.hex()}")

    encoded_data_hash = keccak(encoded_data)
    x19_msg_prefix = b"\x19Ethereum Signed Message:\n" + str(len(encoded_data_hash)).encode('utf-8')
    x19_msg_hash = keccak(x19_msg_prefix + encoded_data_hash)
    print(f"x19_msg (Pure Python): 0x{x19_msg_hash.hex()}")

    print('x19', '0x'+x19_msg_hash.hex())
    print('signature', '0x'+signature)
    recovered_public_key = _ecdsa_recover('0x'+x19_msg_hash.hex(), '0x'+signature)
    print(f"recovered public key: {recovered_public_key}")
    if recovered_public_key:
        public_key_bytes = bytes.fromhex(recovered_public_key[2:])
        address_bytes = keccak(public_key_bytes)[-20:]
        address = '0x' + address_bytes.hex()
        print(f"Recovered Ethereum address: {address}")


if __name__ == '__main__':
    # private_key_hex = "0x0000000000000000000000000000000000000000000000000000000000000001"

    # pk_bytes = bytes.fromhex(private_key_hex[2:])
    # pk = PrivateKey(pk_bytes)
    # public_key_hex = pk.public_key.to_hex()
    # Q = (int(public_key_hex[2:66], 16), int(public_key_hex[66:], 16))
    # print('ETH addr', pk.public_key.to_address())

    # message_text = "hello"
    # encode_defunct_message = encode_defunct(text=message_text)
    # signed_message = Account.sign_message(encode_defunct_message, private_key_hex)

    # r = signed_message.r
    # s = signed_message.s

    # msg_hash = int.from_bytes(signed_message.message_hash, "big")
    # msg_hash_hex = str(hex(msg_hash))
    # print(f"Message hash: {msg_hash_hex}")

    # signature_hex = f"0x{r:064x}{s:064x}"
    # is_valid = _ecdsa_verify(msg_hash_hex, signature_hex, public_key_hex)

    # print(f"Private key: {private_key_hex}")
    # print(f"Public key hex: {public_key_hex}")
    # print(f"Message: '{message_text}'")
    # print(f"Signature hex: {signature_hex}")

    # recovered_public_key = _ecdsa_recover(msg_hash_hex, signature_hex)
    # print(f"Recovered public key: {recovered_public_key}")
    # print(f"Public key matches recovered key: {public_key_hex == recovered_public_key}")
    # if recovered_public_key:
    #     public_key_bytes = bytes.fromhex(recovered_public_key[2:])
    #     address_bytes = keccak(public_key_bytes)[-20:]
    #     address = '0x' + address_bytes.hex()
    #     print(f"Recovered Ethereum address: {address}")

    # Test with a different message to ensure it fails
    #print("\n--- Testing with a different message ---")
    #message_text2 = "goodbye"
    #encode_defunct_message2 = encode_defunct(text=message_text2)
    #msg_hash2 = int.from_bytes(hashlib.sha256(encode_defunct_message2.body).digest(), "big")
    #msg_hash2_hex = str(hex(msg_hash2))
    #is_valid2 = _ecdsa_verify(msg_hash2_hex, signature_hex, public_key_hex)
    #print(f"Message: '{message_text2}'")
    #print(f"Message hash: {msg_hash2_hex}")
    #print(f"Signature valid: {is_valid2}")

    print("\n--- Testing with a real message ---")
    msg_hash_hex3 = '0xf04a4d2ab7f8bc0db307944fe88c7bc69017b0e140c732b007036da1212cc9f6'
    #msg3 = encode_defunct(hexstr=msg_hash_hex3)
    #print(msg3)
    msg3 = defunct_hash_message(hexstr=msg_hash_hex3)
    # signature_hex3 = '0x034da1308a53b6586fed90af2bd4e48cc863913551cc41d6148f43441691e4fd1ea27a1e3daf2b4c1386d0426cc37a4423729204177740768970937c93d648961c'
    signature_hex3 = '0x034da1308a53b6586fed90af2bd4e48cc863913551cc41d6148f43441691e4fd1ea27a1e3daf2b4c1386d0426cc37a4423729204177740768970937c93d6489601'
    print('Message hash: '+msg_hash_hex3)
    print('\\x19 Message hash: 0x'+msg3.hex())
    recovered_public_key3 = _ecdsa_recover('0x'+msg3.hex(), signature_hex3)
    print('recovered_public_key3:', recovered_public_key3)
    public_key_bytes3 = bytes.fromhex(recovered_public_key3[2:])
    if recovered_public_key3:
        public_key_bytes3 = bytes.fromhex(recovered_public_key3[2:])
        address_bytes3 = keccak(public_key_bytes3)[-20:]
        address3 = '0x' + address_bytes3.hex()
        print(f"Recovered Ethereum address: {address3}")

    sig3 = Signature(bytes.fromhex(signature_hex3[2:]))
    recovered_public_key = sig3.recover_public_key_from_msg_hash(msg3).to_hex()
    print(f"Recovered public key: {recovered_public_key}")
    print(f"ETH addr: {PublicKey(public_key_bytes3).to_address()}")
    assert recovered_public_key3 == recovered_public_key


    print("\n--- Testing function ---")
    b = '0x6206649a000000000000000000000000000000000000000002bb373cd1f2103d508000020000000000000000000000000000000000000000000000000000000000002105000000000000000000000000000000000000000000000000000000000000a86a00000000000000000000000051055892893c17ae7db48a0c0f760145bfe9f1e500000000000000000000000009ace2d19b0273a762b0fe22b9e5199505c778de000000000000000000000000000000000000000000000000000250e63a6bfa0800000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000490537058bdddaae99dd4da8b5db5675936bfedf0000000000000000000000000000000000000000000000008ac7230489e80000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041034da1308a53b6586fed90af2bd4e48cc863913551cc41d6148f43441691e4fd1ea27a1e3daf2b4c1386d0426cc37a4423729204177740768970937c93d648961c00000000000000000000000000000000000000000000000000000000000000'
    d = eth_abi.decode(['uint', 'uint', 'uint', 'address', 'address', 'uint', 'bytes[]'], bytes.fromhex(b[10:]))
    print(d[0], 'txid int')
    print(d[1], 'source chain id')
    print(d[2], 'dest chain id')
    print(d[3], 'sender')
    print(d[4], 'receipt')
    # print(d[5], '')
    print(d[6][0].hex(), '_data[0]')
    # print(d[6][1], '_data[2]')
    print(d[6][2].hex(), '_data[2]')
    print({'a':[d[0], d[1], d[2], d[3], d[4], 0, d[6][0].hex(), d[6][1].hex(), d[6][2].hex()], 'f':'bridge_incoming_process', 'p':'zentest'})
    bridge_incoming_process({'sender':'0x1234'},{'a':[d[0], d[1], d[2], d[3], d[4], 0, d[6][0].hex(), d[6][1].hex(), d[6][2].hex()], 'f':'', 'p':''})
