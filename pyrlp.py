def encode(item):
    if isinstance(item, bytes):
        return _encode_bytes(item)
    elif isinstance(item, list):
        return _encode_list(item)
    elif isinstance(item, int):
        if item == 0:
            return b'\x80'
        elif item < 128:
            return bytes([item])
        else:
            b = item.to_bytes((item.bit_length() + 7) // 8, 'big')
            return _encode_bytes(b)
    else:
        raise TypeError("RLP can only encode bytes, lists, or ints")

def _encode_bytes(b):
    if len(b) == 1 and b[0] < 128:
        return b
    elif len(b) < 56:
        return bytes([len(b) + 128]) + b
    else:
        length_bytes = _encode_length(len(b))
        return bytes([183 + len(length_bytes)]) + length_bytes + b

def _encode_list(lst):
    encoded_items = b''.join(encode(item) for item in lst)
    if len(encoded_items) < 56:
        return bytes([len(encoded_items) + 192]) + encoded_items
    else:
        length_bytes = _encode_length(len(encoded_items))
        return bytes([247 + len(length_bytes)]) + length_bytes + encoded_items

def _encode_length(length):
    if length < 256:
        return bytes([length])
    elif length < 65536:
        return bytes([length // 256, length % 256])
    elif length < 16777216:
        return bytes([length // 65536, (length // 256) % 256, length % 256])
    else:
        return bytes([length // 16777216, (length // 65536) % 256, (length // 256) % 256, length % 256])

def decode(encoded):
    if not isinstance(encoded, bytes):
        raise TypeError("RLP decode input must be bytes")
    return _decode(encoded)[0]

def _decode(encoded):
    if len(encoded) == 0:
        raise ValueError("Empty input")
    first_byte = encoded[0]
    if first_byte < 128:
        return encoded[:1], encoded[1:]
    elif first_byte < 184:
        length = first_byte - 128
        if length > len(encoded) - 1:
            raise ValueError("Invalid length")
        return encoded[1:1+length], encoded[1+length:]
    elif first_byte < 192:
        length_length = first_byte - 183
        if length_length > len(encoded) - 1:
            raise ValueError("Invalid length")
        length = int.from_bytes(encoded[1:1+length_length], 'big')
        if 1 + length_length + length > len(encoded):
            raise ValueError("Invalid length")
        return encoded[1+length_length:1+length_length+length], encoded[1+length_length+length:]
    elif first_byte < 248:
        length = first_byte - 192
        if length > len(encoded) - 1:
            raise ValueError("Invalid length")
        items, rest = _decode_list(encoded[1:1+length])
        return items, encoded[1+length:]
    else:
        length_length = first_byte - 247
        if length_length > len(encoded) - 1:
            raise ValueError("Invalid length")
        length = int.from_bytes(encoded[1:1+length_length], 'big')
        if 1 + length_length + length > len(encoded):
            raise ValueError("Invalid length")
        items, rest = _decode_list(encoded[1+length_length:1+length_length+length])
        return items, encoded[1+length_length+length:]

def _decode_list(encoded):
    items = []
    while encoded:
        item, encoded = _decode(encoded)
        items.append(item)
    return items, encoded