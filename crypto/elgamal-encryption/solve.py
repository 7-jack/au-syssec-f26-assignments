import requests 
import base64
import json
import sys
import requests
from Crypto.Util.number import long_to_bytes, bytes_to_long
import math 

#URL = "http://127.0.0.1:5000"
URL = "https://elgamal.syssec.dk"
def json_to_cookie(j: str) -> str:
    """Encode json data in a cookie-friendly way using base64."""
    # The JSON data is a string -> encode it into bytes
    json_as_bytes = j.encode()
    # base64-encode the bytes
    base64_as_bytes = base64.b64encode(json_as_bytes, altchars=b'-_')
    # b64encode returns bytes again, but we need a string -> decode it
    base64_as_str = base64_as_bytes.decode()
    return base64_as_str


def main():
    pk = requests.get(URL + "/params").json()

    # 1. get public key 
    p = pk["p"]
    g = pk["g"]

    msg = bytes_to_long(b'You got a 12 because you are an excellent student! :)')


    m1 = long_to_bytes((msg*pow(2, -1, p))%p).hex()
    r = requests.get(URL + f"/encrypt_random_document_for_students/{m1}/").json()
    c = bytes.fromhex(r["ciphertext"])


    length = math.ceil(p.bit_length() / 8)
    c1 = int.from_bytes(c[:length], "big")
    c2 = int.from_bytes(c[length:], "big")

    c2 = (c2*2)%p
    ciphertext = c1.to_bytes(length, 'big')
    ciphertext += c2.to_bytes(length, 'big')

    forgery = long_to_bytes(msg).hex()
    
    cookie = json_to_cookie(json.dumps({'msg': forgery, 'ciphertext': ciphertext.hex()})) 

    r = requests.get(URL + "/quote/", cookies={'grade': cookie})
    print(r.text)

if __name__ == "__main__":
    main()