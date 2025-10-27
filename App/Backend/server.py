# app.py
from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
import math
import base64
import io
import hashlib
import numpy as np
from PIL import Image
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad


app = Flask(__name__)
CORS(app)
# Utilities

def modInverse(a, m):
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def _shift_char(ch, key_shift, encrypt=True):
    if not ch.isalpha():
        return ch
    shift = 65 if ch.isupper() else 97
    if encrypt:
        return chr((ord(ch) - shift + key_shift) % 26 + shift)
    else:
        return chr((ord(ch) - shift - key_shift) % 26 + shift)

# Root
@app.route("/")
def home():
    return "Hello from the PythonServer"

# Simple classical ciphers

# Ceaser
@app.route("/api/symmetric/Ceaser/encrypt", methods=["POST"])
def CeaserEncrypt():
    data = request.json
    pt = data.get("pt", "")
    key = int(data.get("key", 0))
    result = "".join(_shift_char(ch, key, encrypt=True) for ch in pt)
    return jsonify({"ct": result})

@app.route("/api/symmetric/Ceaser/decrypt", methods=["POST"])
def CeaserDecrypt():
    data = request.json
    ct = data.get("ct", "")
    key = int(data.get("key", 0))
    result = "".join(_shift_char(ch, key, encrypt=False) for ch in ct)
    return jsonify({"pt": result})

# Multiplicative
@app.route("/api/symmetric/Multiplicative/encrypt", methods=["POST"])
def MulEncrypt():
    data = request.json
    pt = data.get("pt", "")
    key = int(data.get("key", 0))
    if math.gcd(key, 26) != 1:
        return jsonify({"error": "Invalid key, must be coprime with 26"}), 400
    result = ""
    for ch in pt:
        if ch.isalpha():
            shift = 65 if ch.isupper() else 97
            result += chr(((ord(ch) - shift) * key) % 26 + shift)
        else:
            result += ch
    return jsonify({"ct": result})

@app.route("/api/symmetric/Multiplicative/decrypt", methods=["POST"])
def MulDecrypt():
    data = request.json
    ct = data.get("ct", "")
    key = int(data.get("key", 0))
    if math.gcd(key, 26) != 1:
        return jsonify({"error": "Invalid key, must be coprime with 26"}), 400
    invkey = modInverse(key, 26)
    if invkey is None:
        return jsonify({"error": "Inverse not found"}), 400
    result = ""
    for ch in ct:
        if ch.isalpha():
            shift = 65 if ch.isupper() else 97
            result += chr(((ord(ch) - shift) * invkey) % 26 + shift)
        else:
            result += ch
    return jsonify({"pt": result})

# Affine
@app.route("/api/symmetric/Affine/Encrypt", methods=["POST"])
def AffineEncrypt():
    data = request.json
    pt = data.get("pt", "")
    a = int(data.get("a", 0))
    b = int(data.get("b", 0))
    if math.gcd(a, 26) != 1:
        return jsonify({"error": "Invalid key, must be coprime with 26"}), 400
    result = ""
    for ch in pt:
        if ch.isalpha():
            shift = 65 if ch.isupper() else 97
            result += chr(((ord(ch) - shift) * a + b) % 26 + shift)
        else:
            result += ch
    return jsonify({"ct": result})

@app.route("/api/symmetric/Affine/Decrypt", methods=["POST"])
def AffineDecrypt():
    data = request.json
    ct = data.get("ct", "")
    a = int(data.get("a", 0))
    b = int(data.get("b", 0))
    if math.gcd(a, 26) != 1:
        return jsonify({"error": "Invalid key, must be coprime with 26"}), 400
    ainv = modInverse(a, 26)
    if ainv is None:
        return jsonify({"error": "inverse of a not found"}), 400
    result = ""
    for ch in ct:
        if ch.isalpha():
            shift = 65 if ch.isupper() else 97
            # p = a_inv * (c - b) mod 26
            c_val = ord(ch) - shift
            p = (ainv * (c_val - b)) % 26
            result += chr(p + shift)
        else:
            result += ch
    return jsonify({"pt": result})

# Autokey cipher
@app.route("/api/symmetric/autokeycipher/encrypt", methods=["POST"])
def AutokeyEncrypt():
    data = request.json
    pt = data.get("pt", "")
    key = data.get("key", "")
    if key is None:
        key = ""
    result = ""
    keystream = key.upper()  # will append plaintext to keystream
    ks_index = 0
    for ch in pt:
        if ch.isalpha():
            shift = 65 if ch.isupper() else 97
            p = ord(ch) - shift
            if ks_index >= len(keystream):
                # next keystream char comes from plaintext (uppercased)
                keystream += ch.upper()
            k = ord(keystream[ks_index]) - 65
            c = (p + k) % 26
            result += chr(c + shift)
            ks_index += 1
        else:
            result += ch
    return jsonify({"ct": result})

@app.route("/api/symmetric/autokeycipher/decrypt", methods=["POST"])
def AutokeyDecrypt():
    data = request.json
    ct = data.get("ct", "")
    key = data.get("key", "")
    if key is None:
        key = ""
    result = ""
    keystream = key.upper()
    ks_index = 0
    for ch in ct:
        if ch.isalpha():
            shift = 65 if ch.isupper() else 97
            c_val = ord(ch) - shift
            if ks_index >= len(keystream):
                # shouldn't happen often because we append plaintext as we go
                keystream += 'A'
            k = ord(keystream[ks_index]) - 65
            p = (c_val - k + 26) % 26
            pch = chr(p + shift)
            result += pch
            keystream += pch.upper()
            ks_index += 1
        else:
            result += ch
    return jsonify({"pt": result})

# Vigenere
@app.route("/api/symmetric/vigenere/encrypt", methods=["POST"])
def vigenereEncrypt():
    data = request.json
    pt = data.get("pt", "")
    key = data.get("key", "")
    key = (key or "").upper()
    if len(key) == 0:
        return jsonify({"error": "Key required"}), 400
    result = ""
    i = 0
    for ch in pt:
        if ch.isalpha():
            shift = 65 if ch.isupper() else 97
            p = ord(ch) - shift
            k = ord(key[i % len(key)]) - 65
            c = (p + k) % 26
            result += chr(c + shift)
            i += 1
        else:
            result += ch
    return jsonify({"ct": result})

@app.route("/api/symmetric/vigenere/decrypt", methods=["POST"])
def vigenereDecrypt():
    data = request.json
    ct = data.get("ct", "")
    key = data.get("key", "")
    key = (key or "").upper()
    if len(key) == 0:
        return jsonify({"error": "Key required"}), 400
    result = ""
    i = 0
    for ch in ct:
        if ch.isalpha():
            shift = 65 if ch.isupper() else 97
            c_val = ord(ch) - shift
            k = ord(key[i % len(key)]) - 65
            p = (c_val - k + 26) % 26
            result += chr(p + shift)
            i += 1
        else:
            result += ch
    return jsonify({"pt": result})

# Playfair (5x5, I/J merged)
def _playfair_generate_table(key):
    key = key.upper().replace('J', 'I')
    seen = []
    table = []
    for ch in key:
        if ch.isalpha() and ch not in seen:
            seen.append(ch)
    for ch in "ABCDEFGHIKLMNOPQRSTUVWXYZ":  # J omitted
        if ch not in seen:
            seen.append(ch)
    # create 5x5
    table = [seen[i*5:(i+1)*5] for i in range(5)]
    lookup = {table[r][c]: (r, c) for r in range(5) for c in range(5)}
    return table, lookup

def _playfair_prepare_text(pt, encrypt=True):
    s = "".join(ch.upper() for ch in pt if ch.isalpha()).replace('J', 'I')
    pairs = []
    i = 0
    while i < len(s):
        a = s[i]
        b = s[i+1] if i+1 < len(s) else 'X'
        if a == b:
            pairs.append(a + 'X')
            i += 1
        else:
            pairs.append(a + b)
            i += 2
    if len(pairs) > 0 and len(pairs[-1]) == 1:
        pairs[-1] += 'X'
    return pairs

@app.route("/api/symmetric/playfair/keygen", methods=["POST"])
def playfairKeyGen():
    data = request.json
    key = data.get("key", "")
    table, lookup = _playfair_generate_table(key)
    # return table as rows
    rows = ["".join(r) for r in table]
    return jsonify({"table": rows})

@app.route("/api/symmetric/playfair/encrypt", methods=["POST"])
def playfairEncrypt():
    data = request.json
    key = data.get("key", "")
    pt = data.get("pt", "")
    table, lookup = _playfair_generate_table(key)
    pairs = _playfair_prepare_text(pt)
    cipher = ""
    for pair in pairs:
        a, b = pair[0], pair[1]
        ra, ca = lookup[a]
        rb, cb = lookup[b]
        if ra == rb:
            # same row -> shift right
            cipher += table[ra][(ca + 1) % 5]
            cipher += table[rb][(cb + 1) % 5]
        elif ca == cb:
            # same column -> shift down
            cipher += table[(ra + 1) % 5][ca]
            cipher += table[(rb + 1) % 5][cb]
        else:
            # rectangle rule
            cipher += table[ra][cb]
            cipher += table[rb][ca]
    return jsonify({"ct": cipher})

@app.route("/api/symmetric/playfair/decrypt", methods=["POST"])
def playfairDecrypt():
    data = request.json
    key = data.get("key", "")
    ct = data.get("ct", "")
    table, lookup = _playfair_generate_table(key)
    # assume ct is already even-length alphabetic uppercase
    ct = "".join(ch for ch in ct.upper() if ch.isalpha()).replace('J', 'I')
    pairs = [ct[i:i+2] for i in range(0, len(ct), 2)]
    plain = ""
    for pair in pairs:
        a, b = pair[0], pair[1]
        ra, ca = lookup[a]
        rb, cb = lookup[b]
        if ra == rb:
            plain += table[ra][(ca - 1) % 5]
            plain += table[rb][(cb - 1) % 5]
        elif ca == cb:
            plain += table[(ra - 1) % 5][ca]
            plain += table[(rb - 1) % 5][cb]
        else:
            plain += table[ra][cb]
            plain += table[rb][ca]
    return jsonify({"pt": plain})

# Data transformation endpoints

# Base64
@app.route("/api/transform/base64/encode", methods=["POST"])
def base64_encode():
    data = request.json
    text = data.get("text", "")
    return jsonify({"result": base64.b64encode(text.encode()).decode()})

@app.route("/api/transform/base64/decode", methods=["POST"])
def base64_decode():
    data = request.json
    text = data.get("text", "")
    try:
        return jsonify({"result": base64.b64decode(text.encode()).decode()})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# Hex
@app.route("/api/transform/hex/encode", methods=["POST"])
def hex_encode():
    data = request.json
    text = data.get("text", "")
    return jsonify({"result": text.encode().hex()})

@app.route("/api/transform/hex/decode", methods=["POST"])
def hex_decode():
    data = request.json
    text = data.get("text", "")
    try:
        return jsonify({"result": bytes.fromhex(text).decode()})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# Hashing
@app.route("/api/transform/hash/sha256", methods=["POST"])
def sha256_hash():
    data = request.json
    text = data.get("text", "")
    return jsonify({"hash": hashlib.sha256(text.encode()).hexdigest()})

@app.route("/api/transform/hash/md5", methods=["POST"])
def md5_hash():
    data = request.json
    text = data.get("text", "")
    return jsonify({"hash": hashlib.md5(text.encode()).hexdigest()})

# XOR (returns base64 to keep binary-safe)
@app.route("/api/transform/xor", methods=["POST"])
def xor_transform():
    data = request.json
    text = data.get("text", "")
    key = data.get("key", "")
    if key == "":
        return jsonify({"error": "Key required"}), 400
    tx = text.encode()
    kx = key.encode()
    res = bytes([tx[i] ^ kx[i % len(kx)] for i in range(len(tx))])
    return jsonify({"result": base64.b64encode(res).decode()})

# Symmetric block ciphers: DES, AES

# DES encrypt/decrypt (ECB). Key must be 8 bytes.
@app.route("/api/symmetric/DES/encrypt", methods=["POST"])
def DES_Encrypt():
    data = request.json
    key = data.get("key", "").encode()
    pt = data.get("pt", "")
    if len(key) != 8:
        return jsonify({"error": "DES key should be 8 bytes long"}), 400
    cipher = DES.new(key, DES.MODE_ECB)
    ct = cipher.encrypt(pad(pt.encode(), DES.block_size))
    result = base64.b64encode(ct).decode()
    return jsonify({"ct": result})

@app.route("/api/symmetric/DES/decrypt", methods=["POST"])
def DES_Decrypt():
    data = request.json
    key = data.get("key", "").encode()
    ct = data.get("ct", "")
    if len(key) != 8:
        return jsonify({"error": "DES key should be 8 bytes long"}), 400
    try:
        ctb = base64.b64decode(ct)
        cipher = DES.new(key, DES.MODE_ECB)
        pt = unpad(cipher.decrypt(ctb), DES.block_size).decode()
        return jsonify({"pt": pt})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# AES (ECB, 128-bit key derived from provided key by padding/truncating)
@app.route("/api/symmetric/AES/encrypt", methods=["POST"])
def AES_Encrypt():
    data = request.json
    key = data.get("key", "").encode()
    pt = data.get("pt", "")
    # produce 16 byte key (pad with nulls or truncate)
    key = (key + b'\0' * 16)[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    ct = cipher.encrypt(pad(pt.encode(), AES.block_size))
    return jsonify({"ct": base64.b64encode(ct).decode()})

@app.route("/api/symmetric/AES/decrypt", methods=["POST"])
def AES_Decrypt():
    data = request.json
    key = data.get("key", "").encode()
    ct = data.get("ct", "")
    key = (key + b'\0' * 16)[:16]
    try:
        ctb = base64.b64decode(ct)
        cipher = AES.new(key, AES.MODE_ECB)
        pt = unpad(cipher.decrypt(ctb), AES.block_size).decode()
        return jsonify({"pt": pt})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# Steganography - LSB (works for PNG/JPEG but PNG recommended)

def _embed_message_in_image(img: Image.Image, message: str) -> Image.Image:
    # convert to RGB
    img = img.convert('RGB')
    arr = np.array(img)
    flat = arr.flatten()
    # Terminator: use a sentinel sequence that is unlikely in normal text (16 bits: 0xFFFF then 0x00)
    # we'll use 16-bit terminator "DELIM" - here use two bytes 0x00 0xFF 0x00 0x00? Simpler: append delimiter of eight 1s then a zero byte char '\x00' is fine.
    # Use a clear sentinel: 16 zeros + 11111111 (we'll keep a simple sentinel): append '\x00' (null) as terminator repeated twice
    sentinel = '\x00\x00'
    binary = ''.join(format(ord(c), '08b') for c in (message + sentinel))
    if len(binary) > len(flat):
        raise ValueError("Message too large to embed in this image")
    for i, bit in enumerate(binary):
        flat[i] = (flat[i] & 0xFE) | int(bit)
    new_arr = flat.reshape(arr.shape)
    return Image.fromarray(new_arr.astype(np.uint8))

def _extract_message_from_image(img: Image.Image) -> str:
    img = img.convert('RGB')
    arr = np.array(img).flatten()
    bits = [str(arr[i] & 1) for i in range(len(arr))]
    chars = [bits[i:i+8] for i in range(0, len(bits), 8)]
    message = ""
    for byte_bits in chars:
        if len(byte_bits) < 8:
            break
        ch = chr(int(''.join(byte_bits), 2))
        message += ch
        # check sentinel
        if message.endswith('\x00\x00'):
            return message[:-2]
    return message  # if sentinel not found, return what we have

@app.route("/api/stego/embed", methods=["POST"])
def stego_embed():
    if 'image' not in request.files:
        return jsonify({"error": "image file is required (field name 'image')"}), 400
    file = request.files['image']
    secret = request.form.get("secret", "")
    if secret is None:
        secret = ""
    try:
        img = Image.open(file.stream)
        out_img = _embed_message_in_image(img, secret)
        buf = io.BytesIO()
        out_img.save(buf, format='PNG')
        buf.seek(0)
        return send_file(buf, mimetype='image/png', as_attachment=True, attachment_filename='stego_output.png')
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/stego/extract", methods=["POST"])
def stego_extract():
    if 'image' not in request.files:
        return jsonify({"error": "image file is required (field name 'image')"}), 400
    file = request.files['image']
    try:
        img = Image.open(file.stream)
        secret = _extract_message_from_image(img)
        return jsonify({"secret": secret})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# Forensic utilities

@app.route("/api/forensic/lsb_visualize", methods=["POST"])
def lsb_visualize():
    if 'image' not in request.files:
        return jsonify({"error": "image file is required (field name 'image')"}), 400
    file = request.files['image']
    try:
        img = Image.open(file.stream).convert('RGB')
        arr = np.array(img)
        lsb = (arr & 1) * 255
        out_img = Image.fromarray(lsb.astype(np.uint8))
        buf = io.BytesIO()
        out_img.save(buf, format='PNG')
        buf.seek(0)
        return send_file(buf, mimetype='image/png', as_attachment=True, attachment_filename='lsb_visual.png')
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/forensic/magic", methods=["POST"])
def magic_analyze():
    if 'file' not in request.files:
        return jsonify({"error": "file required (field name 'file')"}), 400
    file = request.files['file']
    header = file.read(16)
    return jsonify({"magic_bytes_hex": header.hex().upper()})

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404


if __name__ == "__main__":
    app.run(debug=True)