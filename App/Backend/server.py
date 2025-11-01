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
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import base64
import exifread
import os
import binascii


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
@app.route("/api/symmetric/Affine/encrypt", methods=["POST"])
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

@app.route("/api/symmetric/Affine/decrypt", methods=["POST"])
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

# Autokey cipher (fixed)
@app.route("/api/symmetric/Autokey/encrypt", methods=["POST"])
def AutokeyEncrypt():
    data = request.json
    pt = data.get("pt", "")
    key = data.get("key", "") or ""

    pt_letters = [ch for ch in pt if ch.isalpha()]

    keystream = (key.upper() + ''.join(ch.upper() for ch in pt_letters))

    result = ""
    ks_index = 0  # index into keystream (counts only alpha chars)
    for ch in pt:
        if ch.isalpha():
            shift = 65 if ch.isupper() else 97
            p = ord(ch) - shift
            k = ord(keystream[ks_index]) - 65
            c = (p + k) % 26
            result += chr(c + shift)
            ks_index += 1
        else:
            result += ch

    return jsonify({"ct": result})


@app.route("/api/symmetric/Autokey/decrypt", methods=["POST"])
def AutokeyDecrypt():
    data = request.json
    ct = data.get("ct", "")
    key = data.get("key", "") or ""

    result = ""
    keystream = key.upper()  
    ks_index = 0

    for ch in ct:
        if ch.isalpha():
            shift = 65 if ch.isupper() else 97
            c_val = ord(ch) - shift
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
@app.route("/api/symmetric/Vigenere/encrypt", methods=["POST"])
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

@app.route("/api/symmetric/Vigenere/decrypt", methods=["POST"])
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

@app.route("/api/symmetric/Playfair/keygen", methods=["POST"])
def playfairKeyGen():
    data = request.json
    key = data.get("key", "")
    table, lookup = _playfair_generate_table(key)
    # return table as rows
    rows = ["".join(r) for r in table]
    return jsonify({"table": rows})

@app.route("/api/symmetric/Playfair/encrypt", methods=["POST"])
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

@app.route("/api/symmetric/Playfair/decrypt", methods=["POST"])
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


#Hill cipher
def char_to_num(ch):
    return ord(ch.upper()) - 65

def num_to_char(n):
    return chr((n % 26) + 65)

def mod_inverse(a, m=26):
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError("No modular inverse")

def matrix_mod_inv_2x2(matrix):
    det = (matrix[0][0]*matrix[1][1] - matrix[0][1]*matrix[1][0]) % 26
    det_inv = mod_inverse(det)
    inv = [
        [( matrix[1][1]*det_inv) % 26, (-matrix[0][1]*det_inv) % 26],
        [(-matrix[1][0]*det_inv) % 26, ( matrix[0][0]*det_inv) % 26]
    ]
    return [[x % 26 for x in row] for row in inv]

def multiply_matrix_vector(matrix, vector):
    result = []
    for i in range(2):
        val = (matrix[i][0]*vector[0] + matrix[i][1]*vector[1]) % 26
        result.append(val)
    return result

#hill cipher
@app.route('/api/symmetric/Hill/encrypt', methods=['POST'])
def hill_encrypt():
    data = request.get_json()
    pt = data.get('pt', '').upper().replace(' ', '')
    key = data.get('key', [])

    if not key or len(key) != 4:
        return jsonify({"error": "Key must contain 4 integers (2x2 matrix)."}), 400

    key_matrix = [
        [int(key[0]), int(key[1])],
        [int(key[2]), int(key[3])]
    ]

    if len(pt) % 2 != 0:
        pt += 'X'  # padding

    ct = ''
    for i in range(0, len(pt), 2):
        vec = [char_to_num(pt[i]), char_to_num(pt[i+1])]
        enc_vec = multiply_matrix_vector(key_matrix, vec)
        ct += num_to_char(enc_vec[0]) + num_to_char(enc_vec[1])

    return jsonify({"ct": ct})


@app.route('/api/symmetric/Hill/decrypt', methods=['POST'])
def hill_decrypt():
    data = request.get_json()
    ct = data.get('ct', '').upper().replace(' ', '')
    key = data.get('key', [])

    if not key or len(key) != 4:
        return jsonify({"error": "Key must contain 4 integers (2x2 matrix)."}), 400

    key_matrix = [
        [int(key[0]), int(key[1])],
        [int(key[2]), int(key[3])]
    ]

    try:
        inv_key = matrix_mod_inv_2x2(key_matrix)
    except Exception as e:
        return jsonify({"error": f"Invalid key matrix: {str(e)}"}), 400

    pt = ''
    for i in range(0, len(ct), 2):
        vec = [char_to_num(ct[i]), char_to_num(ct[i+1])]
        dec_vec = multiply_matrix_vector(inv_key, vec)
        pt += num_to_char(dec_vec[0]) + num_to_char(dec_vec[1])

    return jsonify({"pt": pt})

# Data transformation endpoints

# Base64

@app.route("/api/transform/Base64/encrypt", methods=["POST"])
def base64_encode():
    data = request.json
    # your frontend sends { "pt": "..." }
    text = data.get("pt", "")
    if not text:
        return jsonify({"error": "No input text provided"}), 400

    encoded = base64.b64encode(text.encode()).decode()
    return jsonify({"ct": encoded})  # returning "ct" to match frontend expectation


@app.route("/api/transform/Base64/decrypt", methods=["POST"])
def base64_decode():
    data = request.json
    # your frontend sends { "ct": "..." }
    text = data.get("ct", "")
    if not text:
        return jsonify({"error": "No input text provided"}), 400

    try:
        decoded = base64.b64decode(text.encode()).decode()
        return jsonify({"pt": decoded})  # returning "pt" to match frontend expectation
    except Exception as e:
        return jsonify({"error": str(e)}), 400

#hex
@app.route("/api/transform/Hex/encrypt", methods=["POST"])
def hex_encode():
    data = request.json
    text = data.get("pt", "")  # frontend sends pt for encrypt
    if not text:
        return jsonify({"error": "No input text provided"}), 400
    encoded = text.encode().hex()
    return jsonify({"ct": encoded})  # match frontend resultKey


@app.route("/api/transform/Hex/decrypt", methods=["POST"])
def hex_decode():
    data = request.json
    text = data.get("ct", "")  # frontend sends ct for decrypt
    if not text:
        return jsonify({"error": "No input text provided"}), 400
    try:
        decoded = bytes.fromhex(text).decode()
        return jsonify({"pt": decoded})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/transform/HashSHA256/encrypt", methods=["POST"])
def sha256_hash():
    data = request.json
    text = data.get("pt", "")
    if not text:
        return jsonify({"error": "No input text provided"}), 400
    return jsonify({"ct": hashlib.sha256(text.encode()).hexdigest()})


@app.route("/api/transform/HashMD5/encrypt", methods=["POST"])
def md5_hash():
    data = request.json
    text = data.get("pt", "")
    if not text:
        return jsonify({"error": "No input text provided"}), 400
    return jsonify({"ct": hashlib.md5(text.encode()).hexdigest()})


#xor
@app.route("/api/transform/XOR", methods=["POST"])
def xor_transform():
    data = request.json
    text = data.get("pt", "")
    key = data.get("key", "")
    if not text or not key:
        return jsonify({"error": "Both text and key are required"}), 400

    tx = text.encode()
    kx = key.encode()
    result = bytes([tx[i] ^ kx[i % len(kx)] for i in range(len(tx))])
    encoded_result = base64.b64encode(result).decode()

    return jsonify({"ct": encoded_result})

# Symmetric block ciphers: DES, AES

# DES encrypt/decrypt (ECB). Key must be 8 bytes.
@app.route("/api/symmetric/DES/encrypt", methods=["POST"])
def DES_Encrypt():
    data = request.json
    key = data.get("key", "").encode()
    pt = data.get("pt", "")
    
    # Check key length
    if len(key) != 8:
        return jsonify({"error": "DES key should be 8 bytes long"}), 400
    
    try:
        cipher = DES.new(key, DES.MODE_ECB)
        ct = cipher.encrypt(pad(pt.encode(), DES.block_size))
        result = base64.b64encode(ct).decode()
        return jsonify({"ct": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/symmetric/DES/decrypt", methods=["POST"])
def DES_Decrypt():
    data = request.json
    key = data.get("key", "").encode()
    ct = data.get("ct", "")
    
    # Check key length
    if len(key) != 8:
        return jsonify({"error": "DES key should be 8 bytes long"}), 400
    
    try:
        ctb = base64.b64decode(ct)
        cipher = DES.new(key, DES.MODE_ECB)
        pt = unpad(cipher.decrypt(ctb), DES.block_size).decode()
        return jsonify({"pt": pt})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
        return jsonify({"error": str(e)}), 400

# AES (ECB, 128-bit key derived from provided key by padding/truncating)
@app.route("/api/symmetric/AES/encrypt", methods=["POST"])
def AES_Encrypt():
    data = request.json
    key = data.get("key", "").encode()
    pt = data.get("pt", "")

    if not pt:
        return jsonify({"error": "Plaintext required"}), 400

    # AES key must be 16, 24, or 32 bytes
    key = (key + b'\0' * 16)[:16]

    try:
        cipher = AES.new(key, AES.MODE_ECB)
        ct = cipher.encrypt(pad(pt.encode(), AES.block_size))
        return jsonify({"ct": base64.b64encode(ct).decode()})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/symmetric/AES/decrypt", methods=["POST"])
def AES_Decrypt():
    data = request.json
    key = data.get("key", "").encode()
    ct = data.get("ct", "")

    if not ct:
        return jsonify({"error": "Ciphertext required"}), 400

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
        # ✅ updated line for Flask 2.3+
        return send_file(buf, mimetype='image/png', as_attachment=True, download_name='stego_output.png')
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

#LSB Visualizer
@app.route("/api/forensic/lsb_visualize", methods=["POST"])
def lsb_visualize():
    if 'file' not in request.files:  # 👈 ensure the field name matches frontend
        return jsonify({"error": "Image file required (field name 'file')"}), 400

    file = request.files['file']

    try:
        img = Image.open(file.stream).convert('RGB')
        arr = np.array(img)

        # Extract least significant bit of each RGB channel
        lsb = (arr & 1) * 255  # produces black/white pattern of hidden bits
        out_img = Image.fromarray(lsb.astype(np.uint8))

        # Save to buffer
        buf = io.BytesIO()
        out_img.save(buf, format='PNG')
        buf.seek(0)

        return send_file(
            buf,
            mimetype='image/png',
            as_attachment=True,
            download_name='lsb_visualized.png'
        )

    except Exception as e:
        return jsonify({"error": f"LSB Visualization failed: {str(e)}"}), 500


# Magic Byte Analyzer
@app.route("/api/forensic/magic_analyze", methods=["POST"])
def magic_analyze():
    if 'file' not in request.files:
        return jsonify({"error": "Image file required (field name 'file')"}), 400

    file = request.files['file']
    file_bytes = file.read(16)  # read first 16 bytes (enough for most headers)
    file.seek(0)

    try:
        magic_bytes_hex = binascii.hexlify(file_bytes).decode("utf-8").upper()

        # --- Magic byte signatures ---
        signatures = {
             # --- Image Formats ---
            "FFD8FF": "JPEG image",
            "89504E47": "PNG image",
            "47494638": "GIF image",
            "424D": "BMP image",
            "49492A00": "TIFF image (Little Endian)",
            "4D4D002A": "TIFF image (Big Endian)",
            "38425053": "PSD (Photoshop Document)",
            "52494646": "WEBP or AVI (depends on bytes 8-11)",
            "00000100": "ICO (Icon)",
            "00000200": "CUR (Cursor Icon)",

            # --- Document Formats ---
            "25504446": "PDF document",
            "D0CF11E0A1B11AE1": "Microsoft Office (DOC, XLS, PPT - pre-2007)",
            "504B0304": "ZIP Archive / OOXML (DOCX, PPTX, XLSX, ODT, ODP)",
            "7573746172": "TAR archive (ustar)",
            "7B5C727466": "RTF document",
            "3C3F786D6C": "XML document",
            "68746D6C3E": "HTML document",
            "EFBBBF": "UTF-8 BOM text file",

            # --- Audio Formats ---
            "494433": "MP3 audio",
            "FFFB": "MP3 audio (no ID3 tag)",
            "4F676753": "OGG audio",
            "664C6143": "FLAC audio",
            "52494646": "WAV audio / AVI / WEBP (RIFF format)",
            "3026B2758E66CF11": "WMA/WMV (ASF container)",
            "664C6143": "FLAC audio",
            "2E736E64": "AU audio file",

            # --- Video Formats ---
            "000001BA": "MPEG video stream",
            "000001B3": "MPEG video file",
            "1A45DFA3": "MKV / WebM video",
            "0000001866747970": "MP4 video",
            "66747970": "MP4 / QuickTime / MOV",
            "3026B2758E66CF11": "WMV / WMA / ASF (Microsoft media container)",
            "4F676753": "OGG / OGV video",
            "52494646": "AVI video / WAV audio / WEBP image",

            # --- Archive / Compression Formats ---
            "504B0304": "ZIP archive / DOCX / XLSX / JAR / APK / ODT",
            "52617221": "RAR archive",
            "1F8B08": "GZIP compressed archive",
            "425A68": "BZIP2 compressed archive",
            "FD377A585A00": "XZ compressed archive",
            "377ABCAF271C": "7-Zip archive",
            "7573746172": "TAR archive",
            "7801": "ZLIB compressed data",
            "7809": "ZLIB compressed data",

            # --- Executables / System Files ---
            "4D5A": "Windows EXE or DLL (MZ header)",
            "7F454C46": "ELF executable (Linux/Unix)",
            "CFFAEDFE": "Mach-O executable (macOS)",
            "FEEDFACE": "Mach-O (32-bit)",
            "FEEDFACF": "Mach-O (64-bit)",
            "CAFEBABE": "Java class file / Mach-O (Universal)",
            "CAFED00D": "Java class (old format)",
            "7B0D0A6F626A": "Binary property list (.plist)",
            "23215F": "Unix script (#!shebang)",
            "23215521": "Unix script (#! /bin/sh)",

            # --- Fonts ---
            "00010000": "TrueType font (TTF)",
            "4F54544F": "OpenType font (OTF)",
            "74727565": "WOFF font (Web Open Font Format)",
            "774F4646": "WOFF2 font (Web Open Font Format 2.0)",

            # --- Disk / Image Files ---
            "EB3C90": "DOS/MBR Boot sector",
            "EB5890": "FAT filesystem image",
            "4D534346": "Cabinet archive (Microsoft .CAB)",
            "4344303031": "ISO CD-ROM image",
            "4D534346": "Microsoft Cabinet file",

            # --- Database / Misc ---
            "53514C69746520666F726D6174203300": "SQLite 3 Database",
            "000100005374616E64617264204A6574204442": "Standard Jet DB (MS Access)",
            "4A4152435300": "JARCS archive",
            "0000000C6A502020": "JPEG2000 image",

            # --- Scripts / Code Files ---
            "3C21444F4354": "HTML document",
            "23212F7573722F62696E2F656E76": "Shell script",
            "23212F7573722F62696E2F707974686F6E": "Python script",
            "23212F62696E2F7368": "Shell script",
            "2F2A2A": "C/C++ source file (comment header)",
        }

        detected_type = "Unknown"
        for magic, ftype in signatures.items():
            if magic_bytes_hex.startswith(magic):
                detected_type = ftype
                break

        return jsonify({
            "detected_type": detected_type,
            "magic_bytes_hex": magic_bytes_hex
        })

    except Exception as e:
        return jsonify({"error": f"Magic byte analysis failed: {str(e)}"}), 500

#metadata
@app.route("/api/forensic/metadata_extract", methods=["POST"])
def metadata_extract():
    # Accept both 'image' or 'file' field names
    uploaded_file = request.files.get('image') or request.files.get('file')
    if not uploaded_file:
        return jsonify({"error": "Image file required (field name 'image' or 'file')"}), 400

    try:
        # Save temporarily (some EXIF readers require a real file)
        temp_dir = "temp_uploads"
        os.makedirs(temp_dir, exist_ok=True)
        temp_path = os.path.join(temp_dir, uploaded_file.filename)
        uploaded_file.save(temp_path)

        with open(temp_path, 'rb') as f:
            tags = exifread.process_file(f, details=False)

        os.remove(temp_path)

        if not tags:
            return jsonify({"message": "No EXIF metadata found"}), 200

        # Convert tags to a readable dict
        metadata = {tag: str(value) for tag, value in tags.items()}

        return jsonify({
            "status": "success",
            "metadata_count": len(metadata),
            "metadata": metadata
        }), 200

    except Exception as e:
        return jsonify({
            "error": f"Metadata extraction failed: {str(e)}"
        }), 500

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404


if __name__ == "__main__":
    app.run(debug=True)