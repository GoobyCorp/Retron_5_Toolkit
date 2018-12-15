#!/usr/bin/env python3

import os
import subprocess
from io import BytesIO
from tarfile import TarFile
from bz2 import BZ2Decompressor
from math import floor, log, pow
from os import mkdir, rename, urandom, remove
from os.path import isdir, isfile, join, basename
from binascii import hexlify as _hexlify, unhexlify

# my library
from StreamIO import *

# pip install pycryptodomex
from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA1, MD5
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Util.Padding import pad, unpad

# most of this was created from decompiled obfuscated java so it's really messy

# constants
DEBUG = True
OUTPUT_DIR = "output"
SYSTEM_IMG_FILE = "retron-system-update.img"
UPDATE_BIN_FILE = "retron-update.bin"
UPDATE_REQ_FILE = "retron-update-request.dat"
PUBLIC_KEY_FILE = "pub_key.pem"
PRIVATE_KEY_FILE = "prv_key.pem"

# I/O vars
BLOCK_SIZE = 8192

# magic
SHARED_MAGIC = 322420958
REQUEST_MAGIC = 1364349014

# secrets
# secret used to decrypt system update files (not app updates)
SYSTEM_SECRET = unhexlify("8704bc739081954c06411f6d8e531c37")
# used to encrypt console's DNA (serial #) for generating update requests
REQUEST_SECRET = unhexlify("9d7a196d7c461eb558ce9d2a29bc5d08")

# this is used to verify system updates
assert isfile(PUBLIC_KEY_FILE), "Public key doesn't exist"
with open(PUBLIC_KEY_FILE, "r") as f:
    RSA_PUB_KEY = RSA.import_key(f.read())
RSA_PUB_BITS = RSA_PUB_KEY.size_in_bits()
RSA_PUB_BYTES = RSA_PUB_KEY.size_in_bytes()

# this is used to sign the console's DNA (serial #) for update requests
assert isfile(PRIVATE_KEY_FILE), "Private key doesn't exist"
with open(PRIVATE_KEY_FILE, "r") as f:
    RSA_PRV_KEY = RSA.import_key(f.read())
RSA_PRV_BITS = RSA_PRV_KEY.size_in_bits()
RSA_PRV_BYTES = RSA_PRV_KEY.size_in_bytes()

def hexlify(b: (bytes, bytearray)) -> str:
    return _hexlify(b).decode("utf8")

def convert_size(size_bytes: int) -> str:
   if size_bytes == 0:
       return "0B"
   size_name = ("B", "KB", "MB", "GB")
   i = int(floor(log(size_bytes, 1024)))
   p = pow(1024, i)
   s = round(size_bytes / p, 2)
   return "%s %s" % (s, size_name[i])

def unpack_img(filename: str) -> bool:
    # determine OS
    exe_path = None
    exe_name = None
    if os.name == "posix":
        exe_path = "linux"
        exe_name = "imgrepackerrk"
    elif os.name == "nt":
        exe_path = "windows"
        exe_name = "imgRePackerRK.exe"
    assert exe_path is not None, "Unsupported OS"
    final_exe_path = join("bin", exe_path, exe_name)

    assert isfile(final_exe_path), "imgRePackerRK doesn't exist"
    cmd = [final_exe_path, "/2nd", filename]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, bufsize=1)
    #if DEBUG:
    #    for line in iter(p.stdout.readline, b''):
    #        print(line.strip(b"\t\r\n").decode("utf8"))
    p.stdout.close()
    p.wait()
    return p.returncode == 0

def pack_img(directory: str) -> bool:
    # determine OS
    exe_path = None
    exe_name = None
    if os.name == "posix":
        exe_path = "linux"
        exe_name = "imgrepackerrk"
    elif os.name == "nt":
        exe_path = "windows"
        exe_name = "imgRePackerRK.exe"
    assert exe_path is not None, "Unsupported OS"
    final_exe_path = join("bin", exe_path, exe_name)

    assert isfile(final_exe_path), "imgRePackerRK doesn't exist"
    cmd = [final_exe_path, "/2nd", directory]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, bufsize=1)
    #if DEBUG:
    #    for line in iter(p.stdout.readline, b''):
    #        print(line.strip(b"\t\r\n").decode("utf8"))
    p.stdout.close()
    p.wait()
    return p.returncode == 0

class UpdateRequestFile(object):
    dna = None
    serial = None
    signature = None

    enc_output = None

    def __init__(self, filename: str = UPDATE_REQ_FILE) -> None:
        self.reset()
        if isfile(filename):
            with open(filename, "rb") as f:
                self.parse(f)
        else:
            self.generate()
            with open(filename, "wb") as f:
                f.write(self.enc_output)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def reset(self) -> None:
        self.dna = None
        self.serial = None
        self.signature = None
        self.enc_output = None

    def generate(self) -> (bytes, bytearray):
        self.dna = urandom(7)
        self.serial = hexlify(self.dna).upper()

        iv = urandom(16)

        cipher = AES.new(REQUEST_SECRET, AES.MODE_CBC, iv)
        signer = PKCS1_v1_5.new(RSA_PRV_KEY)

        # not sure what the data on the end is but whatever, it works :3
        array = pack("<i", REQUEST_MAGIC) + self.dna + (b"\x00" * 8) + b"\x07"
        self.signature = signer.sign(SHA1.new(array))

        dec_data = array + self.signature
        enc_data = cipher.encrypt(pad(dec_data, AES.block_size))

        self.enc_output = iv + enc_data

    def parse(self, stream) -> (bytes, bytearray):
        self.enc_output = stream.read()

        stream.seek(0)

        iv = stream.read(16)

        cipher = AES.new(REQUEST_SECRET, AES.MODE_CBC, iv)
        enc_data = stream.read()  # array + signature
        dec_data = unpad(cipher.decrypt(enc_data), AES.block_size)

        array = dec_data[:-RSA_PRV_BYTES]  # UNIQUE_MAGIC + DNA
        self.signature = dec_data[-RSA_PRV_BYTES:]

        assert unpack("<i", array[:4])[0] == REQUEST_MAGIC, "Invalid magic"

        verifier = PKCS1_v1_5.new(RSA_PRV_KEY)
        assert verifier.verify(SHA1.new(array), self.signature), "Invalid signature"

        self.dna = array[4:11]
        self.serial = hexlify(self.dna).upper()

class UpdateFile(object):
    name: str
    offset: int
    size_nopad: int
    size_pad: int
    unique: bool
    key: (bytes, bytearray)  # SecretKeySpec
    iv: (bytes, bytearray)  # IvParameterSpec
    signature: (bytes, bytearray)
    valid: bool

    def get_dict(self) -> dict:
        return {
            "name": self.name,
            "offset": self.offset,
            "size_nopad": self.size_nopad,
            "size_pad": self.size_pad,
            "unique": self.unique,
            "key": hexlify(self.key),
            "iv": hexlify(self.iv),
            "signature": hexlify(self.signature)
        }

class SystemUpdateFile(object):
    stream = None
    dna_hash: (bytes, bytearray) = None
    h: int = None
    update_files: list = []
    verifier: PKCS1_v1_5 = None

    def __init__(self, f, dna: (bytes, bytearray) = None) -> None:
        self.reset()

        self.stream = f

        self.verifier = PKCS1_v1_5.new(RSA_PUB_KEY)

        if dna is not None:
            self.dna_hash = MD5.new(dna).digest()

        iv = self.stream.read(16)
        cipher = AES.new(SYSTEM_SECRET, AES.MODE_CBC, iv)

        bArr3 = self.stream.read(16)
        bArr3 = cipher.decrypt(bArr3)

        with BytesIO(bArr3) as bio:
            with StreamIO(bio) as sio:
                i = sio.read_int()
                i2 = sio.read_int()
                i3 = sio.read_int()
                self.h = sio.read_int()
                if i != SHARED_MAGIC:
                    raise Exception()
                elif i2 > 1:
                    raise Exception()
                else:
                    i = ((i3 * 256) + 16) + RSA_PUB_BYTES
                    self.stream.seek(16)
                    bArr3 = self.stream.read(i)
                    # re-init
                    cipher = AES.new(SYSTEM_SECRET, AES.MODE_CBC, iv)
                    decrypted = cipher.decrypt(bArr3)
        with BytesIO(decrypted) as bio:
            with StreamIO(bio) as sio:
                if sio.read_int() != SHARED_MAGIC:
                    raise Exception()
                signature = decrypted[-RSA_PUB_BYTES:]
                assert self.verifier.verify(SHA1.new(decrypted[:-RSA_PUB_BYTES]), signature), "Invalid signature"
                sio.seek(16)
                for i4 in range(i3):
                    bArr2 = sio.read(80)
                    file = UpdateFile()
                    file.valid = False
                    file.name = bArr2.split(b"\x00")[0].decode("utf8")
                    file.offset = sio.read_int()
                    file.size_nopad = sio.read_int()
                    file.size_pad = sio.read_int()
                    file.unique = sio.read_int() & 1 != 0
                    key = bytearray(sio.read(16))
                    if file.unique and dna is not None:  # this is only used if it's a console-unique file
                        for i5 in range(len(key)):
                            key[i5] ^= self.dna_hash[i5]
                    file.key = key
                    file.iv = sio.read(16)
                    file.signature = sio.read(RSA_PUB_BYTES)
                    self.update_files.append(file)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stream.close()

    def reset(self) -> None:
        self.stream = None
        self.dna_hash: (bytes, bytearray) = None
        self.h: int = None
        self.update_files: list = []
        self.verifier: PKCS1_v1_5 = None

    def list_files(self) -> list:
        if DEBUG:
            print(">>> " + self.stream.name)
            for single in self.update_files:
                print("+ %s @ %s, %s (%s unpadded)" % (single.name, hex(single.offset), convert_size(single.size_pad), convert_size(single.size_nopad)))
        return [x.name for x in self.update_files]

    def extract_files(self, directory: str = OUTPUT_DIR) -> None:
        for single in self.update_files:
            self.stream.seek(single.offset)
            cipher = AES.new(single.key, AES.MODE_CBC, single.iv)
            hasher = SHA1.new()
            bz2 = BZ2Decompressor()
            read = 0
            with open(join(directory, single.name), "wb") as f0:
                while read < single.size_pad:
                    # calculate the exact size of the read
                    amt = (single.size_pad - read) if (single.size_pad - read) < BLOCK_SIZE else BLOCK_SIZE
                    enc_buff = self.stream.read(amt)
                    # decrypt the buffer
                    dec_buff = cipher.decrypt(enc_buff)
                    # remove padding
                    if len(dec_buff) < BLOCK_SIZE:
                        if single.size_nopad < single.size_pad:
                            diff = single.size_pad - single.size_nopad
                            dec_buff = dec_buff[:-diff]
                    # update the hasher
                    hasher.update(dec_buff)
                    # decompress if bz2
                    if single.name.endswith(".bz2"):
                        dec_buff = bz2.decompress(dec_buff)
                    # output to file
                    f0.write(dec_buff)
                    read += len(enc_buff)
                assert self.verifier.verify(hasher, single.signature), "Invalid signature"
            # rename the .bz2 files because they're already decompressed
            if single.name.endswith(".bz2"):  # .tar.bz2 files
                if DEBUG:
                    print("> Unpacking %s..." % (single.name))
                orig_path = join(directory, single.name)
                new_path = join(directory, single.name.replace(".bz2", ".tar"))
                if isfile(new_path):
                    remove(new_path)
                rename(orig_path, new_path)
                if DEBUG:
                    print("> Renamed %s to %s" % (basename(orig_path), basename(new_path)))
                with TarFile(new_path) as tar_f:
                    if DEBUG:
                        for member in tar_f.getmembers():
                            print("+ %s @ %s, %s" % (member.name, hex(member.offset), convert_size(member.size)))
                    tar_f.extractall(directory)
                remove(new_path)
                if DEBUG:
                    print("- Deleted %s" % (single.name))
            elif single.name.endswith(".img"):  # rk30 images
                if DEBUG:
                    print("> Unpacking %s..." % (single.name))
                assert unpack_img(join(directory, single.name)), "Error unpacking system image"

if __name__ == "__main__":
    # create output directory
    if not isdir(OUTPUT_DIR):
        mkdir(OUTPUT_DIR)

    # parse or generate update request
    update_request = UpdateRequestFile()

    # parse and dump system update file
    #if isfile(SYSTEM_IMG_FILE):
    #    with open(SYSTEM_IMG_FILE, "rb") as f:
    #        with SystemUpdateFile(f, update_request.dna) as su:
    #            su.list_files()
    #            su.extract_files()

    # parse and dump app update file
    #if isfile(UPDATE_BIN_FILE):
    #    with open(UPDATE_BIN_FILE, "rb") as f:
    #        with SystemUpdateFile(f, update_request.dna) as su:
    #            su.list_files()
    #            su.extract_files()