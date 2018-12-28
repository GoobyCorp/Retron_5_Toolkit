#!/usr/bin/env python3

__author__ = "Visual Studio"
__description__ = "A script to make unpacking and packing Retron 5 updates easier (or actually possible)"

import os
import subprocess
from ctypes import *
from io import BytesIO
from tarfile import TarFile
from datetime import datetime
from bz2 import BZ2Decompressor
from math import floor, log, pow
from argparse import ArgumentParser
from os import mkdir, rename, urandom, remove
from os.path import isdir, isfile, join, basename
from binascii import hexlify as _hexlify, unhexlify

# included in the repo
from StreamIO.StreamIO import *

# pip install pycryptodomex
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA1, MD5
from Cryptodome.Cipher import AES, ARC4
from Cryptodome.Util.strxor import strxor
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
SHARED_MAGIC = unhexlify("dec03713")
REQUEST_MAGIC = unhexlify("56505251")
RKFW_MAGIC = b"RKFW"
RKFW_BOOT_MAGIC = b"BOOT"

# secrets
# secret used to decrypt system update files (not app updates)
SYSTEM_SECRET = unhexlify("8704bc739081954c06411f6d8e531c37")
# used to encrypt console's DNA (serial #) for generating update requests
REQUEST_SECRET = unhexlify("9d7a196d7c461eb558ce9d2a29bc5d08")
# RockChip RC4 key
RKFW_KEY = unhexlify("7c4e0304550509072d2c7b38170d1711")

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

# enums
class RKFW_ChipID(IntEnum):
    RK3066 = 0x60
    RK3188 = 0x70

class RKFW_Type(IntEnum):
    UPDATE = 0
    RKAF = 1

# structures
class RKFW_Header(Structure):
    _pack_ = True
    _fields_ = [
        ("Magic", c_byte * 4),
        ("HdrLen", c_uint16),
        ("Version", c_uint32),
        ("Code", c_uint32),
        ("Year", c_uint16),
        ("Month", c_uint8),
        ("Day", c_uint8),
        ("Hour", c_uint8),
        ("Minute", c_uint8),
        ("Second", c_uint8),
        ("ChipID", c_uint32),
        ("LoadOff", c_uint32),
        ("LoadLen", c_uint32),
        ("DataOff", c_uint32),
        ("DataLen", c_uint32),
        ("Unk0", c_uint32),
        ("Type", c_uint32),
        ("SysFStype", c_uint32),
        ("BackupEnd", c_uint32),
        ("Reserved", c_ubyte * 45)
    ]

class StageRec(Structure):
    _pack_ = True
    _fields_ = [
        ("RecType", c_uint8),
        ("RecOff", c_uint32),
        ("RecLen", c_uint8),
    ]

class RKBoot_Header(Structure):
    _pack_ = True
    _fields_ = [
        ("Magic", c_byte * 4),
        ("HdrLen", c_uint16),
        ("Version", c_uint32),
        ("Code", c_uint32),
        ("Year", c_uint16),
        ("Month", c_uint8),
        ("Day", c_uint8),
        ("Hour", c_uint8),
        ("Minute", c_uint8),
        ("Second", c_uint8),
        ("ChipID", c_uint32),
        ("StageRecs", StageRec * 4),
        ("Reserved", c_ubyte * 53)
    ]

class RKBootFileRec(Structure):
    _pack_ = True
    _fields_ = [
        ("FileRecLen", c_uint8),
        ("FileNum", c_uint32),
        ("FileName", c_wchar * 20),
        ("FileOff", c_uint32),
        ("FileSize", c_uint32),
        ("Unk0", c_uint32)
    ]

class UpdFile(Structure):
    _pack_ = True
    _fields_ = [
        ("Name", c_byte * 32),
        ("FileName", c_byte * 60),
        ("NandSize", c_uint32),
        ("Offset", c_uint32),
        ("NandAddr", c_uint32),
        ("ImgFSize", c_uint32),
        ("OrigFSize", c_uint32),
    ]

class RKAF_Header(Structure):
    _pack_ = True
    _fields_ = [
        ("Magic", c_byte * 4),
        ("ImgLen", c_uint32),
        ("Model", c_byte * 34),
        ("ID", c_byte * 30),
        ("Manufacturer", c_byte * 56),
        ("Unk0", c_uint32),
        ("Version", c_uint32),
        ("FileCount", c_uint32),
        ("UpdFiles", UpdFile * 16),
        ("Reserved", c_ubyte * 116)
    ]

class PARM_File(Structure):
    _pack_ = True
    _fields_ = [
        ("Magic", c_byte * 4),
        ("FileLen", c_uint32)
        # File
        # CRC
    ]

class KRNL_File(Structure):
    _pack_ = True
    _fields_ = [
        ("Magic", c_byte * 4),
        ("FileLen", c_uint32)
        # File
        # CRC
    ]

# functions
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

class RKFW(object):
    stream = None
    package_build_datetime: datetime = None
    boot_build_datetime: datetime = None

    def __init__(self, filename: str) -> None:
        self.reset()
        assert isfile(filename), "Specified RKFW image file doesn't exist"
        self.stream = open(filename, "rb")
        self.stream = StreamIO(self.stream)
        self.read_header()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stream.close()

    def read_header(self) -> None:
        # read package header
        fw_hdr = self.stream.read_struct(RKFW_Header)

        # make sure it's a valid package
        assert bytes(fw_hdr.Magic) == RKFW_MAGIC, "Invalid RockChip firmware package magic"
        assert fw_hdr.ChipID == RKFW_ChipID.RK3066, "Invalid RockChip ID"
        self.package_build_datetime = datetime(fw_hdr.Year, fw_hdr.Month, fw_hdr.Day, fw_hdr.Hour, fw_hdr.Minute, fw_hdr.Second)

        self.read_boot()

        if RKFW_Type(fw_hdr.Type) == RKFW_Type.RKAF:
            self.read_rkaf()
        elif RKFW_Type(fw_hdr.Type) == RKFW_Type.UPDATE:
            pass
        else:
            raise Exception("Invalid RKFW type")

    def read_boot(self) -> None:
        boot_img_base = self.stream.tell()
        rk_boot_hdr = self.stream.read_struct(RKBoot_Header)
        assert bytes(rk_boot_hdr.Magic) == RKFW_BOOT_MAGIC, "Invalid RockChip boot magic"
        assert rk_boot_hdr.ChipID == RKFW_ChipID.RK3066, "Invalid RockChip ID"
        self.boot_build_datetime = datetime(rk_boot_hdr.Year, rk_boot_hdr.Month, rk_boot_hdr.Day, rk_boot_hdr.Hour, rk_boot_hdr.Minute, rk_boot_hdr.Second)

        total_size = sizeof(RKBoot_Header)
        for x in range(4):  # 4 files
            # read the file record
            file_rec = self.stream.read_struct(RKBootFileRec)
            # store the location of the last record
            temp = self.stream.tell()
            # seek to the file's data
            self.stream.seek(boot_img_base + file_rec.FileOff)
            # increment the total boot file size
            total_size += file_rec.FileSize + sizeof(RKBootFileRec)
            # read the encrypt file data
            file_data_enc = self.stream.read(file_rec.FileSize)
            # seek back to the end of the last record
            self.stream.seek(temp)
            # decrypt the file
            file_data_dec = ARC4.new(RKFW_KEY).decrypt(file_data_enc)
            # write the file to disk
            with open(join("test", file_rec.FileName), "wb") as f:
                f.write(file_data_dec)
        total_size += 4  # RKFW CRC

        # write the boot image to a file
        self.stream.seek(boot_img_base)
        self.stream.seek(total_size - 4, SEEK_CUR)
        rk_boot_crc = self.stream.read_uint32()
        self.stream.seek(boot_img_base)
        with open(join("test", "boot.bin"), "wb") as f:
            f.write(self.stream.read(total_size))

    def read_rkaf(self) -> None:
        rkaf_base = self.stream.tell()
        rkaf_hdr = self.stream.read_struct(RKAF_Header)
        for single in rkaf_hdr.UpdFiles:
            file_name = str(bytes(single.FileName).rstrip(b"\x00"), "utf8")
            if len(file_name) > 0:
                print(file_name)
                self.stream.seek(rkaf_base + single.Offset)
                file_data = self.stream.read(single.OrigFSize)
                if file_name == "parameter":
                    file_data = file_data[sizeof(PARM_File):-4]
                    parm_crc = unpack("<I", file_data[-4:])[0]
                if file_name not in ["RESERVED"]:
                    with open(join("test", file_name), "wb") as f:
                        f.write(file_data)

    def reset(self) -> None:
        self.stream = None
        self.package_build_datetime: datetime = None
        self.boot_build_datetime: datetime = None

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
        array = REQUEST_MAGIC + self.dna + (b"\x00" * 8) + b"\x07"
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

        assert array[:4] == REQUEST_MAGIC, "Invalid magic"

        verifier = PKCS1_v1_5.new(RSA_PRV_KEY)
        assert verifier.verify(SHA1.new(array), self.signature), "Invalid signature"

        self.dna = array[4:11] # the rest is pointless
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

        header_enc = self.stream.read(16)
        header_dec = cipher.decrypt(header_enc)

        with BytesIO(header_dec) as bio:
            with StreamIO(bio) as sio:
                magic = sio.read(4)
                version = sio.read_int()
                file_count = sio.read_int()
                sio.seek(4, SEEK_CUR)  # this is unused
                if magic != SHARED_MAGIC:
                    raise Exception("Invalid update magic")
                elif version > 1:
                    raise Exception("Invalid update version")
                else:
                    record_size = ((file_count * 256) + 16) + RSA_PUB_BYTES
                    self.stream.seek(16)
                    record_enc = self.stream.read(record_size)
                    # re-init
                    cipher = AES.new(SYSTEM_SECRET, AES.MODE_CBC, iv)
                    record_dec = cipher.decrypt(record_enc)
        with BytesIO(record_dec) as bio:
            with StreamIO(bio) as sio:
                magic = sio.read(4)
                if magic != SHARED_MAGIC:
                    raise Exception("Invalid update magic")
                signature = record_dec[-RSA_PUB_BYTES:]
                assert self.verifier.verify(SHA1.new(record_dec[:-RSA_PUB_BYTES]), signature), "Invalid signature"
                sio.seek(16)
                for x in range(file_count):
                    file = UpdateFile()
                    file.valid = False  # probably not going to check this ever
                    file.name = sio.read(80).split(b"\x00")[0].decode("utf8")  # max file name size is 80 bytes
                    file.offset = sio.read_int()
                    file.size_nopad = sio.read_int()
                    file.size_pad = sio.read_int()
                    file.unique = sio.read_int() & 1 != 0
                    key = bytearray(sio.read(16))
                    if file.unique and dna is not None:  # this is only used if it's a console-unique file
                        key = strxor(key, self.dna_hash)
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
        self.dna_hash = None
        self.h = None
        self.update_files = []
        self.verifier = None

    def list_files(self) -> None:
        #if DEBUG:
        print(">>> " + self.stream.name)
        for single in self.update_files:
            print("+ %s @ %s, %s (%s unpadded)" % (single.name, hex(single.offset), convert_size(single.size_pad), convert_size(single.size_nopad)))

    def extract_files(self, directory: str = OUTPUT_DIR) -> None:
        for single in self.update_files:
            self.stream.seek(single.offset)
            cipher = AES.new(single.key, AES.MODE_CBC, single.iv)
            hasher = SHA1.new()
            bz2 = BZ2Decompressor()
            read = 0
            with open(join(directory, single.name), "wb") as f:
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
                    f.write(dec_buff)
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
    # create argument parser
    parser = ArgumentParser(description="A script to make unpacking and packing Retron 5 updates easier (or actually possible)")
    parser.add_argument("-i", "--in-file", type=str, help="The update file you want to unpack")
    parser.add_argument("-o", "--out-dir", type=str, default=OUTPUT_DIR, help="The directory you want to extract the update to")
    parser.add_argument("-l", "--list", action="store_true", help="List files in the update package")
    parser.add_argument("-e", "--extract", action="store_true", help="Extract files from the update package")
    parser.add_argument("-d", "--debug", action="store_true", help="Print debug info")
    # parse args
    args = parser.parse_args()

    DEBUG = args.debug

    assert args.in_file is not None and isfile(args.in_file), "The specified input file doesn't exist"

    # create output directory
    if not isdir(args.out_dir):
        mkdir(args.out_dir)

    # create or read update request
    update_request = UpdateRequestFile()

    # parse and dump system update file
    """
    with open(args.in_file, "rb") as f:
        with SystemUpdateFile(f, update_request.dna) as su:
            if args.list:
                print("Listing files...")
                su.list_files()
            if args.extract:
                print("Extracting files...")
                su.extract_files()
    """
    with RKFW("output/update.img") as fw:
        pass