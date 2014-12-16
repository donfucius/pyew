"""
:[diStorm64 1.7.29}:
Copyright RageStorm (C) 2007, Gil Dabah

diStorm is licensed under the BSD license.
http://ragestorm.net/distorm/
---
Python binding for diStorm64 written by Victor Stinner
"""

import platform
from ctypes import cdll, c_long, c_ulong, c_int, c_uint, c_char, c_char_p, POINTER, c_byte, Structure, addressof, byref, c_void_p, create_string_buffer, sizeof, cast

# Define (u)int32_t and (u)int64_t types
int32_t = c_int
uint32_t = c_uint
if sizeof(c_ulong) == 8:
    int64_t = c_long
    uint64_t = c_ulong
else:
    from ctypes import c_longlong, c_ulonglong
    assert sizeof(c_longlong) == 8
    assert sizeof(c_ulonglong) == 8
    int64_t = c_longlong
    uint64_t = c_ulonglong

SUPPORT_64BIT_OFFSET = True
if SUPPORT_64BIT_OFFSET:
    _OffsetType = uint64_t
else:
    _OffsetType = uint32_t

import distorm3

Decode16Bits = 0
Decode32Bits = 1
Decode64Bits = 2
DECODERS = (Decode16Bits, Decode32Bits, Decode64Bits)

osVer = platform.system()

if osVer == "Windows":
    if SUPPORT_64BIT_OFFSET:
        #decode_func = distorm.distorm_decode64
        dt = Decode64Bits
    else:
        #decode_func = distorm.distorm_decode32
        dt = Decode32Bits
#else:
#    decode_func = distorm.internal_decode

DECRES_NONE = 0
DECRES_SUCCESS = 1
DECRES_MEMORYERR = 2
DECRES_INPUTERR = 3

MAX_INSTRUCTIONS = 100
MAX_TEXT_SIZE = 60

class _WString(Structure):
    _fields_ = (
        ("pos", c_uint), # Unused.
        ("p", c_char * MAX_TEXT_SIZE),
    )
    def __str__(self):
        return self.p

class _DecodedInst(Structure):
    _fields_ = (
        ("mnemonic", _WString),
        ("operands", _WString),
        ("instructionHex", _WString),
        ("size", c_uint),
        ("offset", _OffsetType),
    )
    def __str__(self):
        return "%s %s" % (self.mnemonic, self.operands)

#decode_func.argtypes = (_OffsetType, c_void_p, c_int, c_int, c_void_p, c_uint, POINTER(c_uint))

def Decode(codeOffset, code, dt=Decode32Bits):
    return list(distorm3.DecodeGenerator(codeOffset, code, dt))
    