"""ctypes binding for libesp, used by the test suite and the tools."""
import ctypes
import os
from ctypes import POINTER, c_char_p, c_int, c_size_t, c_uint8, c_uint32, c_uint64, c_void_p

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_lib = ctypes.CDLL(os.environ.get("ESP_LIB", os.path.join(ROOT, "build", "native", "libesp.so")))

AES_REF, AES_TABLE, AES_HW = 0, 1, 2
IMPL_NAMES = {0: "ref", 1: "table", 2: "hw"}

ESP_OK = 0
ESP_ERR = {
    -1: "PARAM", -2: "SPACE", -3: "SEQ_OVERFLOW", -4: "TRUNCATED", -5: "SPI",
    -6: "REPLAY", -7: "STALE", -8: "AUTH", -9: "PADDING",
}
REPLAY_OK, REPLAY_DUP, REPLAY_STALE = 0, 1, 2
ESP_OVERHEAD = 8 + 8 + 3 + 2 + 16


class EspStats(ctypes.Structure):
    _fields_ = [(n, c_uint64) for n in (
        "packets", "bytes", "err_auth", "err_replay", "err_stale", "err_padding", "err_other")]


def _sig(name, res, *args):
    fn = getattr(_lib, name)
    fn.restype = res
    fn.argtypes = list(args)
    return fn


_sig("aes_hw_available", c_int)
_sig("esp_sa_new", c_void_p, c_uint32, c_char_p, c_size_t, c_int, c_uint32, c_int, c_int)
_sig("esp_sa_free", None, c_void_p)
_sig("esp_sa_set_seq", None, c_void_p, c_uint64)
_sig("esp_sa_set_check_padding", None, c_void_p, c_int)
_sig("esp_sa_get_stats", None, c_void_p, POINTER(EspStats))
_sig("esp_sa_replay_last", c_uint64, c_void_p)
_sig("esp_encap", c_int, c_void_p, c_char_p, c_size_t, c_uint8, c_char_p, c_size_t)
_sig("esp_decap", c_int, c_void_p, c_char_p, c_size_t, c_char_p, c_size_t, POINTER(c_uint8))
_sig("esp_strerror", c_char_p, c_int)
_sig("gcm_new", c_void_p, c_char_p, c_size_t, c_int, c_int)
_sig("gcm_free", None, c_void_p)
_sig("gcm_seal", None, c_void_p, c_char_p, c_char_p, c_size_t, c_char_p, c_size_t, c_char_p, c_char_p)
_sig("gcm_open", c_int, c_void_p, c_char_p, c_char_p, c_size_t, c_char_p, c_size_t, c_char_p, c_size_t, c_char_p)
_sig("replay_new", c_void_p, c_uint32)
_sig("replay_free", None, c_void_p)
_sig("replay_check", c_int, c_void_p, c_uint64)
_sig("replay_update", None, c_void_p, c_uint64)
_sig("replay_infer_esn_hi", c_uint32, c_void_p, c_uint32)


def hw_available():
    return bool(_lib.aes_hw_available())


def impls():
    """Every implementation this CPU can run, for parametrising tests."""
    return [AES_REF, AES_TABLE] + ([AES_HW] if hw_available() else [])


class EspError(Exception):
    def __init__(self, code):
        self.code = code
        self.name = ESP_ERR.get(code, str(code))
        super().__init__(f"{self.name}: {_lib.esp_strerror(code).decode()}")


class SA:
    """One ESP security association (one direction)."""

    def __init__(self, spi, key, esn=False, window=64, aes=AES_TABLE, ghash=AES_TABLE):
        self._h = _lib.esp_sa_new(spi, key, len(key), int(esn), window, aes, ghash)
        if not self._h:
            raise ValueError("esp_sa_new rejected the configuration")

    def __del__(self):
        if getattr(self, "_h", None):
            _lib.esp_sa_free(self._h)
            self._h = None

    def encap(self, payload, next_hdr=4):
        out = ctypes.create_string_buffer(len(payload) + ESP_OVERHEAD)
        n = _lib.esp_encap(self._h, payload, len(payload), next_hdr, out, len(out))
        if n < 0:
            raise EspError(n)
        return out.raw[:n]

    def decap(self, pkt):
        """Returns (payload, next_hdr); raises EspError on any rejection."""
        out = ctypes.create_string_buffer(max(len(pkt), 1))
        nh = c_uint8()
        n = _lib.esp_decap(self._h, pkt, len(pkt), out, len(out), ctypes.byref(nh))
        if n < 0:
            raise EspError(n)
        return out.raw[:n], nh.value

    def set_seq(self, seq):
        _lib.esp_sa_set_seq(self._h, seq)

    def set_check_padding(self, on):
        _lib.esp_sa_set_check_padding(self._h, int(on))

    @property
    def stats(self):
        s = EspStats()
        _lib.esp_sa_get_stats(self._h, ctypes.byref(s))
        return {n: getattr(s, n) for n, _ in EspStats._fields_}

    @property
    def replay_last(self):
        return _lib.esp_sa_replay_last(self._h)


class GCM:
    def __init__(self, key, aes=AES_TABLE, ghash=AES_TABLE):
        self._h = _lib.gcm_new(key, len(key), aes, ghash)
        if not self._h:
            raise ValueError("bad key")

    def __del__(self):
        if getattr(self, "_h", None):
            _lib.gcm_free(self._h)
            self._h = None

    def seal(self, iv, aad, pt):
        ct = ctypes.create_string_buffer(max(len(pt), 1))
        tag = ctypes.create_string_buffer(16)
        _lib.gcm_seal(self._h, iv, aad, len(aad), pt, len(pt), ct, tag)
        return ct.raw[:len(pt)], tag.raw

    def open(self, iv, aad, ct, tag):
        """Returns the plaintext, or None if the tag does not verify."""
        pt = ctypes.create_string_buffer(max(len(ct), 1))
        rc = _lib.gcm_open(self._h, iv, aad, len(aad), ct, len(ct), tag, len(tag), pt)
        return pt.raw[:len(ct)] if rc == 0 else None


class ReplayWindow:
    def __init__(self, window):
        self._h = _lib.replay_new(window)
        if not self._h:
            raise ValueError("bad window size")

    def __del__(self):
        if getattr(self, "_h", None):
            _lib.replay_free(self._h)
            self._h = None

    def check(self, seq):
        return _lib.replay_check(self._h, seq)

    def update(self, seq):
        _lib.replay_update(self._h, seq)

    def infer_esn_hi(self, seq_lo):
        return _lib.replay_infer_esn_hi(self._h, seq_lo)
