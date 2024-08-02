from ctypes import CDLL, Structure, byref, c_int, c_uint32
from os.path import dirname

__all__ = 'shn',

shn_c = CDLL(f'{dirname(__file__)}/libshn.so')

SHN_WORDS = 16
WORD = c_uint32
class shn_ctx(Structure):
	_fields_ = [
		('R',     WORD * SHN_WORDS),
		('CRC',   WORD * SHN_WORDS),
		('initR', WORD * SHN_WORDS),
		('konst', WORD),
		('sbuf',  WORD),
		('mbuf',  WORD),
		('nbuf',  c_int),
	]

class shn:
	__slots__ = '_ctx'

	def __init__(self, key: bytes):
		self._ctx = shn_ctx()
		shn_c.shn_key(byref(self._ctx), key, len(key))

	def nonce(self, nonce: bytes):
		shn_c.shn_nonce(byref(self._ctx), nonce, len(nonce))
	def stream(self, buf: bytes):
		shn_c.shn_stream(byref(self._ctx), buf, len(buf))
		return buf
	def maconly(self, buf: bytes):
		shn_c.shn_stream(byref(self._ctx), buf, len(buf))
	def encrypt(self, buf: bytes):
		shn_c.shn_encrypt(byref(self._ctx), buf, len(buf))
		return buf
	def decrypt(self, buf: bytes):
		shn_c.shn_decrypt(byref(self._ctx), buf, len(buf))
		return buf
	def finish(self, len: int):
		buf = bytes(len)
		shn_c.shn_finish(byref(self._ctx), buf, len)
		return buf
