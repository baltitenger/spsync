from ctypes import CDLL
from os.path import dirname

__all__ = 'ppdecrypt', 'ppkey'

ppdecrypt_c = CDLL(f'{dirname(__file__)}/libppdecrypt.so')

ppkey = bytes.fromhex('01e132cae527bd21620e822f58514932')
def ppdecrypt(enc_key: bytes, file_id: bytes):
	buf = bytes(16)
	ppdecrypt_c.ppdecrypt(enc_key, file_id, buf)
	return buf
