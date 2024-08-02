
from configparser import ConfigParser

VERSION='0.1'

KEYMASTER_CLIENT_ID='65b708073fc0480ea92a077233ca87bd' # desktop (linux?)
# KEYMASTER_CLIENT_ID='9a8d2f0ce77a4e248bb71fefcb557637' # android

B62_CHARS='0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
def b62_decode(b62: str) -> bytes:
	res = 0
	for dgt in b62:
		res *= 62
		res += B62_CHARS.index(dgt)
	return res.to_bytes(16, 'big')
def b62_encode(raw: bytes, width = 22) -> str:
	num = int.from_bytes(raw)
	chars = []
	while num > 0:
		num, rem = divmod(num, 62)
		chars.append(B62_CHARS[rem])
	return ''.join(reversed(chars)).zfill(width)

def read_cfg():
	cfg = ConfigParser()
	cfg.read('config.ini')
	return cfg

def default_cfg():
	cfg = read_cfg()
	return cfg[cfg.sections()[0]]
