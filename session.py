# DEPRECATED

from asyncio import Future, Protocol, create_task, get_event_loop
from enum import IntEnum
import hmac
import secrets
from typing import Callable

import rsa

from api import Api
from common import VERSION
from authentication_pb2 import (
	AUTHENTICATION_STORED_SPOTIFY_CREDENTIALS,
	CPU_UNKNOWN,
	ClientResponseEncrypted,
	LoginCredentials,
	OS_UNKNOWN,
	SystemInfo,
)
from keyexchange_pb2 import (
	APResponseMessage,
	BuildInfo,
	CRYPTO_SUITE_SHANNON,
	ClientHello,
	ClientResponsePlaintext,
	CryptoResponseUnion,
	LoginCryptoDiffieHellmanHello,
	LoginCryptoDiffieHellmanResponse,
	LoginCryptoHelloUnion,
	LoginCryptoResponseUnion,
	PLATFORM_LINUX_X86_64,
	PRODUCT_CLIENT,
	PRODUCT_FLAG_NONE,
	PoWResponseUnion,
)
from mercury_pb2 import Header
from shn import shn

KEYLEN=96
DH_P=0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a63a3620ffffffffffffffff
DH_G=2
SERVER_KEY=0xace0460bffc230aff46bfec3bfbf863da191c6cc336c93a14fb3b01612acac6af180e7f614d9429dbe2e346643e362d2327a1a0d923baedd1402b18155056104d52c96a44c1ecc024ad4b20c001f17edc22fc43521c8f0cbaed2add72b0f9db3c5321a2afe59f35a0dac68f1fa621efb2c8d0cb7392d9247e3d7351a6dbd24c2ae255b88ffab73298a0bcccd0c58673189e8bd3480784a5fc96b899d956bfc86d74f33a6781796c9c32d0d32a5abcd0527e2f710a39613c42f99c027bfed049c3c275804b6b219f9c12f02e94863eca1b642a09d4825f8b39dd0e86af9484da1c2ba863042ea9db3086c190e48b39d66eb0006a25aeea11b13873cd719e655bd
PUBLIC_EXP=65537
SIZELEN=4
NONCELEN=4
MACLEN=4

BUILD_INFO = BuildInfo(
	product=PRODUCT_CLIENT,
	product_flags=[PRODUCT_FLAG_NONE],
	platform=PLATFORM_LINUX_X86_64,
	version=118400716,
)

Handler = Callable[['ApBase', int, bytes], None]
handlers: dict[int, Handler] = {}

def p_handler(type: int):
	def f(func: Handler):
		handlers[type] = func
		return func
	return f

class PType(IntEnum):
	SecretBlock          = 0x02
	Ping                 = 0x04
	StreamChunk          = 0x08
	StreamChunkRes       = 0x09
	ChannelError         = 0x0a
	ChannelAbort         = 0x0b
	RequestKey           = 0x0c
	AesKey               = 0x0d
	AesKeyError          = 0x0e
	Image                = 0x19
	CountryCode          = 0x1b
	Pong                 = 0x49
	PongAck              = 0x4a
	Pause                = 0x4b
	ProductInfo          = 0x50
	LegacyWelcome        = 0x69
	LicenseVersion       = 0x76
	Login                = 0xab
	APWelcome            = 0xac
	AuthFailure          = 0xad
	MercuryReq           = 0xb2
	MercurySub           = 0xb3
	MercuryUnsub         = 0xb4
	MercuryEvent         = 0xb5
	TrackEndedTime       = 0x82
	UnknownData_AllZeros = 0x1f
	PreferredLocale      = 0x74
	Unknown_0x4f         = 0x4f
	Unknown_0x0f         = 0x0f
	Unknown_0x10         = 0x10

class ApBase(Protocol):
	def packet_received(self, type: int, msg: bytes):
		hdl = handlers.get(type)
		if hdl is None:
			print(f'Unhandled packt type: {type:x}')
		else:
			hdl(self, type, msg)

	def data_received(self, data: bytes):
		self.rxbuf.extend(data)
		if not self.connected:
			if self.waiter is None:
				raise Exception('fucked up')
			# receive apresp
			if len(self.rxbuf) < SIZELEN:
				return # need more data
			size = int.from_bytes(self.rxbuf[:SIZELEN])
			if len(self.rxbuf) == size:
				self.waiter.set_result(None)
			if len(self.rxbuf) > size:
				raise Exception('Got too much data for apresp')
			return # continue receiving
		while True:
			if self.hdr is None:
				if len(self.rxbuf) < 1 + 2:
					return # need more data
				# got a header
				self.shn_recv.nonce(self.recv_nonce.to_bytes(NONCELEN))
				self.recv_nonce += 1
				hdr = self.shn_recv.decrypt(bytes(self.rxbuf[:3]))
				del self.rxbuf[:3]
				self.hdr = (hdr[0], int.from_bytes(hdr[1:3]))
			type, size = self.hdr
			if len(self.rxbuf) < size + MACLEN:
				return # need more data
			msg = self.shn_recv.decrypt(bytes(self.rxbuf[:size]))
			mac = self.shn_recv.finish(MACLEN)
			if mac != self.rxbuf[size:size+MACLEN]:
				raise Exception("MACs don't match!")
			del self.rxbuf[:size+MACLEN]
			self.hdr = None
			self.packet_received(type, msg)

	def eof_received(self):
		create_task(self.connect())

	def derive_keys(self, acc: bytearray, key: bytes) -> bytes:
		data = bytearray()
		for i in range(1, 6):
			acc.append(i)
			data.extend(hmac.digest(key, acc, 'SHA1'))
			acc.pop()
		self.shn_send = shn(bytes(data[20:20+32]))
		self.send_nonce = 0
		self.shn_recv = shn(bytes(data[20+32:20+32+32]))
		self.recv_nonce = 0
		return hmac.digest(data[:20], acc, 'SHA1')

	def __init__(self, api: Api, ap = 'ap.spotify.com:4070'):
		self.api = api
		self.host, port = ap.split(':')
		self.port = int(port)
	async def __aexit__(self, exc_type, exc_val, exc_tb):
		self.sock.close()

	async def __aenter__(self):
		await self.connect()
		return self

	async def connect(self):
		loop = get_event_loop()

		self.mercury_seq = 1
		self.mercury_reqs: dict[int, Future] = {}

		self.audiokey_seq = 0
		self.audiokey_reqs: dict[int, Future[bytes]] = {}

		self.connected = False
		self.rxbuf = bytearray()
		self.sock, _ = await loop.create_connection(lambda: self, self.host, self.port)

		acc = bytearray()
		def store_seg(b: bytes):
			acc.extend(b)
			return b

		DH_X = secrets.randbits(8*KEYLEN)
		DH_GX = pow(DH_G, DH_X, DH_P)

		ch = ClientHello(
			build_info=BUILD_INFO,
			cryptosuites_supported=[CRYPTO_SUITE_SHANNON],
			login_crypto_hello=LoginCryptoHelloUnion(
				diffie_hellman=LoginCryptoDiffieHellmanHello(
					gc=DH_GX.to_bytes(KEYLEN),
					server_keys_known=1,
				),
			),
			client_nonce=secrets.token_bytes(16),
		).SerializeToString()
		size = 2 + SIZELEN + len(ch)
		self.sock.write(store_seg(SIZELEN.to_bytes(2)))
		self.sock.write(store_seg(size.to_bytes(SIZELEN)))
		self.sock.write(store_seg(ch))

		self.waiter = loop.create_future()
		await self.waiter
		self.waiter = None
		apresp = APResponseMessage.FromString(store_seg(self.rxbuf)[SIZELEN:])
		self.connected = True
		self.hdr = None
		self.rxbuf.clear()

		dh = apresp.challenge.login_crypto_challenge.diffie_hellman

		rsa.verify(dh.gs, dh.gs_signature, rsa.PublicKey(SERVER_KEY, PUBLIC_EXP))

		DH_GY = int.from_bytes(dh.gs)
		DH_K = pow(DH_GY, DH_X, DH_P)

		challenge = self.derive_keys(acc, DH_K.to_bytes(KEYLEN))

		crp = ClientResponsePlaintext(
			login_crypto_response=LoginCryptoResponseUnion(
				diffie_hellman=LoginCryptoDiffieHellmanResponse(
					hmac=challenge,
				),
			),
			pow_response=PoWResponseUnion(),
			crypto_response=CryptoResponseUnion(),
		).SerializeToString()
		size = SIZELEN + len(crp)
		self.sock.write(size.to_bytes(SIZELEN))
		self.sock.write(crp)

		self.send(PType.Login, ClientResponseEncrypted(
			login_credentials=LoginCredentials(
				username=self.api.login_info.stored_credential.username,
				typ=AUTHENTICATION_STORED_SPOTIFY_CREDENTIALS,
				auth_data=self.api.login_info.stored_credential.data,
			),
			system_info=SystemInfo(
				os=OS_UNKNOWN,
				cpu_family=CPU_UNKNOWN,
				system_information_string=VERSION,
				device_id=self.api.device_id,
			),
			version_string=VERSION,
		).SerializeToString())

	def send(self, type: PType, msg: bytes):
		hdr = type.to_bytes(1) + len(msg).to_bytes(2)
		self.shn_send.nonce(self.send_nonce.to_bytes(NONCELEN))
		self.send_nonce += 1
		self.sock.write(self.shn_send.encrypt(hdr))
		self.sock.write(self.shn_send.encrypt(msg))
		self.sock.write(self.shn_send.finish(MACLEN))

	def mercury_send(self, hdr: Header, parts: list[bytes] = []):
		seq = self.mercury_seq;
		self.mercury_seq += 1;
		msg = bytearray()
		msg.extend((4).to_bytes(2)) # seq len
		msg.extend(seq.to_bytes(4, 'little'))
		msg.extend((1).to_bytes(1)) # flags
		msg.extend((1+len(parts)).to_bytes(2)) # part count

		for part in (hdr.SerializeToString(), *parts):
			msg.extend(len(part).to_bytes(2))
			msg.extend(part)

		type = {'SUB': PType.MercurySub, 'UNSUB': PType.MercuryUnsub}.get(hdr.method, PType.MercuryReq)
		self.send(type, bytes(msg))
		fut = get_event_loop().create_future()
		self.mercury_reqs[seq] = fut
		return fut

	@p_handler(PType.APWelcome)
	def on_apwelcome(self, _, msg: bytes):
		print('got apwelcome')
		# print(APWelcome.FromString(msg))

	@p_handler(PType.Ping)
	def on_ping(self, _, msg: bytes):
		self.send(PType.Pong, msg)

	@p_handler(PType.CountryCode)
	def on_country_code(self, _, msg: bytes):
		print(f'Got country code {msg.decode()}');

	@p_handler(PType.LicenseVersion)
	def on_license_ver(self, _, msg: bytes):
		id = int.from_bytes(msg[:2])
		if id == 0:
			print('Got license version 0')
		else:
			size = msg[3]
			print(f'Got license version {id}: {msg[3:3+size].decode()}')

	@p_handler(PType.SecretBlock)
	@p_handler(PType.ProductInfo)
	@p_handler(PType.UnknownData_AllZeros)
	@p_handler(PType.PongAck)
	def ignore(self, _, msg: bytes):
		pass

	@p_handler(PType.LegacyWelcome)
	def on_legacy_welcome(self, _, msg: bytes):
		print('Got legacy welcome')

	@p_handler(PType.MercuryReq)
	@p_handler(PType.MercurySub)
	@p_handler(PType.MercuryUnsub)
	@p_handler(PType.MercuryEvent)
	def on_mercury(self, type: int, msg: bytes):
		pos = 0
		def rd(n):
			nonlocal pos
			res = msg[pos:pos+n]
			pos += n
			return res
		seqlen = int.from_bytes(rd(2))
		seq = int.from_bytes(rd(seqlen), 'little')
		flags = int.from_bytes(rd(1))
		num_parts = int.from_bytes(rd(2))
		if flags != 1:
			print('idk what this means exactly xd')
			return
		parts = []
		for i in range(num_parts):
			size = int.from_bytes(rd(2))
			parts.append(rd(size))
		hdr = Header.FromString(parts[0])
		fut = self.mercury_reqs.get(seq)
		if fut is not None:
			fut.set_result((hdr, parts[1:]))
		else:
			self.handle_mercury(seq, hdr, parts[1:])

	@p_handler(PType.AesKey)
	@p_handler(PType.AesKeyError)
	def on_key(self, type: int, msg: bytes):
		seq = int.from_bytes(msg[0:4])
		if type == PType.AesKeyError:
			err = int.from_bytes(msg[4:6])
			self.audiokey_reqs.pop(seq).set_exception(Exception(f'aes key error {err}'))
			return
		self.audiokey_reqs.pop(seq).set_result(msg[4:])

	async def key_req(self, gid: bytes, fileid: bytes):
		seq = self.audiokey_seq
		self.audiokey_seq += 1
		self.send(PType.RequestKey, fileid + gid + seq.to_bytes(4) + b'\0\0')
		fut: Future[bytes] = get_event_loop().create_future()
		self.audiokey_reqs[seq] = fut
		return await fut

	def handle_mercury(self, seq: int, hdr: Header, parts: list[bytes]): ...

