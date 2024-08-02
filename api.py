from collections.abc import Iterable
from configparser import SectionProxy
import gzip
from hashlib import sha1
from io import BufferedWriter
import itertools
import json
from math import ceil
from os import uname
import re
import secrets
from time import time, time_ns
from typing import Any, Literal, TYPE_CHECKING

from Crypto.Cipher import AES
from aiohttp import ClientSession
from google.protobuf import json_format
from google.protobuf.message import Message

from autoplay_context_request_pb2 import AutoplayContextRequest
from client_token_pb2 import (
	ClientDataRequest,
	ClientTokenRequest,
	ClientTokenResponse,
	REQUEST_CLIENT_DATA_REQUEST,
)
from collection2v2_pb2 import (
	CollectionItem,
	DeltaRequest,
	DeltaResponse,
	PageRequest,
	PageResponse,
	WriteRequest,
)
from color_lyrics_pb2 import ColorLyrics
from common import KEYMASTER_CLIENT_ID, VERSION, b62_decode, b62_encode
from connect_pb2 import Cluster, PutStateRequest, SetVolumeCommand
from connectivity_pb2 import ConnectivitySdkData, NativePosixData, PlatformSpecificData
from context_pb2 import Context
from duration_pb2 import Duration
from extended_metadata_pb2 import (
	BatchedEntityRequest,
	BatchedExtensionResponse,
	EntityRequest,
	ExtensionQuery,
)
from extension_kind_pb2 import ExtensionKind
from login5_pb2 import (
	HashcashSolution,
	LoginRequest,
	LoginResponse,
	Password,
	StoredCredential,
)
from metadata_pb2 import Track
from playlist4_external_pb2 import (
	Item,
	ItemAttributes,
	ListChanges,
	SelectedListContent,
)
from playplay_pb2 import (
	AUDIO_TRACK,
	DOWNLOAD,
	PlayPlayLicenseRequest,
	PlayPlayLicenseResponse,
)
from ppdecrypt import ppdecrypt, ppkey
from storage_resolve_pb2 import StorageResolveResponse

if TYPE_CHECKING:
	from _typeshed import FileDescriptorOrPath

SetType = Literal['ban', 'artistban', 'collection', 'listenlater', 'show', 'artist', 'ylpin', 'enhanced']
PlDecor = Literal['revision', 'attributes', 'length', 'owner', 'capabilities']
SearchType = Literal['Desktop', 'Tracks', 'Albums', 'Artists', 'Playlists',  'FullEpisodes']
SearchVar = Literal['searchTerm', 'offset', 'limit', 'numberOfTopResults', 'includeAudiobooks']

def good_enough(digest: bytes, length: int):
	pos = -1
	while length > 8 and digest[pos] == 0:
		length -= 8
		pos -= 1
	if length <= 0: return True
	last = digest[pos]
	tz = (last & -last).bit_length() - 1
	return tz >= length

def solve_hc(prefix: bytes, length: int, seed: bytes):
	suffix = int.from_bytes(seed, 'big') << 8*8
	while True:
		md = sha1()
		md.update(prefix)
		md.update(suffix.to_bytes(16, 'big'))
		digest = md.digest()
		if good_enough(digest, length):
			return suffix.to_bytes(16, 'big')
		suffix += 1 + (1 << 8*8)

COLLTYPE = 'application/vnd.collection-v2.spotify.proto'
AUDIO_NONCE = bytes.fromhex('72e067fbddcbcf77')
AUDIO_IV    = bytes.fromhex('ebe8bc643f630d93')

anypat = re.compile('.*open.spotify.com/([a-z]*)/([0-9A-Za-z]{22}).*')

class Api:
	def __init__(self, device_id: str, username: str, stored_cred: str):
		self.client = ClientSession(
			trust_env=True,
			headers={
				'user-agent': f'Spotify-Sync {VERSION}',
			}
		)
		self.device_id = device_id
		self.username = username
		self.stored_cred = stored_cred.encode()
		self.access_token = ''
		self.access_token_expires = 0
		self.client_token = ''
		self.client_token_expires = 0

	@classmethod
	def from_cfg(cls, cfg: SectionProxy):
		return cls(cfg['DeviceId'], cfg['Username'], cfg['StoredCred'])

	async def __aenter__(self):
		await self.client.__aenter__()
		async with self.client.get('https://apresolve.spotify.com/?type=spclient') as resp:
			res = await resp.json()
		self.baseuri = res['spclient'][0]
		return self
	async def __aexit__(self, exc_type, exc_val, exc_tb):
		await self.client.__aexit__(exc_type, exc_val, exc_tb)

	async def login5(self, req: LoginRequest):
		req.client_info.client_id = KEYMASTER_CLIENT_ID
		req.client_info.device_id = self.device_id
		async with self.client.post('https://login5.spotify.com/v3/login',
				data=req.SerializeToString(),
				headers={
					# 'client-token': await self.clienttoken(),
					'content-type': 'application/x-protobuf',
				}) as resp:
			assert resp.ok, (resp.status, await resp.text())
			resp = LoginResponse.FromString(await resp.read())
		return resp

	async def login5_solve(self, req: LoginRequest):
		resp = await self.login5(req)
		if not resp.challenges:
			return resp
		assert len(resp.challenges.challenges) == 1, 'expected one challenge'
		assert resp.challenges.challenges[0].hashcash, 'expected hashcash challenge'

		seed = sha1(resp.login_context).digest()[-8:]
		hc = resp.challenges.challenges[0].hashcash
		start = time_ns()
		solved = solve_hc(hc.prefix, hc.length, seed)
		dur = time_ns() - start

		req.login_context = resp.login_context
		req.challenge_solutions.solutions.add(hashcash=HashcashSolution(
			suffix=solved,
			duration=Duration(seconds=dur // 1_000_000_000, nanos=dur % 1_000_000_000)
		))
		return await self.login5(req)

	async def login_pw(self, id: str, password: str):
		totlen = len(id) + len(password)
		padlen = ceil(totlen / 64) * 64 - totlen
		req = LoginRequest(password=Password(
			id=id,
			password=password,
			padding=bytes((padlen,))*padlen,
		))
		return await self.login5_solve(req)

	async def accesstoken(self):
		if time() < self.access_token_expires:
			return self.access_token
		resp = await self.login5(LoginRequest(stored_credential=StoredCredential(
			username=self.username,
			data=self.stored_cred,
		)))
		assert resp.ok, resp.error
		self.stored_cred = resp.ok.stored_credential
		self.access_token = resp.ok.access_token
		self.access_token_expires = time() + resp.ok.access_token_expires_in
		print('refreshed access token')
		return self.access_token

	async def clienttoken(self):
		if time() < self.client_token_expires:
			return self.client_token
		un = uname()
		req = ClientTokenRequest(
			request_type=REQUEST_CLIENT_DATA_REQUEST,
			client_data=ClientDataRequest(
				client_version='kagi 0.1',
				client_id=KEYMASTER_CLIENT_ID,
				connectivity_sdk_data=ConnectivitySdkData(
					platform_specific_data=PlatformSpecificData(
						posix=NativePosixData(
							machine=un.machine,
							release=un.release,
							sysname=un.sysname,
							version=un.version,
						),
					),
					device_id=self.device_id,
				),
			),
		)
		async with self.client.post('https://clienttoken.spotify.com/v1/clienttoken',
				data=req.SerializeToString(), headers={'Accept': 'application/x-protobuf'}) as resp:
			assert resp.ok, (resp.status, await resp.text())
			resp = ClientTokenResponse.FromString(await resp.read())
		self.client_token = resp.granted_token.token
		self.client_token_expires = time() + resp.granted_token.refresh_after_seconds
		print('refreshed client token')
		return self.client_token

	async def base_req(self, meth: str, url: str, *, headers = {}, **kwargs):
		hdrs = {
			'authorization': f'Bearer {await self.accesstoken()}',
      'client-token': await self.clienttoken(),
			'accept-encoding': 'gzip, deflate',
		}
		hdrs.update(headers)
		async with self.client.request(meth, url, headers=hdrs, **kwargs) as resp:
			assert resp.ok, (resp.status, await resp.text())
			return await resp.read()

	async def req(self, meth: str, url: str, *, headers = {}, **kwargs):
		return await self.base_req(meth, 'https://'+self.baseuri+url, headers=headers, **kwargs)
	
	async def coll_get(self, set: SetType):
		req = PageRequest(
			username=self.username,
			set=set,
			limit=300,
		)
		pages: list[PageResponse] = []
		while True:
			page = PageResponse.FromString(await self.req(
				'POST', '/collection/v2/paging', data=req.SerializeToString(), headers={
					'content-type': COLLTYPE,
					'accept': COLLTYPE,
				}))
			pages.append(page)
			if not page.next_page_token:
				return pages
			req.pagination_token = page.next_page_token

	async def coll_get_liked_tracks(self):
		coll = await self.coll_get('collection')
		return [ it for page in coll for it in page.items if it.uri.startswith('spotify:track:') ]

	async def coll_delta(self, set: SetType, sync_token: str):
		req = DeltaRequest(
			username=self.username,
			set=set,
			last_sync_token=sync_token,
		)
		return DeltaResponse.FromString(await self.req(
			'POST', '/collection/v2/delta', data=req.SerializeToString(), headers={
				'content-type': COLLTYPE,
				'accept': COLLTYPE,
			}))
	
	async def coll_write(self, set: SetType, items: list[CollectionItem]):
		for chunk in itertools.batched(items, 255):
			req = WriteRequest(
				username=self.username,
				set=set,
				items=chunk,
				client_update_id=secrets.token_hex(8),
			)
			try:
				await self.req('POST', '/collection/v2/write', data=req.SerializeToString(), headers={
					'content-type': COLLTYPE,
					'accept': COLLTYPE,
				})
			except:
				print(chunk)

	@staticmethod
	def _uri(type: str, id: str | bytes):
		if isinstance(id, bytes):
			id = b62_encode(id)
		return f'spotify:{type}:{id}'
	@staticmethod
	def pl_uri(id: str | bytes): return Api._uri('playlist', id)
	@staticmethod
	def track_uri(id: str | bytes): return Api._uri('track', id)
	@staticmethod
	def album_uri(id: str | bytes): return Api._uri('album', id)
	@staticmethod
	def unuri(uri: str):
		sp, type, id = uri.split(':')
		assert sp == 'spotify'
		return (type, b62_decode(id))
	@staticmethod
	def getgid(uri: str, type: str): return b62_decode(uri.removeprefix(f'spotify:{type}:'))
	def rootlist_uri(self): return f'spotify:user:{self.username}:rootlist'

	@staticmethod
	def any2uri(s: str):
		if s.startswith('spotify:'):
			return s
		m = anypat.search(s)
		if m is None:
			raise ValueError
		return f'spotify:{m[1]}:{m[2]}'


	@staticmethod
	def it2coll(it: Item):
		return CollectionItem(uri=it.uri, added_at=it.attributes.timestamp//1000)

	@staticmethod
	def coll2it(it: CollectionItem):
		return Item(uri=it.uri, attributes=ItemAttributes(timestamp=it.added_at*1000))


	async def pl_get(self, uri: str, *, decorate: list[PlDecor] | None = None, start: int | None = None, length: int | None = None):
		url = uri.removeprefix('spotify:').replace(':', '/')
		params = {}
		if decorate is not None:
			params['decorate'] = ','.join(decorate)
		if start is not None:
			params['from'] = start
		if length is not None:
			params['length'] = length
		return SelectedListContent.FromString(await self.req(
			'GET', f'/playlist/v2/{url}', params=params))

	def fmt_revision(self, rev: bytes):
		return f'{int.from_bytes(rev[:4])},{rev[4:].hex()}'

	async def pl_diff(self, uri: str, rev: bytes):
		url = uri.removeprefix('spotify:').replace(':', '/')
		return SelectedListContent.FromString(await self.req(
			'GET', f'/playlist/v2/{url}/diff?revision={self.fmt_revision(rev)}'))
	
	async def pl_change(self, uri: str, changes: ListChanges):
		url = uri.removeprefix('spotify:').replace(':', '/')
		return SelectedListContent.FromString(await self.req(
			'POST', f'/playlist/v2/{url}/changes', data=changes.SerializeToString()))

	async def put_conn_state(self, conn_id: str, state: PutStateRequest):
		return Cluster.FromString(await self.req(
			'PUT', f'/connect-state/v1/devices/{self.device_id}', data=state.SerializeToString(), headers={
				'Content-Type': 'application/protobuf',
				'X-Spotify-Connection-Id': conn_id,
		}))

	async def send_command(self, dst: str, command: Any):
		return json.loads(await self.req(
			'POST', f'/connect-state/v1/player/command/from/{self.device_id}/to/{dst}',
			headers={'x-transfer-encoding': 'gzip'},
			data=gzip.compress(json.dumps({'command': command}).encode())))

	async def send_volume(self, dst: str, vol: SetVolumeCommand):
		return json.loads(await self.req(
			'PUT', f'/connect-state/v1/connect/volume/from/{self.device_id}/to/{dst}',
			data=vol.SerializeToString()))

	async def transfer(self, dst: str, target_alias_id: int | None = None):
		return json.loads(await self.req('POST', f'/connect-state/v1/connect/transfer/from/{self.device_id}/to/{dst}',
			data=json.dumps({'target_alias_id': target_alias_id}).encode()))

	async def extd_metadata(self, req: BatchedEntityRequest):
		return BatchedExtensionResponse.FromString(await self.req(
			'POST', '/extended-metadata/v0/extended-metadata', data=req.SerializeToString()))

	async def extd_metadata2[T: Message](self, uris: Iterable[str], kind: ExtensionKind, type: type[T]) -> dict[str, T]:
		resp = await self.extd_metadata(BatchedEntityRequest(
			entity_request=(
				EntityRequest(
					entity_uri=thing,
					query=[ExtensionQuery(extension_kind=kind)],
				) for thing in uris
			),
		))
		return { ext.entity_uri: type.FromString(ext.extension_data.value) for ext in resp.extended_metadata[0].extension_data }

	async def get_meta[T: Message](self, uri: str, kind: ExtensionKind, type: type[T]) -> T:
		res = await self.extd_metadata2((uri,), kind, type)
		return res[uri]

	# async def meta_get_track(self, track: bytes):
	# 	return Track.FromString(await self.req(
	# 		'GET', f'/metadata/4/track/{track.hex()}'))

	# known reasons: interactive, interactive_prefetch, offline
	async def storage_get(self, fileid: bytes, reason = 'offline'):
		return StorageResolveResponse.FromString(await self.req(
			'GET', f'/storage-resolve/v2/files/audio/{reason}/1/{fileid.hex()}'))
	
	async def lyrics_get(self, track: bytes):
		return ColorLyrics.FromString(await self.req(
			'GET', f'/color-lyrics/v2/track/{b62_encode(track)}', headers={
				'app-platform': 'Linux',
			}))

	async def playplay(self, fileid: bytes, req: PlayPlayLicenseRequest):
		return PlayPlayLicenseResponse.FromString(await self.req(
			'POST', f'/playplay/v1/key/{fileid.hex()}', data=req.SerializeToString()))

	async def pathfinderSearch(self, type: SearchType, variables: dict[SearchVar, Any], hash: bytes):
		return json.loads(await self.base_req('GET', 'https://api-partner.spotify.com/pathfinder/v1/query', params={
			'operationName': f'search{type}',
			'variables': json.dumps(variables),
			'extensions': json.dumps({'persistedQuery':{'version':1,'sha256Hash':hash.hex()}}),
			}))

	async def context_resolve(self, ctx_url: str):
		return json_format.Parse(await self.req(
			'GET', f'/context-resolve/v1/{ctx_url.removeprefix("context://")}'), Context())

	async def context_resolve_autoplay(self, req: AutoplayContextRequest):
		return json_format.Parse(await self.req(
			'POST', '/context-resolve/v1/autoplay', body=req), Context())

	async def dl_audio_track(self, file_id: bytes, dest: 'BufferedWriter | FileDescriptorOrPath'):
		pp = await self.playplay(file_id, PlayPlayLicenseRequest(version=2, token=ppkey, interactivity=DOWNLOAD, content_type=AUDIO_TRACK))
		key = ppdecrypt(pp.obfuscated_key, file_id)

		storage = await self.storage_get(file_id)
		# for url in storage.cdnurl:
		url = storage.cdnurl[0]

		skip = 167
		async with self.client.get(url) as resp:
			assert resp.ok, resp
			cipher = AES.new(key, AES.MODE_CTR, nonce=AUDIO_NONCE, initial_value=AUDIO_IV)
			if not isinstance(dest, BufferedWriter):
				dest = open(dest, 'wb')
			with dest:
				async for chunk in resp.content.iter_any():
					chunk = cipher.decrypt(chunk)
					dest.write(chunk[skip:])
					skip -= min(skip, len(chunk))

	async def recently_played(self, limit = 50):
		filter = ['default', 'track', 'collection-new-episodes']
		# TODO makeshift proto:
		# 1: repeated {
		#   1: context uri
		#   2: timestamp ms
		#   3: uri
		# }
		# 3: limit / count returned
		# -> sorted most recent first
		return await self.req('GET', f'/recently-played/v3/user/{self.username}/recently-played', params={
				'limit': limit,
				'filter': filter,
			})
