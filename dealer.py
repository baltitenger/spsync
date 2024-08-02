from asyncio import create_task, ensure_future
from base64 import b64decode
import gzip
import json
from typing import Any

from aiohttp import WSMsgType

from api import Api

__all__ = ['DealerBase']

class DealerBase:
	def __init__(self, api: Api):
		self.api = api

	async def __aenter__(self):
		self.task = create_task(self.run())
		return self
	async def __aexit__(self, exc_type, exc_val, exc_tb):
		self.task.cancel()

	async def run(self):
		while True:
			async with self.api.client.ws_connect('wss://dealer.spotify.com',
					params={'access_token': await self.api.accesstoken()}, heartbeat=30) as self.conn:
				print('dealer connection established')
				async for msg in self.conn:
					if msg.type == WSMsgType.TEXT:
						ensure_future(self.handle(msg.json()))
					else:
						print('poop', msg)

	async def handle(self, msg):
		if not isinstance(msg, dict):
			print('unexpected type for msg:', msg)
		type: str = msg['type']
		headers: dict[str, str] = msg.get('headers', {})
		ctype = headers.get('Content-Type');
		tenc  = headers.get('Transfer-Encoding');
		if type == 'message':
			pl = msg.get('payloads', [''])[0]
			if msg.keys() - {'type', 'uri', 'method', 'headers', 'payloads'}:
				print('message contains unknown keys:', msg)
			if ctype == 'application/json':
				pass # pl: Any
			elif ctype == 'text/plain':
				pass # pl: str
			elif ctype is None or ctype == 'application/octet-stream':
				pl = b64decode(pl)
				if tenc == 'gzip':
					pl = gzip.decompress(pl)
				elif tenc is None:
					pass
				else:
					print('unexpected Transfer-Encoding', msg)
			else:
				print('unexpected Content-Type', msg)
			await self.on_message(msg['uri'], msg.get('method'), headers, pl)
		elif type == 'request':
			if msg.keys() - {'type', 'message_ident', 'headers', 'key', 'payload'}:
				print('request contains unknown keys:', msg)
			pl = msg['payload']
			if tenc == 'gzip':
				pl = json.loads(gzip.decompress(b64decode(pl['compressed'])))
			elif tenc is None:
				pass
			else:
				print('unexpected Transfer-Encoding', msg)
			succ = await self.on_request(msg['message_ident'], headers, pl)
			await self.conn.send_json(
				{'type': 'reply', 'key': msg['key'], 'payload': {'success': succ }})
		else:
			print('unknown message type:', msg)

	async def on_message(self, uri: str, method: str | None, headers: dict[str, str], payload: str | bytes | Any): ...
	async def on_request(self, uri: str, headers: dict[str, str], payload: Any) -> bool: ...

