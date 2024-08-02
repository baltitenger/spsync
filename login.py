#!/usr/bin/env python3

from base64 import urlsafe_b64encode
from hashlib import sha256
import secrets
import subprocess
from time import time
from urllib.parse import urlencode
from uuid import uuid4

from aiohttp import ClientSession, FormData, web

port = 4381
path = '/login'
redirect_uri = f'http://127.0.0.1:{port}{path}'
client_id = '65b708073fc0480ea92a077233ca87bd'
flow_ctx = f'{uuid4()}:{int(time())}'
verif = secrets.token_urlsafe(32)
chall = urlsafe_b64encode(sha256(verif.encode()).digest()).rstrip(b'=').decode('ascii')

url = 'https://accounts.spotify.com/login?' + urlencode({
	'continue':       'https://accounts.spotify.com/oauth2/v2/auth?' + urlencode({
		'client_id':             client_id,
		'response_type':         'code',
		'redirect_uri':          redirect_uri,
		'scope':                 'app-remote-control,playlist-modify,playlist-modify-private,playlist-modify-public,playlist-read,playlist-read-collaborative,playlist-read-private,streaming,ugc-image-upload,user-follow-modify,user-follow-read,user-library-modify,user-library-read,user-modify,user-modify-playback-state,user-modify-private,user-personalized,user-read-birthdate,user-read-currently-playing,user-read-email,user-read-play-history,user-read-playback-position,user-read-playback-state,user-read-private,user-read-recently-played,user-top-read',
		'code_challenge':        chall,
		'code_challenge_method': 'S256',
	}),
	'method':         'login-accounts',
	'creation_flow':  'desktop',
	'creation_point': f'https://login.app.spotify.com/?client_id={client_id}&utm_source=spotify&utm_medium=desktop-linux&utm_campaign=organic',
	'flow_ctx':       flow_ctx,
	'utm_source':     'spotify',
	'utm_medium':     'desktop-linux',
	'utm_campaign':   'organic',
})

async def startup(app: web.Application):
	subprocess.run(['xdg-open', url])

async def login(req: web.Request):
	err = req.query.get('error')
	if err is not None:
		print('got error:', err)
		return web.HTTPFound('https://open.spotify.com/desktop/auth/error')
	code = req.query['code']
	async with ClientSession() as c:
		async with c.post('https://accounts.spotify.com/api/token', data=FormData({
					'client_id':     client_id,
					'grant_type':    'authorization_code',
					'redirect_uri':  redirect_uri,
					'code_verifier': verif,
					'code':          code,
				})) as resp:
			# json = await resp.json()
			# dunno what to do with this, different kind of token
			print(await resp.text())
	return web.HTTPFound('https://open.spotify.com/desktop/auth/success')

def main():
	app = web.Application()
	app.add_routes([web.get('/login', login)])
	app.on_startup.append(startup)
	web.run_app(app, port=port)

if __name__ == '__main__':
	main()
