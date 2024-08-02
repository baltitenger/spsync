#!/usr/bin/env python3

import asyncio
import secrets
from sys import argv

from api import Api

async def main():
	device_id = secrets.token_hex(16)
	id = argv[1]
	password = argv[2]
	async with Api(device_id, '', '') as api:
		res = await api.login_pw(id, password)
		assert res.ok, res.error
		print(f'''[{id}]
DeviceId={device_id}
Username={res.ok.username}
StoredCred={res.ok.stored_credential}
''')

if __name__ == '__main__':
	asyncio.run(main())
