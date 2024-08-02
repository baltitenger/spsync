#!/usr/bin/env python3

from asyncio import run
import sys

from api import Api
from common import default_cfg
from extension_kind_pb2 import EPISODE_V4, TRACK_V4
from metadata_pb2 import AudioFile, Episode, Track

async def main():
	async with Api.from_cfg(default_cfg()) as api:
		uri = api.any2uri(sys.argv[1])
		type, id = api.unuri(uri)
		if type == 'track':
			trck = await api.get_meta(uri, TRACK_V4, Track)
			files = trck.file or trck.alternative[0].file
		elif type == 'episode':
			ep = await api.get_meta(uri, EPISODE_V4, Episode)
			files = ep.audio
		else:
			raise ValueError
		file = [f for f in files if f.format == AudioFile.OGG_VORBIS_320][0]
		await api.dl_audio_track(file.file_id, sys.argv[2])

if __name__ == '__main__':
	run(main())
