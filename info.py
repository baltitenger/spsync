#!/usr/bin/env python3

from asyncio import run
import sys

from api import Api
from audio_files_extension_pb2 import AudioFilesExtensionResponse
from common import default_cfg
from extension_kind_pb2 import (
	ALBUM_V4,
	ARTIST_V4,
	AUDIO_FILES,
	EPISODE_V4,
	ExtensionKind,
	SHOW_V4,
	TRACK_V4,
)
from metadata_pb2 import Album, Artist, Episode, Show, Track

type_map: dict[str, tuple[ExtensionKind, type]] = {
	'artist':  (ARTIST_V4,   Artist),
	'album':   (ALBUM_V4,    Album),
	'track':   (TRACK_V4,    Track),
	'show':    (SHOW_V4,     Show),
	'episode': (EPISODE_V4,  Episode),
	'audio':   (AUDIO_FILES, AudioFilesExtensionResponse),
}

async def main():
	async with Api.from_cfg(default_cfg()) as api:
		uri = api.any2uri(sys.argv[1])
		type, id = api.unuri(uri)
		kind, t = type_map[type]
		res = await api.extd_metadata2([uri], kind, t)
		print(res[uri])

if __name__ == '__main__':
	run(main())
