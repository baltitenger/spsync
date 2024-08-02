#!/usr/bin/env python3

from asyncio import run, sleep
from base64 import b64encode
import os
import re
from subprocess import call
from traceback import print_exc

from mutagen.flac import Picture
from mutagen.oggvorbis import OggVorbis, OggVorbisHeaderError

from api import Api
from common import b62_decode
from creds import DEVICE_ID, LOGIN_DATA
from extended_metadata_pb2 import BatchedEntityRequest, EntityRequest, ExtensionQuery
from extension_kind_pb2 import TRACK_V4
from mercury_pb2 import Header
from metadata_pb2 import Album, Track
import mylists
from session import ApBase

class ApClient(ApBase):
	def handle_mercury(self, seq: int, hdr: Header, parts: list[bytes]):
		pass

path_norm = str.maketrans({
	'/': '_',
  '\\': '_',
	':': '_',
	'"': "'",
	'?': "_",
	'*': "_",
})

async def dl_playlist(api: Api, ap: ApClient, pl_uri: str):
	pl = await api.pl_get(pl_uri)
	outdir = 'dl/'+pl.attributes.name.translate(path_norm)

	uris = [ it.uri for it in pl.contents.items ]
	meta = await api.extd_metadata(BatchedEntityRequest(
		entity_request=[EntityRequest(
			entity_uri=uri,
			query=[ExtensionQuery(extension_kind=TRACK_V4)],
		) for uri in uris]
	))
	tracks = [
		Track.FromString(ext.extension_data.value)
		for ext in meta.extended_metadata[0].extension_data
	]

	covers: dict[bytes, str] = {}
	async def get_cover(album: Album):
		stored = covers.get(album.gid)
		if stored is not None:
			return stored
		img = max(album.cover_group.image, key=lambda i: i.size)
		async with api.client.get(f'https://i.scdn.co/image/{img.file_id.hex()}') as resp:
			data = await resp.read()
		pic = Picture()
		pic.data = data
		pic.type = 3 # PictureType.COVER_FRONT
		pic.mime = 'image/jpeg'
		pic.width = img.width
		pic.height = img.height
		res = b64encode(pic.write()).decode()
		covers[album.gid] = res
		return res

	iv = bytes.fromhex('72e067fbddcbcf77ebe8bc643f630d93')
	paths = {}
	for track in tracks:
		try:
			file = (track.file or track.alternative[0].file)[0]
		except IndexError:
			print(f'Track unavailable: {track.name}')
			continue
		fname = f'{track.artist[0].name} - {track.name}.ogg'.translate(path_norm)
		path = f'{outdir}/{fname}'
		paths[track.gid] = path
		try:
			if not os.path.isfile(path):
				await api.dl_audio_track(file.file_id, path)
				# await sleep(2.5)
				# storage = await api.storage_get(file.file_id)
				# key = await ap.key_req(track.gid, file.file_id)
				# for url in storage.cdnurl:
				# 	if 0 == call(['sh', '-o', 'pipefail', '-c',
				# 			'printf "%28s%s\r" "" "$4"; COLUMNS=27 curl -k -f# "$1" | openssl aes-128-ctr -nopad -iv $2 -K $3 | tail -c +168 >"$4"',
				# 			'sh', url, iv.hex(), key.hex(), path]):
				# 		break
				# else:
				# 	raise Exception('No urls worked')

				ov = OggVorbis(path)
				ov['title'] = track.name
				ov['album'] = track.album.name
				ov['tracknumber'] = str(track.number)
				ov['discnumber'] = str(track.disc_number)
				ov['artist'] = [ artist.name for artist in track.artist ]
				ov['albumartist'] = [ artist.name for artist in track.album.artist ]
				ov['copyright'] = [ cr.text for cr in track.album.copyright ]
				ov['organization'] = track.album.label
				ov['genre'] = list(track.album.genre)
				d = track.album.date
				if d.year:
					date = f'{d.year}'
					if d.month:
						date += f'-{d.month:02}'
						if d.day:
							date += f'-{d.day:02}'
					ov['date'] = date
				ov['metadata_block_picture'] = await get_cover(track.album)
				try:
					ov.save()
				except OggVorbisHeaderError as e:
					# ugly ass hack
					msg = e.args[0].args[0]
					m = re.fullmatch("unable to read full header; got b'(\\\\x00)+'", msg)
					if m:
						l = len(m.group(1))//4
						os.truncate(path, os.stat(path).st_size - l)
						print(f'removed zero padding from {path}')
					else:
						raise
			
			continue
			lrcfile = path.removesuffix('.ogg')+'.lrc8'
			if track.has_lyrics and not os.path.isfile(lrcfile):
				try:
					lyrics = await api.lyrics_get(track.gid)
				except AssertionError:
					pass
				else:
					with open(lrcfile, 'w') as f:
						for line in lyrics.lyrics.lines:
							f.write(f'[{line.startTimeMs//(1000*60):02}:{(line.startTimeMs//1000)%60:02}.{line.startTimeMs%1000:03}]{line.words}\n')

		except Exception:
			print(f'failed downloading {fname}')
			print_exc()

	with open(outdir+'.m3u', 'w') as f:
		for it in sorted(pl.contents.items, key=lambda it: it.attributes.timestamp, reverse=True):
			gid = b62_decode(it.uri.removeprefix('spotify:track:'))
			if gid in paths:
				f.write(f'{paths[gid].removeprefix("dl/")}\n')

async def main():
	async with (
				Api(DEVICE_ID, LOGIN_DATA) as api,
				ApClient(api) as ap,
			):

		await dl_playlist(api, ap, mylists.jukebox)
		await dl_playlist(api, ap, mylists.oldies)
		await dl_playlist(api, ap, mylists.campfire)
		await dl_playlist(api, ap, mylists.ungaris)
		await dl_playlist(api, ap, mylists.todo)
		await dl_playlist(api, ap, mylists.soundcheck)

run(main())
