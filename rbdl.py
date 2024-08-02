#!/usr/bin/env python3

from asyncio import run
import os
import pathlib
import re
from subprocess import call
from traceback import print_exc

from mutagen.oggvorbis import OggVorbis, OggVorbisHeaderError

from api import Api
from common import read_cfg
from creds import DEVICE_ID, LOGIN_DATA
from extended_metadata_pb2 import BatchedEntityRequest, EntityRequest, ExtensionQuery
from extension_kind_pb2 import ALBUM_V4, TRACK_V4
from metadata_pb2 import Album, Track
import mylists

outdir = 'rbdl'
path_norm = str.maketrans(dict.fromkeys('\\/:<>?*|', '_') | {'"': "'"})

def fix_name(name: str):
	name = re.sub(' \\(.*Remaster.*\\)$', '', name)
	name = re.sub(' \\(.*Deluxe.*\\)$',   '', name)
	name = re.sub(' \\(.*Edition.*\\)$',  '', name)
	name = re.sub(' - .*Remaster.*',      '', name)
	name = re.sub(' - .*Deluxe.*',        '', name)
	name = re.sub(' - .*Edition.*',       '', name)
	name = re.sub('[ .]*$',               '', name)
	return name.translate(path_norm)

async def dl_tracks(api: Api, items: set[str]):
	meta = await api.extd_metadata(BatchedEntityRequest(
		entity_request=[EntityRequest(
			entity_uri=uri,
			query=[ExtensionQuery(extension_kind=TRACK_V4)],
		) for uri in items if uri.startswith('spotify:track:')]
	))
	tracks = [
		Track.FromString(ext.extension_data.value)
		for ext in meta.extended_metadata[0].extension_data
	]

	covers: dict[str, bytes] = {} # path -> fileid

	paths: dict[bytes, str] = {}
	for track in tracks:
		try:
			file = (track.file or track.alternative[0].file)[0]
		except IndexError:
			print(f'Track unavailable: {track.name} ({api.track_uri(track.gid)})')
			continue
		dir = '/'.join(map(fix_name, (outdir, track.artist[0].name, track.album.name)))
		pathlib.Path(dir).mkdir(parents=True, exist_ok=True)
		path = f'{dir}/{fix_name(track.name)}.ogg'
		paths[track.gid] = path
		cover = f'{dir}/cover.jpg'
		if not os.path.isfile(cover):
			covers[cover] = max(track.album.cover_group.image, key=lambda i: i.size).file_id
		try:
			if not os.path.isfile(path):
				await api.dl_audio_track(file.file_id, path)
				print('downloaded', path)

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
			print(f'failed downloading {path}')
			print_exc()

	if covers:
		print('downloading covers...')
		call(['curl', '-#'] + [ x for path, file_id in covers.items() for x in ('-:', '-o', path, f'https://i.scdn.co/image/{file_id.hex()}') ][1:])

	return paths

def create_m3u(paths: dict[bytes, str], name: str, tracks: list[bytes]):
	with open(f'{outdir}/{fix_name(name)}.m3u8', 'w') as f:
		for t in tracks:
			path = paths.get(t)
			if path is not None:
				f.write(f'{path.removeprefix(f"{outdir}/")}\n')

async def main():
	async with Api.from_cfg(read_cfg()['baltazar']) as api:

		rootlist = await api.pl_get(api.rootlist_uri(), decorate=['owner'])
		uris = [ it.uri
					 for it, meta in zip(rootlist.contents.items, rootlist.contents.meta_items)
					 if meta.owner_username == api.username and it.uri != mylists.archive ]
		uris.append(api.pl_uri('7jmZquJWib8bIZDUhA8BrC')) # mouth moods samples
		uris.remove(api.pl_uri('3RyOPrahCBIopCnL22MiiM')) # mouth moods
		uris.remove(api.pl_uri('4xzpItlUt0p3qgfEGxLTu0')) # mouth dreams
		lists = [ await api.pl_get(uri) for uri in uris ]

		coll = [ it for page in await api.coll_get('collection') for it in page.items ]
		albums = { it.uri: it.added_at for it in coll if it.uri.startswith('spotify:album:') }
		ext_resp = await api.extd_metadata(BatchedEntityRequest(entity_request=[
			EntityRequest(entity_uri=album, query=[ExtensionQuery(extension_kind=ALBUM_V4)])
			for album in albums
		]))
		albs = [Album.FromString(ext.extension_data.value) for ext in ext_resp.extended_metadata[0].extension_data]

		tracks = \
			{ it.uri for l in lists for it in l.contents.items } | \
			{ api.track_uri(it.gid) for alb in albs for disc in alb.disc for it in disc.track }

		paths = await dl_tracks(api, tracks)

		for pl in lists:
			create_m3u(paths, pl.attributes.name, [ api.getgid(it.uri, 'track') for it in pl.contents.items if it.uri.startswith('spotify:track:') ])

		for alb in albs:
			create_m3u(paths, alb.name, [ it.gid for disc in alb.disc for it in disc.track ])

run(main())
