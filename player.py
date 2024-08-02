#!/usr/bin/python3

from asyncio import create_subprocess_exec, ensure_future, gather, run
from asyncio.subprocess import PIPE
import os.path
import time
from traceback import print_exc
from typing import Any, Iterable

import google.protobuf.json_format

from api import Api
from common import KEYMASTER_CLIENT_ID, default_cfg
from connect_pb2 import (
	AudioOutputDeviceInfo,
	BUILT_IN_SPEAKER,
	CONNECT_STATE,
	Capabilities,
	Cluster,
	ClusterUpdate,
	Device,
	DeviceInfo,
	NEW_CONNECTION,
	PLAYER_STATE_CHANGED,
	PutStateReason,
	PutStateRequest,
	SetVolumeCommand,
	VOLUME_CHANGED,
)
from dealer import DealerBase
from devices_pb2 import UNKNOWN
from extended_metadata_pb2 import BatchedEntityRequest, EntityRequest, ExtensionQuery
from extension_kind_pb2 import TRACK_V4
from metadata_pb2 import Track
from player_pb2 import PlayerState, ProvidedTrack

def dict_to_proto(dict, cls):
	msg = cls()
	google.protobuf.json_format.ParseDict(dict, msg, ignore_unknown_fields=True)
	return msg

def time_ms():
	return time.time_ns() // 1000000

capabilities=Capabilities(
	can_be_player=True,
	# restrict_to_local=False,
	gaia_eq_connect_id=True,
	# supports_logout=False,
	is_observable=True,
	volume_steps=64,
	supported_types=['audio/local', 'audio/track'],
	command_acks=True,
	supports_rename=True,
	# hidden=False,
	# disable_volume=False,
	# connect_disabled=False,
	supports_playlist_v2=True,
	is_controllable=True,
	supports_external_episodes=True,
	supports_set_backend_metadata=True,
	supports_transfer_command=True,
	supports_command_request=True,
	is_voice_enabled=False,
	needs_full_player_state=True, # workaround for kagi bug
	supports_gzip_pushes=True,
	supports_set_options_command=True,
	# supports_hifi=CapabilitySupportDetails(),
	# connect_capabilities='',
	# supports_rooms=False,
	# supports_dj=False,
	# supported_audio_quality=DEFAULT,
)

class Player(DealerBase):
	def __init__(self, api: Api): #, db: aiosqlite.Connection):
		super().__init__(api)
		self.volume = 64
		self.state = PlayerState()
		self.last_command_message_id: int | None = None
		self.last_command_sent_by_device_id: str | None = None
		self.active = False
		# self.db = db
		self.downloading: set[str] = set()
		self.started = 0

	async def cmd(self, cmd: str, arg: str = ''):
		self.sendf.write((cmd+arg+'\n').encode())
		await self.sendf.drain()

	def uri_to_path(self, uri: str):
		type, gid = Api.unuri(uri)
		hexgid = gid.hex()
		return f'player/{type}/{hexgid[0:2]}/{hexgid[2:4]}/{hexgid[4:]}.ogg'

	async def do_recv(self):
		while True:
			l = await self.recvf.readline()
			if not l:
				break
			print('playhelp says', l)
			l = l.decode().strip()
			if l == 'd':
				if self.state.next_tracks:
					self.state.track.CopyFrom(self.state.next_tracks[0])
					del self.state.next_tracks[0]
					self.state.position = 0
					self.state.position_as_of_timestamp = 0
					await self.state_changed()
			elif l == 'l':
				if self.state.next_tracks:
					await self.cmd('n', self.uri_to_path(self.state.next_tracks[0].uri))

	async def run(self):
		# await self.db.execute('CREATE TABLE IF NOT EXISTS audio_file (gid BLOB, format INTEGER, file_id BLOB, PRIMARY KEY (gid, format))')
		proc = await create_subprocess_exec('./playhelp', stdin=PIPE, stdout=PIPE)
		assert proc.stdin is not None and proc.stdout is not None
		self.sendf = proc.stdin
		self.recvf = proc.stdout
		x = await gather(super().run(), self.do_recv())
		return x[0]

	async def pusher_connect(self, conn_id: str):
		self.conn_id = conn_id
		await self.state_changed(NEW_CONNECTION)

	def is_available(self, uri: str):
		return os.path.isfile(self.uri_to_path(uri))

	async def dl_tracks(self, tracks: Iterable[ProvidedTrack]):
		need = { t.uri for t in tracks if t.uri.startswith('spotify:track:') and not (t.uri in self.downloading or self.is_available(t.uri)) }
		if not need:
			return
		self.downloading.update(need)
		resp = await self.api.extd_metadata(BatchedEntityRequest(
			entity_request=(
				EntityRequest(
					entity_uri=thing,
					query=[ExtensionQuery(extension_kind=TRACK_V4)],
				) for thing in need
			),
		))
		for ext in resp.extended_metadata[0].extension_data:
			try:
				uri = ext.entity_uri
				tr = Track.FromString(ext.extension_data.value)
				# print('downloading', uri, tr.name)
				file = (tr.file or tr.alternative[0].file)[0]
				path = self.uri_to_path(uri)
				os.makedirs(path.rsplit('/', 1)[0], exist_ok=True)
				await self.api.dl_audio_track(file.file_id, path)
				self.downloading.discard(uri)
			except Exception:
				print_exc()
			

	async def state_changed(self, reason: PutStateReason = PLAYER_STATE_CHANGED):
		ts = time_ms()
		self.state.timestamp = ts
		req = PutStateRequest(
			device=Device(
				device_info=DeviceInfo(
					can_play=True,
					volume=self.volume,
					name='foo',
					capabilities=capabilities,
					device_type=UNKNOWN,
					device_id=self.api.device_id,
					# is_private_session=False,
					# is_social_connect=False,
					client_id=KEYMASTER_CLIENT_ID,
					brand='asdf',
					model='qwer',
					audio_output_device_info=AudioOutputDeviceInfo(
						audio_output_device_type=BUILT_IN_SPEAKER,
						device_name='zcxv',
					),
				),
				player_state=self.state if self.active else PlayerState(timestamp=ts),
			),
			member_type=CONNECT_STATE,
			put_state_reason=reason,
			client_side_timestamp=ts,
			last_command_message_id=self.last_command_message_id,
			last_command_sent_by_device_id=self.last_command_sent_by_device_id,
			is_active=self.active,
			started_playing_at=self.started,
			has_been_playing_for_ms=ts-self.started if self.started else 0
		)
		await self.api.put_conn_state(self.conn_id, req)

	async def on_cluster(self, cluster: Cluster):
		if self.active:
			# TODO check if other dev became active
			pass
		else:
			self.state = cluster.player_state

	async def on_message(self, uri: str, method: str | None, headers: dict[str, str], payload: str | bytes | Any):
		match uri.removeprefix('hm://').split('/'):
			case ('pusher', 'v1', 'connections', b64):
				print('connecting to pusher')
				await self.pusher_connect(headers['Spotify-Connection-Id'])
			case ('connect-state', 'v1', 'cluster'):
				assert isinstance(payload, bytes)
				update = ClusterUpdate.FromString(payload)
				# print(f'got cluster update, reason: {ClusterUpdateReason.Name(update.update_reason)}')
				await self.on_cluster(update.cluster)
			case ('connect-state', 'v1', 'connect', 'volume'):
				assert isinstance(payload, bytes)
				vol = SetVolumeCommand.FromString(payload)
				self.volume = vol.volume
				await self.state_changed(VOLUME_CHANGED)
			case _:
				print(f'unknown message {method} {uri}: {payload}')

	async def on_request(self, uri: str, headers: dict[str, str], payload: Any) -> bool:
		match uri:
			case 'hm://connect-state/v1/player/command':
				self.last_command_message_id = payload['message_id']
				self.last_command_sent_by_device_id = payload['sent_by_device_id']
				return await self.on_command(payload['target_alias_id'], payload['command'])
			case _:
				print(f'got request {uri}, {headers=}: {payload}')
		return False

	async def on_command(self, alias: int | None, cmd: dict[str, Any]):
		print('got command', cmd['endpoint'])
		match cmd['endpoint']:
			case 'pause':
				self.sendf.write(b'P\n')
				self.state.is_playing = False
				self.state.is_paused = True
			case 'resume':
				self.sendf.write(b'p\n')
				self.state.is_playing = True
				self.state.is_paused = False
			case 'set_options':
				self.state.options.repeating_track = cmd['repeating_track']
				self.state.options.repeating_context = cmd['repeating_context']
			case 'set_queue':
				del self.state.next_tracks[:]
				self.state.next_tracks.extend(dict_to_proto(t, ProvidedTrack) for t in cmd['next_tracks'])
				del self.state.prev_tracks[:]
				self.state.prev_tracks.extend(dict_to_proto(t, ProvidedTrack) for t in cmd['prev_tracks'])
				# TODO should check instead of assign? idk
				self.state.queue_revision = cmd['queue_revision']
				if self.state.next_tracks:
					await self.cmd('n', self.uri_to_path(self.state.next_tracks[0].uri))
			case 'set_shuffling_context':
				self.state.options.shuffling_context = cmd['value']
				# TODO
			case 'skip_next':
				self.sendf.write(b'p\n')
				if self.state.next_tracks:
					self.state.track.CopyFrom(self.state.next_tracks[0])
					del self.state.next_tracks[0]
				# self.state.track = dict_to_proto(cmd['track'], ProvidedTrack)
				# TODO
			case 'skip_prev':
				pass # TODO probably same?
			case 'transfer':
				self.active = True
				# cmd['data'] # is base64 encoded TransferState protobuf
				# from_device_identifier = cmd['from_device_identifier']
				self.started = time_ms()
				if not self.is_available(self.state.track.uri):
					print('buffering...')
					self.state.is_buffering = True
					await self.state_changed()
					await self.dl_tracks([self.state.track])
					self.state.is_buffering = False
				self.state.is_playing = True
				await self.state_changed()
				await self.cmd('n', self.uri_to_path(self.state.track.uri))
				await self.cmd('l', str(self.state.position_as_of_timestamp - self.state.timestamp + time_ms()))
				print('playback started')
				ensure_future(self.dl_tracks(self.state.next_tracks))
			case 'update_context':
				uri: str = cmd['uri'] # e.g. spotify:playlist:asdf
				url: str = cmd['url'] # e.g. context://spotify:playlist:asdf?spotify-apply-lenses=enhance
			case 'seek_to':
				pos: int = cmd['position'] # cmd['value'] is the same(?)
				# rel: int = cmd['relative'] # always 'beginning'
				await self.cmd('s', str(pos))
			case _:
				print(cmd)
				return False
		await self.state_changed()
		return True


async def main():
	async with (
			Api.from_cfg(default_cfg()) as api,
			# aiosqlite.connect('player.sqlite') as db,
			):
		await Player(api).run()

run(main())
