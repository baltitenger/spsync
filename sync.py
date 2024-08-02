#!/usr/bin/env python3

from asyncio import Task, create_task, gather, run, shield, sleep
from configparser import ConfigParser, SectionProxy
from datetime import datetime, timedelta
from difflib import SequenceMatcher
import json
import re
from time import time
from typing import Any, Iterable, TypedDict

import aiosqlite
from attr import dataclass
import google.protobuf.json_format
from google.protobuf.message import Message

from api import Api, Track
from common import KEYMASTER_CLIENT_ID, read_cfg
from connect_pb2 import (
	ALIAS_CHANGED,
	CONNECT_STATE,
	Capabilities,
	Cluster,
	ClusterUpdate,
	ClusterUpdateReason,
	Device,
	DeviceInfo,
	NEW_CONNECTION,
	PutStateReason,
	PutStateRequest,
)
from dealer import DealerBase
from devices_pb2 import DeviceAlias, GAME_CONSOLE
from extended_metadata_pb2 import BatchedEntityRequest, EntityRequest, ExtensionQuery
from extension_kind_pb2 import ALBUM_V4, EPISODE_V4, ExtensionKind, TRACK_V4
from metadata_pb2 import Album, Episode
from player_pb2 import PlayerState, ProvidedTrack
from playlist4_external_pb2 import (
	Add,
	ChangeInfo,
	Delta,
	Item,
	ListAttributeKind,
	ListAttributes,
	ListAttributesPartialState,
	ListChanges,
	Mov,
	Op,
	PlaylistModificationInfo,
	Rem,
	UpdateListAttributes,
)
from playlist_permission_pb2 import PermissionStatePub
from social_connect_v2_pb2 import SessionUpdate

OPT_OFFSET = 0x10 # surely we won't have more than 16 opts
# useful_metas = { 'is_queued', 'provider', 'queued_by' }

opts_pat = re.compile('(?:(.+) )?:set (.+)')

td_ms = timedelta(milliseconds=1)
def ts_fmt(ts: int):
	return datetime.fromtimestamp(ts//1000).isoformat()

def mk_op(op: Add | Rem | Mov | UpdateListAttributes):
	if isinstance(op, Add):
		return Op(kind=Op.ADD, add=op)
	elif isinstance(op, Rem):
		return Op(kind=Op.REM, rem=op)
	elif isinstance(op, Mov):
		return Op(kind=Op.MOV, mov=op)
	elif isinstance(op, UpdateListAttributes):
		return Op(kind=Op.UPDATE_LIST_ATTRIBUTES, update_list_attributes=op)

class PlOpts(TypedDict, total=False):
	ord: bool
	dup: bool

class PlaylistState:
	def __init__(self, api: Api, uri: str, attrs: ListAttributes):
		self.api = api
		self.uri = uri
		self.rev = b''
		self.items: list[Item] = []
		self.set: set[str] = set()
		self.attrs = attrs
		self.opts: PlOpts = {}

	def compute_set(self):
		self.set = { item.uri for item in self.items }

	async def ensure_content(self, last_diff: PlaylistModificationInfo):
		if self.rev:
			return
		pl = await self.api.pl_get(self.uri)
		# print(f'got revision: {self.api.fmt_revision(pl.revision)}')
		self.rev = pl.revision
		self.items = list(pl.contents.items)
		self.compute_set()
		if self.rev == last_diff.new_revision:
			return
		if self.rev == last_diff.parent_revision:
			self.apply_diff(last_diff)
		else:
			self.rev = b''
			raise Exception('got unexpected revision on initial fetch:', self.api.fmt_revision(pl.revision))

	def apply_diff(self, diff: PlaylistModificationInfo):
		pl = self.items
		for op in diff.ops:
			if op.kind == op.ADD:
				if self.rev:
					# guaranteed to have from_index and items
					idx = op.add.from_index
					pl[idx:idx] = op.add.items
			elif op.kind == op.REM:
				if self.rev:
					# guaranteed to have from_index and length
					del pl[op.rem.from_index:op.rem.from_index+op.rem.length]
			elif op.kind == op.MOV:
				if self.rev:
					# guaranteed to have from_index, length and to_index
					frm, len, to = op.mov.from_index, op.mov.length, op.mov.to_index
					pl[to:to] = pl[frm:frm+len]
					if frm >= to: frm += len
					del pl[frm:frm+len]
			elif op.kind == op.UPDATE_LIST_ATTRIBUTES:
				att = op.update_list_attributes.new_attributes
				self.attrs.MergeFrom(att.values)
				for nv in att.no_value:
					self.attrs.ClearField(ListAttributes.DESCRIPTOR.fields_by_number[nv].name)
			else:
				print('warn: ignoring op while applying diff')
				print(op)
		if self.rev:
			self.rev = diff.new_revision
		self.compute_set()

	def get_patch(self, new: list[Item]):
		sm = SequenceMatcher(None, [it.uri for it in self.items], [it.uri for it in new], False)
		ops: list[Op] = []
		shift = 0
		for tag, i1, i2, j1, j2 in sm.get_opcodes():
			if tag == 'replace' or tag == 'delete':
				ops.append(mk_op(Rem(from_index=i1+shift, length=i2-i1)))
			if tag == 'replace' or tag == 'insert':
				ops.append(mk_op(Add(from_index=i1+shift, items=new[j1:j2])))
			shift += (j2-j1) - (i2-i1)
		return ops

	async def send_patch(self, ops: list[Op]):
		await self.api.pl_change(self.uri, ListChanges(
			base_revision=self.rev,
			deltas=[Delta(
				ops=ops,
				info=ChangeInfo(
					user=self.api.username,
					timestamp=int(time()*1000),
				),
			)],
		))

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


@dataclass
class BoolOpt:
	disp: str
	val: bool

	def __str__(self):
		return f'{self.disp}: {"ON" if self.val else "OFF"}'

	def clicked(self):
		self.val = not self.val

class Syncer(DealerBase):
	def __init__(self, api: Api, db: aiosqlite.Connection):
		super().__init__(api)
		self.db = db
		self.track_metas: dict[str, Track] = {}
		self.album_metas: dict[str, Album] = {}
		self.episode_metas: dict[str, Episode] = {}
		self.dedup = BoolOpt('Dedup', True)
		# self.intermix = BoolOpt('Intermix', False)
		# self.shuf_queue = BoolOpt('Shuf-queue', False)
		# self.opts = [self.dedup, self.intermix, self.shuf_queue]
		self.opts = [self.dedup]
		self.opt_offset = 0
		self.queue_update_task: Task | None = None
		self.states: dict[str, PlaylistState] = {}
		self.dedup_delay: timedelta = timedelta(days=2)
		self.last_ctx = ''

	async def update_rootlist(self):
		self.rootlist = await self.api.pl_get(self.api.rootlist_uri(), decorate=['attributes'])
		cons = self.rootlist.contents
		for item, meta in zip(cons.items, cons.meta_items):
			if item.uri not in self.states:
				self.states[item.uri] = PlaylistState(self.api, item.uri, meta.attributes)

	async def ensure_meta[T: Message](self, things: Iterable[str], kind: ExtensionKind, type: type[T], dest: dict[str, T]):
		need = [ thing for thing in things if thing not in dest ]
		if not need:
			return
		resp = await self.api.extd_metadata(BatchedEntityRequest(
			entity_request=(
				EntityRequest(
					entity_uri=thing,
					query=[ExtensionQuery(extension_kind=kind)],
				) for thing in need
			),
		))
		dest |= { ext.entity_uri: type.FromString(ext.extension_data.value) for ext in resp.extended_metadata[0].extension_data }

	async def ensure_track_meta(self, tracks: Iterable[str]):
		await self.ensure_meta(tracks, TRACK_V4, Track, self.track_metas)

	async def ensure_album_meta(self, albums: Iterable[str]):
		await self.ensure_meta(albums, ALBUM_V4, Album, self.album_metas)

	async def ensure_episode_meta(self, episodes: Iterable[str]):
		await self.ensure_meta(episodes, EPISODE_V4, Episode, self.episode_metas)

	async def unrepeat(self, pl: list[Item]):
		await self.ensure_track_meta(  it.uri for it in pl if it.uri.startswith('spotify:track:'))
		# await self.ensure_episode_meta(it.uri for it in pl if it.uri.startswith('spotify:episode:'))
		def getartist(it: Item):
			if it.uri.startswith('spotify:track:'):
				return self.track_metas[it.uri].artist[0].gid
			else:
				return ''
		res: list[Item] = []
		queue: list[Item] = []
		last = b''
		for it in pl:
			artist = getartist(it)
			if artist == last:
				queue.append(it)
				continue
			res.append(it)
			last = artist
			if queue:
				it = queue.pop(0)
				last = getartist(it)
				res.append(it)
		res.extend(queue)
		return res

	async def set_last_played(self, ps: PlayerState):
		uri = ps.track.uri
		old = self.last_played.get(uri, 0)
		if old >= ps.timestamp:
			return
		ts = ps.timestamp - ps.position_as_of_timestamp + ps.duration
		self.last_played[uri] = ts
		await self.db.execute('INSERT OR REPLACE INTO last_played (uri, ts) VALUES (?, ?)', (uri, ts))
		await self.db.commit()
		print(f'last played: {uri} at {ts_fmt(old)} -> {ts_fmt(ts)}')

	async def run(self):
		await self.db.execute('CREATE TABLE IF NOT EXISTS last_played (uri text primary key, ts int)')
		async with self.db.execute('SELECT uri, ts FROM last_played') as curs:
			self.last_played: dict[str, int] = { uri: ts async for uri, ts in curs }

		await self.update_rootlist()

		await self.db.execute('CREATE TABLE IF NOT EXISTS pl_opts (uri text primary key, opts text)')
		async with self.db.execute('SELECT uri, opts FROM pl_opts') as curs:
			async for uri, opts in curs:
				state = self.states.get(uri)
				if state is not None:
					state.opts = json.loads(opts)

		# prefs = [ p for p in self.states.values() if p.attrs.name == 'prefs' ]
		# if prefs:
		# 	self.prefs_pl = prefs[0].uri
		# 	self.prefs = prefs[0].opts
		# self.prefs['']

		return await super().run()

	async def mk_canon_ord(self, items: list[Item]):
		return await self.unrepeat(sorted(items, key=lambda it: it.attributes.timestamp, reverse=True))

	# async def mk_archive(self, add: list[Item]):
	# 	if not add:
	# 		return
	#
	# 	ar = self.states[mylists.archive]
	# 	add.extend(ar.items)
	# 	add.sort(key=lambda it: it.attributes.timestamp, reverse=True)
	# 	add = list({ it.uri: it for it in add }.values())
	# 	add.sort(key=lambda it: it.attributes.timestamp, reverse=True)
	#
	# 	await ar.patch_if_needed(add)

	def pl_get_name(self, uri: str):
		st = self.states.get(uri)
		if st is None:
			return 'unknown'
		return st.attrs.name

	async def handle_pl_opts(self, pl: PlaylistState, desc: str | None, opts: str):
		for opt in opts.split():
			k, v, *_ = opt.split('=') + [None]
			if k == 'ord' or k == 'dup':
				pl.opts[k] = ConfigParser.BOOLEAN_STATES.get(v or '1', True)
		await self.db.execute('INSERT OR REPLACE INTO pl_opts (uri, opts) VALUES (?, ?)', (pl.uri, json.dumps(pl.opts)))
		await self.db.commit()
		return [mk_op(UpdateListAttributes(
			new_attributes=ListAttributesPartialState(
				values=ListAttributes(description=desc),
				no_value=[ListAttributeKind.LIST_DESCRIPTION] if desc is None else [],
			),
		))]

	async def pl_changed(self, pl: str, diff: PlaylistModificationInfo):
		print(f'playlist {self.pl_get_name(pl)} ({pl}) updated')
		print(f'{self.api.fmt_revision(diff.parent_revision)} -> {self.api.fmt_revision(diff.new_revision)}')
		state = self.states.get(pl)
		if state is None:
			print('warning: playlist has no state')
			return
		if state.rev == diff.new_revision:
			return # already applied
		if state.rev and state.rev != diff.parent_revision:
			print('warning: unexpected patch, we had rev:', self.api.fmt_revision(state.rev))
			state.rev = b''
		orig_desc = state.attrs.description
		state.apply_diff(diff)
		desc = state.attrs.description
		ops: list[Op] = []
		if desc != orig_desc:
			m = opts_pat.fullmatch(desc)
			if m is not None:
				ops += await self.handle_pl_opts(state, m.group(1), m.group(2))
		if state.opts.get('ord'):
			await state.ensure_content(diff)
			ops += state.get_patch(await self.mk_canon_ord(state.items))
		if ops:
			print(f'Patching {state.attrs.name}...')
			await state.send_patch(ops)
		# if pl != mylists.archive:
		# 	await self.mk_archive([ it for op in diff.ops if op.kind == Op.ADD for it in op.add.items ])

	async def coll_changed(self, set: str, user: str, diff: list):
		if set != 'collection' or user != self.api.username:
			return

		# state = self.states[mylists.jukebox]
		# items = [ item for item in [
		# 	# [{'type': 'track', 'unheard': False, 'addedAt': 0, 'removed': True, 'identifier': '1li2UA33w6LQcVXt4Di5UA'}]
		# 	Item(
		# 		uri=f'spotify:track:{it["identifier"]}',
		# 		attributes=ItemAttributes(timestamp=it['addedAt']*1000),
		# 	) for it in diff if it['type'] == 'track' and not it['removed']
		# ] if item.uri not in state.set ]
		# await state.patch_if_needed(await self.mk_canon_ord(state.items + items))
		#
		# albums = { f'spotify:album:{it["identifier"]}': it['addedAt']*1000
		# 				for it in diff if it['type'] == 'album' and not it['removed'] }
		# await self.ensure_album_meta(albums)
		# await self.mk_archive([
		# 	Item(
		# 		uri=f'spotify:track:{b62_encode(track.gid)}',
		# 		attributes=ItemAttributes(timestamp=ts),
		# 	)
		# 	for alb, ts in albums.items() for disc in self.album_metas[alb].disc for track in disc.track
		# ])

	async def opts_changed(self, reason: PutStateReason):
		cluster = await self.api.put_conn_state(self.conn_id, PutStateRequest(
			device=Device(
				device_info=DeviceInfo(
					can_play=True,
					capabilities=capabilities,
					device_type=GAME_CONSOLE,
					device_id=self.api.device_id,
					client_id=KEYMASTER_CLIENT_ID,
					device_aliases={
						i+self.opt_offset*OPT_OFFSET: DeviceAlias(id=i+self.opt_offset*OPT_OFFSET, display_name=str(d))
						for i, d in enumerate(self.opts)
					},
				),
			),
			member_type=CONNECT_STATE,
			put_state_reason=reason,
		))
		await self.on_cluster(cluster, ClusterUpdateReason.DEVICE_STATE_CHANGED)

	async def pusher_connect(self, conn_id: str):
		self.conn_id = conn_id
		await self.opts_changed(NEW_CONNECTION)

	def do_dedup(self, cluster: Cluster, tracks: list[ProvidedTrack]):
		filtered = [ t for t in tracks if
					t.metadata.get('provider', t.provider) == 'queue'
					or cluster.player_state.timestamp - self.last_played.get(t.uri, 0) > self.dedup_delay/td_ms ]
		removed = len(tracks) - len(filtered)
		if removed:
			print(f'freq: removing {removed} tracks from next_tracks')
		tracks[:] = filtered
		return removed != 0

	def do_shuf_queue(self, cluster: Cluster, tracks: list[ProvidedTrack]):
		for t in tracks:
			print(f'{t.uri = } {t.uid = } {t.provider = }')

	def should_dedup(self, ctx: str):
		if s := self.states.get(ctx):
			if s.opts.get('dup'):
				return False
		return True

	async def on_cluster(self, cluster: Cluster, reason: ClusterUpdateReason):
		# print(f'cluster updated, reason: {ClusterUpdateReason.Name(reason)}, act: {cluster.active_device_id}')
		self.cluster = cluster
		if not cluster.active_device_id:
			return

		if self.queue_update_task is not None and not self.queue_update_task.done():
			self.queue_update_task.cancel()
		self.queue_update_task = create_task(self.do_queue_update(cluster))

		await self.set_last_played(cluster.player_state)

		ctx = cluster.player_state.context_uri
		if ctx != self.last_ctx:
			if self.dedup.val != self.should_dedup(ctx):
				self.dedup.clicked()
				await self.opts_changed(ALIAS_CHANGED)
			self.last_ctx = ctx

	async def do_queue_update(self, cluster: Cluster):
		await sleep(1) # debounce on cluster updates

		ps = cluster.player_state

		tracks: list[ProvidedTrack] = []
		for t in ps.next_tracks:
			tracks.append(t)
			if t.uri == 'spotify:delimiter':
				break
		changed = False

		if self.dedup.val:
			changed |= self.do_dedup(cluster, tracks)
		# if self.shuf_queue.val:
		# 	changed |= self.do_shuf_queue(cluster, tracks)

		if changed:
			await shield(self.api.send_command(cluster.active_device_id, {
				'endpoint': 'set_queue',
				'queue_revision': ps.queue_revision,
				'prev_tracks': [ google.protobuf.json_format.MessageToDict(t) for t in ps.prev_tracks ],
				'next_tracks': [ google.protobuf.json_format.MessageToDict(t) for t in tracks ],
			}))

	async def on_message(self, uri: str, method: str | None, headers: dict[str, str], payload: str | bytes | Any):
		match uri.removeprefix('hm://').split('/'):
			case ('pusher', 'v1', 'connections', b64):
				print('connecting to pusher')
				await self.pusher_connect(headers['Spotify-Connection-Id'])
			case ('collection', set, user):
				pass # we use the json version
			case ('collection', set, user, 'json'):
				assert isinstance(payload, str)
				chg = json.loads(payload)['items']
				# [{'type': 'track', 'unheard': False, 'addedAt': 0, 'removed': True, 'identifier': '1li2UA33w6LQcVXt4Di5UA'}]
				print(f'set {set} of user {user} updated: {chg}')
				await self.coll_changed(set, user, chg)
			case ('playlist', 'v2', *pl):
				uri = ':'.join(['spotify']+pl)
				if uri == self.api.rootlist_uri():
					print('rootlist updated')
					await self.update_rootlist()
					return
				assert isinstance(payload, bytes)
				info = PlaylistModificationInfo.FromString(payload)
				await self.pl_changed(uri, info)
			case ('playlist', 'user', user, 'rootlist'):
				pass # use v2
			case ('offline2', 'offline', 'v1', 'devices', dev_id_hex, 'cache', cache_id, 'resources:write'):
				dev_id = bytes.fromhex(dev_id_hex)
				print(f'offline resources:write for device {dev_id}: {cache_id=}')
			case ('playlist-permission', 'v1', 'playlist', pl, 'permission', 'state'):
				print(f'playlist permission changed for {self.pl_get_name(uri)} ({uri})')
				assert isinstance(payload, bytes)
				print(PermissionStatePub.FromString(payload))
			# spotify:user:attributes:mutated -> weird proto?, is_maybe_in_social_session, timestamp, other random number
			case ('social-connect', 'v2', 'session_update'):
				update = SessionUpdate()
				google.protobuf.json_format.ParseDict(payload, update, ignore_unknown_fields=True)
				print('got social connect update:', update)
			case ('connect-state', 'v1', 'cluster'):
				assert isinstance(payload, bytes)
				update = ClusterUpdate.FromString(payload)
				await self.on_cluster(update.cluster, update.update_reason)
			case ('offline', 'v1', 'devices', hex2, 'cache', hex, 'resources:write'):
				# fires when something is marked / unmarked to be downloaded
				# no clue what the values are, seems to be fixed per device?
				pass
			case _:
				print(f'unknown message {method} {uri}: {payload}')

	async def on_request(self, uri: str, headers: dict[str, str], payload: Any):
		match uri.removeprefix('hm://').split('/'):
			case ('connect-state', 'v1', 'player', 'command'):
				is_off, alias = divmod(payload.get('target_alias_id') or 0, OPT_OFFSET)
				opt = self.opts[alias]
				if self.opt_offset == is_off:
					self.opt_offset ^= 1
					opt.clicked()
					print(f'toggled opt {alias} {opt}')
					await self.opts_changed(ALIAS_CHANGED)
				return True
			case _:
				print(f'got request {uri}, {headers=}: {payload}')
		return False

async def sync(name: str, cfg: SectionProxy):
	async with (
				Api.from_cfg(cfg) as api,
				aiosqlite.connect(f'{name}.sqlite') as db,
			):
		await Syncer(api, db).run()

async def main():
	cfgs = read_cfg()
	await gather(*(sync(name, cfgs[name]) for name in cfgs.sections()), return_exceptions=True)

run(main())
