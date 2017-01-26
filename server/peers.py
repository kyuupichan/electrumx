# Copyright (c) 2017, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Peer management.'''

import ast
import asyncio
import random
import ssl
import time
from collections import defaultdict, Counter
from functools import partial

from lib.jsonrpc import JSONSession
from lib.peer import Peer
from lib.socks import SocksProxy
import lib.util as util
from server.irc import IRC
import server.version as version


PEERS_FILE = 'peers'
PEER_GOOD, PEER_STALE, PEER_NEVER, PEER_BAD = range(4)
STALE_SECS = 86400
WAKEUP_SECS = 300


def peer_from_env(env):
    '''Return ourself as a peer from the environment settings.'''
    main_identity = env.identities[0]
    hosts = {identity.host : {'tcp_port': identity.tcp_port,
                              'ssl_port': identity.ssl_port}
             for identity in env.identities}
    features = {
        'hosts': hosts,
        'pruning': None,
        'server_version': version.VERSION,
        'protocol_min': version.PROTOCOL_MIN,
        'protocol_max': version.PROTOCOL_MAX,
        'genesis_hash': env.coin.GENESIS_HASH,
    }

    return Peer(main_identity.host, features, 'env')


class PeerSession(JSONSession):
    '''An outgoing session to a peer.'''

    def __init__(self, peer, peer_mgr, kind):
        super().__init__()
        self.max_send = 0
        self.peer = peer
        self.peer_mgr = peer_mgr
        self.kind = kind
        self.failed = False
        self.log_prefix = '[{}] '.format(self.peer)

    def have_pending_items(self):
        self.peer_mgr.ensure_future(self.process_pending_items())

    def connection_made(self, transport):
        '''Handle an incoming client connection.'''
        super().connection_made(transport)
        self.log_prefix = '[{}] '.format(str(self.peer)[:25])

        # Update IP address
        if not self.peer.is_tor:
            peer_info = self.peer_info()
            if peer_info:
                self.peer.ip_addr = peer_info[0]

        # Collect data
        proto_ver = (version.PROTOCOL_MIN, version.PROTOCOL_MAX)
        self.send_request(self.on_version, 'server.version',
                          [version.VERSION, proto_ver])
        self.send_request(self.on_peers_subscribe, 'server.peers.subscribe')
        self.send_request(self.on_features, 'server.features')

    def connection_lost(self, exc):
        '''Handle disconnection.'''
        super().connection_lost(exc)
        self.peer_mgr.connection_lost(self)

    def on_peers_subscribe(self, result, error):
        '''Handle the response to the peers.subcribe message.'''
        if error:
            self.failed = True
            self.log_error('server.peers.subscribe: {}'.format(error))
        else:
            self.check_remote_peers(result)
        self.close_if_done()

    def check_remote_peers(self, updates):
        '''When a peer gives us a peer update.

        Each update is expected to be of the form:
            [ip_addr, hostname, ['v1.0', 't51001', 's51002']]

        Return True if we're in the list of peers.
        '''
        try:
            real_names = [' '.join([u[1]] + u[2]) for u in updates]
            peers = [Peer.from_real_name(real_name, str(self.peer))
                     for real_name in real_names]
        except Exception:
            self.log_error('bad server.peers.subscribe response')
            return False

        self.peer_mgr.add_peers(peers)
        my = self.peer_mgr.myself
        for peer in my.matches(peers):
            if peer.tcp_port == my.tcp_port and peer.ssl_port == my.ssl_port:
                return

        # Announce ourself if not present
        self.log_info('registering with server.add_peer')
        self.send_request(self.on_add_peer, 'server.add_peer', [my.features])

    def on_add_peer(self, result, error):
        '''Handle the response to the add_peer message.'''
        self.close_if_done()

    def on_features(self, features, error):
        # Several peers don't implement this.  If they do, check they are
        # the same network with the genesis hash.
        verified = False
        if not error and isinstance(features, dict):
            forget = False
            our_hash = self.peer_mgr.env.coin.GENESIS_HASH
            their_hash = features.get('genesis_hash')
            if their_hash:
                verified = their_hash == our_hash
                forget = their_hash != our_hash
            if forget:
                self.failed = True
                self.peer.mark_bad()
                self.log_warning('incorrect genesis hash')
            else:
                self.peer.update_features(features)
        # For legacy peers not implementing features, check their height
        # as a proxy to determining they're on our network
        if not verified:
            self.send_request(self.on_headers, 'blockchain.headers.subscribe')
        self.close_if_done()

    def on_headers(self, result, error):
        '''Handle the response to the version message.'''
        if error or not isinstance(result, dict):
            self.failed = True
            self.log_error('bad blockchain.headers.subscribe response')
        else:
            our_height = self.peer_mgr.controller.bp.db_height
            their_height = result.get('block_height')
            if (not isinstance(their_height, int) or
                   abs(our_height - their_height) > 5):
                self.failed = True
                self.peer.mark_bad()
                self.log_warning('bad height {}'.format(their_height))
        self.close_if_done()

    def on_version(self, result, error):
        '''Handle the response to the version message.'''
        if error:
            self.failed = True
            self.log_error('server.version returned an error')
        elif isinstance(result, str):
            self.peer.server_version = result
            self.peer.features['server_version'] = result
        self.close_if_done()

    def close_if_done(self):
        if not self.has_pending_requests():
            is_good = not self.failed
            self.peer.last_connect = time.time()
            self.peer_mgr.set_connection_status(self.peer, is_good)
            if is_good:
                if self.peer.is_tor:
                    self.log_info('verified via {} over Tor'.format(self.kind))
                else:
                    self.log_info('verified via {} at {}'
                                  .format(self.kind,
                                          self.peer_addr(anon=False)))
            self.close_connection()


class PeerManager(util.LoggedClass):
    '''Looks after the DB of peer network servers.

    Attempts to maintain a connection with up to 8 peers.
    Issues a 'peers.subscribe' RPC to them and tells them our data.
    '''
    def __init__(self, env, controller):
        super().__init__()
        # Initialise the Peer class
        Peer.DEFAULT_PORTS = env.coin.PEER_DEFAULT_PORTS
        self.env = env
        self.controller = controller
        self.loop = controller.loop
        self.irc = IRC(env, self)
        self.myself = peer_from_env(env)
        # value is max outgoing connections at a time
        self.semaphore = asyncio.BoundedSemaphore(value=8)
        self.retry_event = asyncio.Event()
        # Peers have one entry per hostname.  Once connected, the
        # ip_addr property is either None, an onion peer, or the
        # IP address that was connected to.  Adding a peer will evict
        # any other peers with the same host name or IP address.
        self.peers = set()
        self.onion_peers = []
        self.last_tor_retry_time = 0
        self.tor_proxy = SocksProxy(env.tor_proxy_host, env.tor_proxy_port,
                                    loop=self.loop)
        self.import_peers()

    def info(self):
        '''The number of peers.'''
        self.set_peer_statuses()
        counter = Counter(peer.status for peer in self.peers)
        return {
            'bad': counter[PEER_BAD],
            'good': counter[PEER_GOOD],
            'never': counter[PEER_NEVER],
            'stale': counter[PEER_STALE],
            'total': len(self.peers),
        }

    def set_peer_statuses(self):
        '''Set peer statuses.'''
        cutoff = time.time() - STALE_SECS
        for peer in self.peers:
            if peer.bad:
                peer.status = PEER_BAD
            elif peer.last_connect > cutoff:
                peer.status = PEER_GOOD
            elif peer.last_connect:
                peer.status = PEER_STALE
            else:
                peer.status = PEER_NEVER

    def rpc_data(self):
        '''Peer data for the peers RPC method.'''
        self.set_peer_statuses()

        descs = ['good', 'stale', 'never', 'bad']
        def peer_data( peer):
            data = peer.serialize()
            data['status'] = descs[peer.status]
            return data

        def peer_key(peer):
            return (peer.bad, -peer.last_connect)

        return [peer_data(peer) for peer in sorted(self.peers, key=peer_key)]

    def add_peers(self, peers, limit=3, check_ports=False, source=None):
        '''Add a limited number of peers that are not already present.'''
        retry = False
        new_peers = []
        for peer in peers:
            matches = peer.matches(self.peers)
            if not matches:
                new_peers.append(peer)
            elif check_ports:
                for match in matches:
                    if match.check_ports(peer):
                        self.logger.info('ports changed for {}'.format(peer))
                        retry = True

        if new_peers:
            retry = True
            source = source or new_peers[0].source
            if limit:
                random.shuffle(new_peers)
                use_peers = new_peers[:limit]
            else:
                use_peers = new_peers
            self.logger.info('accepted {:d}/{:d} new peers of {:d} from {}'
                             .format(len(use_peers), len(new_peers),
                                     len(peers), source))
            self.peers.update(use_peers)

        if retry:
            self.retry_event.set()

    def on_add_peer(self, features, source):
        '''Add peers from an incoming connection.'''
        peers = Peer.peers_from_features(features, source)
        if peers:
            self.log_info('add_peer request received from {}'
                          .format(peers[0].host))
            self.add_peers(peers, check_ports=True)
        return bool(peers)

    def on_peers_subscribe(self, is_tor):
        '''Returns the server peers as a list of (ip, host, details) tuples.

        We return all peers we've connected to in the last day.
        Additionally, if we don't have onion routing, we return up to
        three randomly selected onion servers.
        '''
        cutoff = time.time() - STALE_SECS
        recent = [peer for peer in self.peers
                  if peer.last_connect > cutoff
                  and not peer.bad and peer.is_public]
        onion_peers = []

        # Always report ourselves if valid (even if not public)
        peers = set()
        if self.myself.last_connect > cutoff:
            peers.add(self.myself)

        # Bucket the clearnet peers and select one from each
        buckets = defaultdict(list)
        for peer in recent:
            if peer.is_tor:
                onion_peers.append(peer)
            else:
                buckets[peer.bucket()].append(peer)
        peers.update(random.choice(bpeers) for bpeers in buckets.values())

        # Add up to 20% onion peers (but up to 10 is OK anyway)
        onion_peers = onion_peers or self.onion_peers
        random.shuffle(onion_peers)
        max_onion = 50 if is_tor else max(10, len(peers) // 4)

        peers.update(onion_peers[:max_onion])

        return [peer.to_tuple() for peer in peers]

    def serialize(self):
        serialized_peers = [peer.serialize() for peer in self.peers
                            if not peer.bad]
        data = (1, serialized_peers)  # version 1
        return repr(data)

    def write_peers_file(self):
        with util.open_truncate(PEERS_FILE) as f:
            f.write(self.serialize().encode())
        self.logger.info('wrote out {:,d} peers'.format(len(self.peers)))

    def read_peers_file(self):
        try:
            with util.open_file(PEERS_FILE, create=True) as f:
                data = f.read(-1).decode()
        except Exception as e:
            self.logger.error('error reading peers file {}'.format(e))
        else:
            if data:
                version, items = ast.literal_eval(data)
                if version == 1:
                    peers = [Peer.deserialize(item) for item in items]
                    self.add_peers(peers, source='peers file', limit=None)

    def import_peers(self):
        '''Import hard-coded peers from a file or the coin defaults.'''
        self.add_peers([self.myself])
        coin_peers = self.env.coin.PEERS
        self.onion_peers = [Peer.from_real_name(rn, 'coins.py')
                            for rn in coin_peers if '.onion ' in rn]

        # If we don't have many peers in the peers file, add
        # hard-coded ones
        self.read_peers_file()
        if len(self.peers) < 5:
            peers = [Peer.from_real_name(real_name, 'coins.py')
                     for real_name in coin_peers]
            self.add_peers(peers, limit=None)

    def connect_to_irc(self):
        '''Connect to IRC if not disabled.'''
        if self.env.irc and self.env.coin.IRC_PREFIX:
            pairs = [(self.myself.real_name(ident.host), ident.nick_suffix)
                     for ident in self.env.identities]
            self.ensure_future(self.irc.start(pairs))
        else:
            self.logger.info('IRC is disabled')

    def add_irc_peer(self, nick, real_name):
        '''Add an IRC peer.'''
        peer = Peer.from_real_name(real_name, '{}'.format(nick))
        self.add_peers([peer])

    def ensure_future(self, coro, callback=None):
        '''Schedule the coro to be run.'''
        return self.controller.ensure_future(coro, callback=callback)

    async def main_loop(self):
        '''Main loop performing peer maintenance.  This includes

          1) Forgetting unreachable peers.
          2) Verifying connectivity of new peers.
          3) Retrying old peers at regular intervals.
        '''
        self.connect_to_irc()
        try:
            while True:
                timeout = self.loop.call_later(WAKEUP_SECS,
                                               self.retry_event.set)
                await self.retry_event.wait()
                self.retry_event.clear()
                timeout.cancel()
                await self.retry_peers()
        finally:
            self.write_peers_file()

    def is_coin_onion_peer(self, peer):
        '''Return true if this peer is a hard-coded onion peer.'''
        return peer.is_tor and any(peer.host in real_name
                                   for real_name in self.env.coin.PEERS)

    async def retry_peers(self):
        '''Retry peers that are close to getting stale.'''
        # Exponential backoff of retries
        now = time.time()
        nearly_stale_time = (now - STALE_SECS) + WAKEUP_SECS * 2

        def retry_peer(peer):
            # Try some Tor at startup to determine the proxy so we can
            # serve the right banner file
            if self.last_tor_retry_time == 0 and self.is_coin_onion_peer(peer):
                return True
            # Retry a peer whose ports might have updated
            if peer.other_port_pairs:
                return True
            # Retry a good connection if it is about to turn stale
            if peer.try_count == 0:
                return peer.last_connect < nearly_stale_time
            # Retry a failed connection if enough time has passed
            return peer.last_try < now - WAKEUP_SECS * 2 ** peer.try_count

        peers = [peer for peer in self.peers if retry_peer(peer)]

        # If we don't have a tor proxy drop tor peers, but retry
        # occasionally
        if self.tor_proxy.port is None:
            if now < self.last_tor_retry_time + 3600:
                peers = [peer for peer in peers if not peer.is_tor]
            elif any(peer.is_tor for peer in peers):
                self.last_tor_retry_time = now

        for peer in peers:
            peer.last_try = time.time()
            peer.try_count += 1
            pairs = peer.connection_port_pairs()
            if peer.bad or not pairs:
                self.maybe_forget_peer(peer)
            else:
                await self.semaphore.acquire()
                self.retry_peer(peer, pairs)

    def retry_peer(self, peer, port_pairs):
        kind, port = port_pairs[0]
        # Python 3.5.3: use PROTOCOL_TLS
        sslc = ssl.SSLContext(ssl.PROTOCOL_SSLv23) if kind == 'SSL' else None

        if peer.is_tor:
            create_connection = self.tor_proxy.create_connection
        else:
            create_connection = self.loop.create_connection

        protocol_factory = partial(PeerSession, peer, self, kind)
        coro = create_connection(protocol_factory, peer.host, port, ssl=sslc)
        callback = partial(self.connection_done, peer, port_pairs)
        self.ensure_future(coro, callback)

    def connection_done(self, peer, port_pairs, future):
        '''Called when a connection attempt succeeds or fails.

        If failed, log it and try remaining port pairs.  If none,
        release the connection count semaphore.
        '''
        exception = future.exception()
        if exception:
            kind, port = port_pairs[0]
            self.logger.info('failed connecting to {} at {} port {:d}: {}'
                             .format(peer, kind, port, exception))
            port_pairs = port_pairs[1:]
            if port_pairs:
                self.retry_peer(peer, port_pairs)
            else:
                self.set_connection_status(peer, False)
                self.semaphore.release()

    def connection_lost(self, session):
        '''Called by the peer session when disconnected.'''
        self.semaphore.release()

    def set_connection_status(self, peer, good):
        '''Called when a connection succeeded or failed.'''
        if good:
            peer.try_count = 0
            peer.source = 'peer'
            # Remove matching IP addresses
            for match in peer.matches(self.peers):
                if match != peer and peer.host == peer.ip_addr:
                    self.peers.remove(match)
        else:
            self.maybe_forget_peer(peer)

    def maybe_forget_peer(self, peer):
        '''Forget the peer if appropriate, e.g. long-term unreachable.'''
        if peer.bad:
            forget = peer.last_connect < time.time() - STALE_SECS // 2
        else:
            try_limit = 10 if peer.last_connect else 3
            forget = peer.try_count >= try_limit

        if forget:
            desc = 'bad' if peer.bad else 'unreachable'
            self.logger.info('forgetting {} peer: {}'.format(desc, peer))
            self.peers.discard(peer)

        return forget
