# Copyright (c) 2017, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Peer management.'''

import asyncio
import random
import socket
import ssl
import time
from collections import defaultdict, Counter
from functools import partial

from lib.jsonrpc import JSONSession
from lib.peer import Peer
from lib.socks import SocksProxy
import lib.util as util
import server.version as version


PEER_GOOD, PEER_STALE, PEER_NEVER, PEER_BAD = range(4)
STALE_SECS = 24 * 3600
WAKEUP_SECS = 300


class PeerSession(JSONSession):
    '''An outgoing session to a peer.'''

    def __init__(self, peer, peer_mgr, kind):
        super().__init__()
        self.max_send = 0
        self.peer = peer
        self.peer_mgr = peer_mgr
        self.kind = kind
        self.failed = False
        self.bad = False
        self.remote_peers = None
        self.log_prefix = '[{}] '.format(self.peer)

    async def wait_on_items(self):
        while True:
            await self.items_event.wait()
            await self.process_pending_items()

    def connection_made(self, transport):
        '''Handle an incoming client connection.'''
        super().connection_made(transport)
        self.log_prefix = '[{}] '.format(str(self.peer)[:25])
        self.future = self.peer_mgr.ensure_future(self.wait_on_items())

        # Update IP address
        if not self.peer.is_tor:
            peer_info = self.peer_info()
            if peer_info:
                self.peer.ip_addr = peer_info[0]

        # Collect data
        proto_ver = (version.PROTOCOL_MIN, version.PROTOCOL_MAX)
        self.send_request(self.on_version, 'server.version',
                          [version.VERSION, proto_ver])
        self.send_request(self.on_features, 'server.features')
        self.send_request(self.on_height, 'blockchain.headers.subscribe')
        self.send_request(self.on_peers_subscribe, 'server.peers.subscribe')

    def connection_lost(self, exc):
        '''Handle disconnection.'''
        super().connection_lost(exc)
        self.future.cancel()

    def on_peers_subscribe(self, result, error):
        '''Handle the response to the peers.subcribe message.'''
        if error:
            self.failed = True
            self.log_error('server.peers.subscribe: {}'.format(error))
        else:
            # Save for later analysis
            self.remote_peers = result
        self.close_if_done()

    def on_add_peer(self, result, error):
        '''We got a response the add_peer message.'''
        # This is the last thing we were waiting for; shutdown the connection
        self.shutdown_connection()

    def on_features(self, features, error):
        # Several peers don't implement this.  If they do, check they are
        # the same network with the genesis hash.
        if not error and isinstance(features, dict):
            hosts = [host.lower() for host in features.get('hosts', {})]
            our_hash = self.peer_mgr.env.coin.GENESIS_HASH
            if our_hash != features.get('genesis_hash'):
                self.bad = True
                self.log_warning('incorrect genesis hash')
            elif self.peer.host.lower() in hosts:
                self.peer.update_features(features)
            else:
                self.bad = True
                self.log_warning('ignoring - not listed in host list {}'
                                 .format(hosts))
        self.close_if_done()

    def on_height(self, result, error):
        '''Handle the response to blockchain.headers.subscribe message.'''
        if error:
            self.failed = True
            self.log_error('blockchain.headers.subscribe returned an error')
        elif not isinstance(result, dict):
            self.bad = True
            self.log_error('bad blockchain.headers.subscribe response')
        else:
            controller = self.peer_mgr.controller
            our_height = controller.bp.db_height
            their_height = result.get('block_height')
            if not isinstance(their_height, int):
                self.log_warning('invalid height {}'.format(their_height))
                self.bad = True
            elif abs(our_height - their_height) > 5:
                self.log_warning('bad height {:,d} (ours: {:,d})'
                                 .format(their_height, our_height))
                self.bad = True

            # Check prior header too in case of hard fork.
            if not self.bad:
                check_height = min(our_height, their_height)
                self.send_request(self.on_header, 'blockchain.block.get_header',
                                  [check_height])
                self.expected_header = controller.electrum_header(check_height)
        self.close_if_done()

    def on_header(self, result, error):
        '''Handle the response to blockchain.block.get_header message.
        Compare hashes of prior header in attempt to determine if forked.'''
        if error:
            self.failed = True
            self.log_error('blockchain.block.get_header returned an error')
        elif not isinstance(result, dict):
            self.bad = True
            self.log_error('bad blockchain.block.get_header response')
        else:
            theirs = result.get('prev_block_hash')
            ours = self.expected_header.get('prev_block_hash')
            if ours != theirs:
                self.log_error('our header hash {} and theirs {} differ'
                               .format(ours, theirs))
                self.bad = True

        self.close_if_done()

    def on_version(self, result, error):
        '''Handle the response to the version message.'''
        if error:
            self.failed = True
            self.log_error('server.version returned an error')
        else:
            # Protocol version 1.1 returns a pair with the version first
            if isinstance(result, list) and len(result) == 2:
                result = result[0]
            if isinstance(result, str):
                self.peer.server_version = result
                self.peer.features['server_version'] = result
        self.close_if_done()

    def check_remote_peers(self):
        '''Check the peers list we got from a remote peer.

        Each update is expected to be of the form:
            [ip_addr, hostname, ['v1.0', 't51001', 's51002']]

        Call add_peer if the remote doesn't appear to know about us.
        '''
        try:
            real_names = [' '.join([u[1]] + u[2]) for u in self.remote_peers]
            peers = [Peer.from_real_name(real_name, str(self.peer))
                     for real_name in real_names]
        except Exception:
            self.log_error('bad server.peers.subscribe response')
            return

        self.peer_mgr.add_peers(peers)

        # Announce ourself if not present.  Don't if disabled, we
        # are a non-public IP address, or to ourselves.
        if not self.peer_mgr.env.peer_announce:
            return
        if self.peer in self.peer_mgr.myselves:
            return
        my = self.peer_mgr.my_clearnet_peer()
        if not my or not my.is_public:
            return
        for peer in my.matches(peers):
            if peer.tcp_port == my.tcp_port and peer.ssl_port == my.ssl_port:
                return

        self.log_info('registering ourself with server.add_peer')
        self.send_request(self.on_add_peer, 'server.add_peer', [my.features])

    def close_if_done(self):
        if not self.has_pending_requests():
            if self.bad:
                self.peer.mark_bad()
            elif self.remote_peers:
                self.check_remote_peers()
            # We might now be waiting for an add_peer response
            if not self.has_pending_requests():
                self.shutdown_connection()

    def shutdown_connection(self):
        is_good = not (self.failed or self.bad)
        self.peer_mgr.set_verification_status(self.peer, self.kind, is_good)
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

        # Our clearnet and Tor Peers, if any
        self.myselves =  [Peer(ident.host, env.server_features(), 'env')
                          for ident in env.identities]
        self.retry_event = asyncio.Event()
        # Peers have one entry per hostname.  Once connected, the
        # ip_addr property is either None, an onion peer, or the
        # IP address that was connected to.  Adding a peer will evict
        # any other peers with the same host name or IP address.
        self.peers = set()
        self.permit_onion_peer_time = time.time()
        self.proxy = SocksProxy(env.tor_proxy_host, env.tor_proxy_port,
                                loop=self.loop)
        self.import_peers()

    def my_clearnet_peer(self):
        '''Returns the clearnet peer representing this server, if any.'''
        clearnet = [peer for peer in self.myselves if not peer.is_tor]
        return clearnet[0] if clearnet else None

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
            elif peer.last_good > cutoff:
                peer.status = PEER_GOOD
            elif peer.last_good:
                peer.status = PEER_STALE
            else:
                peer.status = PEER_NEVER

    def rpc_data(self):
        '''Peer data for the peers RPC method.'''
        self.set_peer_statuses()
        descs = ['good', 'stale', 'never', 'bad']

        def peer_data(peer):
            data = peer.serialize()
            data['status'] = descs[peer.status]
            return data

        def peer_key(peer):
            return (peer.bad, -peer.last_good)

        return [peer_data(peer) for peer in sorted(self.peers, key=peer_key)]

    def add_peers(self, peers, limit=2, check_ports=False, source=None):
        '''Add a limited number of peers that are not already present.'''
        retry = False
        new_peers = []
        for peer in peers:
            if not peer.is_public:
                continue
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
            for n, peer in enumerate(use_peers):
                self.logger.info('accepted new peer {:d}/{:d} {} from {} '
                                 .format(n + 1, len(use_peers), peer, source))
            self.peers.update(use_peers)

        if retry:
            self.retry_event.set()

    def permit_new_onion_peer(self):
        '''Accept a new onion peer only once per random time interval.'''
        now = time.time()
        if now < self.permit_onion_peer_time:
            return False
        self.permit_onion_peer_time = now + random.randrange(0, 1200)
        return True

    async def on_add_peer(self, features, source_info):
        '''Add a peer (but only if the peer resolves to the source).'''
        if not source_info:
            self.log_info('ignored add_peer request: no source info')
            return False
        source = source_info[0]
        peers = Peer.peers_from_features(features, source)
        if not peers:
            self.log_info('ignored add_peer request: no peers given')
            return False

        # Just look at the first peer, require it
        peer = peers[0]
        host = peer.host
        if peer.is_tor:
            permit = self.permit_new_onion_peer()
            reason = 'rate limiting'
        else:
            try:
                infos = await self.loop.getaddrinfo(host, 80,
                                                    type=socket.SOCK_STREAM)
            except socket.gaierror:
                permit = False
                reason = 'address resolution failure'
            else:
                permit = any(source == info[-1][0] for info in infos)
                reason = 'source-destination mismatch'

        if permit:
            self.log_info('accepted add_peer request from {} for {}'
                          .format(source, host))
            self.add_peers([peer], check_ports=True)
        else:
            self.log_warning('rejected add_peer request from {} for {} ({})'
                             .format(source, host, reason))

        return permit

    def on_peers_subscribe(self, is_tor):
        '''Returns the server peers as a list of (ip, host, details) tuples.

        We return all peers we've connected to in the last day.
        Additionally, if we don't have onion routing, we return a few
        hard-coded onion servers.
        '''
        cutoff = time.time() - STALE_SECS
        recent = [peer for peer in self.peers
                  if peer.last_good > cutoff and
                  not peer.bad and peer.is_public]
        onion_peers = []

        # Always report ourselves if valid (even if not public)
        peers = set(myself for myself in self.myselves
                    if myself.last_good > cutoff)

        # Bucket the clearnet peers and select up to two from each
        buckets = defaultdict(list)
        for peer in recent:
            if peer.is_tor:
                onion_peers.append(peer)
            else:
                buckets[peer.bucket()].append(peer)
        for bucket_peers in buckets.values():
            random.shuffle(bucket_peers)
            peers.update(bucket_peers[:2])

        # Add up to 20% onion peers (but up to 10 is OK anyway)
        random.shuffle(onion_peers)
        max_onion = 50 if is_tor else max(10, len(peers) // 4)

        peers.update(onion_peers[:max_onion])

        return [peer.to_tuple() for peer in peers]

    def import_peers(self):
        '''Import hard-coded peers from a file or the coin defaults.'''
        self.add_peers(self.myselves)

        # Add the hard-coded ones unless only returning self
        if self.env.peer_discovery != self.env.PD_SELF:
            coin_peers = self.env.coin.PEERS
            peers = [Peer.from_real_name(real_name, 'coins.py')
                     for real_name in coin_peers]
            self.add_peers(peers, limit=None)

    def ensure_future(self, coro, callback=None):
        '''Schedule the coro to be run.'''
        return self.controller.ensure_future(coro, callback=callback)

    async def main_loop(self):
        '''Main loop performing peer maintenance.  This includes

          1) Forgetting unreachable peers.
          2) Verifying connectivity of new peers.
          3) Retrying old peers at regular intervals.
        '''
        if self.env.peer_discovery != self.env.PD_ON:
            self.logger.info('peer discovery is disabled')
            return

        # Wait a few seconds after starting the proxy detection loop
        # for proxy detection to succeed
        self.ensure_future(self.proxy.auto_detect_loop())
        await self.proxy.tried_event.wait()

        self.logger.info('beginning peer discovery; force use of proxy: {}'
                         .format(self.env.force_proxy))

        while True:
            timeout = self.loop.call_later(WAKEUP_SECS, self.retry_event.set)
            await self.retry_event.wait()
            self.retry_event.clear()
            timeout.cancel()
            await self.retry_peers()

    def is_coin_onion_peer(self, peer):
        '''Return true if this peer is a hard-coded onion peer.'''
        return peer.is_tor and any(peer.host in real_name
                                   for real_name in self.env.coin.PEERS)

    async def retry_peers(self):
        '''Retry peers that are close to getting stale.'''
        # Exponential backoff of retries
        now = time.time()
        nearly_stale_time = (now - STALE_SECS) + WAKEUP_SECS * 2

        def should_retry(peer):
            # Retry a peer whose ports might have updated
            if peer.other_port_pairs:
                return True
            # Retry a good connection if it is about to turn stale
            if peer.try_count == 0:
                return peer.last_good < nearly_stale_time
            # Retry a failed connection if enough time has passed
            return peer.last_try < now - WAKEUP_SECS * 2 ** peer.try_count

        peers = [peer for peer in self.peers if should_retry(peer)]

        for peer in peers:
            peer.try_count += 1
            pairs = peer.connection_port_pairs()
            if peer.bad or not pairs:
                self.maybe_forget_peer(peer)
            else:
                self.retry_peer(peer, pairs)

    def retry_peer(self, peer, port_pairs):
        peer.last_try = time.time()
        kind, port = port_pairs[0]
        sslc = ssl.SSLContext(ssl.PROTOCOL_TLS) if kind == 'SSL' else None

        if self.env.force_proxy or peer.is_tor:
            # Only attempt a proxy connection if the proxy is up
            if not self.proxy.is_up():
                return
            create_connection = self.proxy.create_connection
        else:
            create_connection = self.loop.create_connection

        # Use our listening Host/IP for outgoing connections so our
        # peers see the correct source.
        host = self.env.cs_host(for_rpc=False)
        if isinstance(host, list):
            host = host[0]
        local_addr = (host, None) if host else None

        protocol_factory = partial(PeerSession, peer, self, kind)
        coro = create_connection(protocol_factory, peer.host, port, ssl=sslc,
                                 local_addr=local_addr)
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
            self.logger.info('failed connecting to {} at {} port {:d} '
                             'in {:.1f}s: {}'
                             .format(peer, kind, port,
                                     time.time() - peer.last_try, exception))
            port_pairs = port_pairs[1:]
            if port_pairs:
                self.retry_peer(peer, port_pairs)
            else:
                self.maybe_forget_peer(peer)

    def set_verification_status(self, peer, kind, good):
        '''Called when a verification succeeded or failed.'''
        now = time.time()
        if self.env.force_proxy or peer.is_tor:
            how = 'via {} over Tor'.format(kind)
        else:
            how = 'via {} at {}'.format(kind, peer.ip_addr)
        status = 'verified' if good else 'failed to verify'
        elapsed = now - peer.last_try
        self.log_info('{} {} {} in {:.1f}s'.format(status, peer, how, elapsed))

        if good:
            peer.try_count = 0
            peer.last_good = now
            peer.source = 'peer'
            # At most 2 matches if we're a host name, potentially several if
            # we're an IP address (several instances can share a NAT).
            matches = peer.matches(self.peers)
            for match in matches:
                if match.ip_address:
                    if len(matches) > 1:
                        self.peers.remove(match)
                elif peer.host in match.features['hosts']:
                    match.update_features_from_peer(peer)
        else:
            self.maybe_forget_peer(peer)

    def maybe_forget_peer(self, peer):
        '''Forget the peer if appropriate, e.g. long-term unreachable.'''
        if peer.last_good and not peer.bad:
            try_limit = 10
        else:
            try_limit = 3
        forget = peer.try_count >= try_limit

        if forget:
            desc = 'bad' if peer.bad else 'unreachable'
            self.logger.info('forgetting {} peer: {}'.format(desc, peer))
            self.peers.discard(peer)

        return forget
