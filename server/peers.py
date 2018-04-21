# Copyright (c) 2017, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Peer management.'''

import asyncio
import logging
import random
import socket
import ssl
import time
from collections import defaultdict, Counter
from functools import partial

from aiorpcx import ClientSession, RPCError, SOCKSProxy

from lib.peer import Peer
from lib.util import ConnectionLogger


PEER_GOOD, PEER_STALE, PEER_NEVER, PEER_BAD = range(4)
STALE_SECS = 24 * 3600
WAKEUP_SECS = 300


class PeerSession(ClientSession):
    '''An outgoing session to a peer.'''

    sessions = set()

    def __init__(self, peer, peer_mgr, kind, host, port, **kwargs):
        super().__init__(host, port, **kwargs)
        self.peer = peer
        self.peer_mgr = peer_mgr
        self.kind = kind
        self.timeout = 20 if self.peer.is_tor else 10
        context = {'conn_id': f'{host}'}
        self.logger = ConnectionLogger(self.logger, context)

    def connection_made(self, transport):
        super().connection_made(transport)
        self.sessions.add(self)

        # Update IP address if not Tor
        if not self.peer.is_tor:
            address = self.peer_address()
            if address:
                self.peer.ip_addr = address[0]

        # Send server.version first
        controller = self.peer_mgr.controller
        self.send_request('server.version', controller.server_version_args(),
                          self.on_version, timeout=self.timeout)

    def connection_lost(self, exc):
        '''Handle an incoming client connection.'''
        super().connection_lost(exc)
        self.sessions.remove(self)

    def _header_notification(self, header):
        pass

    def notification_handler(self, method):
        # We subscribe so might be unlucky enough to get a notification...
        if method == 'blockchain.headers.subscribe':
            return self._header_notification
        return None

    def is_good(self, request, instance):
        try:
            result = request.result()
        except asyncio.CancelledError:
            return False
        except asyncio.TimeoutError as e:
            self.fail(request, str(e))
            return False
        except RPCError as error:
            self.fail(request, f'{error.message} ({error.code})')
            return False

        if isinstance(result, instance):
            return True

        self.fail(request, f'{request} returned bad result type '
                  f'{type(result).__name__}')
        return False

    def fail(self, request, reason):
        self.logger.error(f'{request} failed: {reason}')
        self.peer_mgr.set_verification_status(self.peer, self.kind, False)
        self.close()

    def bad(self, reason):
        self.logger.error(f'marking bad: {reason}')
        self.peer.mark_bad()
        self.peer_mgr.set_verification_status(self.peer, self.kind, False)
        self.close()

    def on_version(self, request):
        '''Handle the response to the version message.'''
        if not self.is_good(request, (list, str)):
            return

        result = request.result()
        if isinstance(result, str):
            version = result
        else:
            # Protocol version 1.1 returns a pair with the version first
            if len(result) < 2 or not isinstance(result[0], str):
                self.fail(request, 'result array bad format')
                return
            version = result[0]
        self.peer.server_version = version
        self.peer.features['server_version'] = version

        for method, on_done in [
            ('blockchain.headers.subscribe', self.on_height),
            ('server.features', self.on_features),
            ('server.peers.subscribe', self.on_peers_subscribe),
        ]:
            self.send_request(method, on_done=on_done, timeout=self.timeout)

    def on_features(self, request):
        if not self.is_good(request, dict):
            return

        features = request.result()
        hosts = [host.lower() for host in features.get('hosts', {})]
        our_hash = self.peer_mgr.env.coin.GENESIS_HASH
        if our_hash != features.get('genesis_hash'):
            self.bad('incorrect genesis hash')
        elif self.peer.host.lower() in hosts:
            self.peer.update_features(features)
            self.maybe_close()
        else:
            self.bad('ignoring - not listed in host list {}'.format(hosts))

    def on_height(self, request):
        '''Handle the response to blockchain.headers.subscribe message.'''
        if not self.is_good(request, dict):
            return

        result = request.result()
        controller = self.peer_mgr.controller
        our_height = controller.bp.db_height
        their_height = result.get('block_height')
        if not isinstance(their_height, int):
            self.bad('invalid height {}'.format(their_height))
            return
        if abs(our_height - their_height) > 5:
            self.bad('bad height {:,d} (ours: {:,d})'
                     .format(their_height, our_height))
            return
        # Check prior header too in case of hard fork.
        check_height = min(our_height, their_height)
        expected_header = controller.electrum_header(check_height)
        self.send_request('blockchain.block.get_header', [check_height],
                          partial(self.on_header, expected_header),
                          timeout=self.timeout)

    def on_header(self, expected_header, request):
        '''Handle the response to blockchain.block.get_header message.
        Compare hashes of prior header in attempt to determine if forked.'''
        if not self.is_good(request, dict):
            return

        result = request.result()
        theirs = result.get('prev_block_hash')
        ours = expected_header.get('prev_block_hash')
        if ours == theirs:
            self.maybe_close()
        else:
            self.bad('our header hash {} and theirs {} differ'
                     .format(ours, theirs))

    def on_peers_subscribe(self, request):
        '''Handle the response to the peers.subcribe message.'''
        if not self.is_good(request, list):
            return

        # Check the peers list we got from a remote peer.
        # Each is expected to be of the form:
        #    [ip_addr, hostname, ['v1.0', 't51001', 's51002']]
        # Call add_peer if the remote doesn't appear to know about us.
        raw_peers = request.result()
        try:
            real_names = [' '.join([u[1]] + u[2]) for u in raw_peers]
            peers = [Peer.from_real_name(real_name, str(self.peer))
                     for real_name in real_names]
        except Exception:
            self.bad('bad server.peers.subscribe response')
            return

        features = self.peer_mgr.features_to_register(self.peer, peers)
        if features:
            self.logger.info(f'registering ourself with "server.add_peer"')
            self.send_request('server.add_peer', [features],
                              self.on_add_peer, timeout=self.timeout)
        else:
            self.maybe_close()

    def on_add_peer(self, request):
        '''We got a response the add_peer message.  Don't care about its
        form.'''
        self.maybe_close()

    def maybe_close(self):
        '''Close the connection if no requests are outstanding, and mark peer
        as good.
        '''
        if not self.all_requests():
            self.close()
            self.peer_mgr.set_verification_status(self.peer, self.kind, True)


class PeerManager(object):
    '''Looks after the DB of peer network servers.

    Attempts to maintain a connection with up to 8 peers.
    Issues a 'peers.subscribe' RPC to them and tells them our data.
    '''
    def __init__(self, env, controller):
        self.logger = logging.getLogger(self.__class__.__name__)
        # Initialise the Peer class
        Peer.DEFAULT_PORTS = env.coin.PEER_DEFAULT_PORTS
        self.env = env
        self.controller = controller
        self.loop = controller.loop

        # Our clearnet and Tor Peers, if any
        self.myselves =  [Peer(ident.host, controller.server_features(), 'env')
                          for ident in env.identities]
        self.retry_event = asyncio.Event()
        # Peers have one entry per hostname.  Once connected, the
        # ip_addr property is either None, an onion peer, or the
        # IP address that was connected to.  Adding a peer will evict
        # any other peers with the same host name or IP address.
        self.peers = set()
        self.permit_onion_peer_time = time.time()
        self.proxy = None
        self.last_proxy_try = 0

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

    def features_to_register(self, peer, remote_peers):
        '''If we should register ourselves to the remote peer, which has
        reported the given list of known peers, return the clearnet
        identity features to register, otherwise None.
        '''
        self.add_peers(remote_peers)

        # Announce ourself if not present.  Don't if disabled, we
        # are a non-public IP address, or to ourselves.
        if not self.env.peer_announce or peer in self.myselves:
            return None
        my = self.my_clearnet_peer()
        if not my or not my.is_public:
            return None
        # Register if no matches, or ports have changed
        for peer in my.matches(remote_peers):
            if peer.tcp_port == my.tcp_port and peer.ssl_port == my.ssl_port:
                return None
        return my.features

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
            self.logger.info('ignored add_peer request: no source info')
            return False
        source = source_info[0]
        peers = Peer.peers_from_features(features, source)
        if not peers:
            self.logger.info('ignored add_peer request: no peers given')
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
            self.logger.info('accepted add_peer request from {} for {}'
                             .format(source, host))
            self.add_peers([peer], check_ports=True)
        else:
            self.logger.warning('rejected add_peer request from {} for {} ({})'
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

    async def maybe_detect_proxy(self):
        '''Detect a proxy if we don't have one and some time has passed since
        the last attempt.

        If found self.proxy is set to a SOCKSProxy instance, otherwise
        None.
        '''
        if self.proxy or time.time() - self.last_proxy_try < 900:
            return
        self.last_proxy_try = time.time()

        host = self.env.tor_proxy_host
        if self.env.tor_proxy_port is None:
            ports = [9050, 9150, 1080]
        else:
            ports = [self.env.tor_proxy_port]
        self.logger.info(f'trying to detect proxy on "{host}" ports {ports}')

        cls = SOCKSProxy
        result = await cls.auto_detect_host(host, ports, None, loop=self.loop)
        if isinstance(result, cls):
            self.proxy = result
            self.logger.info(f'detected {self.proxy}')

    def proxy_peername(self):
        '''Return the peername of the proxy, if there is a proxy, otherwise
        None.'''
        return self.proxy.peername if self.proxy else None

    async def main_loop(self):
        '''Main loop performing peer maintenance.  This includes

          1) Forgetting unreachable peers.
          2) Verifying connectivity of new peers.
          3) Retrying old peers at regular intervals.
        '''
        if self.env.peer_discovery != self.env.PD_ON:
            self.logger.info('peer discovery is disabled')
            return

        self.logger.info('beginning peer discovery. Force use of proxy: {}'
                         .format(self.env.force_proxy))

        self.import_peers()
        await self.maybe_detect_proxy()

        try:
            while True:
                timeout = self.loop.call_later(WAKEUP_SECS,
                                               self.retry_event.set)
                await self.retry_event.wait()
                self.retry_event.clear()
                timeout.cancel()
                await self.retry_peers()
        finally:
            for session in list(PeerSession.sessions):
                session.abort()
                await session.wait_closed()

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

        if self.env.force_proxy or any(peer.is_tor for peer in peers):
            await self.maybe_detect_proxy()

        for peer in peers:
            peer.try_count += 1
            pairs = peer.connection_port_pairs()
            if peer.bad or not pairs:
                self.maybe_forget_peer(peer)
            else:
                self.retry_peer(peer, pairs)

    def retry_peer(self, peer, port_pairs):
        peer.last_try = time.time()

        kwargs = {'loop': self.loop}

        kind, port = port_pairs[0]
        if kind == 'SSL':
            kwargs['ssl'] = ssl.SSLContext(ssl.PROTOCOL_TLS)

        host = self.env.cs_host(for_rpc=False)
        if isinstance(host, list):
            host = host[0]

        if self.env.force_proxy or peer.is_tor:
            if not self.proxy:
                return
            kwargs['proxy'] = self.proxy
            kwargs['resolve'] = not peer.is_tor
        elif host:
            # Use our listening Host/IP for outgoing non-proxy
            # connections so our peers see the correct source.
            kwargs['local_addr'] = (host, None)

        session = PeerSession(peer, self, kind, peer.host, port, **kwargs)
        callback = partial(self.on_connected, peer, port_pairs)
        self.controller.create_task(session.create_connection(), callback)

    def on_connected(self, peer, port_pairs, task):
        '''Called when a connection attempt succeeds or fails.

        If failed, close the session, log it and try remaining port pairs.
        '''
        if not task.cancelled() and task.exception():
            kind, port = port_pairs.pop(0)
            elapsed = time.time() - peer.last_try
            self.logger.info(f'failed connecting to {peer} at {kind} port '
                             f'{port} in {elapsed:.1f}s: {task.exception()}')
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
        self.logger.info(f'{status} {peer} {how} in {elapsed:.1f}s')

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
