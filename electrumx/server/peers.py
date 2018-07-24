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

from aiorpcx import ClientSession, RPCError, SOCKSProxy, ConnectionError

from electrumx.lib.peer import Peer
from electrumx.lib.util import class_logger, protocol_tuple


PEER_GOOD, PEER_STALE, PEER_NEVER, PEER_BAD = range(4)
STALE_SECS = 24 * 3600
WAKEUP_SECS = 300


class RequestError(Exception):
    pass


class BadPeerError(Exception):
    pass


def assert_good(request, instance):
    result = request.result()
    if not isinstance(result, instance):
        raise RequestError(f'{request} returned bad result type '
                           f'{type(result).__name__}')


class PeerSession(ClientSession):
    '''An outgoing session to a peer.'''

    def _header_notification(self, header):
        pass

    def notification_handler(self, method):
        # We subscribe so might be unlucky enough to get a notification...
        if method == 'blockchain.headers.subscribe':
            return self._header_notification
        return None


class PeerManager(object):
    '''Looks after the DB of peer network servers.

    Attempts to maintain a connection with up to 8 peers.
    Issues a 'peers.subscribe' RPC to them and tells them our data.
    '''
    def __init__(self, env, tasks, chain_state):
        self.logger = class_logger(__name__, self.__class__.__name__)
        # Initialise the Peer class
        Peer.DEFAULT_PORTS = env.coin.PEER_DEFAULT_PORTS
        self.env = env
        self.tasks = tasks
        self.chain_state = chain_state
        self.loop = tasks.loop

        # Our clearnet and Tor Peers, if any
        sclass = env.coin.SESSIONCLS
        self.myselves = [Peer(ident.host, sclass.server_features(env), 'env')
                         for ident in env.identities]
        self.server_version_args = sclass.server_version_args()
        self.retry_event = asyncio.Event()
        # Peers have one entry per hostname.  Once connected, the
        # ip_addr property is either None, an onion peer, or the
        # IP address that was connected to.  Adding a peer will evict
        # any other peers with the same host name or IP address.
        self.peers = set()
        self.permit_onion_peer_time = time.time()
        self.proxy = None
        self.last_proxy_try = 0

    def _my_clearnet_peer(self):
        '''Returns the clearnet peer representing this server, if any.'''
        clearnet = [peer for peer in self.myselves if not peer.is_tor]
        return clearnet[0] if clearnet else None

    def _set_peer_statuses(self):
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

    def _features_to_register(self, peer, remote_peers):
        '''If we should register ourselves to the remote peer, which has
        reported the given list of known peers, return the clearnet
        identity features to register, otherwise None.
        '''
        self.add_peers(remote_peers)

        # Announce ourself if not present.  Don't if disabled, we
        # are a non-public IP address, or to ourselves.
        if not self.env.peer_announce or peer in self.myselves:
            return None
        my = self._my_clearnet_peer()
        if not my or not my.is_public:
            return None
        # Register if no matches, or ports have changed
        for peer in my.matches(remote_peers):
            if peer.tcp_port == my.tcp_port and peer.ssl_port == my.ssl_port:
                return None
        return my.features

    def _permit_new_onion_peer(self):
        '''Accept a new onion peer only once per random time interval.'''
        now = time.time()
        if now < self.permit_onion_peer_time:
            return False
        self.permit_onion_peer_time = now + random.randrange(0, 1200)
        return True

    def _import_peers(self):
        '''Import hard-coded peers from a file or the coin defaults.'''
        self.add_peers(self.myselves)

        # Add the hard-coded ones unless only returning self
        if self.env.peer_discovery != self.env.PD_SELF:
            coin_peers = self.env.coin.PEERS
            peers = [Peer.from_real_name(real_name, 'coins.py')
                     for real_name in coin_peers]
            self.add_peers(peers, limit=None)

    async def _maybe_detect_proxy(self):
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
        else:
            self.logger.info('no proxy detected')

    async def _discover_peers(self):
        '''Main loop performing peer maintenance.  This includes

          1) Forgetting unreachable peers.
          2) Verifying connectivity of new peers.
          3) Retrying old peers at regular intervals.
        '''
        self._import_peers()

        while True:
            await self._maybe_detect_proxy()
            await self._retry_peers()
            timeout = self.loop.call_later(WAKEUP_SECS, self.retry_event.set)
            await self.retry_event.wait()
            self.retry_event.clear()
            timeout.cancel()

    async def _retry_peers(self):
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

        for peer in self.peers:
            if should_retry(peer):
                self.tasks.create_task(self._retry_peer(peer))

    async def _retry_peer(self, peer):
        peer.try_count += 1
        success = False

        for kind, port in peer.connection_port_pairs():
            peer.last_try = time.time()

            kwargs = {}
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

            try:
                async with PeerSession(peer.host, port, **kwargs) as session:
                    await self._verify_peer(session, peer)
                success = True
            except RPCError as e:
                self.logger.error(f'[{peer}] RPC error: {e.message} '
                                  f'({e.code})')
            except (RequestError, asyncio.TimeoutError) as e:
                self.logger.error(f'[{peer}] {e}')
            except BadPeerError as e:
                self.logger.error(f'[{peer}] marking bad: ({e})')
                peer.mark_bad()
            except (OSError, ConnectionError) as e:
                self.logger.info(f'[{peer}] {kind} connection to '
                                 f'port {port} failed: {e}')
                continue

            self._set_verification_status(peer, kind, success)
            if success:
                return

        self._maybe_forget_peer(peer)

    async def _verify_peer(self, session, peer):
        if not peer.is_tor:
            address = session.peer_address()
            if address:
                peer.ip_addr = address[0]

        timeout = 20 if peer.is_tor else 10

        # server.version goes first
        request = session.send_request(
            'server.version', self.server_version_args, timeout=timeout)
        result = await request
        assert_good(request, list)

        # Protocol version 1.1 returns a pair with the version first
        if len(result) != 2 or not all(isinstance(x, str) for x in result):
            raise RequestFailure(f'bad server.version result: {result}')
        server_version, protocol_version = result
        peer.server_version = server_version
        peer.features['server_version'] = server_version
        ptuple = protocol_tuple(protocol_version)

        jobs = [self.tasks.create_task(message) for message in (
            self._send_headers_subscribe(session, peer, timeout, ptuple),
            self._send_server_features(session, peer, timeout),
            self._send_peers_subscribe(session, peer, timeout)
        )]
        await asyncio.wait(jobs)

    async def _send_headers_subscribe(self, session, peer, timeout, ptuple):
        request = session.send_request('blockchain.headers.subscribe',
                                       timeout=timeout)
        result = await request
        assert_good(request, dict)

        our_height = self.chain_state.db_height()
        if ptuple < (1, 3):
            their_height = result.get('block_height')
        else:
            their_height = result.get('height')
        if not isinstance(their_height, int):
            raise BadPeerError(f'invalid height {their_height}')
        if abs(our_height - their_height) > 5:
            raise BadPeerError(f'bad height {their_height:,d} '
                               f'(ours: {our_height:,d})')

        # Check prior header too in case of hard fork.
        check_height = min(our_height, their_height)
        raw_header = self.chain_state.raw_header(check_height)
        if ptuple >= (1, 4):
            ours = raw_header.hex()
            request = session.send_request('blockchain.block.header',
                                           [check_height], timeout=timeout)
            theirs = await request
            assert_good(request, str)
            if ours != theirs:
                raise BadPeerError(f'our header {ours} and '
                                   f'theirs {theirs} differ')
        else:
            ours = self.env.coin.electrum_header(raw_header, check_height)
            request = session.send_request('blockchain.block.get_header',
                                           [check_height], timeout=timeout)
            result = await request
            assert_good(request, dict)
            theirs = result.get('prev_block_hash')
            ours = ours.get('prev_block_hash')
            if ours != theirs:
                raise BadPeerError(f'our header hash {ours} and '
                                   f'theirs {theirs} differ')

    async def _send_server_features(self, session, peer, timeout):
        request = session.send_request('server.features', timeout=timeout)
        features = await request
        assert_good(request, dict)
        hosts = [host.lower() for host in features.get('hosts', {})]
        if self.env.coin.GENESIS_HASH != features.get('genesis_hash'):
            raise BadPeerError('incorrect genesis hash')
        elif peer.host.lower() in hosts:
            peer.update_features(features)
        else:
            raise BadPeerError(f'not listed in own hosts list {hosts}')

    async def _send_peers_subscribe(self, session, peer, timeout):
        request = session.send_request('server.peers.subscribe',
                                       timeout=timeout)
        raw_peers = await request
        assert_good(request, list)

        # Check the peers list we got from a remote peer.
        # Each is expected to be of the form:
        #    [ip_addr, hostname, ['v1.0', 't51001', 's51002']]
        # Call add_peer if the remote doesn't appear to know about us.
        try:
            real_names = [' '.join([u[1]] + u[2]) for u in raw_peers]
            peers = [Peer.from_real_name(real_name, str(peer))
                     for real_name in real_names]
        except Exception:
            raise BadPeerError('bad server.peers.subscribe response')

        features = self._features_to_register(peer, peers)
        if not features:
            return
        self.logger.info(f'registering ourself with {peer}')
        request = session.send_request('server.add_peer', [features],
                                       timeout=timeout)
        # We only care to wait for the response
        await request

    def _set_verification_status(self, peer, kind, good):
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
            self._maybe_forget_peer(peer)

    def _maybe_forget_peer(self, peer):
        '''Forget the peer if appropriate, e.g. long-term unreachable.'''
        if peer.last_good and not peer.bad:
            try_limit = 10
        else:
            try_limit = 3
        forget = peer.try_count >= try_limit

        if forget:
            desc = 'bad' if peer.bad else 'unreachable'
            self.logger.info(f'forgetting {desc} peer: {peer}')
            self.peers.discard(peer)

    #
    # External interface
    #
    def start_peer_discovery(self):
        if self.env.peer_discovery == self.env.PD_ON:
            self.logger.info(f'beginning peer discovery. Force use of '
                             f'proxy: {self.env.force_proxy}')
            self.tasks.create_task(self._discover_peers())
        else:
            self.logger.info('peer discovery is disabled')

    def add_peers(self, peers, limit=2, check_ports=False, source=None):
        '''Add a limited number of peers that are not already present.'''
        retry = False
        new_peers = []
        for peer in peers:
            if not peer.is_public or (peer.is_tor and not self.proxy):
                continue

            matches = peer.matches(self.peers)
            if not matches:
                new_peers.append(peer)
            elif check_ports:
                for match in matches:
                    if match.check_ports(peer):
                        self.logger.info(f'ports changed for {peer}')
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
                self.logger.info(f'accepted new peer {n+1}/{len(use_peers)} '
                                 f'{peer} from {source}')
            self.peers.update(use_peers)

        if retry:
            self.retry_event.set()

    def info(self):
        '''The number of peers.'''
        self._set_peer_statuses()
        counter = Counter(peer.status for peer in self.peers)
        return {
            'bad': counter[PEER_BAD],
            'good': counter[PEER_GOOD],
            'never': counter[PEER_NEVER],
            'stale': counter[PEER_STALE],
            'total': len(self.peers),
        }

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
            permit = self._permit_new_onion_peer()
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
            self.logger.info(f'accepted add_peer request from {source} '
                             f'for {host}')
            self.add_peers([peer], check_ports=True)
        else:
            self.logger.warning(f'rejected add_peer request from {source} '
                                f'for {host} ({reason})')

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

    def proxy_peername(self):
        '''Return the peername of the proxy, if there is a proxy, otherwise
        None.'''
        return self.proxy.peername if self.proxy else None

    def rpc_data(self):
        '''Peer data for the peers RPC method.'''
        self._set_peer_statuses()
        descs = ['good', 'stale', 'never', 'bad']

        def peer_data(peer):
            data = peer.serialize()
            data['status'] = descs[peer.status]
            return data

        def peer_key(peer):
            return (peer.bad, -peer.last_good)

        return [peer_data(peer) for peer in sorted(self.peers, key=peer_key)]
