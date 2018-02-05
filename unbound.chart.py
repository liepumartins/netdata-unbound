# -*- coding: utf-8 -*-
# Description: unbound dns server netdata python.d module
# Authors: liepumartins

from subprocess import Popen, PIPE
from copy import deepcopy

from bases.collection import find_binary
from bases.FrameworkServices.ExecutableService import ExecutableService

priority = 60000
retries = 60
update_every = 1

ORDER = ['answers', 'num_queries', 'num_queries_flags', 'memory', 'cache']

METRICS = dict(
    THREAD=[
        'num.queries',
        # number of queries received by thread
        'num.queries_ip_ratelimited',
        # number of queries rate limited by thread
        'num.cachehits',
        # number of queries that were successfully answered using a  cache lookup
        'num.cachemiss',
        # number of queries that needed recursive processing
        'num.dnscrypt.crypted',
        # number  of queries that were encrypted and successfully decapsulated by dnscrypt.
        'num.dnscrypt.cert',
        # number of queries that were requesting dnscrypt certificates.
        'num.dnscrypt.cleartext',
        # number of queries received on dnscrypt port that were  cleartext and not a request for certificates.
        'num.dnscrypt.malformed',
        # number  of  request  that  were  neither  cleartext,  not  valid dnscrypt messages.
        'num.prefetch',
        # number of cache prefetches performed.  This number  is  included in  cachehits, as the original query
        # had the unprefetched answer from cache, and resulted in recursive processing, taking a slot in the
        # requestlist. Not part of the recursivereplies (or the histogram thereof) or cachemiss,
        # as a cache response was sent.
        'num.zero_ttl',
        # number of replies with ttl zero, because they served an  expired cache entry.
        'num.recursivereplies',
        # The number of replies sent to queries that needed recursive pro-cessing.
        # Could be smaller than threadX.num.cachemiss if due to
        # timeouts no replies were sent for some queries.
        'requestlist.avg',
        # The  average  number  of requests in the internal recursive pro-cessing request
        # list on insert of a new incoming recursive  pro-cessing query.
        'requestlist.max',
        # Maximum  size  attained  by  the  internal  recursive processing request list.
        'requestlist.overwritten',
        # Number of requests in the request list that were overwritten  by newer  entries.
        # This happens if there is a flood of queries that recursive processing and the server has a hard time.
        'requestlist.exceeded',
        # Queries that were dropped because the  request  list  was  full.
        # This  happens  if  a flood of queries need recursive processing, and the server can not keep up.
        'requestlist.current.all',
        # Current size of the request list, includes internally  generated
        # queries (such as priming queries and glue lookups).
        'requestlist.current.user',
        # Current  size of the request list, only the requests from client queries.
        'recursion.time.avg',
        # Average time it took to answer  queries  that  needed  recursive
        # processing.  Note that queries that were answered from the cache are not in this average.
        'recursion.time.median',
        # The median of the time it took to  answer  queries  that  needed recursive processing.
        # The  median  means that 50% of the user queries were answered in less than this time.
        # Because of big outliers (usually queries to non responsive servers), the average can
        # be bigger than the median. This median has been calculated by interpolation from a histogram.
        'tcpusage',
        # The currently held tcp buffers for incoming connections. A spot value on the time of the request.
        # This helps you spot if the incoming-num-tcp buffers are full.
    ],
    GLOBAL=[
        'total.num.queries',
        # summed over threads.
        'total.num.cachehits',
        # summed over threads.
        'total.num.cachemiss',
        # summed over threads.
        'total.num.dnscrypt.crypted',
        # summed over threads.
        'total.num.dnscrypt.cert',
        # summed over threads.
        'total.num.dnscrypt.cleartext',
        # summed over threads.
        'total.num.dnscrypt.malformed',
        # summed over threads.
        'total.num.prefetch',
        # summed over threads.
        'total.num.zero_ttl',
        # summed over threads.
        'total.num.recursivereplies',
        # summed over threads.
        'total.requestlist.avg',
        # averaged over threads.
        'total.requestlist.max',
        # the maximum of the thread requestlist.max values.
        'total.requestlist.overwritten',
        # summed over threads.
        'total.requestlist.exceeded',
        # summed over threads.
        'total.requestlist.current.all',
        # summed over threads.
        'total.recursion.time.median',
        # averaged over threads.
        'total.tcpusage',
        # summed over threads.
        'time.now',
        # current time in seconds since 1970.
        'time.up',
        # uptime since server boot in seconds.
        'time.elapsed',
        # time since last statistics printout, in seconds.
        'mem.cache.rrset',
        # Memory in bytes in use by the RRset cache.
        'mem.cache.message',
        # Memory in bytes in use by the message cache.
        'mem.cache.dnscrypt_shared_secret',
        # Memory in bytes in use by the dnscrypt shared secrets cache.
        'mem.cache.dnscrypt_nonce',
        # Memory in bytes in use by the dnscrypt nonce cache.
        'mem.mod.iterator',
        # Memory in bytes in use by the iterator module.
        'mem.mod.validator',
        # Memory in bytes in use by the validator module. Includes the key cache and negative cache.
        'num.query.type.A',
        # The total number of queries over all threads with query type  A.
        # Printed  for  the  other  query  types as well, but only for the
        # types for which queries were received, thus =0 entries are omitted for brevity.
        'num.query.type.AAAA',
        'num.query.type.CNAME',
        'num.query.type.MX',
        'num.query.type.NS',
        'num.query.type.PTR',
        'num.query.type.SOA',
        'num.query.type.SRV',
        'num.query.type.TXT',
        'num.query.type.other',
        # Number of queries with query types 256-65535.
        'num.query.class.IN',
        # The total number of queries over all threads with query class IN (internet).
        # Also printed for other classes (such as CH  (CHAOS) sometimes  used  for  debugging),
        # or NONE, ANY, used by dynamic update. num.query.class.other is printed for classes 256-65535.
        'num.query.opcode.QUERY',
        # The total number of queries over all threads with  query  opcode QUERY.
        # Also printed for other opcodes, UPDATE, ...
        'num.query.tcp',
        # Number  of  queries that were made using TCP towards the unbound server.
        'num.query.tcpout',
        # Number of queries that the unbound server made using TCP  outgoing towards other servers.
        'num.query.ipv6',
        # Number  of queries that were made using IPv6 towards the unbound server.
        'num.query.flags.RD',
        'num.query.flags.QR',
        'num.query.flags.AA',
        'num.query.flags.TC',
        'num.query.flags.RA',
        'num.query.flags.Z',
        'num.query.flags.AD',
        'num.query.flags.CD',
        # The number of queries that had the RD flag set  in  the  header.
        # Also  printed  for  flags  QR, AA, TC, RA, Z, AD, CD.  Note that
        # queries with flags QR, AA or TC may have been  rejected  because of that.
        'num.query.edns.present',
        # number of queries that had an EDNS OPT record present.
        'num.query.edns.DO',
        # number  of  queries  that  had  an  EDNS  OPT record with the DO (DNSSEC OK) bit set.
        # These queries are  also  included  in  the num.query.edns.present number.
        'num.query.ratelimited',
        # The  number  of  queries that are turned away from being send to nameserver due to ratelimiting.
        'num.query.dnscrypt.shared_secret.cachemiss',
        # The number of dnscrypt queries that did not find a shared secret in  the  cache.
        # The  can  be  use to compute the shared secret hitrate.
        'num.query.dnscrypt.replay',
        # The number of dnscrypt queries that found a  nonce  hit  in  the nonce cache and hence
        # are considered a query replay.
        'num.answer.rcode.NXDOMAIN',
        # The  number of answers to queries, from cache or from recursion, that had the return code NXDOMAIN.
        #  Also printed  for  the  other return codes.
        'num.answer.rcode.nodata',
        # The number of answers to queries that had the pseudo return code nodata.
        # This means the actual return code was  NOERROR, but additionally, no data was carried in
        # the answer (making what is called  a  NOERROR/NODATA  answer).
        # These  queries are also included  in  the  num.answer.rcode.NOERROR  number.
        # Common for AAAA lookups when an A record exists, and no AAAA.
        'num.answer.secure',
        # Number of answers that were secure.  The answer  validated  cor-
        # rectly.   The  AD  bit  might  have  been  set  in some of these
        # answers, where the client signalled (with DO or AD  bit  in  the
        # query) that they were ready to accept the AD bit in the answer.
        'num.answer.bogus',
        # Number  of  answers  that were bogus.  These answers resulted in
        # SERVFAIL to the client because the answer failed validation.
        'num.rrset.bogus',
        # The number of rrsets marked bogus by the  validator. Increased for every RRset inspection that fails.
        'unwanted.queries',
        # Number of queries that were refused or dropped because they failed the access control settings.
        'unwanted.replies',
        # Replies that were unwanted or unsolicited.  Could have been random  traffic,
        # delayed duplicates, very late answers, or could be spoofing attempts.
        # Some low level of late answers  and  delayed duplicates  are to be expected with the UDP protocol.
        # Very high values could indicate a threat (spoofing).
        'msg.cache.count',
        # The number of items (DNS replies) in the message cache.
        'rrset.cache.count',
        # The number of RRsets in the rrset cache.  This  includes  rrsets used  by  the messages
        # in the message cache, but also delegation information.
        'infra.cache.count',
        # The number of items in the infra cache.  These are IP  addresses with their
        #  timing and protocol support information.
        'key.cache.count',
        # The  number  of  items in the key cache.  These are DNSSEC keys,
        # one item per delegation point, and their validation status.
        'dnscrypt_shared_secret.cache.count',
        # The number of items in the shared secret cache. These  are  pre-
        # computed  shared  secrets  for  a given client public key/server
        # secret key pair. Shared secrets are CPU intensive and this cache
        # allows  unbound to avoid recomputing the shared secret when mul-
        # tiple dnscrypt queries are sent from the same client.
        'dnscrypt_nonce.cache.count',
        # The number of items in the client nonce  cache.  This  cache  is
        # used  to  prevent dnscrypt queries replay. The client nonce must
        # be unique for each client public  key/server  secret  key  pair.
        # This cache should be able to host QPS * `replay window` interval
        # keys to prevent replay of a query during  `replay  window`  seconds.
    ]
)

CHARTS = {
    'num_queries': {
        'options': [None, 'By type', 'count', 'queries', 'unbound.num_queries', 'stacked'],
        'lines': [
            ['num.query.type.A', 'A', 'absolute'],
            ['num.query.type.AAAA', 'AAAA', 'absolute'],
            ['num.query.type.CNAME', 'CNAME', 'absolute'],
            ['num.query.type.MX', 'MX', 'absolute'],
            ['num.query.type.NS', 'NS', 'absolute'],
            ['num.query.type.PTR', 'PTR', 'absolute'],
            ['num.query.type.SOA', 'SOA', 'absolute'],
            ['num.query.type.SRV', 'SRV', 'absolute'],
            ['num.query.type.TXT', 'TXT', 'absolute'],
            ['num.query.type.other', 'other', 'absolute'],
        ]
    },
    'num_queries_flags': {
        'options': [None, 'By flag', 'count', 'queries', 'unbound.num_queries_flags', 'line'],
        'lines': [
            ['num.query.flags.QR', 'query reply', 'absolute'],
            ['num.query.flags.AA', 'auth answer', 'absolute'],
            ['num.query.flags.TC', 'truncated', 'absolute'],
            ['num.query.flags.RD', 'recursion desired', 'absolute'],
            ['num.query.flags.RA', 'rec available', 'absolute'],
            ['num.query.flags.Z', 'zero', 'absolute'],
            ['num.query.flags.AD', 'auth data', 'absolute'],
            ['num.query.flags.CD', 'check disabled', 'absolute'],
            ['num.query.edns.present', 'EDNS OPT present', 'absoulte'],
            ['num.query.edns.DO', 'DNSSEC OK', 'absolue']
        ]
    },
    'memory': {
        'options': [None, 'Memory', 'KB', 'memory', 'unbound.memory', 'stacked'],
        'lines': [
            ['mem.cache.rrset', 'RRset cache', 'absolute', 1, 1024],
            ['mem.cache.message', 'Messages cache', 'absolute',  1, 1024],
            ['mem.cache.dnscrypt_shared_secret', 'dnscrypt shared secret', 'absolute',  1, 1024],
            ['mem.cache.dnscrypt_nonce', 'dnscrypt nonce', 'absolute',  1, 1024],
            ['mem.mod.iterator', 'Iterator', 'absolute',  1, 1024],
            ['mem.mod.validator', 'Validator', 'absolute',  1, 1024],
        ]
    },
    'cache': {
        'options': [None, 'Unwanted', 'count', 'totals', 'unbound.totals', 'line'],
        'lines': [
            ['total.num.queries', 'total queries', 'absolute'],
            ['total.num.cachehits', 'cache hits', 'absolute'],
            ['total.requestlist.overwritten', 'requestlist overwritten', 'absolute'],
            ['total.requestlist.exceeded', 'requestlist exceeded', 'absolute'],
            ['unwanted.queries', 'unwanted queries', 'absolute'],
            ['unwanted.replies', 'unwanted replies', 'absolute'],
            ['num.query.tcp', 'TCP', 'absolute'],
            ['num.query.ipv6', 'IPv6', 'absolute'],
        ]
    },
    'answers': {
        'options': [None, 'Answers', 'count', 'answers', 'unbound.answers', 'line'],
        'lines': [
            ['num.answer.rcode.NOERROR', 'NOERROR', 'absolute'],
            ['num.answer.rcode.SERVFAIL', 'SERVFAIL', 'absolute'],
            ['num.answer.rcode.NXDOMAIN', 'NXDOMAIN', 'absolute'],
            ['num.answer.rcode.nodata', 'nodata', 'absolute'],
            ['num.answer.secure', 'answer secure', 'absolute'],
            ['num.answer.bogus', 'answer bogus', 'absolute'],
            ['num.rrset.bogus', 'rrsets bogus', 'absolute'],
        ]
    }

}

TEMPLATES = {

}


class Service(ExecutableService):
    def __init__(self, configuration=None, name=None):
        ExecutableService.__init__(self, configuration=configuration, name=name)
        self.order = ORDER
        self.definitions = deepcopy(CHARTS)
        self.binary = find_binary('unbound-control')
        self.data = dict()
        self.command = ''

    def check(self):
        if not self.binary:
            self.error('Cannot locate "unbound-control" binary')
            return False

        run_command = Popen(['sudo', self.binary, 'stats_noreset'], stdout=PIPE, stderr=PIPE)
        run_command.wait()

        if not run_command.returncode:
            self.command = ['sudo', self.binary, 'stats_noreset']
            self._init_data()
            return True
        self.error('Error running "%s stats_noreset"' % self.binary)
        return False

    def _init_data(self):
        for metric in METRICS['GLOBAL']:
            self.data[metric] = 0

    def _get_data(self):
        raw_data = self._get_raw_data()

        if raw_data is None:
            return None

        raw_data = (line.split('=', 1) for line in raw_data)

        for line in raw_data:
            try:
                key, value = (l.strip() for l in line)
            except ValueError:
                continue
            if value:
                self.data[key] = value.split()[0]

        return self.data
