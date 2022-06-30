#!/usr/bin/python3
import json
import logging
import os
import signal
from datetime import datetime
from pathlib import Path
from textwrap import wrap
from time import sleep

import dnslib
from dnslib import DNSLabel, QTYPE, RR, dns
from dnslib.proxy import ProxyResolver
from dnslib.server import DNSServer

SERIAL_NO = int((datetime.utcnow() - datetime(1970, 1, 1)).total_seconds())

handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
handler.setFormatter(logging.Formatter('%(asctime)s: %(message)s', datefmt='%H:%M:%S'))

logger = logging.getLogger(__name__)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

TYPE_LOOKUP = {
    'A': (dns.A, QTYPE.A),
    'AAAA': (dns.AAAA, QTYPE.AAAA),
    'CAA': (dns.CAA, QTYPE.CAA),
    'CNAME': (dns.CNAME, QTYPE.CNAME),
    'DNSKEY': (dns.DNSKEY, QTYPE.DNSKEY),
    'MX': (dns.MX, QTYPE.MX),
    'NAPTR': (dns.NAPTR, QTYPE.NAPTR),
    'NS': (dns.NS, QTYPE.NS),
    'PTR': (dns.PTR, QTYPE.PTR),
    'RRSIG': (dns.RRSIG, QTYPE.RRSIG),
    'SOA': (dns.SOA, QTYPE.SOA),
    'SRV': (dns.SRV, QTYPE.SRV),
    'TXT': (dns.TXT, QTYPE.TXT),
    'SPF': (dns.TXT, QTYPE.TXT),
}

import re
base_domains = ['ip.rtmp.asia.', 'ip.recolic.net.', 'ip.recolic.cc.']
ns_ipaddr = '127.0.0.1'

def parse_requested_ip(qn_without_basedomain):
    # This function receives qn without base domain, validate and parse it. Returns a good IPV4 or ipv6 address. 
    if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', qn_without_basedomain):
        # 1.1.1.1.ip.recolic.cc
        return qn_without_basedomain
    elif re.match(r'^(?:[0-9]{1,3}-){3}[0-9]{1,3}$', qn_without_basedomain):
        # 1-1-1-1.ip.recolic.cc
        return qn_without_basedomain.replace('-','.')
    else:
        print("Invalid request ip format: " + qn_without_basedomain)
        return None

def gen_response(qt, qn):
    global base_domains
    matched_base_domains = list(filter(lambda d: qn == d or qn.endswith('.'+d), base_domains))
    if len(matched_base_domains) != 1:
        print("Error: invalid request domain {} in {}".format(qn, base_domains))
        return None
    base_domain = matched_base_domains[0]
    print('REQ: ', qt, qn)

    if qt == 'SOA':
        generated_soa = dnslib.SOA(mname="todo."+base_domain, rname="root@recolic.net", times=(
            201307231,  # serial number
            10000,  # refresh
            2400,  # retry
            604800,  # expire
            3600,  # minimum
        ))
        return RR(rname=base_domain, rtype=QTYPE.SOA, rclass=1, ttl=86400, rdata=generated_soa)
        # return {"mname": "todo."+base_domain, "rname": "root@recolic.net", "serial": "10", "refresh": 3600, "retry": 600, "expire": 604800, "minimum": 86400}
    elif qt == 'A':
        requested_ip = parse_requested_ip(qn[:len(qn)-len(base_domain)].strip('.'))
        generated_a = dnslib.A(requested_ip)
        return RR(rname=qn, rtype=QTYPE.A, rclass=1, ttl=86400, rdata=generated_a)
    elif qt == 'NS':
        generated_ns = dnslib.NS(ns_ipaddr)
        return RR(rname=base_domain, rtype=QTYPE.NS, rclass=1, ttl=86400, rdata=generated_ns)
    else:
        print("Invalid qt=" + qt)
        return None




class Record:
    def __init__(self, rname, rtype, args):
        self._rname = DNSLabel(rname)

        rd_cls, self._rtype = TYPE_LOOKUP[rtype]

        if self._rtype == QTYPE.SOA and len(args) == 2:
            # add sensible times to SOA
            args += (SERIAL_NO, 3600, 3600 * 3, 3600 * 24, 3600),

        if self._rtype == QTYPE.TXT and len(args) == 1 and isinstance(args[0], str) and len(args[0]) > 255:
            # wrap long TXT records as per dnslib's docs.
            args = wrap(args[0], 255),

        if self._rtype in (QTYPE.NS, QTYPE.SOA):
            ttl = 3600 * 24
        else:
            ttl = 300

        self.rr = RR(
            rname=self._rname,
            rtype=self._rtype,
            rdata=rd_cls(*args),
            ttl=ttl,
        )

    def match(self, q):
        return q.qname == self._rname and (q.qtype == QTYPE.ANY or q.qtype == self._rtype)

    def sub_match(self, q):
        return self._rtype == QTYPE.SOA and q.qname.matchSuffix(self._rname)

    def __str__(self):
        return str(self.rr)


class Resolver(ProxyResolver):
    def __init__(self, upstream):
        super().__init__(upstream, 53, 5)

    def resolve(self, request, handler):
        qt = QTYPE[request.q.qtype]
        qn = str(request.q.qname).lower()
        reply = request.reply()

        if qt == 'CAA':
            # CAA query should return empty response. It's ok. 
            return reply

        try:
            resp = gen_response(qt, qn)
            if resp != None:
                if qt == 'SOA':
                    reply.add_auth(resp)
                elif qt == 'NS':
                    reply.add_ar(resp)
                else:
                    reply.add_answer(resp)
        except:
            pass

        if reply.rr:
            return reply
        else:
            # I don't want to support other records. Disable the fallback resolver and return empty. 
            # return super().resolve(request, handler)
            return reply


def handle_sig(signum, frame):
    logger.info('pid=%d, got signal: %s, stopping...', os.getpid(), signal.Signals(signum).name)
    exit(0)


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, handle_sig)

    port = int(os.getenv('PORT', 53))
    upstream = os.getenv('UPSTREAM', '8.8.8.8')
    resolver = Resolver(upstream)
    udp_server = DNSServer(resolver, port=port)
    tcp_server = DNSServer(resolver, port=port, tcp=True)

    logger.info('starting DNS server on port %d, upstream DNS server "%s"', port, upstream)
    udp_server.start_thread()
    tcp_server.start_thread()

    try:
        while udp_server.isAlive():
            sleep(1)
    except KeyboardInterrupt:
        pass


