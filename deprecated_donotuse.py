#!/usr/bin/env python
# coding=utf-8

import argparse
import datetime
import sys
import time
import threading
import traceback
import socketserver
import struct
import re
try:
    from dnslib import *
except ImportError:
    print("Missing dependency dnslib: <https://pypi.python.org/pypi/dnslib>. Please install it with `pip`.")
    sys.exit(2)

serving_domains = ['example.com.', 'ip4.recolic.net.', 'ip4.recolic.cc.']
ns_ipaddr = '127.0.0.1'

def gen_response(qt, qn):
    global serving_domains
    prefix_ = list(filter(lambda d: qn == d or qn.endswith('.'+d), serving_domains))
    if len(prefix_) != 1:
        print("Error: invalid request domain {} in {}".format(qn, serving_domains))
        return None
    prefix = prefix_[0]

    if qt == 'SOA':
        generated_soa = SOA(mname="todo."+domain_text, rname="root@recolic.net", times=(
            201307231,  # serial number
            10000,  # refresh
            2400,  # retry
            604800,  # expire
            3600,  # minimum
        ))
        return RR(rname=prefix, rtype=QTYPE.SOA, rclass=1, ttl=86400, rdata=generated_soa)
        # return {"mname": "todo."+domain_text, "rname": "root@recolic.net", "serial": "10", "refresh": 3600, "retry": 600, "expire": 604800, "minimum": 86400}
    elif qt == 'A':
        requested_ip = qn[:len(qn)-len(prefix)].strip('.')
        if not re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', requested_ip):
            print("Invalid requested_ip: " + requested_ip)
            return None
        generated_a = A(requested_ip)
        return RR(rname=qn, rtype=QTYPE.A, rclass=1, ttl=86400, rdata=generated_a)
    elif qt == 'NS':
        generated_ns = NS(ns_ipaddr)
        return RR(rname=prefix, rtype=QTYPE.NS, rclass=1, ttl=86400, rdata=generated_ns)
    else:
        print("Invalid qt=" + qt)
        return None



def dns_response(data):
    request = DNSRecord.parse(data)

    print(request)

    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)

    qname = request.q.qname
    qn = str(qname)
    qtype = request.q.qtype
    qt = QTYPE[qtype]

    print("DEBUG: GOT REQUEST qt={}, qn={}".format(qt, qn))
    resp = gen_response(qt, qn)
    if resp != None:
        if qt == 'SOA':
            reply.add_auth(resp)
        elif qt == 'NS':
            reply.add_ar(resp)
        else:
            reply.add_answer(resp)

    print("---- Reply:\n", reply)
    return reply.pack()


class BaseRequestHandler(socketserver.BaseRequestHandler):

    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
        print("\n\n%s request %s (%s %s):" % (self.__class__.__name__[:3], now, self.client_address[0],
                                               self.client_address[1]))
        try:
            data = self.get_data()
            print(len(data), data)  # repr(data).replace('\\x', '')[1:-1]
            self.send_data(dns_response(data))
        except Exception:
            traceback.print_exc(file=sys.stderr)


class TCPRequestHandler(BaseRequestHandler):

    def get_data(self):
        data = self.request.recv(8192).strip()
        sz = struct.unpack('>H', data[:2])[0]
        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")
        return data[2:]

    def send_data(self, data):
        sz = struct.pack('>H', len(data))
        return self.request.sendall(sz + data)


class UDPRequestHandler(BaseRequestHandler):

    def get_data(self):
        return self.request[0].strip()

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)


def main():
    parser = argparse.ArgumentParser(description='Start a DNS implemented in Python.')
    parser = argparse.ArgumentParser(description='Start a DNS implemented in Python. Usually DNSs use UDP on port 53.')
    parser.add_argument('--port', default=53, type=int, help='The port to listen on.')
    parser.add_argument('--tcp', action='store_true', help='Listen to TCP connections.')
    parser.add_argument('--udp', action='store_true', help='Listen to UDP datagrams.')
    
    args = parser.parse_args()
    if not (args.udp or args.tcp): parser.error("Please select at least one of --udp or --tcp.")

    print("Starting nameserver...")

    servers = []
    if args.udp: servers.append(socketserver.ThreadingUDPServer(('', args.port), UDPRequestHandler))
    if args.tcp: servers.append(socketserver.ThreadingTCPServer(('', args.port), TCPRequestHandler))

    for s in servers:
        thread = threading.Thread(target=s.serve_forever)  # that thread will start one more thread for each request
        thread.daemon = True  # exit the server thread when the main thread terminates
        thread.start()
        print("%s server loop running in thread: %s" % (s.RequestHandlerClass.__name__[:3], thread.name))

    try:
        while 1:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()

    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()

if __name__ == '__main__':
    main()
