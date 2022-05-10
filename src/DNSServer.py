from threading import Thread
import pickle

import Recourse

from dnslib import *

PORT = 53
HOST = '127.0.0.1'
HOSTDNS = '8.26.56.26'
cash = {}
Alive = True
flag = False
default_ttl = 20


def save():
    with open("save.pickle", "wb") as write_file:
        pickle.dump(cash, write_file)


def load():
    global cash, default_ttl
    with open("save.pickle", "rb") as read_file:
        cash = pickle.load(read_file)


def send_req_dns(dns_server, p):
    try:
        dns_server.send(p)
        p2, a2 = dns_server.recvfrom(1024)
        print('*Sent request to my dns server*')

        return p2
    except:
        print('*has no response from dns server*')
        return


def start_server():
    global cash, Alive, flag, default_ttl
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns_server:
            server.bind((HOST, PORT))
            server.settimeout(10)

            dns_server.connect((HOSTDNS, PORT))
            dns_server.settimeout(10)

            print('*server started*')
            while True:
                while Alive:
                    try:
                        client_req, client_addr = server.recvfrom(1024)
                        client_data = DNSRecord.parse(client_req)
                        print(f'got request:\n{client_data.q.qname}\n{client_data.q.qtype}')
                    except:
                        print('had no request within 10 secs')
                        continue
                    flag = True
                    if str(client_data.q.qname) in cash:
                        recourse: Recourse = cash.get(str(client_data.q.qname))
                        query = client_data.reply()
                        if client_data.q.qtype == QTYPE.A and recourse.A:
                            flag = False
                            for addr in recourse.A:
                                query.add_answer(
                                    dns.RR(rname=client_data.q.qname,
                                           rclass=client_data.q.qclass,
                                           rtype=QTYPE.A,
                                           ttl=default_ttl,
                                           rdata=A(addr.data)))
                            for ns in recourse.NS:
                                query.add_auth(
                                    dns.RR(rname=client_data.q.qname,
                                           rclass=client_data.q.qclass,
                                           rtype=QTYPE.NS,
                                           ttl=default_ttl,
                                           rdata=NS(ns.label)))
                            for e in recourse.NSA:
                                ns, nsA = e
                                if len(nsA.data) == 4:
                                    query.add_ar(dns.RR(rname=ns.label,
                                                        rclass=client_data.q.qclass,
                                                        rtype=QTYPE.A,
                                                        ttl=default_ttl,
                                                        rdata=A(nsA.data)))
                                if len(nsA.data) == 16:
                                    query.add_ar(dns.RR(rname=ns.label,
                                                        rclass=client_data.q.qclass,
                                                        rtype=QTYPE.AAAA,
                                                        ttl=default_ttl,
                                                        rdata=AAAA(nsA.data)))
                        elif client_data.q.qtype == QTYPE.AAAA and recourse.AAAA:
                            flag = False
                            for addr in recourse.AAAA:
                                query.add_answer(
                                    dns.RR(rname=client_data.q.qname,
                                           rclass=client_data.q.qclass,
                                           rtype=QTYPE.AAAA,
                                           ttl=default_ttl,
                                           rdata=AAAA(addr.data)))
                            for ns in recourse.NS:
                                query.add_auth(
                                    dns.RR(rname=client_data.q.qname,
                                           rclass=client_data.q.qclass,
                                           rtype=QTYPE.NS,
                                           ttl=default_ttl,
                                           rdata=NS(ns.label)))
                            for e in recourse.NSA:
                                ns, nsA = e
                                if len(nsA.data) == 4:
                                    query.add_ar(dns.RR(rname=ns.label,
                                                        rclass=client_data.q.qclass,
                                                        rtype=QTYPE.A,
                                                        ttl=default_ttl,
                                                        rdata=A(nsA.data)))
                                if len(nsA.data) == 16:
                                    query.add_ar(dns.RR(rname=ns.label,
                                                        rclass=client_data.q.qclass,
                                                        rtype=QTYPE.AAAA,
                                                        ttl=default_ttl,
                                                        rdata=AAAA(nsA.data)))
                        elif client_data.q.qtype == QTYPE.PTR and recourse.PTR:
                            flag = False
                            query.add_auth(dns.RR(rname=client_data.q.qname,
                                                  rclass=client_data.q.qclass,
                                                  rtype=QTYPE.SOA,
                                                  ttl=default_ttl,
                                                  rdata=recourse.PTR))
                        elif client_data.q.qtype == QTYPE.NS and recourse.NS:
                            flag = False
                            for ns in recourse.NS:
                                query.add_answer(
                                    dns.RR(rname=client_data.q.qname,
                                           rclass=client_data.q.qclass,
                                           rtype=QTYPE.NS,
                                           ttl=default_ttl,
                                           rdata=NS(ns.label)))
                            for e in recourse.NSA:
                                ns, nsA = e
                                if len(nsA.data) == 4:
                                    query.add_ar(dns.RR(rname=ns.label,
                                                        rclass=client_data.q.qclass,
                                                        rtype=QTYPE.A,
                                                        ttl=default_ttl,
                                                        rdata=A(nsA.data)))
                                if len(nsA.data) == 16:
                                    query.add_ar(dns.RR(rname=ns.label,
                                                        rclass=client_data.q.qclass,
                                                        rtype=QTYPE.AAAA,
                                                        ttl=default_ttl,
                                                        rdata=AAAA(nsA.data)))
                        else:
                            server_packet = send_req_dns(dns_server, client_req)
                            server_data: DNSRecord = DNSRecord.parse(
                                server_packet)
                            cash.get(str(client_data.q.qname)).add_recourse(
                                server_data)
                            print("cached")
                            server.sendto(server_packet, client_addr)
                            print('sent answer')
                            continue
                    if flag:
                        server_packet = send_req_dns(dns_server, client_req)
                        server_data = DNSRecord.parse(server_packet)
                        cash[str(client_data.q.qname)] = Recourse.Recourse(
                            str(client_data.q.qname))
                        cash.get(str(client_data.q.qname)).add_recourse(
                            server_data)
                        print(f'cached:\n{client_data.q.qname}\n{client_data.q.qtype}')
                        server.sendto(server_packet, client_addr)
                        print('sent answer')
                    else:
                        server.sendto(query.pack(), client_addr)
                        print(f"sent cached package:\n{client_data.q.qname}  {client_data.q.qtype}")
                save()
                cash = {}
                print('saved cache')
                print('server turned off')
                while not Alive:
                    time.sleep(5)
                print('server started')
                load()
                print('download saved')


def main():
    global Alive
    Thread(target=start_server).start()
    while True:
        Alive = True
        while input() != 'q':
            continue
        Alive = False
        while input() != 's':
            continue


if __name__ == '__main__':
    main()
