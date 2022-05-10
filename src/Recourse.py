import time
from threading import Thread
from DNSServer import save, load

from dnslib import DNSRecord, QTYPE


class Recourse:
    def __init__(self, name):
        self.name = name
        self.NS = None
        self.A = None
        self.AAAA = None
        self.PTR = None
        self.off = False

    def __hash__(self):
        return hash(self.name)

    def add_recourse(self, data: DNSRecord):
        if data.q.qtype == QTYPE.A:
            self.A = list(map(lambda x: x.rdata, data.rr))
            self.NS = list(map(lambda x: x.rdata, data.auth))
        elif data.q.qtype == QTYPE.AAAA:
            self.AAAA = list(map(lambda x: x.rdata, data.rr))
            self.NS = list(map(lambda x: x.rdata, data.auth))
        elif data.q.qtype == QTYPE.PTR:
            self.PTR = data.auth[0].rdata
        elif data.q.qtype == QTYPE.NS:
            self.NS = list(map(lambda x: x.rdata, data.rr))
        else:
            pass
        Thread(target=Recourse.remove_recourse, args=(self, data.q.qtype,
                                                      20)).start()

    @staticmethod
    def remove_recourse(self, qtype: QTYPE, ttl):
        time.sleep(ttl)
        if qtype == QTYPE.A:
            self.A = None
            self.NS = None
        elif qtype == QTYPE.AAAA:
            self.AAAA = None
            self.NS = None
        elif qtype == QTYPE.PTR:
            self.PTR = None
        elif qtype == QTYPE.NS:
            self.NS = None
        else:
            pass
        print(f'removed from cached: {self.name}  {qtype}')
        save()
        print(f"saved current cache")
        load()
