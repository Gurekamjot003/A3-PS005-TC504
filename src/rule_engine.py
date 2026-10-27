import numpy as np
from enum import Enum

class status(Enum):
    VALID = 1
    ORIGIN_ANOMALY = 2
    SUBPREFIX_ANOMALY = 3
    UNKNOWN = 4

class rule_engine:
    class bgp_data: #this will be stored as satellite data in the trie
        def __init__(self, asn, max_len = 32):
            self.asn = asn
            self.max_len = max_len

    class radix_trie:
        def __init__(self):
            self.root = {}

        def insert(self, network_address, data = None):
            node = self.root
            for i in range(31, -1, -1):
                bit = (network_address >> i) & 1
                if bit not in node:
                    node[bit] = {}
                node = node[bit]
            self.data = data

        def search(self, network_address):
            node = self.root
            for i in range(31, -1, -1):
                bit = (network_address >> i) & 1
                if bit not in node:
                    return False
                node = node[bit]
            return self.data is not None

    def pref_parser(prefix):
        parts = prefix.split('/')
        network_address = int(np.sum([int(x) << (8 * (3 - i)) for i, x in enumerate(parts[0].split('.'))]))
        prefix_length = int(parts[1])
        return network_address, prefix_length

    def rule_baseline(self, asn, prefix, data = None):
        _, prefix_length = self.pref_parser(prefix)
        if data is None:
            return status.UNKNOWN
        if asn != data.asn:
            return status.ORIGIN_ANOMALY
        if prefix_length > data.max_len:
            return status.SUBPREFIX_ANOMALY
        return status.VALID

    def __init__(self, full_data):
        for asn, max_len, prefix in full_data:
            network_address, _ = self.pref_parser(prefix)
            data = self.bgp_data(asn, max_len)
            self.trie.insert(network_address, data)
        