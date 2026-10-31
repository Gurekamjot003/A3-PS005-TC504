from __future__ import annotations

import ipaddress
from enum import Enum


class status(Enum):
    VALID = 1
    ORIGIN_ANOMALY = 2
    SUBPREFIX_ANOMALY = 3
    UNKNOWN = 4


class rule_engine:
    class bgp_data:  # this will be stored as satellite data in the trie
        def __init__(self, asn, max_len=32):
            self.asn = asn
            self.max_len = max_len

    class radix_trie:
        def __init__(self):
            self.root = {}

        def insert(self, network_address, prefix_length, data=None):
            node = self.root
            for i in range(prefix_length - 1, -1, -1):
                bit = (network_address >> i) & 1
                if bit not in node:
                    node[bit] = {}
                node = node[bit]
            node["data"] = data

        def search(self, network_address):
            node = self.root
            best_match = None
            for i in range(31, -1, -1):
                bit = (network_address >> i) & 1
                if bit not in node:
                    break
                node = node[bit]
                if "data" in node and node["data"] is not None:
                    best_match = node["data"]
            return best_match

    @staticmethod
    def pref_parser(prefix):
        network = ipaddress.ip_network(prefix, strict=False)
        network_address = int(network.network_address)
        prefix_length = int(network.prefixlen)
        return network_address, prefix_length

    def rule_baseline(self, asn, prefix):
        network_address, prefix_length = self.pref_parser(prefix)
        data = self.trie.search(network_address)
        if data is None:
            return status.UNKNOWN
        if asn != data.asn:
            return status.ORIGIN_ANOMALY
        if prefix_length > data.max_len:
            return status.SUBPREFIX_ANOMALY
        self.trie.insert(network_address, prefix_length, data)  # update the trie with the new prefix length
        return status.VALID

    def __init__(self, full_data):
        self.trie = self.radix_trie()
        for asn, max_len, prefix in full_data:
            network_address, prefix_length = self.pref_parser(prefix)
            data = self.bgp_data(asn, max_len)
            self.trie.insert(network_address, prefix_length, data)

