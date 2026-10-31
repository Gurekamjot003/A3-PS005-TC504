from __future__ import annotations

import ipaddress
from enum import Enum


class status(Enum):
    VALID = 1
    ORIGIN_ANOMALY = 2
    SUBPREFIX_ANOMALY = 3
    UNKNOWN = 4


class rule_engine:
    class bgp_data:  # stored as satellite data in the trie
        def __init__(self, asn: int, max_len: int = 32):
            self.asn = asn
            self.max_len = max_len

    class radix_trie:
        def __init__(self):
            # Separate roots for IPv4 (32-bit) and IPv6 (128-bit)
            self.roots = {4: {}, 6: {}}

        def insert(self, network_address: int, prefix_length: int, version: int, data=None):
            node = self.roots[version]
            total_bits = 32 if version == 4 else 128

            # Walk from the MOST significant bit (top bit) down prefix_length steps
            for i in range(total_bits - 1, total_bits - 1 - prefix_length, -1):
                bit = (network_address >> i) & 1
                if bit not in node:
                    node[bit] = {}
                node = node[bit]

            if "data" not in node:
                node["data"] = []
            node["data"].append(data)

        def search_covering(self, network_address: int, prefix_length: int, version: int):
            """Return all ROAs from covering prefixes (length 0 up to prefix_length)."""
            node = self.roots[version]
            total_bits = 32 if version == 4 else 128
            covering_roas = []

            if "data" in node:
                covering_roas.extend(node["data"])

            # Only walk down to the announced prefix_length (never into more-specific children)
            for i in range(total_bits - 1, total_bits - 1 - prefix_length, -1):
                bit = (network_address >> i) & 1
                if bit not in node:
                    break
                node = node[bit]
                if "data" in node:
                    covering_roas.extend(node["data"])

            return covering_roas

    @staticmethod
    def pref_parser(prefix: str):
        network = ipaddress.ip_network(prefix, strict=False)
        network_address = int(network.network_address)
        prefix_length = int(network.prefixlen)
        version = network.version
        return network_address, prefix_length, version

    def rule_baseline(self, asn: int, prefix: str) -> status:
        network_address, prefix_length, version = self.pref_parser(prefix)
        covering_roas = self.trie.search_covering(network_address, prefix_length, version)

        # 1. No covering ROAs at all -> UNKNOWN (NotFound)
        if not covering_roas:
            return status.UNKNOWN

        # 2. Check if ANY covering ROA makes this announcement VALID
        asn_matched = False
        for roa in covering_roas:
            if asn == roa.asn:
                asn_matched = True
                if prefix_length <= roa.max_len:
                    return status.VALID

        # 3. If ASN matched at least one covering ROA, but prefix_length > max_len -> SUBPREFIX_ANOMALY
        if asn_matched:
            return status.SUBPREFIX_ANOMALY

        # 4. Covering ROA(s) exist, but none match the Origin ASN -> ORIGIN_ANOMALY
        return status.ORIGIN_ANOMALY

    def __init__(self, full_data):
        self.trie = self.radix_trie()
        for asn, max_len, prefix in full_data:
            network_address, prefix_length, version = self.pref_parser(prefix)
            data = self.bgp_data(asn, max_len)
            self.trie.insert(network_address, prefix_length, version, data)