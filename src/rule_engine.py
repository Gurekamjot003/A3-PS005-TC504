from __future__ import annotations

import ipaddress
from enum import Enum
from platform import node


class status(Enum):
    VALID = 1
    ORIGIN_ANOMALY = 2
    SUBPREFIX_ANOMALY = 3
    UNKNOWN = 4


class rule_engine:
    class bgp_data:  # stored as satellite data in the trie
        def __init__(self, asn: int, max_len: int):
            self.asn = asn
            self.max_len = max_len

    class radix_trie:
        def __init__(self):
            self.root = None

        @staticmethod
        def _encode_bits(bits: str):
            return "".join("00" if bit == "0" else "01" for bit in bits)

        @classmethod
        def _encode_prefix(cls, bits: str):
            # Encode address bits as 00/01 and the terminating "$" as 1.
            return cls._encode_bits(bits) + "1"

        @staticmethod
        def _new_leaf(label: str, data):
            return {
                "label": label,
                "data": [data],
                "zero": None,
                "one": None,
            }

        def _insert_node(self, node, key: str, data):
            label = node["label"]
            common_length = 0
            while (
                common_length < min(len(key), len(label))
                and key[common_length] == label[common_length]
            ):
                common_length += 1

            if common_length < len(label):
                old_suffix = label[common_length:]
                new_suffix = key[common_length:]
                if not new_suffix or old_suffix[0] == new_suffix[0]:
                    raise ValueError("Encoded prefix keys must be prefix-free.")

                node["label"] = old_suffix
                branch = {
                    "label": label[:common_length],
                    "data": [],
                    "zero": None,
                    "one": None,
                }
                old_side = "zero" if old_suffix[0] == "0" else "one"
                new_side = "zero" if new_suffix[0] == "0" else "one"
                branch[old_side] = node
                branch[new_side] = self._new_leaf(new_suffix, data)
                return branch

            remaining = key[common_length:]
            if not remaining:
                if node["zero"] is not None or node["one"] is not None:
                    raise ValueError("An encoded prefix cannot end at a branch.")
                if data not in node["data"]:
                    node["data"].append(data)
                return node

            if node["zero"] is None and node["one"] is None:
                raise ValueError("Encoded prefix keys must be prefix-free.")

            first_bit = remaining[0]
            side = "zero" if first_bit == "0" else "one"
            child = node[side]
            if child is None:
                raise ValueError("Compressed trie branch is missing a child.")
            node[side] = self._insert_node(child, remaining, data)
            return node

        def insert(self, network_address: int, prefix_length: int, data=None):
            bits = format(network_address, "032b")[:prefix_length]
            key = self._encode_prefix(bits)
            node = self.root
            if node is None:
                self.root = self._new_leaf(key, data)
            else:
                self.root = self._insert_node(node, key, data)

        def search_covering(self, network_address: int, prefix_length: int):
            """Return all ROAs from covering prefixes (length 0 up to prefix_length)."""
            node = self.root
            bits = format(network_address, "032b")[:prefix_length]
            encoded_bits = self._encode_bits(bits)
            covering_roas = []
            position = 0
            path = ""

            while node is not None:
                label = node["label"]
                remaining = encoded_bits[position:]
                common_length = 0
                while (
                    common_length < min(len(remaining), len(label))
                    and remaining[common_length] == label[common_length]
                ):
                    common_length += 1

                if common_length < len(label):
                    if (
                        node["zero"] is None
                        and node["one"] is None
                        and common_length == len(label) - 1
                    ):
                        covering_roas.extend(node["data"])
                    break

                position += len(label)
                path += label
                if node["zero"] is None and node["one"] is None:
                    break

                # At an address-bit boundary, a "1" child is the "$" terminator.
                if position % 2 == 0:
                    terminal = node["one"]
                    if terminal is not None:
                        covering_roas.extend(terminal["data"])

                if position == len(encoded_bits):
                    break
                node = (
                    node["zero"]
                    if encoded_bits[position] == "0"
                    else node["one"]
                )

            return covering_roas

    @staticmethod
    def pref_parser(prefix: str):
        network = ipaddress.ip_network(prefix, strict=False)
        if network.version != 4:
            return None
        return int(network.network_address), int(network.prefixlen)

    def rule_baseline(self, asn: int, prefix: str) -> status | None:
        parsed_prefix = self.pref_parser(prefix)
        if parsed_prefix is None:
            return None
        network_address, prefix_length = parsed_prefix
        covering_roas = self.trie.search_covering(network_address, prefix_length)

        # 1. No covering ROAs at all -> UNKNOWN (NotFound)
        if not covering_roas:
            return status.UNKNOWN

        # 2. Check if ANY covering ROA makes this announcement VALID
        asn_matched = False
        for roa in covering_roas:
            if asn != 0 and asn == roa.asn: #RFC 6483 => ROA with ASN = 0 explicitly declares "this prefix must NEVER be announced by any AS."
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
            parsed_prefix = self.pref_parser(prefix)
            if parsed_prefix is None:
                continue
            network_address, prefix_length = parsed_prefix
            effective_max_len = prefix_length if max_len is None else int(max_len)
            if effective_max_len < prefix_length or effective_max_len > 32:
                continue  # skip malformed ROA
            data = self.bgp_data(int(asn), effective_max_len)
            self.trie.insert(network_address, prefix_length, data)