#!/usr/bin/env python3

import sys
from tabulate import tabulate
import yaml

table = [['Algorithm', 'Claimed NIST Level', 'Code Point', 'oid']]

config = {}
with open('generate.yml', mode='r', encoding='utf-8') as f:
    config = yaml.safe_load(f.read())

# Generate the signature table

for sig in config['sigs'][1:]:
    for variant in sig['variants']:
        claimed_nist_level = 0
        if variant['security'] == 128:
            claimed_nist_level = 1
        elif variant['security'] == 192:
            claimed_nist_level = 3
        elif variant['security'] == 256:
            claimed_nist_level = 5
        else:
            sys.exit("variant['security'] value malformed.")

        table.append([variant['name'], claimed_nist_level, variant['code_point'], variant['oid']])
        for hybrid in variant['mix_with']:
            table.append([variant['name'] + ' **hybrid with** ' + hybrid['name'], claimed_nist_level, hybrid['code_point'], hybrid['oid']])

with open('oqs-sig-info.md', mode='w', encoding='utf-8') as f:
    f.write(tabulate(table, tablefmt="pipe", headers="firstrow"))

# Generate the kem table

table = [['Family', 'Variant', 'Claimed NIST Level', 'PQ-only Code Point', 'Hybrid Elliptic Curve', 'Hybrid Code Point']]
x25519_table = [['Family', 'Variant', 'Claimed NIST Level', 'PQ-only Code Point', 'Hybrid Elliptic Curve', 'Hybrid Code Point']]

for kem in config['kems']:
    claimed_nist_level = 0
    hybrid_elliptic_curve = ''
    if kem['bit_security'] == 128:
        claimed_nist_level = 1
        hybrid_elliptic_curve = 'secp256_r1'
    elif kem['bit_security'] == 192:
        claimed_nist_level = 3
        hybrid_elliptic_curve = 'secp384_r1'
    elif kem['bit_security'] == 256:
        claimed_nist_level = 5
        hybrid_elliptic_curve = 'secp521_r1'
    else:
        sys.exit("kem['bit_security'] value malformed.")

    if kem['name_group'] == 'kyber512':
        table.append([kem['family'], kem['name_group'], claimed_nist_level, kem['nid'], 'x25519', '0x2F26'])
    elif kem['name_group'] == 'sikep434':
        table.append([kem['family'], kem['name_group'], claimed_nist_level, kem['nid'], 'x25519', '0x2F27'])
    elif kem['name_group'] == 'bike1l1fo':
        table.append([kem['family'], kem['name_group'], claimed_nist_level, kem['nid'], 'x25519', '0x2F28'])

    table.append([kem['family'], kem['name_group'], claimed_nist_level, kem['nid'], hybrid_elliptic_curve, kem['nid_hybrid']])

with open('oqs-kem-info.md', mode='w', encoding='utf-8') as f:
    f.write(tabulate(table, tablefmt="pipe", headers="firstrow"))
