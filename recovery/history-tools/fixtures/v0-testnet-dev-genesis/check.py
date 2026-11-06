#!/usr/bin/env python3
"""Inspect target metadata and record identity; current nodes verify the block."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('generated',type=Path)
p.add_argument('original',type=Path)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args()
b=(a.generated/'genesis.bin').read_bytes()
# Pinned old block/header codec: one version byte, two32-byte block hashes,
# one header-version byte, six32-byte header roots, then metadata.
offset=1+2*32+1+6*32
values=struct.unpack_from('<BHQI16s16sQQQqq',b,offset)
assert b[0]==1 and b[65]==1
assert values[:4]==(1,1,0,0), values[:4]
assert values[6:9]==(31,8,31), values[6:9]
metadata={'version':values[0],'network':values[1],'round':values[2],'height':values[3],
'coinbase_target':values[6],'proof_target':values[7],'last_coinbase_target':values[8],
'last_coinbase_timestamp':values[9],'timestamp':values[10]}
manifest=json.loads((a.generated/'manifest.json').read_text())
original=json.loads((a.original/'manifest.json').read_text())
assert manifest['creator_revision']=='9741f1159a8cd18e2d676d5a095eeffad71ab52c'
assert manifest['record_version']==0 and len(manifest['records'])==4
assert manifest['validator_addresses']==original['validator_addresses']
checked=[]
for name,expected in manifest['files'].items():
 data=(a.generated/name).read_bytes()
 assert len(data)==expected['bytes'] and hashlib.sha256(data).hexdigest()==expected['sha256']
 if name!='genesis.bin':
  assert data==(a.original/name).read_bytes(), name
  checked.append(name)
assert manifest['records']==original['records']
report={'result':'passed','metadata_codec_source_revision':manifest['creator_revision'],
'genesis_hash':manifest['genesis_hash'],'genesis_bytes':len(b),
'genesis_sha256':hashlib.sha256(b).hexdigest(),'decoded_metadata':metadata,
'identical_historical_record_artifacts':checked,
'identical_record_commitment_serial_manifest':True,
'unchanged_original_genesis_sha256':hashlib.sha256((a.original/'genesis.bin').read_bytes()).hexdigest(),
'scope':'Byte-level target and artifact inspection, not a replacement for current Block parsing, proof verification, ledger initialization or migration acceptance.'}
a.output.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
