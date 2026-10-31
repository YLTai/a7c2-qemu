"""Build data-only Hello World and deliberately invalid test programs."""
import struct
import sys
from pathlib import Path
out=Path(sys.argv[1]);out.mkdir(parents=True,exist_ok=True)
def program(instructions):
    return b'A7BC0001'+struct.pack('<H',len(instructions))+bytes(6)+b''.join(bytes(i) for i in instructions)
glyphs=((17,17,17,31,17,17,17),(31,16,16,30,16,16,31),(16,16,16,16,16,16,31),
        (14,17,17,17,17,17,14),(17,17,17,21,21,21,10),(30,17,17,30,20,18,17),
        (30,17,17,17,17,17,30),(0,0,0,0,0,0,0))
letters=(0,1,2,2,3,7,4,3,5,2,6)
hello=[(1,8+k*12+x*2+dx,4+y*2+dy,255)
       for k,g in enumerate(letters) for y in range(7) for x in range(5)
       if glyphs[g][y]&(16>>x) for dy in range(2) for dx in range(2)]
fixtures={'hello':program(hello+[(0,0,0,0)]),'malformed':program([(1,8,4,255),(1,160,0,255),(0,0,0,0)]),
          'crash':program([(3,0,0,0)]),'timeout':program([(2,0,0,0)]),
          'forbidden':program([(255,0,0,0)]),'invalid_elf':b'\x7fELF'+bytes(20)}
for name,data in fixtures.items():
    path=out/('ram-plugin-'+name);path.write_bytes(data);path.chmod(0o644)
