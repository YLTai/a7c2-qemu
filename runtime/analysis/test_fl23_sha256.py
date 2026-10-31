"""Compare bounded guest digest implementation against independent hashlib."""
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest

class Sha256Tests(unittest.TestCase):
    def test_padding_and_streaming_against_hashlib(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            source=root/'hash.c'
            source.write_text('''#include <stdio.h>
#include "fl23-sha256.h"
int main(void){
 struct fl23_sha256 s;unsigned char b[7],out[32];size_t n;
 fl23_sha_init(&s);while((n=fread(b,1,sizeof b,stdin)))fl23_sha_update(&s,b,n);
 if(ferror(stdin))return 1;
 fl23_sha_final(&s,out);for(unsigned i=0;i<32;i++)printf("%02x",out[i]);return 0;
}
''')
            binary=root/'hash'
            subprocess.run(['cc','-std=c11','-O2','-Wall','-Wextra','-Werror',
                            '-I',str(Path(__file__).parent),str(source),'-o',str(binary)],check=True)
            for size in (0,1,3,55,56,63,64,65,119,120,127,128,16384,1000000):
                data=bytes((i*37+11)%256 for i in range(size))
                with self.subTest(size=size):
                    actual=subprocess.run([str(binary)],input=data,capture_output=True,check=True).stdout.decode()
                    self.assertEqual(actual,hashlib.sha256(data).hexdigest())
