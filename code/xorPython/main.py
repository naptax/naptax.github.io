import struct
file_data = open('rudesbies.par','rb').read()

out = []
key = struct.pack('<I',0x919E1E2E)
code_offset = 0x0000014E
enc_code = file_data[code_offset:]



for i in range(len(enc_code)):
    out.append(enc_code[i] ^ key[i % len(key)])

open('stage2.bin','wb').write(bytes(out))