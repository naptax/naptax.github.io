from binaryninja import *

xor_key = struct.pack('<I',0x919E1E2E)
code_offset = 0x0000014E
code_before = bytearray
code_after  = []

view = bv

start_addr = view.start + code_offset
end_addr = view.end

code_before = view.read(start_addr, end_addr - start_addr)
print(f'Binaire (size = {len(code_before)} ) AVANT le xor:\t', code_before[0:24])


for i in range(len(code_before)):
    code_after.append(code_before[i] ^ xor_key[i % len(xor_key)])

print(f'Binaire (size = {len(code_after)} ) APRES le xor:\t', bytearray(code_after[0:24]))


view.write(start_addr, bytearray(code_after))

view.update_analysis_and_wait()