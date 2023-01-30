from binaryninja import *

xor_key = struct.pack('<I',0x919E1E2E)
code_offset = 0x0000014E
code_before = []
out  = []

view = bv

start_addr = view.start + code_offset
end_addr = view.end

code_before = view.read(start_addr, end_addr - start_addr).hex()
print(code_before)



# view.write(start_addr, bytearray(code_after))

view.update_analysis_and_wait()
# view.save('c:\\temp\part2.bin')
