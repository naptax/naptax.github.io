LEN = 0x500
START = 0x0000014E
XOR_KEY = 0x919E1E2E

doc = Document.getCurrentDocument()
seg = doc.getCurrentSegment()
segLEN = seg.getLength()

def decrypt(addr):
    data = seg.readUInt32LE(addr) ^ XOR_KEY
    return data

# Passe le XOR
for x in range(0,segLEN):
    decrypted = decrypt(START+(x*4))
    seg.writeUInt32LE(START+(x*4), decrypted)

# Add references to decrypted text
for x in range(0,segLEN):
    refs = doc.getSegmentAtAddress(START+x).getReferencesOfAddress(START+x)
    decrypted = doc.getSegmentAtAddress(START+x).readUInt64LE(START+x)
    for ref in refs:
        try:
            doc.getSegmentAtAddress(ref).setInlineCommentAtAddress(ref, 'Decrypted: %s' % (doc.getSegmentAtAddress(ref).readBytes(START+x,16)))
        except:
            doc.getSegmentAtAddress(ref).setInlineCommentAtAddress(ref, 'Error referencing decryption')
