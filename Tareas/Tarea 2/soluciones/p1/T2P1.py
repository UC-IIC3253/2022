from Crypto.Cipher import AES
import copy



def AES_128(key: bytearray, message: bytearray) -> bytearray:
    a = AES.new(bytes(key), AES.MODE_ECB)
    return bytearray(a.encrypt(bytes(message)))



def davies_meyer(encrypt, l_key: int, l_message: int):
    """
    Arguments:
      encrypt: an encryption function
      l_key: length in bytes of the keys for encrypt
      l_message: length in bytes of the messages for encrypt
    Returns:
      A compression function from messages of length l_key + l_message to
      messages of length l_message, defined by using the Davies-Meyer
      construction 
    """
    def compresion(m: bytearray) -> bytearray:
        l = m[0:l_key]
        r = m[l_key:l_key+l_message]
        c = encrypt(l,r)
        ans = bytearray(b'')
        for (x,y) in zip(c,r):
            ans += (x^y).to_bytes(1, byteorder="big")
        return ans
    return compresion



def pad(message: bytearray, l_block: int) -> bytearray:
    """
    Arguments:
      message: message to be padded
      l_block: length in bytes of the block
    Returns:
      extension of message that includes the length of message
      (in bytes) in its last block 
    """
    last = len(message).to_bytes(l_block, byteorder="big")
    result = copy.deepcopy(message)
    if len(message)%l_block != 0:
        dif = l_block - len(message)%l_block
        add = bytearray(b'\x01')
        while (dif > 0):
            result += add
            add = bytearray(b'\x00')
            dif -= 1
    return result + last



def merkle_damgard(IV: bytearray, comp, l_block: int):
    """
    IV: initialization vector for a hash function
      comp: compression function to be used in the Merkle-Damgard
      construction
      l_block: length in bytes of the blocks to be used in the Merkle-Damgard
      construction
    Returns:
      A hash function for messages of arbitrary length, defined by using
      the Merkle-Damgard construction
    """
    def hash(m: bytearray) -> bytearray:
        p = pad(m, l_block)
        num = len(p)//l_block
        H = IV
        for i in range(0, num):
            H = comp(p[l_block*i : l_block*(i+1)] + H)
        return H
    return hash
    


if __name__ == "__main__":
    compresion = davies_meyer(AES_128, 16, 16)
    hash = merkle_damgard(bytearray(b'1234567890123456'), compresion, 16)

    s1 = bytearray(b'Este es un mensaje de prueba para la tarea 2')
    s2 = bytearray(b'Este es un mensaje de Prueba para la tarea 2')
    s3 = bytearray(b'Un mensaje corto')
    s4 = bytearray(b'')

    h1 = hash(s1)
    h2 = hash(s2)
    h3 = hash(s3)
    h4 = hash(s4)
    
    print(h1)
    print(h2)
    print(h3)
    print(h4)
