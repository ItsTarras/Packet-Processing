import struct
def payload_check(packet):
    """We gotta push the payload!"""
    x = bytes(packet)
    #print(len(x))
    index = 0
    iterable = []
    
    
    while index < len(x) - 1:
        X = x[index]
        
        Y = x[index + 1]
        number1 = bin(X)[2:]
        number2 = bin(Y)[2:]
        number1 = number1[::-1]
        number2 = number2[::-1]
        while len(number1) < 8:
            number1 += '0'
        while len(number2) < 8:
            number2 += '0'
        number1 = number1[::-1]
        number2 = number2[::-1]
        index += 2
        iterable.append((number1 + number2))
        
    honourable_death = []
    headerlength = int(iterable[0][4:8], 2)
    for item in x[(headerlength * 4):]:
        honourable_death.append(item)
        
        
    return bytearray(honourable_death)

def compose_header(version, hdrlen, tosdscp, totallength, identification, flags, fragmentoffset, timetolive, protocoltype, headerchecksum, sourceaddress, destinationaddress):
    """returns the header packet, or an error depending on the input"""

    byte_array = []
    if version != 4:
        return 1
    else:
        byte = '0100'
        
    #4 Bit error code
    if hdrlen >= 2**4 or hdrlen < 5:
        return 2
    else:
        temp = bin(hdrlen)[2:]
        temp = temp[::-1]
        while len(temp) < 4:
            temp += '0'
        temp = temp[::-1]
        byte += temp
        byte_array.append(int(str(byte), 2))
        #(byte, "added to array")
        byte = '00000000'
        
    #6 bit error code
    if tosdscp >= 2**6 or tosdscp < 0:
        return 3
    else:
        temp = bin(tosdscp)[2:]
        temp = temp[::-1]
        while len(temp) < 6:
            temp += '0'
        temp = temp[::-1]
        byte = str(temp)
        byte += '00'
        byte_array.append(int(str(byte), 2))
        #(byte, "added to array")
        byte = '00000000'
        
    #16 bit error code
    if totallength >= 2**16 or totallength < 0:
        return 4
    if totallength < 2**8:
        byte_array.append(int('00000000'))

    values = hex(totallength)[2:]
    #Big endian code, string with even
    if len(values) % 2 == 0:
        index = 0
    else:
        byte_array.append(int(f'0{values[0]}', 16))
        index = 1
        #(f'unhex of {values[0]} added to array')
    while index < len(values):
        temp = values[index] + values[index + 1]
        byte_array.append(int(str(temp), 16))
        index += 2
        #(f'int({temp}, 16) added to array')
        #(byte_array)
        
    #16 bit error code
    if identification >= 2**16 or identification < 0:
        return 5
    if identification < 2**8:
        byte_array.append(int('00000000'))

    values = hex(identification)[2:]
    #Big endian code, string with even
    if len(values) % 2 == 0:
        index = 0
    else:
        byte_array.append(int(f'0{values[0]}', 16))
        index = 1
        #(f'unhex of {values[0]} added to array')
    while index < len(values):
        temp = values[index] + values[index + 1]
        byte_array.append(int(str(temp), 16))
        index += 2
        #(f'int({temp}, 16) added to array')
        #(byte_array)
    
    #3 bit error code
    if flags >= 2**3 or flags < 0:
        return 6
    else:
        temp = bin(flags)[2:]
        temp = temp[::-1]
        while len(temp) < 3:
            temp += '0'
            
        temp = temp[::-1]
        byte = str(temp)     
        
    #13 bit error code
    if fragmentoffset >= 2**13 or fragmentoffset < 0:
        return 7
    else:
        temp = bin(fragmentoffset)[2:]
        temp = temp[::-1]
        while len(temp) < 13:
            temp += '0'
        temp = temp[::-1]
        #print(temp)
        byte += temp[:5]
        byte_array.append(int(byte, 2))
        byte_array.append(int(temp[5:], 2))
        
        
    #(byte_array)
    
    #8 bit errror code
    if timetolive >= 2**8 or timetolive < 0:
        return 8
    values = hex(timetolive)[2:]
    #Big endian code, string with even
    if len(values) % 2 == 0:
        index = 0
    else:
        byte_array.append(int(f'0{values[0]}', 16))
        index = 1
        #(f'unhex of {values[0]} added to array')
    while index < len(values):
        temp = values[index] + values[index + 1]
        byte_array.append(int(str(temp), 16))
        index += 2
        #(f'int({temp}, 16) added to array')
        
    #(byte_array)
    
    #8 bit error code
    if protocoltype >= 2**8 or protocoltype < 0:
        return 9
    values = hex(protocoltype)[2:]
    #Big endian code, string with even
    if len(values) % 2 == 0:
        index = 0
    else:
        byte_array.append(int(f'0{values[0]}', 16))
        index = 1
        #(f'unhex of {values[0]} added to array')
    while index < len(values):
        temp = values[index] + values[index + 1]
        byte_array.append(int(str(temp), 16))
        index += 2
        #(f'int({temp}, 16) added to array')
        
    #(byte_array)    
    
    #16 bit error code
    if headerchecksum >= 2**16 or headerchecksum < 0:
        return 4
    if headerchecksum < 2**8:
        byte_array.append(int('00000000'))
    #print(headerchecksum, 'ah')
    values = hex(headerchecksum)[2:]
    #Big endian code, string with even
    if len(values) % 2 == 0:
        index = 0
    else:
        byte_array.append(int(f'0{values[0]}', 16))
        index = 1
        #(f'unhex of {values[0]} added to array')
    while index < len(values):
        temp = values[index] + values[index + 1]
        byte_array.append(int(str(temp), 16))
        index += 2
        #(f'int({temp}, 16) added to array')
        #(byte_array)
        
    #(byte_array)    
    #32 bit error code
    if sourceaddress >= 2**32 or sourceaddress < 0:
        return 11
    if sourceaddress < 2**16:
        byte_array.append(0)
    values = hex(sourceaddress)[2:]
    #Big endian code, string with even
    if len(values) % 2 == 0:
        index = 0
    else:
        byte_array.append(int(f'0{values[0]}', 16))
        index = 1
        #(f'unhex of {values[0]} added to array')
    while index < len(values):
        temp = values[index] + values[index + 1]
        byte_array.append(int(str(temp), 16))
        index += 2
        #(f'int({temp}, 16) added to array')
        
    #(byte_array)    

    #32 bit error code
    if destinationaddress >= 2**32 or destinationaddress < 0:
        return 12
    if destinationaddress < 2**16:
        byte_array.append(0)
    values = hex(destinationaddress)[2:]
    #Big endian code, string with even
    if len(values) % 2 == 0:
        index = 0
    else:
        byte_array.append(int(f'0{values[0]}', 16))
        index = 1
        #(f'unhex of {values[0]} added to array')
    while index < len(values):
        temp = values[index] + values[index + 1]
        byte_array.append(int(str(temp), 16))
        index += 2
        #(f'int({temp}, 16) added to array')
    
    if hdrlen > 5:
        for num in range(hdrlen - 5):
            for item in range(4):
                byte_array.append(int('00000000'))
            #(byte_array)

    return bytearray(byte_array)

def compose_packet(hdrlen, tosdscp, identification, flags, fragmentoffset, timetolive, protocoltype, sourceaddress, destinationaddress, payload):
    """Takes all arguments for a packet header, and an extra for the packet data
    which is the payload parameter. It will check the data for validity, and then
    return an error code, or a byte_array containing the header AND packet."""
    total_length = hdrlen * 4 + len(payload)
    x = (compose_header(4, hdrlen, tosdscp, total_length, identification, flags, fragmentoffset, timetolive, protocoltype, 0, sourceaddress, destinationaddress))
    binary_num = []
    if type(x) == type(0):
        return x
    
    for item in x:
        binary_num.append(bin(item)[2:])
    

    index = 0
    iterable = []
    
    while index < len(binary_num) - 1:
        X = binary_num[index]
        Y = binary_num[index + 1]
        number1 = X
        number2 = Y
        number1 = number1[::-1]
        number2 = number2[::-1]
        while len(number1) < 8:
            number1 += '0'
        while len(number2) < 8:
            number2 += '0'
        number1 = number1[::-1]
        number2 = number2[::-1]
        index += 2
        iterable.append(int(number1 + number2, 2))
        #print(number1, number2)
    #OK SO WE THIS FAR
    X = 0
    #print(iterable)
    for item in iterable:
        X += item
        
    #Next step:
    while X > 0XFFFF:
        X0 = X & 0xFFFF
        X1 = X >> 16
        X = X0 + X1
    
    X = (bin(X)[2:])
    
    #print(X)
    empt = ''
    for i in range(len(X)):
        if X[i] == '1':
            empt += '0'
        else:
            empt += '1'
    #print(empt)
    X = empt
    #print(X)
    headerchecksum = int(X, 2)
    #print(headerchecksum)
    
    x = (compose_header(4, hdrlen, tosdscp, total_length, identification, flags, fragmentoffset, timetolive, protocoltype, headerchecksum, sourceaddress, destinationaddress))
    
    d = (payload_check(payload))
    x.extend(d)
    
    return x
    
    
        
packet = compose_packet(6, 24, 4711, 0, 22, 64, 0x06, 0x22334455, 0x66778899, bytearray([0x10, 0x11, 0x12, 0x13, 0x14, 0x15]))
print(packet.hex())

print(compose_packet(16,0,4000,0,63,22,0x06, 2190815565, 3232270145, bytearray([])))
print(compose_packet(5,63,0x10000,0,63,22,0x06, 2190815565, 3232270145, bytearray([])))