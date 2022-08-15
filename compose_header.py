import struct
def compose_header(version, hdrlen, tosdscp, totallength, identification, flags, fragmentoffset, timetolive, protocoltype, headerchecksum, sourceaddress, destinationaddress):
    """returns the header packet, or an error depending on the input"""

    byte_array = []
    if version != 4:
        return 1
    else:
        byte = '0100'
    #4 Bit error code
    if hdrlen >= 2**4 or hdrlen < 0:
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
    else:
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
        while len(temp) < 6:
            temp += '0'
            
        temp = temp[::-1]
        byte = str(temp)
        byte += '00'
        byte_array.append(int(str(byte), 2))
        #(byte, "added to array")
        byte = '00000000'        
        
    #13 bit error code
    if fragmentoffset >= 2**13 or fragmentoffset < 0:
        return 7
    values = hex(fragmentoffset)[2:]
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
        return 10
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
    #32 bit error code
    if sourceaddress >= 2**32 or sourceaddress < 0:
        return 11
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
        
    #(byte_array)
    
    return bytearray(byte_array)

header = compose_header(4,6,24,0,4200,0,63,22,6,4711, 2190815565, 3232270145)
print(header)
print(len(header))
print(header.hex())