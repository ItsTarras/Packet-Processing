def payload(packet):
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

packet = bytearray([0x46, 0x00, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x68, 0x86, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x00, 0x00, 0x00, 0x00, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18])
print(payload(packet))

packet = bytearray([0x45, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x69, 0x8d, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x10, 0x11, 0x12])
print(payload(packet))