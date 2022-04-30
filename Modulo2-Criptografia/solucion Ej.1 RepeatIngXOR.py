from statistics import mean
import re
import base64

def otp(data, key):
    out = [(lambda a, b : a ^ b)(*l) for l in zip(data, key)]
    return bytes(out)

def repeatingxor(b, key):   
    k = (key * len(b))[0:len(b)]
    return otp(b, k)

english_frequency = {
    b'a': 0.08167,
    b'b': 0.01492,
    b'c': 0.02782,
    b'd': 0.04253,
    b'e': 0.12702,
    b'f': 0.02228,
    b'g': 0.02015,
    b'h': 0.06094,
    b'i': 0.06966,
    b'j': 0.00153,
    b'k': 0.00772,
    b'l': 0.04025,
    b'm': 0.02406,
    b'n': 0.06749,
    b'o': 0.07507,
    b'p': 0.01929,
    b'q': 0.00095,
    b'r': 0.05987,
    b's': 0.06327,
    b't': 0.09056,
    b'u': 0.02758,
    b'v': 0.00978,
    b'w': 0.02360,
    b'x': 0.00150,
    b'y': 0.01974,
    b'z': 0.00074,
}

def frequency_analysis(text):
    # try:
    regex = re.compile(b'[^a-zA-Z]')
    alpha = regex.sub(b'', text).decode().lower()
    observed_frequency = { i: 0 for i in list(english_frequency.keys()) }
    for char in alpha:
        observed_frequency[char.encode('ascii')] += 1

    observed_list = list(observed_frequency.values())
    expected_list = list(english_frequency.values())

    meanSqErr = mean([(lambda f1, f2 : (f1-f2)**(2.0))(*l) for l in zip(expected_list, observed_list)])
    spaces = text.count(b' ')
    symbolFreq = 1.0 - ( float(len(alpha) + spaces) / float(len(text)) )
    if symbolFreq > 0.7:
        return 1000
    penalizer = 1.0 + (symbolFreq*7)
    return meanSqErr * penalizer

def transpose(m):
    return [bytes([m[j][i] for j in range(len(m))]) for i in range(len(m[0]))]

# group: bytes
def brute_force(group):
    DEBUG = True
    best_k = 0
    best_score = -1
    if (DEBUG):
        print("----------------------------------------------------")
    for i in range(0, 128):
        k = bytes([i])
        plain = repeatingxor(group, k)
        f_score = frequency_analysis(plain)
        if (f_score < 100 and DEBUG):
            print("[" + str(f_score) + "] (" + str(k) + ") " + str(plain))
        if best_score < 0 or f_score < best_score:
            best_k = k
            best_score = f_score
    return best_k

# enc_messages: bytes[]
# Como mas mensajes mejor
def get_key_many_time_pad(enc_messages):
    groups = transpose(enc_messages)
    print(groups)
    # print(groups[1])
    # print(groups[2]) # 5 grupos

    # first_letter = []
    # for cipher in encrypted_messages:
    #     first_letter.append(cipher[0])
    # first_letter = bytes(first_letter)
    # print(brute_force(first_letter))

    key = []
    for g in groups:
        k = brute_force(g)
        key.append(k)
    return b''.join(key)

'''
common_5_letter_words = [
    b"seven",
    b"world",
    b"about", b"again", b"heart", b"pizza", b"water", b"Happy", b"sixty", b"board", b"month", b"angel", b"death", b"green", b"music",
    b"fifty", b"three", b"party", b"piano", b"kelly", b"mouth", b"woman", b"sugar", b"amber", b"dream", b"hello", b"world", b"apple", b"laugh", b"tiger",
    b"faith", b"earth", b"river", b"money"
]
'''
#Convierto el mensaje encriptado en base64 en hexadecimal
mb64_to_mhex = base64.b64decode('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').hex()
#print(mb64_to_mhex)

#Divido el mensaje en bloques de 20 caracteres hexadecimal  
hex_encrypted_message = "3c004202064f0a064e141f17041e040a161a4e130445091f150a6e3001124b0e0b1f144f10010b4719100915104f05070a47180a45140c4f2d632f470d10091c430c0b04030e1f08001e17481749190f0a1145394402441d060e050e0c1e044f0b0f643e041045070c1a080d00401f450215174f100107144b03171f0e4f0507174704110d15114f031c176d22450f05101b441e0f09050445040603084917081e450d1f144f2d4e03470d00001c0a01036329081f1104500e0e0f0c4e1e041045050d0b011b1d130a0b017a2d0a120c1c470c0a0b1e024f030018024b1c0a05431a146320021d00175004000a070f47070011501a0011490a081c0b6f3e0619011b4e00040b0b11431d11074e06190a101e074f05070a470f001615111b44100112612b0006061d440e01090504451d0204014917081e4506021a652a0c18021945021f0d0105491d061245021f0c0b06100b6d25001315114f030600090a4511150f0344084e0b020045110d0b44011b151f451c1f1665330c49110e450e1e0c180a490b06080d451f1707011b4e01041745030c4f08060000613c0a05114f0c0c0f151f421650010a01074e06080d0c1e044f061c1a47120a1057110a441d01084b160d09431b0b491d0612450c0469260a1a07030e451215430d0b1d0647000b0a0743180c081a40184507150601440e010e0502451f0d65330c4e0c050a1250170701490906060045110d0b441e0b40190045170c010a084e1707041c500a1b6e2800034b0c03501a0011490f140045081543070b1e4e2e4c084516060a0800000061210a1e441b441d0b0b0745081543160b1c49150e45111f0c4f060507090f45111f431c010c64290e13000243080b0700064b020c06064f1d061b471e156f3e0619011b4e00040b0b114303011d4e1e041045140c180a6320021d00175004000a070f4719100b50021d0b1c00034b040b14430b011a0b151f451c1f16652a0c18021945021f0d0105490306000045090c1a440a1c1e612b0006061d440e0109050445030216440e01080f071c156921011f0b154b020a1e0d0e441d0b0b074504500f0601490f090f450d05111b44100112612b0006061d440e0109050445170a19014917081e4510006921011f0b154b020a1e0d0e44050b134b1c0a05430b0b1e006d25001315114f030600090a4517050d4f051b0112050145110d0b440d0b140e1711501a00116320021d00175004000a070f4706040e1543160b1c4e04191c6f3e0619011b4e00040b0b11431c05104e00040a01121a0a6e270b110e1745170c010a084e130e090950024f08000b470a0b01500b1a161d4e1e04106f3e0619011b4e00040b0b1143080d1f0b4b4b0b0006061d440e0109050445170a1901634620021300501a0011491b17426f4d3f0c074d4920021d00175004000a070f470c0c13154f4f0a0c18021945021f0d010549090e1d006f582406120c4e1e0410450513466e3e0b401d00451b0d0013074e020a060d500c1b0c0c1c470d0a17501000440501090c6f3c1f161d44010b0619114203430d010c00470a060d190d08440b1b134b1c0a05441d01491a08044516181a4f10064e140a1c451917652d071d0e0f004507064f06061a0f4b0e0b1f144f13010f134c164512060a0a490908020b02500c016e3e0b47000b0a07431b0c0c4e000a0800500201004919024c17005004000a070f471b090409430610632747011016044318050700064b11001c0f4f1d061b47030a12502a48094908020e090c1e046523061a130a450811080a441001124b100b14061d171d0f090f6f2b15150a16490908050b04500406120c4e1e0410450513652a0c18021945021f0d01054902021f451c1f164f00061909612b0006061d440e010905044502160144081c081e0b0150020100490a021800170443160b1c64290e13000243080b0700064b08041b064f1d061b4708171c7a2d0a120c1c470c0a0b1e024f170817470c0a0a140116016320021d00175004000a070f471f00091c430e440507024b040b144307111b1a47120a107a2d0a120c1c470c0a0b1e024f030018024b1c0a05431a146320021d00175004000a070f47070011501a0011490a081c0b6f3e0619011b4e00040b0b11431d11074e06190a101e074f05070a470f001615111b44100112612b0006061d440e01090504451d0204014917081e4506021a652a0c18021945021f0d0105491d061245021f0c0b06100b6d25001315114f030600090a4511150f0344084e0b020045110d0b44011b151f451c1f16652a0c18021945021f0d010549090e1d0045090c1a441c1e6d25001315114f030600090a450915174f1d061b470f0a121e6921011f0b154b020a1e0d0e441b1b094b04171f160100490f090f450115100a161d4e1e04106f3e0619011b4e00040b0b11430205020b47120a1050001d1d"
ciphertext1= bytes.fromhex(hex_encrypted_message)
print (ciphertext1)
blocks = [ ciphertext1[i:i+20] for i in range(0, len(ciphertext1), 20) ]
#print(blocks)

def transpose_blocks(message, key_sz):
    transposed_blocks = []
    partitioned_blocks = blocks(message, key_sz)
    for byte_i in range(0, 10):
        transposed_block_i = ''
        transposed_block_i = ''.join([ chr(block[byte_i]) for block in partitioned_blocks ])
        transposed_blocks.append(transposed_block_i)

    return transposed_blocks


def decrypt_message(message, key):
    partitioned_blocks = blocks(message, len(key))
    #print(partitioned_blocks)
    return ''.join([  ''.join([ chr( ord(key[i]) ^ block[i] ) for i in range(0, len(key) ) ]) for block in partitioned_blocks ])

# ***** Intuyo que parte de la solución del ejercicio puede estar en esta linea siguiente. Me falta saber por que valor 
# tengo que sustituir la b"HELLOWORLD" para que la key no sea esa, sino la que sale como solución como la mas probable
# He puesto b"HELLOWORLD" para que la key sea de 10 caracteres, igual que Sergi en clase puso "HELLO" porque quería una 
# clave de 5 caracteres, pero intuyo que esta no es la solución para hallar la clave correcta ********
# decrypted_message = list(map((lambda x: otp(x, b"THISISAKEY")), blocks))

# **** Pregunta para SERGI: ¿Hace falta conocer como modificar la funcion lambda de la linea anterior para resolver el 
# ejercicio y hallar la clave de 10 caracteres? ********


#key = get_key_many_time_pad(ciphertext1)
print("key found!")
#print(key)

# b'seven'
# b'hello'
# c=b'12345' -> [0]

# httP:/youtube
# AAAAAAAAAAAAA
# XXXXXXXXXXXXX

# swaffate
# HHHHHHHH
# XXXXXXXX
