# Importing library
from hashlib import md5
from Cryptodome.Cipher import AES
from os import urandom
import glob, os
import sys
import base64
import qrcode 
from PIL import Image
from pyzbar.pyzbar import decode
from PIL import Image


def derive_key_and_iv(password, salt, key_length, iv_length): #derive key and IV from password and salt.
    d = d_i = b''
    while len(d) < key_length + iv_length:
        d_i = md5(d_i + str.encode(password) + salt).digest() #obtain the md5 hash value
        d += d_i
    return d[:key_length], d[key_length:key_length+iv_length]

def encrypt(in_file, out_file, password, key_length=32):
    bs = AES.block_size #16 bytes
    salt = urandom(bs) #return a string of random bytes
    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    out_file.write(salt)
    finished = False

    while not finished:
        chunk = in_file.read(1024 * bs) 
        if len(chunk) == 0 or len(chunk) % bs != 0:#final block/chunk is padded before encryption
            padding_length = (bs - len(chunk) % bs) or bs
            chunk += str.encode(padding_length * chr(padding_length))
            finished = True
        out_file.write(cipher.encrypt(chunk))

def decrypt(in_file, out_file, password, key_length=32):
    bs = AES.block_size
    salt = in_file.read(bs)
    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    next_chunk = ''
    finished = False
    while not finished:
        chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))
        if len(next_chunk) == 0:
            padding_length = chunk[-1]
            chunk = chunk[:-padding_length]
            finished = True 
        out_file.write(bytes(x for x in chunk)) 

def spliter(input_file):
    lines_per_file = 4
    smallfile = None
    counter = 0
    with open(input_file) as bigfile:
        for lineno, line in enumerate(bigfile):
            if lineno % lines_per_file == 0:
                if smallfile:
                    smallfile.close()
                small_filename = str(counter)+'.text'
                smallfile = open(small_filename, "w")
                counter += 1
            smallfile.write(line)
            
        if smallfile:
            smallfile.close()

def concatenation():
    with open('decrypted_file', 'w') as outfile:
        for fname in sorted(glob.glob('*.text-decrypted-decoded-base64')):
            with open(fname) as infile:
                for line in infile:
                    outfile.write(line)
            os.remove(fname)
                
        

def qrcode_generator(input_file):
    with open(input_file, "r") as input_file:
        img = qrcode.make(input_file.read())
        qrcode_file_name = input_file.name+'.png'
        img.save(qrcode_file_name)
        os.remove(input_file.name)

def qrcode_convertor(input_file):
    decocdeQR = decode(Image.open(input_file))
    return(decocdeQR[0].data.decode('ascii'))


def add_text_to_qrcode(in_file):   
    background = Image.new('RGBA', (1000, 1000), (255,255,255,255))
    from PIL import ImageDraw
    draw = ImageDraw.Draw(background)
    draw.text((5,5), in_file, (0,0,0))
    qr = Image.open(in_file)
    background.paste(qr, (0,20))
    background.save(in_file)

def cleanup():
    files = [f for f in os.listdir('.') if f.endswith('.png')]
    for file in files: 
        os.remove(file)
#=====================================================================================
#=====================================================================================
#=====================================================================================
# cleanup
cleanup()


password = 'YOUR_STRONG_PASSWORD' #shouldn't be something this simple

mode = sys.argv[1] if len(sys.argv[1]) >= 7 else exit(1)
file_name = sys.argv[2] if len(sys.argv[2]) >= 3 else exit(1)
if os.path.isfile(file_name):
    ## encrypt mode description
    if "encrypt" in mode:
        # split file into some files that each file has 4 lines
        spliter(file_name)
        files = [f for f in os.listdir('.') if f.endswith('.text')]
        # encrypt each file with password and AES 
        for file in files:
            with open(file, 'rb') as in_file, open(file+'-encrypted', 'wb') as out_file:
                encrypt(in_file, out_file, password)
            
                
            # encode each encrypted file with base64
            with open (file+'-encrypted', 'rb') as encrypted_file, open(file+'-encrypted-encoded-base64', 'wb') as encrypted_file_base64:
                encoded_data = base64.b64encode(encrypted_file.read())
                encrypted_file_base64.write(encoded_data)

            # generate qrcode from every base64 files
            qrcode_generator(str(file)+'-encrypted-encoded-base64')
            os.remove(file)
            os.remove(file+'-encrypted')

        files = [f for f in os.listdir('.') if f.endswith('.png')]
        for file in files:
            add_text_to_qrcode(file)

    # decrypt mode description
    elif "decrypt" in mode:
        # read qrcode from every base64 files
        for input_file in sorted(glob.glob('*.text-encrypted-encoded-base64.png')):
            with open(input_file, 'rb') as in_file, open(input_file.replace(".png",""), 'wb') as out_file:
                converted_png = qrcode_convertor(in_file)
                out_file.write(converted_png.encode())
                os.remove(input_file)
        
        
        # decode each encrypted files with base64
        for input_file in sorted(glob.glob('*.text-encrypted-encoded-base64')):
            with open(input_file, 'rb') as in_file, open(input_file.replace("encrypted-encoded-base64","encrypted-decoded-base64"), 'wb') as decrypted_file_base64:
                decoded_data = base64.b64decode(in_file.read())
                decrypted_file_base64.write(decoded_data)
                os.remove(input_file)

        # decrypt each file with password and AES 
        for input_file in sorted(glob.glob('*.text-encrypted-decoded-base64')):
            with open(input_file, 'rb') as in_file, open(input_file.replace("encrypted","decrypted"), 'wb') as out_file:
                decrypt(in_file, out_file, password)
                os.remove(input_file)

        # concatenation files into 1 file
        concatenation()
    else:
        print("choose encrypt or decrypt")
else:
    print("file not found !")
