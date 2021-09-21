# Parser for command-line options, arguments and sub-commands
import argparse 
# Base16, Base32, Base64, Base85 Data Encodings
import base64 
# Miscellaneous operating system interfaces
import os
# Interpret bytes as packed binary data
import struct   


#-----------------------------------------------------

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# PBKDF2 - Password Based Key Derivation Function 2
# HMAC - hash-based message authentication code
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import Image

#------------------------------------------------------

class Header:
    MAX_FORMAT_LENGTH=8
    magicnum = "hide"
    size = 0
    fformat = "txt" #file_format

#------------------------------------------------------

def encode_in_pixel(byte, pixel):
    """Encodes a byte in the two least significant bits of each channel.
    A 4-channel pixel is needed, which should be a tuple of 4 values from 0 to 255."""

    r = (byte&3)	# getting last 2 bits
    g = (byte&12)>>2	# getting last 2 bits with right-shift 
    b = (byte&48)>>4
    a = (byte&192)>>6
    # Binary(252) = 11111100, changing last two bits and merging with data pixel channels
    color = (r+(pixel[0]&252),\
             g+(pixel[1]&252),\
             b+(pixel[2]&252),\
             a+(pixel[3]&252))
    return color

#------------------------------------------------------

def decode_from_pixel(pixel):
    """Retrieves an encoded byte from the pixel.
    The pixel should be a tuple of 4 values from 0 to 255."""
    
    r = pixel[0]&3
    g = pixel[1]&3
    b = pixel[2]&3
    a = pixel[3]&3
    # recreating the original channels
    result = r + (g<<2) + (b<<4) + (a<<6)
    # packing pixel as binary string 
    return struct.pack("B", result)

#------------------------------------------------------

def encode(image, data, filename, encryption=False, password=""):
    im = Image.open(image)
    px = im.load() 

    #Create a header
    header = Header()
    header.size = len(data)
    # if filename/extension is missing = ""
    # else get "extension" from [filename, extension]
    header.fformat = "" if (len(filename.split(os.extsep))<2) else filename.split(os.extsep)[1]

    # Add the header to the file data
    # Packs a list of values into a String representation of the specified type
    headerdata = struct.pack("4s"+"I"+str(Header.MAX_FORMAT_LENGTH)+"s",header.magicnum.encode(), header.size, header.fformat.encode())

    filebytes = headerdata + data

    #Optional encryption step
    if encryption:
        if password:
            filebytes = encrypt(filebytes, password,padding=im.width*im.height - len(filebytes))
        else:
            print ("Password is empty, encryption skipped")

    #Ensure the image is large enough to hide the data
    if len(filebytes) > im.width*im.height:
        print("Image too small to encode the file. You can store 1 byte per pixel.")
        exit()
    
    for i in range(len(filebytes)):
        coords = (i%im.width, i/im.width)
        
        byte = filebytes[i]
        
        #pixel = px[coords[0],coords[1]]
        px[coords[0], coords[1]] = encode_in_pixel(byte, px[coords[0],coords[1]])

    im.save("output.png", "PNG")

#-------------------------------------------------------------------------------

def decode(image, password=""):
    im = Image.open(image)
    px = im.load()
    # returns utf-8 encoded version of the string
    data = "".encode()  # "" -> b""

    #Decode the contents of the hidden data
    for i in range(im.height):
        for j in range(im.width):
            data += decode_from_pixel(px[j, i])
        print('running')

    #Optional decryption step
    if password :#len(password) > 0:
        nonce = data[:16]
        password =bytes(password)
        #Use key stretching to generate a secure key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), # HashAlgorithm
            length=32, # length of the derived key in bytes
            salt=bytes(password), # to add bytes of password as salt for security
            iterations=100000, # no of times algorithm runs
            backend=default_backend()) # An optional instance of PBKDF2HMACBackend

        key = kdf.derive(bytes(password))
	"""
	algorithm – CipherAlgorithm (AES: Block Cipher)
	mode - mode instance for algorithm
	CTR - transforms a block cipher into a stream cipher
	nonce - unique
	"""
        cipher = Cipher(algorithms.AES(key),modes.CTR(nonce), backend=default_backend())
	# decrypting CipherContext instance
        dec = cipher.decryptor()
        # getting data excluding header
        data = dec.update(data[16:]) + dec.finalize()

    # Create the header for reading
    header = Header()
    """ 
    Unpacks the header into its original representation with the specified format
    s - string, I - int
    4+4 = headersize+magicnum
    """
    headerdata = struct.unpack("4s"+"I"+str(Header.MAX_FORMAT_LENGTH)+"s",data[:4+4+Header.MAX_FORMAT_LENGTH])
    header.magicnum = headerdata[0].decode()
    header.size = headerdata[1]
    var12 = headerdata[2].decode()
    header.fformat = var12.strip("\x00")

    #Verify integrity of recovered data
    if header.magicnum != Header.magicnum:
        print ("There is no data to recover, quitting")
        exit()

    data = data[4+4+Header.MAX_FORMAT_LENGTH:4+4+Header.MAX_FORMAT_LENGTH+header.size]
    # Prints output.extension
    print ("Saving decoded output as {}".format("output"+os.extsep+header.fformat))
    with open("output"+os.extsep+header.fformat, 'wb') as outf:
        outf.write(data)

#-------------------------------------------------------------------------------

def encrypt(data, password, padding=0):
    """Encrypts data using the password.
    Encrypts the data using the provided password using the cryptography module.
    The password is converted into a base64-encoded key which is then used in a
    symmetric encryption algorithm.
    """

    if padding < 0:
        print ("Image too small to encode the file. You can store 1 byte per pixel.")
        exit()

    password = bytes(password)

    #Use key stretching to generate a secure key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(password),
        iterations=100000,
        backend=default_backend())

    key = kdf.derive(bytes(password))

    nonce = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    enc = cipher.encryptor()
    ct = enc.update(data) + enc.finalize()

    #Add padding if needed
    ct += os.urandom(padding-16)

    #add nonce to data to allow decryption later (nonce does not need to be kept
    #secret and is indistinguishable from random noise)
    return bytes(nonce) + ct

#-------------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Process images")
    # A backslash at the end of a line tells Python to extend the current logical line over across to the next physical line
    parser.add_argument("-i", "--image", help="The name of the file to be \
    encoded or decoded", required=True)
    parser.add_argument("-f", "--file")
    parser.add_argument("-a", "--action", required=True)
    parser.add_argument("-p", "--password", help="password used to decode \
    or encode secret data. If not used, the data will not be encrypted.")
    args = parser.parse_args()

    if action=="encode":
        if not file:
            print ("You need to specify a file to encode.")
            exit()

        with open(file, 'rb') as data:
            if password!=None and len(password)>0:
                var = data.read()
                encode(image, var, file, encryption=True,password=password)
            else:
                encode(image, data.read(), file)

    elif action=="decode":
        if password!=None and len(password)>0:
            decode(image, password=password)
        else:
            decode(image)
    else:
        print ("Incorrect action selected (choose encode or decode)")

if __name__ == '__main__':
    main()
