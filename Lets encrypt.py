## Encryption software based on my ransomware lmfao
## This code is an absolute abomination lol I have
## no idea if this works or not. 
import os, threading, subprocess, cffi, ctypes, win32api, hashlib, webbrowser
import tkinter as tk
from Crypto.Cipher import AES, ChaCha20, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from tkinter import messagebox
from tkinter import filedialog ## Why do we have to import this seperatly if we import everything? like how stupid is this

## Currently AES-CTR-256 and CHACHA20
## are planned to be supported
## So we use RSA to encrypt the metadata of the file
## and it also encrypts the encryption key used to 
## encrypt the files. Wow that was a mouth full. 

## Encryptor
def encrypt_file(path_to_file, encryption_mode,  rsa_key_pub, rsa_key_size, delete_og_file) :
    ## We have a checker to make sure that
    ## the data inputted is correct
    datalist = []

    global cryptographic_library_version 
    cryptographic_library_version = "2023-09-09.rc1.gpc_main"
    

    ## We raise an exception if the RSA key is less than 3072 
    ## bits long. This is not done for security but its security
    ## improvements are welcomed. This is done because the
    ## amount of data that RSA-2048 can encrypt is only about 256
    ## but if the key is 3072 it means that we can encrypt 384-bytes
    ## of data which should be enough for what we're doing here.
    rsa_key_pub = RSA.import_key(rsa_key_pub)
    if rsa_key_pub.can_encrypt() is False :
        raise Exception("The inputted RSA cannot be used to encrypt files, please select or generate another key.")
    if rsa_key_size < 3072 :
        raise Exception("RSA key too small! RSA keys of 3072 and larger keys are supported. This is due to the file header being longer than RSA 2048's maximum encryption length.")

    try :
        with open(path_to_file, 'rb') as plain_file :
            plain_text = plain_file.read()
        file_size = os.path.getsize(path_to_file)
    except FileNotFoundError :
        raise FileNotFoundError("The requested file for encryption does not exist.")
    
    file_name = os.path.basename(path_to_file)

    ## Generating the encryption key
    encryption_key = get_random_bytes(32)

    ## If AES is used
    if 'AES' in encryption_mode :
        cipher = AES.new(encryption_key, AES.MODE_CTR)
        nonce = cipher.nonce

    ## Elif CHACHA20 is used
    elif 'CHACHA' in encryption_mode :

        ## CHACHA20-RFC-7539 can only encrypt 256 GiBs worth of data due to using a 96-bit nounce.
        ## This will probably not be an issue for most people but it is important to catch it when
        ## it does happen.
        if file_size >= 2199023255552 :
            raise OverflowError("CHACHA20 in its RFC-7539 compliant configuration uses a 96-bit nounce, which limits the amount of data it can encrypt to 256 GiB which is ≈ 256 GB")

        ## We use a 12-byte nonce to increase security and
        ## comply with RFC-7539 which requires a 12-byte
        ## nonce for improved security. Which limits us to
        ## only 256 GiBs worth of data we can encrypt.
        nonce = get_random_bytes(12)
        cipher = ChaCha20.new(key=encryption_key, nonce=nonce)

        ## This is the part where we encrypt the encryption keys
        ## with the RSA keys to make sure that it stays secure in
        ## transit.
        ## Order of the list
        ## [Encryption key, nonce/iv, encryption mode, file size, file hash after encryption, file hash before encryption, hash algorithm]
        ## Example datalist
        ## ['256-bit encryption key', '96-bit IV', 'AES-256-CTR', 12345678910, 'Some-generic-SHA512 hash', 'Another-generic-SHA512 hash', 'SHA2-512']
    none_enc_hash = hash_object(plain_text)
    plain_text = cipher.encrypt(plain_text)
    datalist.append(encryption_key)
    datalist.append(nonce)
    datalist.append(encryption_mode)
    datalist.append(file_size)
    datalist.append(hash_object(plain_text))
    datalist.append(none_enc_hash)
    datalist.append(file_name)

    cipher = PKCS1_OAEP.new(rsa_key_pub)
    datalist = cipher.encrypt(datalist)

    if rsa_key_size >= 100000 :
        raise ValueError("RSA key too long, we recommend using 4096-bit to 8192-bit RSA keys for encryption.")
    header_length = len(datalist)
    header_length = '0' + str(header_length)

    ## We overwrite the original non-encrypted
    ## file because people can recover it with
    ## special software. But by re-writting
    ## it with encrypted data, they will only 
    ## see the encrypted data. 
    if delete_og_file == True :
        with open(path_to_file, 'wb') as encrypted_file :
            encrypted_file.write(b'Hello, World!:-)')
            encrypted_file.write(bytes(header_length))
            encrypted_file.write(datalist)
            encrypted_file.write(plain_text)
        os.rename(path_to_file, path_to_file + '.encr')

    elif delete_og_file == False :
        with open(path_to_file + '.encr', 'wb') as encrypted_file :
            encrypted_file.write(b'Hello, World!:-)')
            encrypted_file.write(bytes(header_length))
            encrypted_file.write(datalist)
            encrypted_file.write(plain_text)
        
## The formatt of the encrypted file should be :
## File head/Hello World!
## RSA key size
## RSA encrypted datalist
## The encrypted data

def decrypt_file(path_to_file, rsa_key, delete_og_file) :
    ## Basically we are doing the excapt same thing as the
    ## encrypt_file() function except its backwards and it
    ## requires way less inputs inorder to get an output
    try :
        with open(path_to_file, 'rb') as plain_file :
            head = plain_file.read(16)

            if head != b'Hello, World!:-)' :
                raise ValueError('The file has been corrupted or edited.')

            rsa_key_size = plain_file.read(5)
            rsa_key_size = int(rsa_key_size)
            datalist = plain_file.read(rsa_key_size)
            cipher_text = plain_file.read()
    except FileNotFoundError :
        raise FileNotFoundError("The requested file for encryption does not exist.")
    
    cipher = PKCS1_OAEP.new(rsa_key)

    datalist = cipher.decrypt(datalist)
    datalist = list(datalist)
    encryption_key = datalist[0]
    nonce = datalist[1]
    encryption_mode = datalist[2]
    file_size = datalist[3]
    enc_hash = datalist[4]
    none_enc_hash = datalist[5]
    file_name = datalist[6]

    current_filename = os.path.basename(path_to_file)
    new_path_to_file = path_to_file.replace(current_filename, file_name)

    if enc_hash != hash_object(cipher_text) :
        raise Exception("File encrypted file hashes does not match.")

    if 'AES' in encryption_mode :
        cipher = AES.new(encryption_key, AES.MODE_CTR, nonce=nonce)

    elif 'CHACHA' in encryption_mode :
        cipher = ChaCha20.new(encryption_key, nonce=nonce)
    
    cipher_text = cipher.decrypt(cipher_text)
    
    if none_enc_hash != hash_object(cipher_text) :
        raise Exception("Decrypted file hashes does not match.")

    if delete_og_file == True :
        with open(path_to_file, 'wb') as decrypted_file :
            decrypted_file.write(cipher_text)
        
        os.rename(path_to_file, new_path_to_file)
        
    elif delete_og_file == False :
        with open(new_path_to_file, 'wb') as decrypted_file :
            decrypted_file.write(cipher_text)
        
    if file_size != os.path.getsize(new_path_to_file) :
        raise Exception("File sizes do not match.")


def gen_rsa(rsa_key_size) :
    if rsa_key_size >= 65537 :
        raise ValueError("RSA key sizes of over 65537 cause unexpected behaviour, please choose a shorter key length.")
    elif rsa_key < 3072 :
        raise ValueError("RSA key sizes of under 3072 is considered insecure for this application, please choose a longer key length.")
    rsa_key = RSA.generate(rsa_key_size)
    private_key = RSA.import_key(rsa_key)
    rsa_key_pub = private_key.public_key().export_key('PEM')
    return rsa_key, rsa_key_pub

def hash_object(object_to_hash) :
    obj_bytes = str(object_to_hash).encode('utf-8')
    hasher = hashlib.sha3_512()
    hasher.update(obj_bytes)
    hashed_object = hasher.hexdigest()
    return hashed_object

def createnewthread(thefunction, arguments):
    newthread = threading.Thread(target=thefunction, args=arguments, daemon=True)
    newthread.start()

## This is the variable sh-- I mean stuff
## for frontend.

## Defines screen size
Yvalue = str(600)
Xvalue = str(800)

about_txt = """
Let's Encrypt Build 2023-09-04.rc1.gpc_main
Made by: A Random Person
License: Apache License
Date of programming: 2023-09-04 23:00:00
Why did I do this: No idea
"""

build_string = "2023-09-09.rc1.gpc_main"

## GPC is desktop, there are multiple "branches"
## of the encryptor.



## This is the frontend
class PopupManager:

    def __init__(self, max_popups):
        self.max_popups = max_popups
        self.popups = []

    def create_popup(self, popup_title, popup_text):
        if len(self.popups) < self.max_popups:
            popup = tk.Toplevel(root)
            popup.title(popup_title)
            popup.geometry(str(int(int(Xvalue)/2)) + "x" + str(int(int(Yvalue)/2))) ## This is so stupidly jank by converting it into int twice, we can first turn a string into int which we divide which gives float then int again to get a int only to string again...
            tk.Label(popup, text=popup_text, font=(16)).place(x=5, y=5)
            self.popups.append(popup)
            popup.protocol("WM_DELETE_WINDOW", lambda p=popup: self.close_popup(p))
        else : 
            messagebox.showwarning(title="Too many popups!", message="Please close a popup before opening another.")

    ## IDK what this is for, but I asked ChatGPT to write it so ¯\_(ツ)_/¯
    def close_popup(self, popup):
        popup.destroy()
        self.popups.remove(popup)
    

def about_cmd(): 
    popup_manager.create_popup(popup_title="About: Let's Encrypt!", popup_text=about_txt)

def redir_to_site():
    webbrowser.open("https://randomperson.net/")

## Main loop stuff idk what this does ¯\_(ツ)_/¯
root = tk.Tk()

popup_manager = PopupManager(max_popups=3)

root.title("Let's, Encrypt!")



root.geometry(Xvalue + 'x' + Yvalue)

menu = tk.Menu(root)

## Help command
helpcmd = tk.Menu(menu)
helpcmd.add_command(label="Website", command=redir_to_site)
helpcmd.add_command(label="About", command=about_cmd)


## About version command
menu.add_cascade(label="Help", menu=helpcmd)
root.config(menu=menu)


## I gaved up on electron lmfao
root.mainloop()


