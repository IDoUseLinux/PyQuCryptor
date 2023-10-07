## Encryption software based on my ransomware lmao
## This code is an absolute abomination lol I have
## no idea if this works or not. 
import os, threading, subprocess, cffi, ctypes, hashlib, webbrowser, sys, json
import tkinter as tk
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from random import SystemRandom
from tkinter import messagebox
from tkinter import filedialog ## Why do we have to import this seperatly if we import everything? like how stupid is this

## Currently AES-256-CTR is the only cipher suit supported 
## Here is the defining that comes before everything else
def is_admin() :
    global is_user_admin
    try:
        if ctypes.windll.shell32.IsUserAnAdmin() == '1' :
            is_user_admin = True
            return True
        else :
            is_user_admin = False
            return False
    except:
        is_user_admin = False
        return False

## For the like 1 other person that will ever see this program
## This segment of code requests for admin privilidges.  
def request_uac_elevation() :
    global is_user_admin
    if is_user_admin == False :
        try :
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            if is_admin() :
                is_user_admin = True
                return True
            else :
                return False
        except :
            is_user_admin = False
            return False
    else: return True

#hashtemp = '' ## LOL the random variable that breaks the program if not defined
## Encryptor/decryptor object
class enc_dec_obj() :

    cryptographic_library_version = "2023-10-02.gpc_main.rc3.v05"
    
    admin = is_admin()

    def __init__(self) -> None:
        pass

    def encrypt_file(self, password, path_to_file, delete_og_file=False) :
        ## datalist is for unencrypted metadata of the file. datalist2 is for the encrypted metadata.
        datalist = [] ## Non-encrypted file header
        datalist2 = [] ## Encrypted file header
        datalist3 = [] ## Temporary copy of non-encrypted version of encrypted file header
        try :
            with open(path_to_file, 'rb') :
                pass
        except FileNotFoundError :
            raise FileNotFoundError("The requested file for encryption does not exist.")
        
        ## Generating the encryption key
        encryption_key = get_random_bytes(32)

        cipher = AES.new(encryption_key, AES.MODE_CTR, nonce=get_random_bytes(11))

        ## Passwod salt
        datalist.append(get_random_bytes(24))

        ## Encryption Nonce
        datalist.append(get_random_bytes(12))

        ## The encryption key used to encrypt files
        datalist2.append(encryption_key)
        ## The nonce used to encrypt files
        datalist2.append(cipher.nonce)

        hash_thread = threading.Thread(target=hash_object, args=(None, path_to_file, 'a')) ## a mode auto-assigns the variable to the datalist
        hash_thread.start()
        hash_thread.join()

        datalist2.append(hashtemp)

        ## This stupid line of code somehow **works first time**
        ## But basically it takes in a password, combines it with 
        ## a salt and turns it into an encryption key that is used
        ## to encrypt the file header.
        datalist3 = datalist2.copy()

        encr_encr_key = hashlib.pbkdf2_hmac("sha3_256", bytes(password, 'utf-8'), datalist[0], 1048576, 32)

        datalist.append(hash_object(object_to_hash=datalist2[0] + datalist2[1] + bytes.fromhex(datalist2[2]), mode="r"))

        datalist[2] = bytes.fromhex(datalist[2])
        
        cipher = AES.new(encr_encr_key, AES.MODE_CTR, nonce=datalist[1])

        datalist2[0] = cipher.encrypt(datalist2[0])

        datalist2[1] = cipher.encrypt(datalist2[1])

        ## We have to encode this in bytes because of AES encryption.
        datalist2[2] = cipher.encrypt(bytes.fromhex(datalist2[2]))

        cipher = AES.new(datalist3[0], AES.MODE_CTR, nonce=datalist3[1])

        with open(path_to_file, 'rb') as plain_file :
            with open(path_to_file + '.encr', 'wb') as encrypted_file :

                ## Password salt
                encrypted_file.write(datalist[0])

                ## Non-encrypted cipher nonce
                encrypted_file.write(datalist[1])

                ## Hash of encrypted file header
                encrypted_file.write(datalist[2])

                ## Encrypted 32-byte Encryption key
                encrypted_file.write(datalist2[0])

                ## Encrypted 11-byte Nonce
                encrypted_file.write(datalist2[1])

                ## Encrypted SHA3-512 Hash/Checksum
                encrypted_file.write(datalist2[2])

                ## Encrypting
                buffer = plain_file.read(65536)
                while len(buffer) > 0 :
                    ## Encrypted File
                    encrypted_file.write(cipher.encrypt(buffer))
                    buffer = plain_file.read(65536)

                print("encrypted file")
        if delete_og_file == True :
            os.remove(path_to_file)

        messagebox.showinfo(title="Let's Encrypt: Finished Encryption!", message="Finished Encryption of file(s).") 
        

    def decrypt_file(self, password, path_to_file, delete_og_file = False ) :
        ## Basically we are doing the excapt same thing as the
        ## encrypt_file() function except its backwards and it
        ## requires way less inputs inorder to get an output
        datalist = []
        datalist2 = []
        
        try : 
            with open(path_to_file, 'rb') as encr_key_loc :
                
                ## Password Salt
                datalist.append(encr_key_loc.read(24))
                ## Encryptor's Nonce
                datalist.append(encr_key_loc.read(12))
                ## Encrypted file header hash
                datalist.append(bytes.hex(encr_key_loc.read(64))) 
                
                ## Encrypted Encryption Key 32 bytes
                datalist2.append(encr_key_loc.read(32))
                ## Encrypted Nonce 11 bytes
                datalist2.append(encr_key_loc.read(11))
                ## Encrypted non-encrypted file checksum/hash 64 bytes
                datalist2.append(encr_key_loc.read(64)) 
                ## We don't read the rest of the file because we only need the header
                ## Plus it would nuke the system's memory if we were to do so

        except FileNotFoundError :
            raise FileNotFoundError("The requested file for decryption does not exist.")

        ## This stupid line of code somehow **works first time**
        ## But basically it takes in a password, combines it with 
        ## a salt and turns it into an encryption key that is used
        ## to decrypt the file header.
        cipher = AES.new(hashlib.pbkdf2_hmac("sha3_256", bytes(password, 'utf-8'), datalist[0], 1048576, 32), AES.MODE_CTR, nonce=datalist[1])
        
        ## Decrypts the encrypted metadata
        datalist2[0] = cipher.decrypt(datalist2[0])

        datalist2[1] = cipher.decrypt(datalist2[1])

        datalist2[2] = bytes.hex(cipher.decrypt(datalist2[2]))

        if datalist[2] != hash_object(object_to_hash=datalist2[0] + datalist2[1] + bytes.fromhex(datalist2[2]), mode="r") :
            messagebox.showerror(title="Decrypt Error", message="Incorrect password and/or corrupted file header.")
            raise ValueError("Password is incorrect.")

        ## Overwrites the original cipher object with the one to decrypt files with. 
        cipher = AES.new(datalist2[0], AES.MODE_CTR, nonce=datalist2[1])

        with open(path_to_file, 'rb') as encrypted_file :
            encrypted_file.read(207) ## We read the file header first
            with open(path_to_file + ".temp", 'wb') as decrypted_file :
                buffer = encrypted_file.read(65536)
                while len(buffer) > 0 :
                    decrypted_file.write(cipher.decrypt(buffer))
                    buffer = encrypted_file.read(65536)

        hash_thread = threading.Thread(target=hash_object, args=(None, path_to_file + ".temp", 'a')) ## a mode auto-assigns the variable to hash_temp
        hash_thread.start()
        hash_thread.join()
        ## We check if the file that has been decrypted is
        ## the same as the file that was originally encrypted
        if datalist2[2] != hashtemp :
            messagebox.showerror(title="Decrypt Error", message="File hashes does not match.")
            os.remove(path_to_file + ".temp")
            raise Exception("File encrypted file hashes does not match.")
        else :
            if delete_og_file == False :
                try : 
                    open(str.replace(path_to_file, ".encr", ''))
                    hashtemp_copy = hashtemp
                    hash_thread = threading.Thread(target=hash_object, args=(None, str.replace(path_to_file, '.encr', ''), 'a')) ## a mode auto-assigns the variable to hash_temp
                    hash_thread.start()
                    hash_thread.join()
                    if hashtemp == hashtemp_copy :
                        messagebox.showerror(title="Exact File Already exists", message="The exact decrypted file already exists.")
                    else :
                        messagebox.showerror(title="File Already exists", message="The decrypted file alreayd exists.")
                    os.remove(path_to_file + ".temp")
                except FileNotFoundError: os.rename(path_to_file + ".temp", str.replace(path_to_file, ".encr", ''))
            if delete_og_file == True :
                os.replace(path_to_file + ".temp", path_to_file)
                os.replace(path_to_file, str.replace(path_to_file, '.encr', ''))
            
        messagebox.showinfo(title="Let's Encrypt: Finished Decryption!", message="Finished Decryption of file(s).")

## Hashes the object with SHA3-512 no duh like you could have just read like a but further to understand what it does
## this code isn't obfuscated at all and yet you need comments to understand it???
## But it basically allows for less memory usage as it does not read all of it at the
## same time. 
def hash_object(object_to_hash=None, file_path=None, mode="r") :
    global hashtemp
    ## But heres the API doc anyways, if you specify the object_to_hash, then its going to be using the older hash algo
    ## but if you specify file_path you will get the new algo which will read the file by chunck to increase perf 
    ## If the mode is 'r' it will return, if it is a it will assign, but any other character also works for this
    hasher = hashlib.sha3_512()
    if file_path != None :
        with open(file_path, 'rb') as hash_file :
            buffer = hash_file.read(65536)
            while len(buffer) > 0:
                hasher.update(str(buffer).encode('utf-8'))
                buffer = hash_file.read(65536)
    else :
        hasher.update(object_to_hash)
    hashed_object = hasher.hexdigest()
    print("hashed")
    del hasher
    del file_path
    if mode == 'r' :
        return hashed_object
    else : hashtemp = hashed_object

def gen_password(length = 24, test_password = True) :
    characters_pool = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "`", "~", "!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "-", "_", "=", "+", "[", "{", "]", "}", "|", ";", ":", "<", ".", "?", "/", ",", "|"  ]
    characters_pool_rnd = []
    return_password = ''
    ## First we generate a random password pool
    for i in range(len(characters_pool)*32) :
        characters_pool_rnd.append(i)
    ## Then from that list we generate the password
    if test_password == False :
        for i in range(length) : 
            return_password += characters_pool_rnd[SystemRandom().randint(0, len(characters_pool_rnd))]
    if test_password == True :
        while return_password == "" and return_password.isalpha() == False and return_password.isdigit() == False and return_password.isalnum() == False :
            return_password = ''
            for i in range(length) : 
                return_password += characters_pool_rnd[SystemRandom().randint(0, len(characters_pool_rnd))]
    return return_password

## This thing basically tests the backend of the program to make sure it works
def test_crypto_backend() :
    pass

## This is the frontend now but this front end is used for
## debugging purposes and is not an actual production GUI
## (I can't design GUIs even if I wanted to and this
##  GUI simply sucks.)
class PopupManager:

    def __init__(self, max_popups):
        self.max_popups = max_popups
        self.popups = []

    def create_popup(self, popup_title, popup_text, popup_size=None):
        if len(self.popups) < self.max_popups:
            popup = tk.Toplevel(root)
            popup.title(popup_title)
            if popup != None :
                try :
                    popup.geometry(str(popup_size))
                except : pass
            else : 
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
    popup_manager.create_popup(popup_title="About:  ", popup_text=about_txt, popup_size='400x150')

def redir_to_site():
    ## You can't have arguments when calling a function in Python
    ## which is really dumb...
    webbrowser.open("https://randomperson.net/")

def encrypt_file_cmd():
    if is_user_admin is False :
        request_uac_elevation()
    file_path = filedialog.askopenfilename()
    if file_path != "" :
        encryptor = enc_dec_obj()
        encryptor.encrypt_file("Hello, World!", file_path, False)
        del file_path
        del encryptor

def decrypt_file_cmd():
    if is_user_admin is False :
        request_uac_elevation()
    file_path = filedialog.askopenfilename()
    if file_path != '' :
        decryptor = enc_dec_obj()
        decryptor.decrypt_file("Hello, World!", file_path, False)
        del file_path
        del decryptor

## First thing that runs checks whether or not
## the user started this program with admin
## privileges
is_admin()

## Defines screen size
Yvalue = str(600)
Xvalue = str(800)

about_txt = """\
Let's Encrypt Build 2023-10-03.gpc_main.rc3.v05
Made by: Jinghao Li, Kekoa Dang, Skidaux
License: BSD 3-Clause No Nuclear License 2014 
Date of programming: 2023-10-02
Why did we do this: No idea"""

build_string = "2023-10-04.gpc_main.rc3.v05"

dev_branch = "Mainline"

dev_stage = "Alpha"

def get_versions() :
    json_version = '{"crypto_version"="enc_dec_obj().cryptographic_library_version", "build_string"="buildstring"}'

## Main loop stuff idk what this does ¯\_(ツ)_/¯
root = tk.Tk()

popup_manager = PopupManager(max_popups=3)

root.title("Let's, Encrypt!")

root.geometry(Xvalue + 'x' + Yvalue)

menu = tk.Menu(root)

## Help command
helpcmd = tk.Menu(menu)
helpcmd.add_command(label="Website", command=redir_to_site)
## About version command
helpcmd.add_command(label="About", command=about_cmd)

## Encrypt/decrypt file commands
filecmd = tk.Menu(menu)
filecmd.add_command(label="Encrypt", command=encrypt_file_cmd)
filecmd.add_command(label="Decrypt", command=decrypt_file_cmd)

menu.add_cascade(label="File", menu=filecmd)
menu.add_cascade(label="Help", menu=helpcmd)

root.config(menu=menu)

## I gaved up on electron lmao
root.mainloop()