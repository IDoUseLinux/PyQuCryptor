## Encryption software based on my ransomware lmao
## This code is an absolute abomination lol I have
## no idea if this works or not. 
import os, threading, subprocess, cffi, ctypes, hashlib, webbrowser, sys, json
import tkinter as tk
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from tkinter import messagebox
from tkinter import filedialog ## Why do we have to import this seperatly if we import everything? like how stupid is this

## Currently AES-256-CTR is planned to be supported
## So we use RSA to encrypt the metadata of the file
## and it also encrypts the encryption key used to 
## encrypt the files. Wow that was a mouth full. 

## Here is the defining that comes before everything else
def is_admin():
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
def request_uac_elevation():
    global is_user_admin
    if is_user_admin == False:
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

## Encryptor/decryptor object
class enc_dec_obj() :

    cryptographic_library_version = "2023-09-30.gpc_main.rc2.v01"
    
    admin = is_admin()

    def __init__(self) -> None:
        pass

    def encrypt_file(self, path_to_file, delete_og_file) :
        ## We have a checker to make sure that
        ## the data inputted is correct
        datalist = []
        try :
            with open(path_to_file, 'rb') as plain_file :
                plain_text = plain_file.read()
            #file_size = os.path.getsize(path_to_file)
        except FileNotFoundError :
            raise FileNotFoundError("The requested file for encryption does not exist.")
        
        ## Generating the encryption key
        encryption_key = get_random_bytes(32)

        cipher = AES.new(encryption_key, AES.MODE_CTR, nonce=get_random_bytes(12))

        datalist.append(encryption_key)
        
        datalist.append(cipher.nonce)

        datalist.append(hash_object(plain_text))

        plain_text = cipher.encrypt(plain_text)

        ## We overwrite the original non-encrypted
        ## file because people can recover it with
        ## special software. But by re-writting
        ## it with encrypted data, they will only 
        ## see the encrypted data. 
        if delete_og_file == True :
            with open(path_to_file, 'wb') as encrypted_file :
                encrypted_file.write(plain_text)
            os.rename(path_to_file, path_to_file + '.encr')

        elif delete_og_file == False :
            with open(path_to_file + '.encr', 'wb') as encrypted_file :
                encrypted_file.write(plain_text)
                
    
        with open(path_to_file + ".decr", 'wb') as keyfile :
            keyfile.write(datalist[0])
            keyfile.write(datalist[1])
            keyfile.write(bytes.fromhex(datalist[2]))
        
        messagebox.showinfo(title="Let's Encrypt: Finished Encryption!", message="Finished Encryption of file(s).")
            
    ## The formatt of the encrypted file should be :
    ## File head/Hello World!
    ## RSA key size
    ## RSA encrypted datalist
    ## The encrypted data

    def decrypt_file(self, path_to_file, enc_key, delete_og_file) :
        ## Basically we are doing the excapt same thing as the
        ## encrypt_file() function except its backwards and it
        ## requires way less inputs inorder to get an output
        datalist = []

        try :
            with open(path_to_file, 'rb') as plain_file :
                cipher_text = plain_file.read()
        except FileNotFoundError :
            raise FileNotFoundError("The requested file for decryption does not exist.")
        
        try : 
            with open(enc_key, 'rb') as encr_key_loc :
                datalist.append(encr_key_loc.read(32))
                datalist.append(encr_key_loc.read(12))
                datalist.append(encr_key_loc.read(64).hex())
                #for line in file:
        #read_data_list.append(int(line.strip()))
        except FileNotFoundError :
            raise FileNotFoundError("The decryption file does not exist.")

        cipher = AES.new(datalist[0], AES.MODE_CTR, nonce=datalist[1])

        current_filename = os.path.basename(path_to_file)

        cipher_text = cipher.decrypt(cipher_text)

        if datalist[2] != hash_object(cipher_text) :
            print("file hashes does not match")
            messagebox.showerror(title="Decrypt Error", message="File hashes does not match.")
            raise Exception("File encrypted file hashes does not match.")
        
        if delete_og_file == True :
            with open(path_to_file, 'wb') as decrypted_file :
                decrypted_file.write(cipher_text)
            
            os.rename(path_to_file, str.replace(path_to_file, ".encr"))
            
        elif delete_og_file == False :
            with open(str.replace(path_to_file, '.encr', ''), 'wb') as decrypted_file :
                decrypted_file.write(cipher_text)
        messagebox.showinfo(title="Let's Encrypt: Finished Decryption!", message="Finished Decryption of file(s).")

## Hashes the object with SHA3-512 no duh like you could have just read like a but further to understand what it does
## this code isn't obfuscated at all and yet you need comments to understand it???
def hash_object(object_to_hash) :
    obj_bytes = str(object_to_hash).encode('utf-8')
    hasher = hashlib.sha3_512()
    hasher.update(obj_bytes)
    hashed_object = hasher.hexdigest()
    return hashed_object


## "Creating a new thread for dummies"
def createnewthread(thefunction, arguments):
    newthread = threading.Thread(target=thefunction, args=arguments, daemon=True)
    newthread.start()

## This is the frontend now
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
    popup_manager.create_popup(popup_title="About:  ", popup_text=about_txt, popup_size='500x150')

def redir_to_site():
    ## You can't have arguments when calling a function in Python
    ## which is really dumb...
    webbrowser.open("https://randomperson.net/")

def encrypt_file_cmd():
    if is_user_admin is False :
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        #if is_user_admin is False:
        #    raise PermissionError('This program requires administrator priveledges.')
    file_path = filedialog.askopenfilename()
    if file_path != "" :
        encryptor = enc_dec_obj()
        encryptor.encrypt_file(file_path, False)
    del file_path

def decrypt_file_cmd():
    if is_user_admin is False :
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    file_path = filedialog.askopenfilename()
    file_path2 = filedialog.askopenfilename()

    if file_path != '' or file_path2 != '' :
        decryptor = enc_dec_obj()
        decryptor.decrypt_file(file_path, file_path2, False)
    del file_path, file_path2

    

## First thing that runs checks whether or not
## the user started this program with admin
## privileges
is_admin()

## This is the variable sh-- I mean stuff
## for frontend.

## Defines screen size
Yvalue = str(600)
Xvalue = str(800)

about_txt = """Let's Encrypt Build 2023-09-30.gpc_main.rc2.v01
Made by: A Random Person
License: MIT License
Date of programming: 2023-09-22 15:00:00
Why did I do this: No idea"""

build_string = "2023-09-30.gpc_main.rc2.v01"

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