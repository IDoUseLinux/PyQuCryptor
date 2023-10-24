## Encryption software based on my ransomware LOL
## This is main, and is designed for Windows
import customtkinter, secrets, string, json, webbrowser, requests ## Random stuff for GUI and backend
import os, threading, ctypes, hashlib, sys  ## Crypto stuff 
import tkinter as tk 
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from tkinter import messagebox, filedialog
from PIL import Image, ImageDraw

## Since I have no idea how to do version control
about_txt = """\
PyQuCryptor Build 2023-10-23.lpt_main.rc4.v42
Made by: Jinghao Li, Kekoa Dang, Skidaux
License: BSD 3-Clause No Nuclear License 2014 
Date of programming: 2023-10-23
Programming language: Python 3.11 (Compatible with Python 3.12 with SetupTools)
Why did we do this: No idea"""

## Yes the license is a joke but it is a real license used by Oracle somehow
license_txt = """\
BSD 3-Clause No Nuclear License 2014 (© Oracle Corporation)
© IDoUseLinux (https://randomperson.net/), SmashTheCoder1, Skidaux (https://skidaux.net/), 2023
The use of this software is subject to license terms.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    - Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    - Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    - Neither the name of the developers nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

You acknowledge that this software is not designed, licensed or intended for use in the design, construction, operation or maintenance of any nuclear facility."""

## IDK what this is for now considering we've never used it
build_string = "2023-10-23.lpt_main.rc4.v42"
## But the build tag is pratically just a joke
dev_branch = "Mainline"

dev_stage = "Beta 3"

## Frontend stuff
app = customtkinter.CTk()
customtkinter.deactivate_automatic_dpi_awareness()
has_shown_program_status = False

## Jesus these variable names are stupid but you understand them... right?
## but these are the default settings for the app
## User settings storage section
user_config_default = {
    "Delete_og_file_when_encrypting" : False,
    "Delete_og_file_when_decrypting" : False,
    "Dark_mode" : True,
    "Scramble_filename" : False,
    "Allow_web_connections" : True,
    "End_of_life_status" : False,
}

## Gets the current script location so we can read/write the config file
user_config_file_path = os.path.dirname(os.path.realpath(__file__)) + "/pyqucryptor_config.json"

## Try statement to see if the file exists or nah
try :
    with open(user_config_file_path, 'r') as config_file :
        user_config_file = json.load(config_file)
except :
    with open(user_config_file_path, 'w') as config_file :
        json.dump(user_config_default, config_file)
    with open(user_config_file_path, 'r') as config_file :
        user_config_file = json.load(config_file)

## Tries to get the variable values
try :
    user_config_delete_og_file_when_encrypting = user_config_file['Delete_og_file_when_encrypting']
    user_config_delete_og_file_when_decrypting = user_config_file['Delete_og_file_when_decrypting']
    user_config_dark_mode = user_config_file['Dark_mode']
    user_config_scramble_filename = user_config_file['Scramble_filename']
    user_config_allow_web_connection = user_config_file['Allow_web_connections']
    program_current_end_of_life_status = user_config_file['End_of_life_status']
## If something goes wrong, it resets the config file
except :
    with open(user_config_file_path, 'w') as config_file :
        json.dump(user_config_default, config_file)
    with open(user_config_file_path, 'r') as config_file :
        user_config_file = json.load(config_file)
    user_config_delete_og_file_when_encrypting = user_config_file['Delete_og_file_when_encrypting']
    user_config_delete_og_file_when_decrypting = user_config_file['Delete_og_file_when_decrypting']
    user_config_dark_mode = user_config_file['Dark_mode']
    user_config_scramble_filename = user_config_file['Scramble_filename']
    user_config_allow_web_connection = user_config_file['Allow_web_connections']
    program_current_end_of_life_status = user_config_file['End_of_life_status']

## Currently AES-256-CTR is the only cipher suit supported 
## Here is the defining that comes before everything else

## Admin Checker
def is_admin() :
    global is_user_admin
    try :
        if ctypes.windll.shell32.IsUserAnAdmin() == 1 :
            is_user_admin = True
            return True
        else :
            is_user_admin = False
            return False
    except:
        is_user_admin = False
        return False

## For the like 1 other person that will ever see this program
## This segment of code requests for admin privilidges. We can
## swap this out for some other segment of code that actually 
## works sometime in the future... b/c this code is somehow 
## broken despite the fact that it shows the prompt for UAC
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

class enc_dec_obj() :

    cryptographic_library_version = "2023-10-20.lpt_main.rc4.v27"
    
    def __init__(self) -> None:
        pass

    def encrypt_file(self, password, path_to_file, delete_og_file=user_config_delete_og_file_when_encrypting, scramble_filename = user_config_scramble_filename) :
        ## datalist is for unencrypted metadata of the file. datalist2 is for the encrypted metadata.
        datalist = [] ## Non-encrypted file header
        datalist2 = [] ## Encrypted file header
        datalist3 = [] ## Temporary copy of non-encrypted version of encrypted file header
        try :
            with open(path_to_file, 'rb') :
                pass
        except PermissionError :
            request_uac_elevation()
            try :
                with open(path_to_file, 'rb') : pass
            except FileNotFoundError :
                raise FileNotFoundError
        except FileNotFoundError :
            raise FileNotFoundError("The requested file for encryption does not exist.")
        basename = os.path.basename(path_to_file)

        ## Its just easier to scramble the file name first and then encrypt it
        ## because the file is getting deleted anyways
        if scramble_filename and delete_og_file :
            path_to_file_temp = str(path_to_file).replace(basename, '') + generate_password(12, 'return') ## This works LOL
            try : 
                while True :
                    open(path_to_file_temp, 'rb')
                    path_to_file_temp = str(path_to_file).replace(basename, '') + generate_password(12, 'return')
            except : pass
            os.rename(path_to_file, path_to_file_temp)
            path_to_file = path_to_file_temp ## Updates the new path to the file 
            del path_to_file_temp

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

        ## IDK how threading works
        hash_thread = threading.Thread(target=hash_object, args=(None, path_to_file, 'a')) ## a mode auto-assigns the variable to the datalist
        hash_thread.start()
        hash_thread.join()

        datalist2.append(hashtemp)

        datalist3 = datalist2.copy()

        ## This stupid line of code somehow **works first try**
        ## But basically it takes in a password, combines it with 
        ## a salt and turns it into an encryption key that is used
        ## to encrypt the file header.
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
            ## Does basically the same thing as when delete_og_file == True
            if scramble_filename == True and delete_og_file == False :
                scrambled_filename = generate_password(12, 'return') ## This works LOL
                path_to_file = str(path_to_file).replace(basename, '') + scrambled_filename ## This also works LOL
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

                buffer = plain_file.read(65536)
                while len(buffer) > 0 :
                    ## Encrypted File
                    encrypted_file.write(cipher.encrypt(buffer))
                    buffer = plain_file.read(65536)
                
        if delete_og_file == True :
            secure_erase(path_to_file, False)
        messagebox.showinfo(title="PyQuCryptor", message="Finished Encryption of file(s).") 

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
                
        except PermissionError :
            request_uac_elevation()
            try : 
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
            finally:
                print("just put this implace to run it. remove after line 204")
                
        except FileNotFoundError :
            raise FileNotFoundError("The requested file for decryption does not exist.")

        ## This stupid line of code somehow **works first try**
        ## But basically it takes in a password, combines it with 
        ## a salt and turns it into an encryption key that is used
        ## to decrypt the file header.
        cipher = AES.new(hashlib.pbkdf2_hmac("sha3_256", bytes(password, 'utf-8'), datalist[0], 1048576, 32), AES.MODE_CTR, nonce=datalist[1])
        
        ## Decrypts the encrypted metadata
        datalist2[0] = cipher.decrypt(datalist2[0])

        datalist2[1] = cipher.decrypt(datalist2[1])

        datalist2[2] = bytes.hex(cipher.decrypt(datalist2[2]))

        if datalist[2] != hash_object(object_to_hash=datalist2[0] + datalist2[1] + bytes.fromhex(datalist2[2]), mode="r") :
            messagebox.showerror(title="PyQuCryptor: Decrypt Error", message="Incorrect password and/or corrupted file header.")
            raise ValueError("Password is incorrect.")

        ## Overwrites the original cipher object with the one to decrypt files with. 
        cipher = AES.new(datalist2[0], AES.MODE_CTR, nonce=datalist2[1])

        with open(path_to_file, 'rb') as encrypted_file :
            encrypted_file.read(207) ## We read the file header first but we dont need this bc we already have it
            with open(path_to_file + ".temp", 'wb') as decrypted_file :
                buffer = encrypted_file.read(65536)
                while len(buffer) > 0 :
                    decrypted_file.write(cipher.decrypt(buffer))
                    buffer = encrypted_file.read(65536)

        ## Still have no idea how this stuff works
        hash_thread = threading.Thread(target=hash_object, args=(None, path_to_file + ".temp", 'a')) ## a mode auto-assigns the variable to hash_temp
        hash_thread.start()
        hash_thread.join()
        ## We check if the file that has been decrypted is
        ## the same as the file that was originally encrypted
        if datalist2[2] != hashtemp :
            messagebox.showerror(title="PyQuCryptor: Decrypt Error", message="File hashes does not match.")
            os.remove(path_to_file + ".temp") ## We don't have to securely delete this as it is probably just gibberish
            raise Exception("File encrypted file hashes does not match.")
        else :
            if delete_og_file == False :
                try : 
                    open(str.replace(path_to_file, ".encr", ''))
                    if messagebox.askyesno(title="PyQucryptor: File Error", message="A file with the same name already exists. Do you want to overwrite?") :
                        os.replace(path_to_file + ".temp", str.replace(path_to_file, ".encr", ''))
                    else : os.remove(path_to_file + ".temp")
                except FileNotFoundError: 
                    os.rename(path_to_file + ".temp", str.replace(path_to_file, ".encr", ''))
            if delete_og_file == True :
                secure_erase(path_to_file, False)
                ## .encr delete 
                os.rename(path_to_file + ".temp", path_to_file)
                ## .temp -> .encr
                #secure_erase(str.replace(path_to_file, '.encr', ''), False)
                os.rename(path_to_file, str.replace(path_to_file, '.encr', ''))
                ## .encr -> og_file extension

        messagebox.showinfo(title="PyQucryptor: Decryption", message= "Finished Decryption of file(s).")


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
                hasher.update(buffer)
                buffer = hash_file.read(65536)
    else :
        hasher.update(object_to_hash)
    hashed_object = hasher.hexdigest()
    del hasher
    del file_path
    if mode == 'r' :
        return hashed_object
    else : hashtemp = hashed_object

def secure_erase(file_path, replace_with_zero = True) :
    file_size = os.path.getsize(file_path)
    if replace_with_zero == False :
        with open(file_path, 'wb') as deleting_file :
            while file_size > 65536 :
                deleting_file.write(get_random_bytes(65536))
                file_size -= 65536
            deleting_file.write(get_random_bytes(file_size))
    else : 
        with open(file_path, 'wb') as deleting_file :
            while file_size > 65536 :
                deleting_file.write(b"\x00"*65536) ## We are going to change this later because this is probably not zero in binary
                file_size -= 65536
            else : 
                deleting_file.write(b"\x00"*file_size)
    try :
        os.remove(file_path)
    except :
        try :
            request_uac_elevation()
            os.remove(file_path)
        except :
            messagebox.showerror(title = "PyQuCryptor: File Deletion Error", message="Error while deleing file.")

def encryptcmd(): #encrypt button command + 3 checks to make sure everything is there
    global errorlabel
    password = password_prompt.get()
    file_path = file_path_label.get()
    #password = password.replace(" ", "")  
    password_prompt.delete(0, tk.END)
    password_prompt.insert(0, password)
    
    if not os.path.isfile(file_path) : # check 1 to see if the file exsisted 
        error_message = "Error: Unknown file."

    elif password == "": # check to see if you got a password
        error_message = "Please enter a password."

    elif password.startswith(password[:1]*3) : ## Checks if the first 3 letters are the same b/c strong passwords
        error_message = "Please enter a stronger password."
    
    elif len(password) < 12 or len(password) > 50: # checks if password length is the right amount if characters
        error_message = "Password must be between 12 and 50 characters."

    else:
        error_message = None 

    try:
        errorlabel.pack_forget()
    except:
        pass

    if error_message: # gives the error message if any
        messagebox.showerror(title="PyQuCryptor: Error", message=error_message)
    else: # File path + password
        password_prompt.delete(0, tk.END)
        file_path_label.delete(0, tk.END)
        password_prompt.delete(0, tk.END)
        encryptor = enc_dec_obj()
        encryptor.encrypt_file(password, file_path, user_config_delete_og_file_when_encrypting)
        del encryptor
     
def generate_password(pwd_length = 16, options = None):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for _ in range(pwd_length)) ## What the hell is that variable name for UNDERSCORE??????????
    if options == 'return' : 
        return password
    else :
        password_prompt.delete(0, tk.END)
        password_prompt.insert(0, password)

def update_config_status() :
    global user_config_delete_og_file_when_encrypting, user_config_delete_og_file_when_decrypting, user_config_scramble_filename
    user_config_delete_og_file_when_encrypting = user_config_file['Delete_og_file_when_encrypting']
    user_config_delete_og_file_when_decrypting = user_config_file['Delete_og_file_when_decrypting']
    user_config_scramble_filename = user_config_file["Scramble_filename"]

## Web stuff
def check_for_updates() :
    global program_current_end_of_life_status
    ## If this returns 404, then its not eol, but if it doesn't it is in eol
    if str(requests.get("http://randomperson.net/pyqucryptor/eol.txt")) != "<Response [404]>" :
        program_current_end_of_life_status = True
        user_config_file['End_of_life_status'] = True
        messagebox.showwarning(title="PyQuCryptor: Warning", message='PyQyCryptor has reached End-of-Life. It is no longer maintained! Thanks for using the software!') 

    if str(requests.get("http://randomperson.net/pyqucryptor/" + build_string)) == '<Response [404]>' :
        if messagebox.askyesno("PyQuCryptor: Info", 'An update is Available, would you like to visit the github page?') :
            webbrowser.open("https://github.com/IDoUseLinux/PyQuCryptor/")

def reset_config() :
    with open(user_config_file_path, 'w') as config_file :
        json.dump(user_config_default, config_file)
    
    if messagebox.askyesno(title="PyQuCryptor: Settings", message="In order for some settings to take affect, the program must be restarted, would you like to restart?") :
        app.quit()
## Above this is backend
## This is frontend now

## Popup manager for managing the amount of popups
class PopupManager:

    def __init__(self, max_popups):
        self.max_popups = max_popups
        self.popups = []

    def create_popup(self, popup_title, popup_text, popup_size=None):
        if len(self.popups) < self.max_popups:
            popup = tk.Toplevel(app)
            popup.title(popup_title)
            if popup != None :
                try :
                    popup.geometry(str(popup_size))
                except : pass
            else : 
                popup.geometry(str(int(int(350)/2)) + "x" + str(int(int(600)/2))) ## This is so stupidly jank by converting it into int twice, we can first turn a string into int which we divide which gives float then int again to get a int only to string again...
            tk.Label(popup, text=popup_text, font=(16)).place(x=5, y=5)
            self.popups.append(popup)
            popup.protocol("WM_DELETE_WINDOW", lambda p=popup: self.close_popup(p))
        else : 
            messagebox.showwarning(title="Too many popups!", message="Please close a popup before opening another.")

    ## IDK what this is for, but I asked ChatGPT to write it so ¯\_(ツ)_/¯
    def close_popup(self, popup):
        popup.destroy()
        self.popups.remove(popup)

## GUI logic stuff
def redir_to_site():
    ## You can't have arguments when calling a function in Python
    ## which is really dumb...
    webbrowser.open("https://randomperson.net/")

def redir_to_github() :
    webbrowser.open("https://github.com/IDoUseLinux/PyQuCryptor")

#file_path = ""
def encryptupload(): #uploads file to encrypt button
    file_path = filedialog.askopenfilename(defaultextension=".encr") ## Default file extension is .encr
    file_path_label.delete(0, tk.END)
    file_path_label.insert(0,file_path)

def decryptcmd():
    global errorlabel
    password = password_prompt.get()
    file_path = file_path_label.get()

    if file_path[len(file_path)-5:] != ".encr" : ## This checks for whether or not the file ends in .encr and if it does not end in .encr it will rename it
        try : 
            open(file_path + '.encr', 'rb')
            if messagebox.askyesno(title= "File error", message=f"File {os.path.basename(file_path) + '.encr'} already exists. Do you want to overwrite?") : ## I know this code is ugly
                os.replace(file_path, file_path + '.encr')
            else : error_message = "Error when renaming non .encr file to .encr file."
        except FileNotFoundError :
            os.rename(file_path, file_path + ".encr")
        file_path += '.encr'

    if not os.path.isfile(file_path): # Check 1: to see if the file exsists
        error_message = "Error: Unknown file."
    elif password == "": # Check 2: to see if you got a password
        error_message = "Please enter your password."
    elif len(password) < 12 or len(password) > 50: # checks if password length is the right amount if characters
        error_message = "Password must be between \n12 and 50 characters."
    
    else:
        error_message = None
    try:
        errorlabel.pack_forget()
    except :
        pass
    if error_message: # gives the error message if any
        messagebox.showerror(title="PyQuCryptor: Error", message=error_message)
    else: # File + password is ready to be used
        password_prompt.delete(0, tk.END)
        decryptor = enc_dec_obj()
        decryptor.decrypt_file(password, file_path, user_config_delete_og_file_when_decrypting) ## Last variable is for deleting original file. If True, it delete, if False, it does not delete

def quit_program():
    app.quit()

## GUI stuff
def settingscmd():

    try : # removes encrypt screen
        encrypt_button.pack_forget()
        password_prompt.pack_forget()
        set_password.pack_forget()
        encryptupload_button.pack_forget()
        file_path_label.pack_forget()
        generate_password_button.pack_forget()
        selectmode.pack_forget()
    except :
        #print("got error passing")
        pass

def selectmodecmd(value): # select what screen your on encrypt / decrypt
    global encrypt_button, encryptupload_button, file_path_label
    global password_prompt, set_password, generate_password_button
    try: # removes encrypt screen
        encrypt_button.pack_forget()
        password_prompt.pack_forget()
        set_password.pack_forget()
        encryptupload_button.pack_forget()
        file_path_label.pack_forget()
        generate_password_button.pack_forget()
    except:
        pass
    if value == " 🔓 Decrypt File ": # decrypt screen

        topframe = customtkinter.CTkFrame(app, width=400, height=74, fg_color="#44AE4E", corner_radius=0)
        topframe.place(x=0, y=0)

        options_button = customtkinter.CTkButton(app, text="⚙️", font=("Arial", 30), hover_color="#44AE4E", bg_color="#44AE4E", fg_color="#44AE4E", command=settingscmd, height=30, width=30)
        options_button.pack(side=tk.TOP, anchor=tk.NE) 
        options_button.place(x = 290, y = 17)

        applabelname = customtkinter.CTkLabel(app, text="PyQuCryptor", bg_color="#44AE4E", text_color="white", font=("Arial",30, "bold"))
        applabelname.pack(side=tk.TOP, pady=(10,0), padx=(20,0), anchor=tk.NW)
        applabelname.place(x = 20, y = 20)

        encrypt_button = customtkinter.CTkButton(app, text="🔓 Decrypt File", font=("Arial", 25, "bold"), fg_color="#E34039", command=decryptcmd, height=50, width=325)
        encrypt_button.pack(side=tk.BOTTOM, padx=(30), pady=(10,25), anchor=tk.CENTER)    

        password_prompt = customtkinter.CTkEntry(app, placeholder_text="E.g. 1234", height=35, width=325, bg_color="#192E45", font=("Arial", 15)) 
        password_prompt.pack(side=tk.BOTTOM, padx=(30), pady=(0, 67), anchor=tk.CENTER)                  
        
        set_password = customtkinter.CTkLabel(app, text="Enter Your Password", bg_color="#192E45", font=("Arial", 18, "bold"))
        set_password.pack(side=tk.BOTTOM, padx=(30), pady=(0,2), anchor=tk.W)   
            
        encryptupload_button = customtkinter.CTkButton(app, text="Select Encrypted File", font=("Arial", 18), fg_color="#393939", bg_color="#192E45", hover_color="#2E2E2E", command=encryptupload, height=25, width=325)
        encryptupload_button.pack(side=tk.BOTTOM, padx=(30), pady=(15, 25), anchor=tk.CENTER)

        file_path_label = customtkinter.CTkEntry(app, placeholder_text="Encypted File Path", height=35, width=325, bg_color="#192E45", font=("Arial", 15)) 
        file_path_label.pack(side=tk.BOTTOM, padx=(30), anchor=tk.CENTER)    
    else: # encrypt screen
        topframe = customtkinter.CTkFrame(app, width=400, height=74, fg_color="#E34039", corner_radius=0)
        topframe.place(x=0, y=0)
        options_button = customtkinter.CTkButton(app, text="⚙️", font=("Arial", 30), hover_color="#E34039", bg_color="#E34039", fg_color="#E34039", command=settingscmd, height=30, width=30)
        options_button.pack(side=tk.TOP, anchor=tk.NE) 
        options_button.place(x = 290, y = 17)

        applabelname = customtkinter.CTkLabel(app, text="PyQuCryptor", bg_color="#E34039", text_color="white", font=("Arial",30, "bold"))
        applabelname.pack(side=tk.TOP, pady=(10,0), padx=(20,0), anchor=tk.NW)
        applabelname.place(x = 20, y = 20)

        encrypt_button = customtkinter.CTkButton(app, text="🔒 Encrypt File", font=("Arial", 22, "bold") ,fg_color="#44AD4D", bg_color="#192E45", hover_color="#28482B", command=encryptcmd, height=50, width=325)
        encrypt_button.pack(side=tk.BOTTOM, padx=(30), pady=(10,25), anchor=tk.CENTER)    

        generate_password_button = customtkinter.CTkButton(app, text="Generate Password", font=("Arial", 18), fg_color="#393939", bg_color="#192E45", hover_color="#2E2E2E", command=generate_password, height=25, width=325)
        generate_password_button.pack(side=tk.BOTTOM, padx=(30), pady=(15, 25), anchor=tk.CENTER)

        password_prompt = customtkinter.CTkEntry(app, placeholder_text="12 - 50 characters", height=35, width=325, bg_color="#192E45", font=("Arial", 15)) 
        password_prompt.pack(side=tk.BOTTOM, padx=(30), anchor=tk.CENTER)
        
        set_password = customtkinter.CTkLabel(app, text="Set a Password", bg_color="#192E45", font=("Arial", 18, "bold"))
        set_password.pack(side=tk.BOTTOM, padx=(30), pady=(0,2), anchor=tk.W)   
            
        encryptupload_button = customtkinter.CTkButton(app, text="Select File", font=("Arial", 18), fg_color="#393939", bg_color="#192E45", hover_color="#2E2E2E", command=encryptupload, height=25, width=325)
        encryptupload_button.pack(side=tk.BOTTOM, padx=(30), pady=(15, 25), anchor=tk.CENTER)

        file_path_label = customtkinter.CTkEntry(app, placeholder_text="File Path", height=35, width=325, bg_color="#192E45", font=("Arial", 15)) 
        file_path_label.pack(side=tk.BOTTOM, padx=(30), anchor=tk.CENTER)  
    
        
mainframe = customtkinter.CTkFrame(app, width=400, height=600, fg_color="#192E45", corner_radius=0)
mainframe.place(x=0, y=0)

autoselectmode = customtkinter.StringVar(value=" 🔒 Encrypt File ")
selectmode = customtkinter.CTkSegmentedButton(app, values=[" 🔒 Encrypt File ", " 🔓 Decrypt File "], font=("Arial", 20, "bold"),
                                              selected_color="#393939", fg_color="#1A1A1A", unselected_color="#141414", unselected_hover_color="#2E2E2E", selected_hover_color="#393939",
                                                border_width=7, corner_radius=13, height=50, bg_color="#192E45", variable=autoselectmode, width=325, command=selectmodecmd)
selectmode.pack(side=customtkinter.TOP, padx=10, pady=(100,0)) 


def center_window(root, width, height): # centers the app to your pc res
    #global adjust_width, adjust_height
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()

    # print(height)
    # print(screen_width)
    # width_temp = width
    #height = int((screen_height / 1080) * height * 2)
    #width = int((screen_width / 2560) * width * 2)
    #height = int(height * (width/width_temp))
    # print(height)
    # print(width)
    #screen_width = screen_width / 1.35
    #screen_height = screen_height / 1.6

    # Calculate the X and Y coordinates for the window to be centered
    x = (screen_width - width) // 4
    y = (screen_height - height) // 4
    
    #adjust_width = screen_width / 2.7
    #adjust_height = screen_height / 3.2

    # Set the window's position
    root.geometry(f"{width}x{height}+{x}+{y}")

center_window(app, 350, 600)
app.resizable(False, False) # makes it unable to resize the app
app.title("PyQuCryptor") # title 
value=" 🔒 Encrypt File " # sets value for line below
selectmodecmd(value) # selects encrypt screen first, if this is not here then it will be a blank screen then give a error

width, height = 350, 600

start_color_hex = "#0063C4"  # top color
end_color_hex = "#010810"    # bottem color

start_color = tuple(int(start_color_hex[i:i + 2], 16) for i in (1, 3, 5))
end_color = tuple(int(end_color_hex[i:i + 2], 16) for i in (1, 3, 5))

img = Image.new('RGBA', (width, height))
draw = ImageDraw.Draw(img)

for y in range(height):
    r = start_color[0] + (end_color[0] - start_color[0]) * y / height
    g = start_color[1] + (end_color[1] - start_color[1]) * y / height
    b = start_color[2] + (end_color[2] - start_color[2]) * y / height
    for x in range(width):
        draw.point((x, y), fill=(int(r), int(g), int(b), 255))

customtkinter.set_appearance_mode("dark")
## We check for updates before starting the app
## if the user allows for it.
if user_config_allow_web_connection :
    check_for_updates()

app.mainloop()

with open(user_config_file_path, 'w') as config_file :
    json.dump(user_config_file, config_file)

## Wanted Changlist:
## -Add configs menu
##