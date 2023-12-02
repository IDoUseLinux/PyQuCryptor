## PyQuCryptor for Windows 10/11
## Writing crappy code is my passion
import customtkinter, secrets, string, json, webbrowser, requests, multiprocessing ## Random stuff for GUI and backend
import os, threading, ctypes, hashlib, sys ## Crypto stuff 
import tkinter as tk ## More GUI Stuff
from PIL import Image
from tkinter import messagebox, filedialog
from Crypto.Cipher import AES ## More Crypto stuff
from Crypto.Random import get_random_bytes

## Since I have no idea how to do version control
version = "V2.0" ## The actual version of the program. 
build_string = "Build 2023-12-01.v2-0.main.r007" ## Build string is just for personal tracking 
is_dev_version = True ## Change this to False in order for check for updates as this prevents my site from getting DoSed by myself from debugging the amazon rainforest worth of bugs
has_auto_checked = True

## About dialog text
about_txt = f"""\
PyQuCryptor {version}
PyQuCryptor {build_string}
Made by: Jinghao Li (Backend, frontend, head-developer), Kekoa Dang (Frontend), Zoe Murata (Logo designer)
License: BSD 3-Clause No Nuclear License 2014 
Date of programming: 2023-11-05
Programming language: Python 3.12
Why did we do this: No idea
Is Dev version: {is_dev_version}"""

## Yes the license is a joke but it is a real license used by Oracle somehow
license_txt = """\
ALL SOFTWARE BELONGS TO THEIR RESPECTIVE OWNERS!!!
I give full consent for Congress to use this app to market the congressional app challenge in any way they seem fit as long as they include the copyright notice!!!

BSD 3-Clause No Nuclear License 2014
© 2023 IDoUseLinux/Jinghao Li (https://randomperson.net/), SmashTheCoder1/Kekoa Dang
The use of this software is subject to license terms.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    - Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    - Redistributions in binary form must reproduce the above copyright notice, this list of con ditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    - Neither the name of the developers nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

You acknowledge that this software is not designed, licensed or intended for use in the design, construction, operation or maintenance of any nuclear facility."""

## We need this snippet for our program to work. Yes this was stack overflow
def resource_path(relative_path):
    try :
        base_path = sys._MEIPASS
    except Exception :
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

with open(resource_path("resources/other_licenses.txt"), 'r') as license_file:
    other_licenses = license_file.read()

## Get's user's home dir so we can store configs in the user's home folder
user_config_file_path = "C:/Users/" + os.getlogin() + "/pyqucryptor.json"

logo_path = resource_path('resources/PyQuCryptorv4.png')

config_default = {
    "Delete Original (ENC)" : False,
    "Delete Original (DEC)" : True,
    "Scramble Filename" : False,
    "Auto Update" : False,
    "End of life" : False, 
    "First use" : True,
    "Gen password length" : 16,}

try :
    with open(user_config_file_path, 'r') as config_file :
        user_config = json.load(config_file)
except :
    user_config = config_default

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

class cryptor() :
    cryptographic_library_version = "Version 1.0" ## This is the version of the crypto stuff it doesn't have to match the build string
    
    def __init__(self) -> None : ## IDK what this is for lmao I used the auto-generated thingy
        pass

    ## AES-256-CTR is used for encryption
    def encrypt_file(self, password, path_to_file, delete_og_file=False, scramble_filename = False) :
        ## nonEncList is for unencrypted metadata of the file. encryptedList is for the encrypted metadata.
        nonEncList = [] ## Non-encrypted file header
        encryptedList = [] ## Encrypted file header
        try :
            with open(path_to_file, 'rb') :
                pass
        except PermissionError :
            request_uac_elevation()
            with open(path_to_file, 'rb') : pass
        except FileNotFoundError :
            raise FileNotFoundError("The requested file for encryption does not exist.")
        try :
            if os.stat(path_to_file) > 17179869184 : ## Checks the file to see if its over 16 GiBs b/c weird stuff happens with big files
                messagebox.showwarning(title="PyQuCryptor: Large File size", message="PyQuCryptor can become unstable when dealing with large file sizes.")
        except : pass
        basename = os.path.basename(path_to_file)

        ## Its just easier to scramble the file name first and then encrypt it
        ## because the file is getting deleted anyways
        if scramble_filename and delete_og_file :
            path_to_file_temp = str(path_to_file).replace(basename, '') + ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16)) ## This works LOL
            try : 
                while True :
                    open(path_to_file_temp, 'rb')
                    path_to_file_temp = str(path_to_file).replace(basename, '') + ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
            except : pass
            os.rename(path_to_file, path_to_file_temp)
            path_to_file = path_to_file_temp ## Updates the new path to the file 
            del path_to_file_temp

        ## Generating the encryption key
        encryption_key = get_random_bytes(32)

        cipher = AES.new(encryption_key, AES.MODE_CTR, nonce=get_random_bytes(11), use_aesni=True)

        ## Passwod salt
        nonEncList.append(get_random_bytes(24))

        ## Encryption Nonce
        nonEncList.append(get_random_bytes(12))

        ## The encryption key used to encrypt files
        encryptedList.append(encryption_key)
        ## The nonce used to encrypt files
        encryptedList.append(cipher.nonce)

        ## IDK how threading works
        hash_thread = threading.Thread(target=self.hash_object, args=(None, path_to_file, 'a')) ## a mode auto-assigns the variable to the nonEncList
        hash_thread.start()
        hash_thread.join()

        encryptedList.append(self.hashtemp)

        encryptedList_copy = encryptedList.copy() ## Temporary copy of non-encrypted version of encrypted file header
        ## This stupid line of code somehow **worked first try**
        ## But basically it takes in a password, combines it with 
        ## a salt and turns it into an encryption key that is used
        ## to encrypt the file header.
        encr_encr_key = hashlib.pbkdf2_hmac("sha3_256", bytes(password, 'utf-8'), nonEncList[0], 1048576, 32)

        nonEncList.append(self.hash_object(object_to_hash=encryptedList[0] + encryptedList[1] + bytes.fromhex(encryptedList[2]), mode="r"))

        nonEncList[2] = bytes.fromhex(nonEncList[2])
        
        cipher = AES.new(encr_encr_key, AES.MODE_CTR, nonce=nonEncList[1], use_aesni=True)

        encryptedList[0] = cipher.encrypt(encryptedList[0])

        encryptedList[1] = cipher.encrypt(encryptedList[1])

        ## We have to encode this in bytes because of AES encryption.
        encryptedList[2] = cipher.encrypt(bytes.fromhex(encryptedList[2]))

        cipher = AES.new(encryptedList_copy[0], AES.MODE_CTR, nonce=encryptedList_copy[1], use_aesni=True)
        with open(path_to_file, 'rb') as plain_file :
            ## Does basically the same thing as when delete_og_file == True
            if scramble_filename and delete_og_file == False :
                path_to_file = str(path_to_file).replace(basename, '') + ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16)) ## What the hell is this line of code
                try : 
                    while True :
                        open(path_to_file, 'r')
                        path_to_file = str(path_to_file).replace(basename, '') + ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16)) ## What the hell is this line of code
                except : pass

            with open(path_to_file + '.encr', 'wb') as encrypted_file :
                ## Password salt
                encrypted_file.write(nonEncList[0])
                ## Non-encrypted cipher nonce
                encrypted_file.write(nonEncList[1])
                ## Hash of encrypted file header
                encrypted_file.write(nonEncList[2])

                ## Encrypted 32-byte Encryption key
                encrypted_file.write(encryptedList[0])
                ## Encrypted 11-byte Nonce
                encrypted_file.write(encryptedList[1])
                ## Encrypted SHA3-512 Hash/Checksum
                encrypted_file.write(encryptedList[2])

                buffer = plain_file.read(65536)
                while len(buffer) > 0 :
                    ## Encrypted File
                    encrypted_file.write(cipher.encrypt(buffer))
                    buffer = plain_file.read(65536)
                
        if delete_og_file == True :
            secure_erase(path_to_file)
        messagebox.showinfo(title="PyQuCryptor: Encryption Complete", message="Finished Encryption of file(s).") 

    def decrypt_file(self, password, path_to_file, delete_og_file = False) :
        ## Basically we are doing the excapt same thing as the
        ## encrypt_file() function except its backwards and it
        ## requires way less inputs inorder to get an output
        nonEncList = []
        encryptedList = []
        try :
            if os.stat(path_to_file) > 17179869184 : ## Warns the user about large file sizes
                messagebox.showwarning(title="PyQuCryptor: Large File size", message="PyQuCryptor can become unstable when dealing with large file sizes.")
        except : pass

        try : 
            with open(path_to_file, 'rb') as encr_key_loc :
                ## Password Salt
                nonEncList.append(encr_key_loc.read(24))
                ## Encryptor's Nonce
                nonEncList.append(encr_key_loc.read(12))
                ## Encrypted file header hash
                nonEncList.append(bytes.hex(encr_key_loc.read(64))) 
                
                ## Encrypted Encryption Key 32 bytes
                encryptedList.append(encr_key_loc.read(32))
                ## Encrypted Nonce 11 bytes
                encryptedList.append(encr_key_loc.read(11))
                ## Encrypted non-encrypted file checksum/hash 64 bytes
                encryptedList.append(encr_key_loc.read(64))
                ## We don't read the rest of the file because we only need the header
                ## Plus it would nuke the system's memory if we were to do so
                
        except PermissionError :
            request_uac_elevation()
            ## Password Salt
            nonEncList.append(encr_key_loc.read(24))
            ## Encryptor's Nonce
            nonEncList.append(encr_key_loc.read(12))
            ## Encrypted file header hash
            nonEncList.append(bytes.hex(encr_key_loc.read(64))) 
            
            ## Encrypted Encryption Key 32 bytes
            encryptedList.append(encr_key_loc.read(32))
            ## Encrypted Nonce 11 bytes
            encryptedList.append(encr_key_loc.read(11))
            ## Encrypted non-encrypted file checksum/hash 64 bytes
            encryptedList.append(encr_key_loc.read(64))
            ## We don't read the rest of the file because we only need the header
            ## Plus it would nuke the system's memory if we were to do so
            
        except FileNotFoundError :
            raise FileNotFoundError("The requested file for decryption does not exist.")

        ## This stupid line of code somehow **worked first try**
        ## But basically it takes in a password, combines it with 
        ## a salt and turns it into an encryption key that is used
        ## to decrypt the file header.
        cipher = AES.new(hashlib.pbkdf2_hmac("sha3_256", bytes(password, 'utf-8'), nonEncList[0], 1048576, 32), AES.MODE_CTR, nonce=nonEncList[1], use_aesni=True)
        
        ## Decrypts the encrypted metadata
        encryptedList[0] = cipher.decrypt(encryptedList[0])

        encryptedList[1] = cipher.decrypt(encryptedList[1])

        encryptedList[2] = bytes.hex(cipher.decrypt(encryptedList[2]))

        if nonEncList[2] != self.hash_object(object_to_hash=encryptedList[0] + encryptedList[1] + bytes.fromhex(encryptedList[2]), mode="r") :
            messagebox.showerror(title="PyQuCryptor: Decrypt Error", message="Incorrect password and/or corrupted file header.")
            raise ValueError("Password is incorrect.")

        ## Overwrites the original cipher object with the one to decrypt files with. 
        cipher = AES.new(encryptedList[0], AES.MODE_CTR, nonce=encryptedList[1], use_aesni=True)

        with open(path_to_file, 'rb') as encrypted_file :
            encrypted_file.read(207) ## We read the file header first but we dont need this bc we already have it
            ## We write to a .temp file to help memory usage and integrity checking
            with open(path_to_file + ".temp", 'wb') as decrypted_file :
                buffer = encrypted_file.read(65536)
                while len(buffer) > 0 :
                    decrypted_file.write(cipher.decrypt(buffer))
                    buffer = encrypted_file.read(65536)

        ## Still have no idea how this stuff works
        hash_thread = threading.Thread(target=self.hash_object, args=(None, path_to_file + ".temp", 'a')) ## a mode auto-assigns the variable to hash_temp
        hash_thread.start()
        hash_thread.join()
        ## We check if the file that has been decrypted is
        ## the same as the file that was originally encrypted
        if encryptedList[2] != self.hashtemp :
            messagebox.showerror(title="PyQuCryptor: Decrypt Error", message="File hashes does not match, This file has been tampered with.")
            os.remove(path_to_file + ".temp") ## We don't have to securely delete this as it is probably just gibberish
            raise Exception("File encrypted file hashes does not match.")
        
        else :
            if delete_og_file == False :
                try : 
                    open(str.replace(path_to_file, ".encr", ''))
                    if messagebox.askyesno(title="PyQucryptor: File Already Exists Error", message="A file with the same name already exists. Do you want to overwrite?") :
                        os.replace(path_to_file + ".temp", str.replace(path_to_file, ".encr", ''))
                    else : 
                        os.remove(path_to_file + ".temp")
                except FileNotFoundError : 
                    os.rename(path_to_file + ".temp", str.replace(path_to_file, ".encr", ''))
                
                except PermissionError :
                    ____ = os.path.basename(path_to_file) ## Again I need a variable name
                    messagebox.showerror(title="Decrypt Error", message=f"Unable to rename file (Is the file just called .encr?), file renamed to {____ + '.temp'}")
            
            __ = False ## I just need a variable name
            if delete_og_file == True :
                try :
                    open(str.replace(path_to_file, ".encr", ''), 'r')
                    if messagebox.askyesno(title="PyQuCryptor: File Already Exists Error", message="A file with the same name already exists. Do you want to overwrite?") :
                        os.remove(str.replace(path_to_file, ".encr", '')) ## I dont think we have to secure erase this b/c in theory its not related to encrypted data
                    else : __ = True ## I just need a variable name
                        
                except FileNotFoundError : pass
                except Exception : os.remove(path_to_file + '.temp') ## Deletes the temp file if anything goes wrong

                if __ :
                    secure_erase(path_to_file + '.temp', False)
                    
                else : 
                    secure_erase(path_to_file)
                    ## .encr delete 
                    os.rename(path_to_file + ".temp", path_to_file)
                    ## .temp -> .encr
                    os.rename(path_to_file, str.replace(path_to_file, '.encr', ''))
                    ## .encr -> og_file extension
        messagebox.showinfo(title="PyQucryptor: Decryption Complete", message= "Finished Decryption of file.")

    def hash_object(self, object_to_hash=None, file_path=None, mode="r") :
        ## But heres the API doc anyways, if you specify the object_to_hash, then its going to be using the older hash algo
        ## but if you specify file_path you will get the new algo which will read the file by chunck to increase perf 
        ## If the mode is 'r' it will return, if it is a it will assign, but any other character also works for this
        self.hasher = hashlib.sha3_512()
        if file_path != None :
            with open(file_path, 'rb') as hash_file :
                buffer = hash_file.read(65536)
                while len(buffer) > 0:
                    self.hasher.update(buffer)
                    buffer = hash_file.read(65536)
        else :
            self.hasher.update(object_to_hash)
        hashed_object = self.hasher.hexdigest()
        del self.hasher
        del file_path
        if mode == 'r' :
            return hashed_object
        else : self.hashtemp = hashed_object

def secure_erase(file_path) :
    file_size = os.path.getsize(file_path)
    with open(file_path, 'wb') as deleting_file :
        while file_size > 65536 :
            deleting_file.write(get_random_bytes(65536))
            file_size -= 65536
        deleting_file.write(get_random_bytes(file_size))
    try :
        os.remove(file_path)
    except :
        try :
            request_uac_elevation()
            os.remove(file_path)
        except :
            messagebox.showerror(title = "PyQuCryptor: File Deletion Error", message="Error while deleing file.")

def check_for_updates() :
    if not is_dev_version :
        try :
            if str(requests.get("https://randomperson.net/pyqucryptor/eol.txt")) != "<Response [404]>" :
                messagebox.showwarning("PyQuCryptor: End of Life", "PyQuCryptor is no longer supported! Thanks for using the software though!")
            if str(requests.get(f"https://randomperson.net/pyqucryptor/{version}")) == "<Response [404]>" : ## We now ping using version to simplify the web request 
                messagebox.showinfo("PyQuCryptor: Updates", "An update for PyQuCryptor is avalible, would you like to go to the GitHub page?")
            else : 
                messagebox.showinfo("PyQuCryptor: Updates", "PyQuCryptor is Up-To-Date")
        except Exception as error:
            messagebox.showerror("PyQuCryptor: Updates", f"Error whilst trying to fetch updates! Error code: {error}")
    else : messagebox.showinfo("PyQuCryptor: Updates", "This is a development build. It does not check for updates for the sakes of my personal website not being DoSed by myself.")

def update_setting(key, value) :
    user_config[key] = value

## This is GUI stuff now
class GUI_Controller :
    all_screen_obj = []
    current_screen = ""
    prev_screen = ""
    GITHUB_URL = "https://github.com/IDoUseLinux/PyQuCryptor/"
    WEBSITE_URL = "https://randomperson.net/PyQuCryptor/"
    RICKROLL_URL = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
    has_selector = False
    selectmode = None

    def __init__(self, app, start_screen) :        
        self.app = app
        self.app.iconbitmap(resource_path("resources/PyQuCryptorv4.ico"))

        self.app.resizable(False, False) ## makes it unable to resize the app
        self.app.title("PyQuCryptor") 
        self.app.geometry("350x600")
        customtkinter.set_appearance_mode("dark")
        self.app.config(background="#192e45")
        self.has_selector = False
        self.selector_var = customtkinter.StringVar(value=start_screen)
        self.set_screen(value=start_screen)

    def set_screen(self, value) :
        ## Tries to clear the screen first
        try :
            while self.all_screen_obj :
                self.all_screen_obj[0].destroy()
                del self.all_screen_obj[0]
        except : pass

        ## The actual set screen part
        if value == " 🔒 Encrypt File " :
            self.spawn_selector()
            self.encrypt_screen()
        elif value == " 🔓 Decrypt File " :
            self.spawn_selector()
            self.decrypt_screen()

        elif value == "Settings" :
            self.selectmode.destroy()
            self.has_selector = False
            self.settings_menu()
        self.prev_screen, self.current_screen = self.current_screen, value
    
    def spawn_selector(self) :
        if not self.has_selector :
            self.selector_var = customtkinter.StringVar(value=self.current_screen)
            self.selectmode = customtkinter.CTkSegmentedButton(self.app, values=[" 🔒 Encrypt File ", " 🔓 Decrypt File "], font=("Arial", 20, "bold"), selected_color="#393939", fg_color="#1A1A1A", unselected_color="#141414", unselected_hover_color="#2E2E2E", selected_hover_color="#393939",border_width=8, corner_radius=10, height=50, bg_color="#192E45", variable=self.selector_var, width=325, command=self.set_screen)
            self.selectmode.pack(side=customtkinter.TOP, padx=10, pady=(100,0)) 
            self.selectmode.set(self.current_screen)
            self.has_selector = True

    def encrypt_screen(self) :
        topframe = customtkinter.CTkFrame(app, width=400, height=74, fg_color="#E34039", corner_radius=0)
        topframe.place(x=0, y=0)
        self.all_screen_obj.append(topframe)

        options_button = customtkinter.CTkButton(app, text="⚙️", font=("Arial", 30), hover_color="#75322f", bg_color="#E34039", fg_color="#E34039", command=lambda : self.set_screen("Settings"), height=30, width=30)
        options_button.pack(side=tk.TOP, anchor=tk.NE) 
        options_button.place(x = 290, y = 17)
        self.all_screen_obj.append(options_button)

        applabelname = customtkinter.CTkLabel(app, text="PyQuCryptor", bg_color="#E34039", text_color="white", font=("Arial",30, "bold"))
        applabelname.pack(side=tk.TOP, pady=(10,0), padx=(20,0), anchor=tk.NW)
        applabelname.place(x = 20, y = 20)
        self.all_screen_obj.append(applabelname)

        encrypt_button = customtkinter.CTkButton(app, text="🔒 Encrypt File", font=("Arial", 25, "bold") ,fg_color="#44AD4D", bg_color="#192E45", hover_color="#28482B", command=self.encrypt_file, height=50, width=325)
        encrypt_button.pack(side=tk.BOTTOM, padx=(30), pady=(10,25), anchor=tk.CENTER)    
        self.all_screen_obj.append(encrypt_button)

        generate_password_button = customtkinter.CTkButton(app, text="Generate Password", font=("Arial", 18), fg_color="#393939", bg_color="#192E45", hover_color="#2E2E2E", command=self.generate_pwd, height=25, width=325)
        generate_password_button.pack(side=tk.BOTTOM, padx=(30), pady=(15, 25), anchor=tk.CENTER)
        self.all_screen_obj.append(generate_password_button)

        self.password_prompt = customtkinter.CTkEntry(app, placeholder_text="12 - 50 characters", height=35, width=325, bg_color="#192E45", font=("Arial", 15)) 
        self.password_prompt.pack(side=tk.BOTTOM, padx=(30), anchor=tk.CENTER)
        self.all_screen_obj.append(self.password_prompt)
        
        set_password = customtkinter.CTkLabel(app, text="Set a Password", bg_color="#192E45", font=("Arial", 18, "bold"))
        set_password.pack(side=tk.BOTTOM, padx=(30), pady=(0,2), anchor=tk.W)   
        self.all_screen_obj.append(set_password)
            
        encrypt_fd_button = customtkinter.CTkButton(app, text="Select File", font=("Arial", 18), fg_color="#393939", bg_color="#192E45", hover_color="#2E2E2E", command=lambda : self.select_file("Select file for Encryption", [("All files", "*.*"), ]), height=25, width=325)
        encrypt_fd_button.pack(side=tk.BOTTOM, padx=(30), pady=(15, 25), anchor=tk.CENTER)
        self.all_screen_obj.append(encrypt_fd_button)

        self.file_path_label = customtkinter.CTkEntry(app, placeholder_text="File Path", height=35, width=325, bg_color="#192E45", font=("Arial", 15)) 
        self.file_path_label.pack(side=tk.BOTTOM, padx=(30), anchor=tk.CENTER)
        self.all_screen_obj.append(self.file_path_label)

        ## Lmao I still suck with names
        file_path_label_label = customtkinter.CTkLabel(app, text="Select Your File", font=('Arial', 18, 'bold'), text_color='white', bg_color="#192E45")
        file_path_label_label.pack(side=tk.BOTTOM, padx=(30), anchor=tk.W)
        self.all_screen_obj.append(file_path_label_label)

    def decrypt_screen(self) :
        topframe = customtkinter.CTkFrame(app, width=400, height=74, fg_color="#44AE4E", corner_radius=0)
        topframe.place(x=0, y=0)
        self.all_screen_obj.append(topframe)

        options_button = customtkinter.CTkButton(app, text="⚙️", font=("Arial", 30), hover_color="#28482b", bg_color="#44AE4E", fg_color="#44AE4E", command=lambda : self.set_screen("Settings"), height=30, width=30)
        options_button.pack(side=tk.TOP, anchor=tk.NE) 
        options_button.place(x = 290, y = 17)
        self.all_screen_obj.append(options_button)

        applabelname = customtkinter.CTkLabel(app, text="PyQuCryptor", bg_color="#44AE4E", text_color="white", font=("Arial",30, "bold"))
        applabelname.pack(side=tk.TOP, pady=(10,0), padx=(20,0), anchor=tk.NW)
        applabelname.place(x = 20, y = 20)
        self.all_screen_obj.append(applabelname)

        decrypt_button = customtkinter.CTkButton(app, text="🔓 Decrypt File", font=("Arial", 25, "bold"), fg_color="#E34039", hover_color="#75322f", command=self.decrypt_file, height=50, width=325)
        decrypt_button.pack(side=tk.BOTTOM, padx=(30), pady=(10,25), anchor=tk.CENTER)    
        self.all_screen_obj.append(decrypt_button)

        self.password_prompt = customtkinter.CTkEntry(app, placeholder_text="E.g. 1234", height=35, width=325, bg_color="#192E45", font=("Arial", 15)) 
        self.password_prompt.pack(side=tk.BOTTOM, padx=(30), pady=(0, 67), anchor=tk.CENTER)                  
        self.all_screen_obj.append(self.password_prompt)

        set_password = customtkinter.CTkLabel(app, text="Enter Your Password", bg_color="#192E45", font=("Arial", 18, "bold"))
        set_password.pack(side=tk.BOTTOM, padx=(30), pady=(0,2), anchor=tk.W)   
        self.all_screen_obj.append(set_password)

        encrypt_fd_button = customtkinter.CTkButton(app, text="Select Encrypted File", font=("Arial", 18), fg_color="#393939", bg_color="#192E45", hover_color="#2E2E2E", command=lambda : self.select_file("Select the encrypted file", filetypes=[("ENCR file", "*.encr"), ("All files", "*.*")]), height=25, width=325)
        encrypt_fd_button.pack(side=tk.BOTTOM, padx=(30), pady=(15, 25), anchor=tk.CENTER)
        self.all_screen_obj.append(encrypt_fd_button)

        self.file_path_label = customtkinter.CTkEntry(app, placeholder_text="Encrypted File Path", height=35, width=325, bg_color="#192E45", font=("Arial", 15)) 
        self.file_path_label.pack(side=tk.BOTTOM, padx=(30), anchor=tk.CENTER) 
        self.all_screen_obj.append(self.file_path_label)

        file_path_label_text = customtkinter.CTkLabel(app, text="Select Your File", font=('Arial', 18, 'bold'), text_color='white', bg_color="#192E45")
        file_path_label_text.pack(side=tk.BOTTOM, padx=(30), anchor=tk.W)
        self.all_screen_obj.append(file_path_label_text)

    def settings_menu(self) :
        ## This stuff is taken from the old GUI, nothing has really changed except for some optimizations
        ## Top banner
        banner = customtkinter.CTkFrame(master=app, width=400, height=74, fg_color="#2A4D73", corner_radius=0)
        banner.place(x=0, y=0)
        self.all_screen_obj.append(banner)

        applabelname = customtkinter.CTkLabel(app, text="Settings", bg_color="#2A4D73", text_color="white", font=("Arial",30, "bold"))
        applabelname.pack(side=tk.TOP, padx=(10,0), pady=(25,0), anchor=tk.W)
        applabelname.place(x = 20, y = 20)
        self.all_screen_obj.append(applabelname)

        settings_button = customtkinter.CTkButton(app, text="⚙️", font=("Arial", 30), hover_color="#192E45", bg_color="#2A4D73", fg_color="#2A4D73", command=lambda : self.set_screen(self.prev_screen), height=30, width=30)
        settings_button.pack(side=tk.TOP, anchor=tk.NE) 
        settings_button.place(x = 290, y = 17)
        self.all_screen_obj.append(settings_button)

        about_button = customtkinter.CTkButton(app, text="About", width=90, font=("Arial", 20, 'bold'), fg_color="#1F6AA5", bg_color="#192E45", command=lambda : messagebox.showinfo("PyQuCryptor: About", about_txt), border_color="#1F6AA5")
        about_button.pack(side=tk.BOTTOM, anchor=tk.CENTER)
        about_button.place(x=30, y=445)
        self.all_screen_obj.append(about_button)

        ## About thingy
        ## Draws the app logo
        photo_thingy = customtkinter.CTkLabel(app, image=customtkinter.CTkImage(Image.open(logo_path), size=(120, 120)), text='', bg_color='#192E45', fg_color="#192E45", text_color='white', font=("Arial", 25, 'bold'))
        photo_thingy.pack(side=tk.TOP, padx=(0,0), pady=(0,0), anchor=tk.W)
        photo_thingy.place(x=0, y=75)
        self.all_screen_obj.append(photo_thingy)

        ## Draws PyQuCryptor
        photo_thingy_label = customtkinter.CTkLabel(app, text="PyQuCryptor " + version, bg_color='#192E45', text_color='white', font=('Arial', 25, 'bold'))
        photo_thingy_label.pack(side=tk.TOP, padx=(0,0), pady=(0,0), anchor=tk.S)
        photo_thingy_label.place(x=95, y=125)
        self.all_screen_obj.append(photo_thingy_label)

        ## build string
        build_tag = customtkinter.CTkLabel(app, text=f"Version {build_string}", bg_color="#192E45", text_color='white', font=("Arial", 15, 'bold'))
        build_tag.pack(side=tk.TOP,padx=(10,0), pady=(0,0), anchor=tk.CENTER)
        build_tag.place(x = 45, y = 195)
        self.all_screen_obj.append(build_tag)

        ## Setting switches
        config_list = ["Delete Original (ENC)", "Delete Original (DEC)", "Scramble Filename", "Auto Update", ]
        config_list_status = []
        for config in config_list :
            if user_config[config] :
                config_list_status.append(customtkinter.StringVar(value="on"))
            else : 
                config_list_status.append(customtkinter.StringVar(value="off"))

        for index, config in enumerate(config_list) :
            frame = customtkinter.CTkFrame(master=app, width=350, height=50, corner_radius=0, fg_color="#2A4D73")
            frame.place(x=0, y=220 + index * 55)

            switch = customtkinter.CTkSwitch(master=frame, text="", command= lambda: update_setting(config, not user_config[config]), variable=config_list_status[index], switch_height=35, switch_width=60, onvalue="on", offvalue="off", progress_color="#44AE4E")
            switch.place(relx=0.90, rely=0.5, anchor=tk.CENTER)

            frame_label = customtkinter.CTkLabel(master=frame, text=config, text_color="white", font=("Arial", 20, "bold"))
            frame_label.place(relx=0.35, rely=0.75, anchor=tk.S)
            ## We need to add them to backwards to delete them in the correct order 
            self.all_screen_obj.append(frame_label)
            self.all_screen_obj.append(switch)
            self.all_screen_obj.append(frame)

        ## Bottom buttons
        github_button = customtkinter.CTkButton(app, text="GitHub", width=90, font=("Arial", 20, 'bold'), fg_color="#1F6AA5", bg_color="#192E45", command=lambda : self.redir_to_site(self.GITHUB_URL), border_color="#1F6AA5")
        github_button.pack(side=tk.BOTTOM, anchor=tk.CENTER)
        github_button.place(x=130, y=445)
        self.all_screen_obj.append(github_button)

        update_button = customtkinter.CTkButton(app, text="Update", width=90, font=("Arial", 20, 'bold'), fg_color="#1F6AA5", bg_color="#192E45", command=check_for_updates, border_color="#1F6AA5")
        update_button.pack(side=tk.BOTTOM, anchor=tk.CENTER)
        update_button.place(x=230, y=445)
        self.all_screen_obj.append(update_button)

        license_button = customtkinter.CTkButton(app, text="License", width=140, font=("Arial", 20, 'bold'), fg_color="#1F6AA5", bg_color="#192E45", command=lambda : self.display_popup(messagebox.showinfo,"PyQuCryptor: License", license_txt), border_color="#1F6AA5")
        license_button.pack(side=tk.BOTTOM, anchor=tk.CENTER)
        license_button.place(x=30, y=485)
        self.all_screen_obj.append(license_button)

        other_license_button = customtkinter.CTkButton(app, text="Other", width=140, font=("Arial", 20, "bold"), fg_color="#1F6AA5", bg_color="#192E45", command=lambda : self.display_popup(messagebox.showinfo, "PyQuCryptor: License", other_licenses), border_color="#1F6AA5")
        other_license_button.pack(side=tk.BOTTOM, anchor=tk.CENTER)
        other_license_button.place(x=180, y=485)
        self.all_screen_obj.append(other_license_button)

        back_button = customtkinter.CTkButton(app, text="Back", font=("Arial", 25, "bold"), fg_color="#E34039", bg_color="#192E45", hover_color="#75322f", command=lambda : self.set_screen(self.prev_screen), height=50, width=325, border_color="#1F6AA5")
        back_button.pack(side=tk.BOTTOM, padx=(30), pady=(10,25), anchor=tk.CENTER)  
        self.all_screen_obj.append(back_button)

    def select_file(self, title, file_etx): 
        self.file_path_label.delete(0, tk.END)
        self.file_path_label.insert(0, filedialog.askopenfilename(title=title, filetypes=file_etx))

    def redir_to_site(self, url) : 
        webbrowser.open(url)

    def generate_pwd(self, pwd_length=user_config["Gen password length"]) : 
        characters = string.ascii_letters + string.digits + string.punctuation
        self.password_prompt.delete(0, tk.END)
        self.password_prompt.insert(0, ''.join(secrets.choice(characters) for _ in range(pwd_length)))

    def encrypt_file(self) : 
        password = self.password_prompt.get()
        file_path = self.file_path_label.get()

        ## Checks for VeraCrypt containers
        if file_path[len(file_path)-3:] == ".hc" :
            if  messagebox.askyesno(title="PyQuCryptor: Encrypt", message="Are you sure you want to encrypt a VeraCrypt container? VeraCrypt containers that expands can cause errors with PyQuCryptor.") : pass
            else : raise TypeError("User does not want to encrypt VeraCrypt container.")
        
        if file_path == "" :
            error_message = "Please select the file you want to encrypt."
        elif not os.path.isfile(file_path) : # check 1 to see if the file exsisted 
            error_message = "Unknown file."
        elif password == "" : # Check to see if you got a password
            error_message = "Please enter a password."
        elif password.startswith(password[:1]*3) : ## Checks if the first 3 letters are the same b/c strong passwords
            error_message = "Please enter a stronger password."
        elif len(password) < 12 or len(password) > 50: # checks if password length is the right amount if characters
            error_message = "Password must be between 12 and 50 characters."
        else:
            error_message = None 
        
        if error_message : # gives the error message if any
            messagebox.showerror(title="PyQuCryptor: Encrypt Error", message=error_message)

        else: # File path + password
            self.file_path_label.delete(0, tk.END)
            self.password_prompt.delete(0, tk.END)
            cryptor().encrypt_file(password, file_path, user_config["Delete Original (ENC)"], user_config["Scramble Filename"])

    def decrypt_file(self) : 
        password = self.password_prompt.get()
        file_path = self.file_path_label.get()

        if file_path == "" :
            error_message = "Please select the file you want to decrypt."
        elif file_path[len(file_path)-5:] != ".encr" : ## This checks for whether or not the file ends in .encr and if it does not end in .encr it will rename it
            try : 
                open(file_path + '.encr', 'rb')
                if messagebox.askyesno(title= "PyQuCryptor: File Already Exists Error", message=f"File {os.path.basename(file_path) + '.encr'} already exists. Do you want to overwrite?") : ## I know this code is ugly
                    os.replace(file_path, file_path + '.encr')
                else : error_message = "Error when renaming non .encr file to .encr file."
            except FileNotFoundError :
                os.rename(file_path, file_path + ".encr")
            file_path += '.encr'
        elif not os.path.isfile(file_path): # Check 1: to see if the file exsists
            error_message = "Error: Unknown file."
        elif password == "": # Check 2: to see if you got a password
            error_message = "Please enter your password."
        elif len(password) < 12 or len(password) > 50: # checks if password length is the right amount if characters
            error_message = "Password must be between \n12 and 50 characters."
        
        else:
            error_message = None

        if error_message: # gives the error message if any
            messagebox.showerror(title="PyQuCryptor: Decrypt Error", message=error_message)
        else: ## File + password is ready to be used
            self.password_prompt.delete(0, tk.END)
            cryptor().decrypt_file(password, file_path, user_config["Delete Original (DEC)"]) ## Last variable is for deleting original file. If True, it delete, if False, it does not delete

## This snippet is for multi-threading so that the app dupe itself
if __name__ == "__main__" :
    app = customtkinter.CTk()
    ## Sets the app controller to be the app.
    app_controller = GUI_Controller(app=app, start_screen=" 🔒 Encrypt File ")
    ## We check for updates before starting the app
    ## if the user allows for it.
    app.mainloop()
    ## On exit we write the user config back to the config file so that we save the user's settings
    with open(user_config_file_path, 'w') as config_file :
        json.dump(user_config, config_file)