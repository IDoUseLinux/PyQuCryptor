#commands for the buttons are like command=blah blah blah, in the button ()
import customtkinter, secrets, string
import os, threading, subprocess, ctypes, hashlib, webbrowser, sys ## Crypto library stuff
import tkinter as tk
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from tkinter import messagebox, filedialog

about_txt = """\
Let's Encrypt Build 2023-10-06.gpc_main.rc3.v12
Made by: Jinghao Li, Kekoa Dang, Skidaux
License: BSD 3-Clause No Nuclear License 2014 
Date of programming: 2023-10-02
Why did we do this: No idea"""

build_string = "2023-10-06.gpc_main.rc3.v12"

dev_branch = "Mainline"

dev_stage = "Beta"

app = customtkinter.CTk()

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

                buffer = plain_file.read(65536)
                while len(buffer) > 0 :
                    ## Encrypted File
                    encrypted_file.write(cipher.encrypt(buffer))
                    buffer = plain_file.read(65536)
                
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
                        os.remove(path_to_file + ".temp")
                    else :
                        if messagebox.askyesno(title="File Already exists", message="The decrypted file already exists. Do you want to overwrite?") :
                             os.replace(path_to_file + ".temp", str.replace(path_to_file, ".encr", ''))
                        else : os.remove(path_to_file + ".temp")
                except FileNotFoundError: 
                    os.rename(path_to_file + ".temp", str.replace(path_to_file, ".encr", ''))
            if delete_og_file == True :
                os.replace(path_to_file + ".temp", path_to_file)
                os.replace(path_to_file, str.replace(path_to_file, '.encr', ''))
            
        messagebox.showinfo(title="Let's Encrypt: Finished Decryption!", message="Finished Decryption of file(s).")

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
    del hasher
    del file_path
    if mode == 'r' :
        return hashed_object
    else : hashtemp = hashed_object

#delete_og_file = True

def encryptbcmd(): #encrypt button command + 3 checks to make sure everything is there
    global errorlabel
    password = password_prompt.get()
    #password = password.replace(" ", "")  
    password_prompt.delete(0, tk.END)
    password_prompt.insert(0, password)
    
    if not os.path.isfile(file_path): # check 1 to see if the file exsisted 
        error_message = "Error: Unknown file."

    elif password == "": # check 2 to see if you got a password
        error_message = "Please enter a password."

    elif password.startswith("   ") :
        error_message = "Please enter a stronger password."
    
    elif len(password) < 12 or len(password) > 50: # checks if password length is the right amount if characters
        error_message = "Password must be between \n12 and 50 characters."

    else:
        error_message = None 

    try:
        errorlabel.pack_forget()
    except:
        pass

    if error_message: # gives the error message if any
        errorlabel = customtkinter.CTkLabel(app, text=error_message, fg_color="transparent", text_color="red", font=("",20))
        errorlabel.pack(side=tk.BOTTOM, padx=(70), pady=(0, 50), anchor=tk.CENTER)
        app.after(3000, lambda: errorlabel.pack_forget())
    else: # File + password
        password_prompt.delete(0, tk.END)
        file_path_label.delete(0, tk.END)
        password_prompt.delete(0, tk.END)
        encryptor = enc_dec_obj()
        encryptor.encrypt_file(password, file_path, False)
        del encryptor
     
def generate_password(pwd_length = 16):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for _ in range(pwd_length))
    password_prompt.delete(0, tk.END)
    password_prompt.insert(0, password)

file_path = ""
def encryptupload(): #uploads file to encrypt button
    global file_path
    file_path = filedialog.askopenfilename()
    file_path_label.insert(0,file_path)

def decryptbcmd():
    global errorlabel
    password = password_prompt.get()
    if not os.path.isfile(file_path): # check 1 to see if the file exsisted 
        error_message = "Error: Unknown file."
    elif password == "": # check 2 to see if you got a password
        error_message = "Please enter your password."
    # i dont know how you decrypt it, so this is the most i can do
    elif len(password) < 12 or len(password) > 50: # checks if password length is the right amount if characters
            error_message = "Password must be between \n12 and 50 characters."
    else:
        error_message = None
    try:
        errorlabel.pack_forget()
    except:
        pass
    if error_message: # gives the error message if any
        errorlabel = customtkinter.CTkLabel(app, text=error_message, fg_color="transparent", text_color="red", font=("",20))
        errorlabel.pack(side=tk.BOTTOM, padx=(75), pady=(0, 55), anchor=tk.CENTER)
        app.after(1500, lambda: errorlabel.pack_forget())
    else: # File + password is ready to be used
        password_prompt.delete(0, tk.END)
        decryptor = enc_dec_obj()
        decryptor.decrypt_file(password, file_path, False) ## Last variable is for deleting original file. If True, it delete, if False, it does not delete
        print("decypting! ALL CHECKS PASSED!")

def quit_program():
    app.quit()

def selectmodecmd(value): # select what screen your on encrypt / decrypt
    global decrypt_button, encrypt_button, encryptupload_button, file_path_label
    global password_prompt, set_password, generate_password_button
    if value == " 🔓 Decrypt File ": # decrypt screen
        try: # removes encrypt screen
            encrypt_button.pack_forget()
            password_prompt.pack_forget()
            set_password.pack_forget()
            encryptupload_button.pack_forget()
            file_path_label.pack_forget()
            generate_password_button.pack_forget()
        except:
            quit_program() # closes if something fails
        finally:
            decrypt_button = customtkinter.CTkButton(app, text="🔓 Decrypt File", font=("Arial", 25, "bold"), command=decryptbcmd, height=50, width=250)
            decrypt_button.pack(side=tk.BOTTOM, padx=(75), pady=(20,55), anchor=tk.CENTER)    

            password_prompt = customtkinter.CTkEntry(app, placeholder_text="E.g. 1234", width=250)
            password_prompt.pack(side=tk.BOTTOM, padx=(20), pady=(0,57), anchor=tk.CENTER)                         
            
            set_password = customtkinter.CTkLabel(app, text="Enter Your Password", font=("Arial", 15, "bold"))
            set_password.pack(side=tk.BOTTOM, padx=(76), anchor=tk.W)   
                
            encryptupload_button = customtkinter.CTkButton(app, text="Select Encrypted File", font=("Arial", 18), fg_color="#393939", hover_color="#2E2E2E", command=encryptupload, height=25, width=250)
            encryptupload_button.pack(side=tk.BOTTOM, padx=(75), pady=(15, 25), anchor=tk.CENTER)   

            file_path_label = customtkinter.CTkEntry(app, placeholder_text="Encrypted File Path", width=250)
            file_path_label.pack(side=tk.BOTTOM, padx=(20), anchor=tk.CENTER)      
    else: # encrypt screen
        try: # removes decrypt screen
            decrypt_button.pack_forget()
            password_prompt.pack_forget()
            set_password.pack_forget()
            encryptupload_button.pack_forget()
            file_path_label.pack_forget()
        except:
            quit_program() # closes if something fails
        finally:      
            encrypt_button = customtkinter.CTkButton(app, text="🔒 Encrypt File", font=("Arial", 25, "bold"), command=encryptbcmd, height=50, width=250)
            encrypt_button.pack(side=tk.BOTTOM, padx=(75), pady=(10,55), anchor=tk.CENTER)    

            generate_password_button = customtkinter.CTkButton(app, text="Generate Password", font=("Arial", 18), fg_color="#393939", hover_color="#2E2E2E", command=generate_password, height=25, width=250)
            generate_password_button.pack(side=tk.BOTTOM, padx=(75), pady=(15, 25), anchor=tk.CENTER)   

            password_prompt = customtkinter.CTkEntry(app, placeholder_text="12 - 50 characters", width=250)
            password_prompt.pack(side=tk.BOTTOM, padx=(20), anchor=tk.CENTER)                         
            
            set_password = customtkinter.CTkLabel(app, text="Set a Password", font=("Arial", 15, "bold"))
            set_password.pack(side=tk.BOTTOM, padx=(76), anchor=tk.W)   
                
            encryptupload_button = customtkinter.CTkButton(app, text="Select File", font=("Arial", 18), fg_color="#393939", hover_color="#2E2E2E", command=encryptupload, height=25, width=250)
            encryptupload_button.pack(side=tk.BOTTOM, padx=(75), pady=(15,25), anchor=tk.CENTER)   

            file_path_label = customtkinter.CTkEntry(app, placeholder_text="File Path", width=250)
            file_path_label.pack(side=tk.BOTTOM, padx=(20), anchor=tk.CENTER)  

autoselectmode = customtkinter.StringVar(value=" 🔒 Encrypt File ")
selectmode = customtkinter.CTkSegmentedButton(app, values=[" 🔒 Encrypt File ", " 🔓 Decrypt File "], font=("Arial", 20, "bold"),
                                              selected_color="#393939", fg_color="#1A1A1A", unselected_color="#141414", unselected_hover_color="#2E2E2E", selected_hover_color="#393939",
                                                border_width=7, corner_radius=13, height=50, variable=autoselectmode, command=selectmodecmd)
selectmode.pack(side=customtkinter.TOP, pady=(50,20))

quit_button = customtkinter.CTkButton(app, text="Quit", font=("Arial", 15, "bold"), command=quit_program, fg_color="red", hover_color="darkred", height=35, width=200) 
quit_button.pack(side=customtkinter.BOTTOM, pady=10)

def center_window(root, width, height): # centers the app to your pc res
    # Get the screen width and height
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    
    # Calculate the X and Y coordinates for the window to be centered
    x = (screen_width - width) // 2
    y = (screen_height - height) // 2
    
    # Set the window's position
    root.geometry(f"{width}x{height}+{x}+{y}")

app.resizable(False, False) # makes it unable to resize the app
center_window(app, 400, 600)
app.title("PyQuCryptor") # title 
value=" 🔒 Encrypt File " # sets value for line below
selectmodecmd(value) # selects encrypt screen first, if this is not here then it will be a blank screen then give a error
app.mainloop()