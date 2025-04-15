import datetime
import ast
from cryptography.fernet import Fernet
import base64
import hashlib
import os
import getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pyperclip



def encrypt_symmetric(data: str, key: bytes) -> tuple:
    aesgcm = AESGCM(key)

    encrypted = aesgcm.encrypt(nonce, data.encode(), None)
    return encrypted, nonce


def decrypt_symmetric(encrypted: bytes,nonce_value: bytes,  key: bytes) -> str:
    aesgcm = AESGCM(key)

    decrypted = aesgcm.decrypt(nonce_value, encrypted, None)
    return decrypted.decode()



def generate_key(password: str) -> bytes:
    digest = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(digest)

def encrypt_text_file(password: str, content: str, filename: str = "CryptoSafe.txt"):
    key = generate_key(password)
    cipher = Fernet(key)
    final_content="{}||{}||{}".format(content,key_password,nonce)
    encrypted = cipher.encrypt(final_content.encode())

    with open(filename, 'wb') as f:
        f.write(encrypted)



def decrypt_text_file(password: str, filename: str = "CryptoSafe.txt"):
    key = generate_key(password)
    cipher = Fernet(key)

    with open(filename, 'rb') as f:
        encrypted_data = f.read()

    try:
        decrypted = cipher.decrypt(encrypted_data)
        return decrypted.decode()
    except:
        print("Invalid password or file is corrupted.")

def save_to_file():
    encrypt_text_file(master_password, str(keyDataBase), "CryptoSafe.txt")

def do_function(option_selected):
    found_status = False
    current_time = datetime.datetime.now()
    if option_selected == 1:
        if len(keyDataBase) == 0:
            print("-------------------------------------------------------------")
            print("No Keys available")
        else:
            search_key = input("Enter the name of the key you would like to find\n")

            for i  in range(0,len(keyDataBase)):
                if search_key in (keyDataBase[i][0]) or search_key in (keyDataBase[i][1]):
                    print("")
                    print("")
                    print("")
                    found_status = True
                    print("Key Name:{}".format(keyDataBase[i][0]))
                    print("Key Description:{}".format(keyDataBase[i][1]))
                    print_key=decrypt_symmetric(keyDataBase[i][2],nonce, key_password)
                    pyperclip.copy(print_key)
                    print("Key CreatedDate:{}".format(keyDataBase[i][3]))
                    keyDataBase[i][4] += ("{} accessed on {}.{}.{} {}  ,\n".format(getpass.getuser(), current_time.month,
                                                                        current_time.day, current_time.year,
                                                                        current_time.strftime("%H:%M:%S")))
                    print("last Accessed Time:{}".format(keyDataBase[i][4]))
                    print("Key copied to clipboard, you can paste the key!")

                    print("-------------------------------------------------------------")

        if not found_status:
            print("Key not found!")
        show_options()

    elif option_selected == 2:
        key_name = input("Enter the name of the Key\n")
        key_description = input("Enter the Description for the key:\n")
        key_value = input("Enter the value of the key:\n")
        key_saved_date = ("{}.{}.{} {}".format(current_time.month, current_time.day, current_time.year,
                                             current_time.strftime("%H:%M:%S")))
        last_accessed_time=("{} accessed on {}.{}.{} {} ,\n".format(getpass.getuser(),current_time.month, current_time.day, current_time.year,
                                             current_time.strftime("%H:%M:%S")))
        new_list = [key_name, key_description, encrypt_symmetric(key_value, key_password)[0] , key_saved_date,last_accessed_time]
        keyDataBase.insert(0, new_list)

        save_to_file()
        show_options()
    elif option_selected==3:
        search_key = input("Enter the name of the key you would like to overwrite \n")
        for i  in range(0,len(keyDataBase)):
            if search_key in (keyDataBase[i][0]) or search_key in (keyDataBase[i][1]):
                print("")
                print("")
                print("")
                found_status = True
                print("Key Name:{}".format(keyDataBase[i][0]))
                print("Key Description:{}".format(keyDataBase[i][1]))


                print("Key CreatedDate:{}".format(keyDataBase[i][3]))
                keyDataBase[i][4] =keyDataBase[i][4] + ("{} accessed on {}.{}.{} {} ,\n".format(getpass.getuser(),current_time.month, current_time.day, current_time.year,
                                             current_time.strftime("%H:%M:%S")))
                print("last Accessed Time:{}".format(keyDataBase[i][4]))
                print("-------------------------------------------------------------")

                new_value=input("Enter in the new value\n")
                keyDataBase[i][2]=encrypt_symmetric(new_value, key_password)[0]
                print("Successfully updated")
                save_to_file()

        if not found_status:
            print("Key not found!")
        show_options()
    elif option_selected==4:
        for keys in keyDataBase:
            print("Key Name:{}".format(keys[0]))
            print("Key Description:{}".format(keys[1]))

            print("Key copied to clipboard, you can paste the key!")

            print("Key CreatedDate:{}".format(keys[3]))

            keys[4] +=("{} accessed on {}.{}.{} {}  ,\n".format(getpass.getuser(),current_time.month, current_time.day, current_time.year,
                                             current_time.strftime("%H:%M:%S")))
            print("last Accessed Time:{}".format(keys[4]))
            print("-------------------------------------------------------------")

        save_to_file()
        do_function(1)

    elif option_selected == 5:
        delete_key = input("Enter the name of the key you would like to Delete\n")
        found_status=False
        for i in range(0, len(keyDataBase)):
            if delete_key in (keyDataBase[i][0]) or delete_key in (keyDataBase[i][1]):
                print("")
                print("")
                print("")
                print("Key Name:{}".format(keyDataBase[i][0]))
                print("Key Description:{}".format(keyDataBase[i][1]))
                found_status=True


                print("Key CreatedDate:{}".format(keyDataBase[i][3]))
                print("-------------------------------------------------------------")

                confirmation_value = input("Would you like to delete y / n \n")
                if confirmation_value=="y":
                    keyDataBase.pop(i)
                    save_to_file()

        if not found_status:
            print("Key not found!")

        show_options()



    elif option_selected==6:
        print("Thank you")
    else:
        print("Invalid Option")
        show_options()

def show_options():
    options=["Find a key","Enter a new key","Overwrite a key","List all keys","Delete a key","Exit"]
    print()
    for optionListIndex in range(0,len(options)):
         print("{}. {}".format(optionListIndex+1,options[optionListIndex]))
    print()
    print()
    print()
    option_selected = input("Select an option from above \n")

    try:
        if int(option_selected):

            do_function(int(option_selected))
    except:
        print("Invalid input")
        show_options()





keyDataBase=[]
master_password=""
if os.path.isfile("CryptoSafe.txt"):

    master_password = getpass.getpass("Enter Password:")
    try:
        text=decrypt_text_file(master_password, "CryptoSafe.txt")
        value=text.split("||")
        keyDataBase = ast.literal_eval(value[0])
        key_password =ast.literal_eval(value[1])
        nonce =ast.literal_eval(value[2])
        show_options()
    except Exception as e:
        print("error ",e)
else:
    try:
        master_password = getpass.getpass("Create a password to access keys\n")
        nonce = os.urandom(12)
        key_password = AESGCM.generate_key(256)
        show_options()
    except:
        print()






