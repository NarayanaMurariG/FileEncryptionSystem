from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
import json
from .FileServer import insert_into_file_server, search_file_in_server


def generateAESKey():
    AESKey = get_random_bytes(32)
    return AESKey


# def encryptFile(fileName, AESKey):
#     fileRead = open(fileName, "rb")
#     data = fileRead.read()
#     cipher = AES.new(AESKey, AES.MODE_CBC)
#     ct_bytes = cipher.encrypt(pad(data, AES.block_size))
#     iv = b64encode(cipher.iv).decode('utf-8')
#     ct = b64encode(ct_bytes).decode('utf-8')
#     api_paste_key = post_paste(ct, "5mbFile")
#     fileRead.close()
#     return api_paste_key, iv


def encryptFile(fileName, fileData, AESKey):
    # Check file data and convert into bytes if not in bytes
    # File Data is received in Bytes
    # AESKey received is b64encoded and have to decode before using
    AESKey = b64decode(AESKey)
    cipher = AES.new(AESKey, AES.MODE_CBC)
    fileData = bytes(fileData, 'utf-8')
    file_name = bytes(fileName, 'utf-8')
    ct_bytes = cipher.encrypt(pad(fileData, AES.block_size))
    file_name_bytes = cipher.encrypt(pad(file_name, AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    file_name = b64encode(file_name_bytes).decode('utf-8')
    # dataToInsert = {'file_name': fileName, 'data': ct}
    dataToInsert = {'file_name': file_name, 'data': ct}

    flag, api_paste_key = insert_into_file_server(dataToInsert)
    # api_paste_key and iv are sent as string which is b64encoded
    if flag:
        return file_name, api_paste_key, iv
    else:
        return None, None, None


# def decryptFileAndSave(api_paste_key, AESKey, iv):
#     fileWrite = open("outputFile.txt", "wb")
#     try:
#         iv = b64decode(iv)
#         ct = b64decode(fetch_pastes(api_paste_key))
#         cipher = AES.new(AESKey, AES.MODE_CBC, iv)
#         pt = unpad(cipher.decrypt(ct), AES.block_size)
#         fileWrite.write(pt)
#         print("The message was: ", pt)
#     except ValueError:
#         print("Incorrect Value")
#     except KeyError:
#         print("Incorrect decryption")


def decryptFile(api_paste_key, AESKey, iv):
    try:
        iv = b64decode(iv)
        AESKey = b64decode(AESKey)
        results = search_file_in_server(api_paste_key)
        ct = b64decode(results[0]['encrypted_data'])
        file_name = b64decode(results[0]['file_name'])
        cipher = AES.new(AESKey, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        file_name_bytes = unpad(cipher.decrypt(file_name), AES.block_size)
        message = pt.decode("utf-8")
        file_name = file_name_bytes.decode("utf-8")

        return message, file_name, True
    except ValueError:
        print("Incorrect Value")
        # "Value Error data type has to be the same type as pt"
        return "ValueError", None, False
    except KeyError:
        print("Incorrect decryption")
        # "Key Error data type has to be the same type as pt"
        return "KeyError", None, False
