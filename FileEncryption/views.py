from base64 import b64decode, b64encode

from django.shortcuts import render
import json

from FileEncryption.PublicKeysInfo import get_user_public_key, insert_public_key_to_db
from FileEncryption.SharedFilesInfo import delete_shared_file_from_db, get_all_shared_files_from_db, \
    insert_into_shared_files

from .FileServer import delete_file, search_file_in_server
from .Logger import insert_log_into_logger
from .PublicFiles import get_all_files_in_public_files, search_file_in_public_files, insert_into_public_files, \
    delete_public_file_from_db
from .UserOnboarding import generatePublicPrivateKeys
from .database import DatabaseQueries
from .utils import Utils
from django.http import JsonResponse
from rest_framework import status
from .RSAModule import decryptAESKey, decryptSharedAESKey, encryptAESKey, encryptSharedAESKey
from .AESModule import decryptFile, encryptFile, generateAESKey


# Create your views here.
def create_log_string(operated_by, operation_type, message):
    from datetime import datetime
    now = datetime.now()
    current_time = now.strftime("%D - %H:%M:%S")
    output = current_time + " , " + operated_by + " , " + operation_type + " , " + message
    insert_log_into_logger(output)


def index_page(request, template='homepage.html'):
    return render(request, template, {})


def login_page(request, template='login.html'):
    return render(request, template, {})


def signup_page(request, template='register.html'):
    return render(request, template, {})


def user_home_page(request, template='userhome.html'):
    return render(request, template, {})


def error_page(request, template='error.html'):
    return render(request, template, {})


def get_api_key_iv_from_user(username, filepath):
    db_object = DatabaseQueries()
    user_obj = db_object.search_user(username)
    encrypted_aes_key = user_obj[0].get('aes_key', None)
    root_dir = user_obj[0].get('root', None)
    filepath_object = root_dir.get(filepath)
    api_paste_key = filepath_object['api_paste_key']
    iv = filepath_object['iv']
    access_level = filepath_object['access_level']

    return encrypted_aes_key, api_paste_key, iv, access_level


def get_all_users(request):
    username = request.GET.get('username', None)
    db_object = DatabaseQueries()
    result_set = db_object.getUsers()
    users_list = []
    for user in result_set:
        users_list.append(user['username'])
    users_list.remove(username)
    return JsonResponse(users_list, safe=False, status=status.HTTP_200_OK)


# API to get a file data
def getRecordAPI(request):
    username = request.GET.get('username', None)
    encrypted_file_path = request.GET.get('encrypted_file_path', None)
    private_key = request.GET.get('secret_key', None)

    utils = Utils()
    flag = utils.authenticate_user(username=username, privateKey=private_key)
    if flag:
        encrypted_aes_key, api_paste_key, iv, access_level = get_api_key_iv_from_user(username, encrypted_file_path)
        decrypted_aes_key = decryptAESKey(encrypted_aes_key, private_key)
        message, file_name, decrypt_status = decryptFile(api_paste_key, decrypted_aes_key, iv)
        create_log_string(username, "Read File", encrypted_file_path)
        return JsonResponse({"filename": file_name, "responseMessage": message, "responseCode": 1}, safe=False,
                            status=status.HTTP_200_OK)
    else:
        return JsonResponse({"responseMessage": "Unauthorised user", "responseCode": 0},
                            status=status.HTTP_400_BAD_REQUEST)


# API for SignUP
def SignupAPI(request):
    username = request.GET.get('username', None)
    AES_Key = generateAESKey()
    privateKey, publicKey = generatePublicPrivateKeys()
    encryptedAESKey = encryptAESKey(AES_Key, publicKey)
    db_object = DatabaseQueries()
    data = {'username': username, 'aes_key': encryptedAESKey, 'rsa_public_key': publicKey}
    flag, response = db_object.insert_user(data)
    if flag:
        json_obj = {
            'username': data['username'],
            'RSAPublicKey': publicKey
        }
        insert_public_key_to_db(json_obj)
        return JsonResponse(privateKey, safe=False, status=status.HTTP_200_OK)
    else:
        return JsonResponse(response, safe=False, status=status.HTTP_400_BAD_REQUEST)


# API for login
def LoginAPI(request):
    username = request.GET.get('username', None)
    secret_key = request.GET.get('secret_key', None)
    utils = Utils()
    flag = utils.authenticate_user(username=username, privateKey=secret_key)
    if flag:
        return JsonResponse({"responseMessage": "User is an authenticated user", "responseCode": 1},
                            status=status.HTTP_200_OK)
    else:
        return JsonResponse({"responseMessage": "User is not an authenticated user", "responseCode": 0},
                            status=status.HTTP_400_BAD_REQUEST)


# API to add files
def UpdateAPI(request):
    username = request.GET.get('username', None)
    filepath = request.GET.get('filepath', None)
    file_data = request.GET.get('file_data', None)
    private_key = request.GET.get('secret_key', None)
    access_level = request.GET.get('access_level', None)

    data = {
        "username": username,
        "filepath": filepath,
        "file_data": file_data
    }

    if access_level == 'public':
        public_flag, obj = insert_into_public_files(data)
        if public_flag:
            create_log_string(username, "Created public File", filepath)
            return JsonResponse({"responseMessage": "Public file created !!", "responseCode": 1},
                                safe=False, status=status.HTTP_200_OK)
        return JsonResponse({"responseMessage": "Error while creating public file", "responseCode": 1},
                            safe=False, status=status.HTTP_400_BAD_REQUEST)

    utils = Utils()
    flag = utils.authenticate_user(username=username, privateKey=private_key)
    db_object = DatabaseQueries()

    if flag:
        user_obj = db_object.search_user(username)
        encrypted_aes_key = user_obj[0].get('aes_key', None)
        decrypted_aes_key = decryptAESKey(encrypted_aes_key, private_key)
        encrypted_filepath, api_paste_key, iv = encryptFile(fileName=filepath, fileData=file_data,
                                                            AESKey=decrypted_aes_key)
        update_fields = {
            'filepath': encrypted_filepath,
            'api_paste_key': api_paste_key,
            'iv': iv,
            'access_level': access_level
        }
        flag, message = db_object.update_user(update_fields, username)
        if flag:
            create_log_string(username, "Created private File", encrypted_filepath)
            return JsonResponse({"responseMessage": message, "responseCode": 1},
                                safe=False, status=status.HTTP_200_OK)
        else:
            return JsonResponse({"responseMessage": message, "responseCode": 1},
                                safe=False, status=status.HTTP_400_BAD_REQUEST)
    else:
        return JsonResponse({"responseMessage": "Unauthorised user", "responseCode": 0},
                            status=status.HTTP_400_BAD_REQUEST)


def getPrivateFilesListAPI(request):
    username = request.GET.get('username', None)
    private_key = request.GET.get('secret_key', None)

    utils = Utils()
    flag = utils.authenticate_user(username=username, privateKey=private_key)
    db_object = DatabaseQueries()

    if flag:
        filepath_dict = {}
        user_obj = db_object.search_user(username)
        root_dir = user_obj[0].get('root')
        encrypted_aes_key = user_obj[0].get('aes_key', None)
        decrypted_aes_key = decryptAESKey(encrypted_aes_key, private_key)

        for file in root_dir.keys():
            iv = root_dir.get(file).get('iv')
            api_paste_key = root_dir.get(file).get('api_paste_key')
            message, decrypted_file_path, flag = decryptFile(api_paste_key=api_paste_key, AESKey=decrypted_aes_key,
                                                             iv=iv)
            if flag:
                filepath_dict.update({decrypted_file_path: file})
        create_log_string(username, "Read private Files", 'None')
        return JsonResponse({"responseMessage": filepath_dict, "responseCode": 1},
                            safe=False, status=status.HTTP_200_OK)
    return JsonResponse({"responseMessage": "Unauthorised user", "responseCode": 0},
                        status=status.HTTP_400_BAD_REQUEST)


def delete_files_from_server(request):
    username = request.GET.get('username', None)
    private_key = request.GET.get('secret_key', None)
    encrypted_file_path = request.GET.get('encrypted_file_path', None)

    utils = Utils()
    flag = utils.authenticate_user(username=username, privateKey=private_key)
    db_object = DatabaseQueries()

    if flag:
        user_obj = db_object.search_user(username)
        root_dir = user_obj[0].get('root')
        api_paste_key = root_dir[encrypted_file_path].get('api_paste_key')
        root_dir.pop(encrypted_file_path)
        user_obj[0]['root'] = root_dir
        update_flag, message = db_object.perform_update(user_obj, username)
        if update_flag:
            delete_status, message = delete_file(api_paste_key)
            if delete_status:
                create_log_string(username, "Deleted private File", encrypted_file_path)
                return JsonResponse({"responseMessage": "Deleted Successfully !!", "responseCode": 1},
                                    safe=False, status=status.HTTP_200_OK)
        return JsonResponse({"responseMessage": message, "responseCode": 0},
                            safe=False, status=status.HTTP_400_BAD_REQUEST)
    return JsonResponse({"responseMessage": "Unauthorised user", "responseCode": 0},
                        status=status.HTTP_400_BAD_REQUEST)


def get_all_public_files(request):
    flag, results = get_all_files_in_public_files()
    if flag:
        return JsonResponse(results, safe=False, status=status.HTTP_200_OK)
    return JsonResponse(results, safe=False, status=status.HTTP_400_BAD_REQUEST)


def get_public_file(request):
    public_file_name = request.GET.get('file_name', None)

    results = search_file_in_public_files(public_file_name)
    return JsonResponse(results, safe=False, status=status.HTTP_200_OK)


def delete_public_file(request):
    username = request.GET.get('username', None)
    public_file_name = request.GET.get('file_name', None)
    flag, message = delete_public_file_from_db(public_file_name, username)
    if flag:
        create_log_string(username, "Deleted public File", public_file_name)
        return JsonResponse({"responseMessage": "File Deleted !!"}, safe=False, status=status.HTTP_200_OK)
    return JsonResponse({"responseMessage": message}, safe=False, status=status.HTTP_200_OK)


def share_file_with_another_user(request):
    username = request.GET.get('username', None)
    encrypted_file_path = request.GET.get('encrypted_file_path', None)
    private_key = request.GET.get('secret_key', None)
    share_with = request.GET.get('share_with', None)

    utils = Utils()
    flag = utils.authenticate_user(username=username, privateKey=private_key)

    if flag:
        # Getting the file content from user 1
        encrypted_aes_key, api_paste_key, iv, access_level = get_api_key_iv_from_user(username, encrypted_file_path)
        decrypted_aes_key = decryptAESKey(encrypted_aes_key, private_key)
        message, file_name, decrypt_status = decryptFile(api_paste_key, decrypted_aes_key, iv)

        shared_AES_key = generateAESKey()
        from .UserOnboarding import encodeBytesToString
        shared_AES_key = encodeBytesToString(shared_AES_key)
        encrypted_filepath, api_paste_key, iv = encryptFile(fileName=file_name, fileData=message, AESKey=shared_AES_key)

        # Encrypt and sign user key
        public_key_obj = get_user_public_key(share_with)
        if len(public_key_obj) == 0:
            return JsonResponse({"responseMessage": "User does not exist in the system", "responseCode": 0},
                                safe=False, status=status.HTTP_400_BAD_REQUEST)

        share_with_public_key = public_key_obj[0]['RSAPublicKey']

        encrypted_shared_AES_key, signature = encryptSharedAESKey(shared_AES_key, user1_PemPvt=private_key,
                                                                  user2_PemPbc=share_with_public_key)

        json_obj = {
            'username': share_with,
            'sharedAESKey': encrypted_shared_AES_key,
            'signature': signature,
            'file_name': encrypted_filepath,
            'ref_key': api_paste_key,
            'iv_value': iv,
            'shared_by': username,
        }
        insert_status = insert_into_shared_files(json_obj)
        if insert_status:
            create_log_string(username, "File shared with " + str(share_with), encrypted_file_path)
            return JsonResponse({"responseMessage": "File Shared with concerned user", "responseCode": 1},
                                safe=False, status=status.HTTP_200_OK)
    else:
        return JsonResponse({"responseMessage": "Unauthorised user", "responseCode": 0},
                            status=status.HTTP_400_BAD_REQUEST)


# Below function is working and tested using Postman
def get_all_shared_files(request):
    username = request.GET.get('username', None)
    private_key = request.GET.get('secret_key', None)

    utils = Utils()
    flag = utils.authenticate_user(username=username, privateKey=private_key)

    if flag:
        # Getting the file content from user 1
        shared_files = get_all_shared_files_from_db(username)
        files_list = {}
        shared_by_list = {}
        for shared_file in shared_files:
            encryptedSharedAESKey = shared_file.get('sharedAESKey')
            signature = shared_file.get('signature')
            shared_by = shared_file.get('File').get('shared_by')
            public_key_obj = get_user_public_key(shared_by)
            if len(public_key_obj) != 0:
                user1_PemPbc = public_key_obj[0]['RSAPublicKey']
                encrypted_file_path = list(shared_file.get('File').keys())[0]
                api_paste_key = shared_file.get('File').get(encrypted_file_path).get('api_paste_key')
                iv = shared_file.get('File').get(encrypted_file_path).get('iv')
                decrypted_shared_AES_key, shared_key_decryption_status = decryptSharedAESKey(encryptedSharedAESKey,
                                                                                             user1_PemPbc, private_key,
                                                                                             signature)
                if shared_key_decryption_status:
                    message, file_name, decrypt_status = decryptFile(api_paste_key, decrypted_shared_AES_key, iv)
                    files_list.update({file_name: encrypted_file_path})
                    shared_by_list.update({file_name: shared_by})

        create_log_string(username, "Read shared files", "None")
        return JsonResponse({"responseMessage": files_list, "shared_by": shared_by_list, "responseCode": 1},
                            safe=False, status=status.HTTP_200_OK)
    return JsonResponse({"responseMessage": "Unauthorised user", "responseCode": 0},
                        status=status.HTTP_400_BAD_REQUEST)


# Below function working fine
def get_shared_file(request):
    username = request.GET.get('username', None)
    private_key = request.GET.get('secret_key', None)
    encrypted_file_path = request.GET.get('encrypted_file_path', None)

    utils = Utils()
    flag = utils.authenticate_user(username=username, privateKey=private_key)

    if flag:
        shared_files = get_all_shared_files_from_db(username)
        shared_file = {}
        for shared_object in shared_files:
            file_obj_keys = list(shared_object['File'].keys())
            if encrypted_file_path == file_obj_keys[0]:
                shared_file = shared_object
                break

        encryptedSharedAESKey = shared_file.get('sharedAESKey')
        signature = shared_file.get('signature')
        shared_by = shared_file.get('File').get('shared_by')

        public_key_obj = get_user_public_key(shared_by)
        if len(public_key_obj) == 0:
            return JsonResponse({"responseMessage": "User does not exist in the system", "responseCode": 0},
                                safe=False, status=status.HTTP_400_BAD_REQUEST)

        user1_PemPbc = public_key_obj[0]['RSAPublicKey']
        encrypted_file_path = list(shared_file.get('File').keys())[0]
        api_paste_key = shared_file.get('File').get(encrypted_file_path).get('api_paste_key')
        iv = shared_file.get('File').get(encrypted_file_path).get('iv')
        decrypted_shared_AES_key, shared_key_decryption_status = decryptSharedAESKey(encryptedSharedAESKey,
                                                                                     user1_PemPbc, private_key,
                                                                                     signature)
        if shared_key_decryption_status:
            message, file_name, decrypt_status = decryptFile(api_paste_key, decrypted_shared_AES_key, iv)
            create_log_string(username, "Read shared file", encrypted_file_path)
            return JsonResponse({"responseMessage": message, "responseCode": 1}, safe=False, status=status.HTTP_200_OK)

    return JsonResponse({"responseMessage": "Unauthorised user", "responseCode": 0},
                        status=status.HTTP_400_BAD_REQUEST)


# Working sucessfully
def delete_shared_file(request):
    username = request.GET.get('username', None)
    private_key = request.GET.get('secret_key', None)
    encrypted_file_path = request.GET.get('encrypted_file_path', None)

    utils = Utils()
    flag = utils.authenticate_user(username=username, privateKey=private_key)

    if flag:
        # Getting the file content from user 1
        shared_files = get_all_shared_files_from_db(username)
        shared_file = {}
        for shared_object in shared_files:
            file_obj_keys = list(shared_object['File'].keys())
            if encrypted_file_path == file_obj_keys[0]:
                shared_file = shared_object
                break

        encrypted_file_path = list(shared_file.get('File').keys())[0]
        api_paste_key = shared_file.get('File').get(encrypted_file_path).get('api_paste_key')
        delete_status = delete_shared_file_from_db(encrypted_file_path)
        if delete_status:
            delete_file(api_paste_key)
            create_log_string(username, "Deleted shared file", encrypted_file_path)
            return JsonResponse({"responseMessage": "Deletion of shared file successful", "responseCode": 1},
                                safe=False, status=status.HTTP_200_OK)
        else:
            return JsonResponse({"responseMessage": "Error while deleting file", "responseCode": 0},
                                safe=False, status=status.HTTP_400_BAD_REQUEST)
    else:
        return JsonResponse({"responseMessage": "Unauthorised user", "responseCode": 0},
                            status=status.HTTP_400_BAD_REQUEST)


def change_file_permission(request):
    username = request.GET.get('username', None)
    private_key = request.GET.get('secret_key', None)
    current_access_level = request.GET.get('access_level', None)
    file_path = request.GET.get('file_path', None)
    utils = Utils()
    flag = utils.authenticate_user(username=username, privateKey=private_key)
    db_object = DatabaseQueries()

    if flag:
        # Getting the file content from user 1
        if current_access_level == 'private':
            # Change to public , decrypt and add to public files
            encrypted_file_path = file_path
            encrypted_aes_key, api_paste_key, iv, access_level = get_api_key_iv_from_user(username, encrypted_file_path)
            decrypted_aes_key = decryptAESKey(encrypted_aes_key, private_key)
            message, file_name, decrypt_status = decryptFile(api_paste_key, decrypted_aes_key, iv)

            public_data = {
                'username': username,
                'filepath': file_name,
                'file_data': message
            }
            public_flag, obj = insert_into_public_files(public_data)
            if public_flag:
                user_obj = db_object.search_user(username)
                root_dir = user_obj[0].get('root')
                api_paste_key = root_dir[encrypted_file_path].get('api_paste_key')
                root_dir.pop(encrypted_file_path)
                user_obj[0]['root'] = root_dir
                update_flag, message = db_object.perform_update(user_obj, username)
                if update_flag:
                    delete_status, message = delete_file(api_paste_key)
                    if delete_status:
                        create_log_string(username, "File permission changed from private to public",
                                          encrypted_file_path)
                        return JsonResponse({"responseMessage": "Public file created !!", "responseCode": 1},
                                            safe=False, status=status.HTTP_200_OK)
            return JsonResponse({"responseMessage": "Error while creating public file", "responseCode": 1},
                                safe=False, status=status.HTTP_400_BAD_REQUEST)

        else:
            # Retrive file, get aes key and update in user object
            public_file_path = file_path
            public_file_object = search_file_in_public_files(public_file_path)
            fileOwner = public_file_object[0]['fileOwner']
            file_path = public_file_object[0]['filePath']
            file_data = public_file_object[0]['fileData']
            if username == fileOwner:
                user_obj = db_object.search_user(username)
                encrypted_aes_key = user_obj[0].get('aes_key', None)
                decrypted_aes_key = decryptAESKey(encrypted_aes_key, private_key)
                encrypted_filepath, api_paste_key, iv = encryptFile(fileName=file_path, fileData=file_data,
                                                                    AESKey=decrypted_aes_key)
                update_fields = {
                    'filepath': encrypted_filepath,
                    'api_paste_key': api_paste_key,
                    'iv': iv,
                    'access_level': "private"
                }
                flag, message = db_object.update_user(update_fields, username)
                if flag:
                    delete_public_file_from_db(public_file_path, username)
                    create_log_string(username, "File permission changed from public to private",
                                      file_path)
                    return JsonResponse({"responseMessage": "File Permission Changed Successfully", "responseCode": 1},
                                        safe=False, status=status.HTTP_200_OK)
                else:
                    return JsonResponse({"responseMessage": "File Permission Change failed", "responseCode": 1},
                                        safe=False, status=status.HTTP_400_BAD_REQUEST)

            else:
                return JsonResponse({"responseMessage": "You are not the owner of this file", "responseCode": 1},
                                    safe=False, status=status.HTTP_200_OK)

    else:
        return JsonResponse({"responseMessage": "Unauthorised user", "responseCode": 0},
                            status=status.HTTP_400_BAD_REQUEST)


# Edit private file from here
def edit_private_file(request):
    username = request.GET.get('username', None)
    updated_filepath = request.GET.get('newfilepath', None)
    previous_filepath = request.GET.get('oldfilepath', None)  # EncryptedFilePath
    file_data = request.GET.get('file_data', None)
    private_key = request.GET.get('secret_key', None)
    access_level = request.GET.get('access_level', None)
    utils = Utils()
    flag = utils.authenticate_user(username=username, privateKey=private_key)
    db_object = DatabaseQueries()

    if flag:
        user_obj = db_object.search_user(username)
        root_dir = user_obj[0].get('root')
        file_object = root_dir.get(previous_filepath)
        prev_api_paste_key = file_object.get('api_paste_key')
        encrypted_aes_key = user_obj[0].get('aes_key', None)
        decrypted_aes_key = decryptAESKey(encrypted_aes_key, private_key)
        encrypted_filepath, api_paste_key, iv = encryptFile(fileName=updated_filepath, fileData=file_data,
                                                            AESKey=decrypted_aes_key)
        update_fields = {
            'filepath': encrypted_filepath,
            'api_paste_key': api_paste_key,
            'iv': iv,
            'access_level': access_level
        }

        # Delete old record
        root_dir.pop(previous_filepath)
        user_obj[0]['root'] = root_dir
        update_flag, message = db_object.perform_update(user_obj, username)
        delete_file(prev_api_paste_key)
        # Now update new one
        flag, message = db_object.update_user(update_fields, username)
        if flag:
            create_log_string(username, "Updated private File", encrypted_filepath)
            return JsonResponse({"responseMessage": message, "responseCode": 1},
                                safe=False, status=status.HTTP_200_OK)
        else:
            return JsonResponse({"responseMessage": message, "responseCode": 1},
                                safe=False, status=status.HTTP_400_BAD_REQUEST)
    else:
        return JsonResponse({"responseMessage": "Unauthorised user", "responseCode": 0},
                            status=status.HTTP_400_BAD_REQUEST)


# Edit Public file from here
def edit_public_file(request):
    username = request.GET.get('username', None)
    updated_filepath = request.GET.get('newfilepath', None)
    previous_filepath = request.GET.get('oldfilepath', None)  # EncryptedFilePath
    file_data = request.GET.get('file_data', None)
    access_level = request.GET.get('access_level', None)

    #Delete public file below
    flag, message = delete_public_file_from_db(previous_filepath, username)

    if flag:
        create_log_string(username, "Deleted public File", previous_filepath)
        data = {
            "username": username,
            "filepath": updated_filepath,
            "file_data": file_data
        }
        public_flag, obj = insert_into_public_files(data)
        if public_flag:
            create_log_string(username, "Created public File", updated_filepath)
            return JsonResponse({"responseMessage": "File Has been updated !!"}, safe=False, status=status.HTTP_200_OK)
    else:
        return JsonResponse({"responseMessage": message}, safe=False, status=status.HTTP_200_OK)


# Get Encrypted Data
def getEncryptedRecordAPI(request):
    username = request.GET.get('username', None)
    encrypted_file_path = request.GET.get('encrypted_file_path', None)
    private_key = request.GET.get('secret_key', None)

    utils = Utils()
    flag = utils.authenticate_user(username=username, privateKey=private_key)
    if flag:
        encrypted_aes_key, api_paste_key, iv, access_level = get_api_key_iv_from_user(username, encrypted_file_path)
        results = search_file_in_server(api_paste_key)
        print(type(results[0]['encrypted_data']))
        # pt = b64encode(results[0]['encrypted_data'])
        # print(type(pt))
        # message = pt.decode("utf-8")

        create_log_string(username, "Read File", encrypted_file_path)
        return JsonResponse({"filename": encrypted_file_path, "responseMessage": results[0]['encrypted_data'],
                             "responseCode": 1},
                            safe=False, status=status.HTTP_200_OK)
    else:
        return JsonResponse({"responseMessage": "Unauthorised user", "responseCode": 0},
                            status=status.HTTP_400_BAD_REQUEST)


def getEncryptedSharedFile(request):
    username = request.GET.get('username', None)
    private_key = request.GET.get('secret_key', None)
    encrypted_file_path = request.GET.get('encrypted_file_path', None)

    utils = Utils()
    flag = utils.authenticate_user(username=username, privateKey=private_key)

    if flag:
        shared_files = get_all_shared_files_from_db(username)
        shared_file = {}
        print(shared_file)
        for shared_object in shared_files:
            file_obj_keys = list(shared_object['File'].keys())
            if encrypted_file_path == file_obj_keys[0]:
                shared_file = shared_object
                break
        api_paste_key = shared_file['File'][encrypted_file_path]['api_paste_key']
        results = search_file_in_server(api_paste_key)
        # pt = b64encode(results[0]['encrypted_data'])
        # print(type(pt))
        # message = pt.decode("utf-8")

        create_log_string(username, "Read File", encrypted_file_path)
        return JsonResponse({"filename": encrypted_file_path, "responseMessage": results[0]['encrypted_data'],
                             "responseCode": 1},
                            safe=False, status=status.HTTP_200_OK)
    else:
        return JsonResponse({"responseMessage": "Unauthorised user", "responseCode": 0},
                            status=status.HTTP_400_BAD_REQUEST)


