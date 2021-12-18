# create FileServer to store the encrypted messages instead of PasteBin
from tinydb import TinyDB, Query
from Crypto.Random import get_random_bytes
import json

from tinydb.queries import where

db = TinyDB('SharedFiles.json')

Server = Query()

server = db.table('SharedFiles')


# SharedFiles : {
#     'userName' : 'UserY',
#     'AESKey' : 'EncryptedSharedAESKey'
#     'File' : {'FileName' : {'api_paste_key' : 'afgwergh', 'iv' : 'iv'}, 'SharedBy' : 'UserX'}
# }

def build_json(data: dict) -> dict:
    try:
        json_obj = {
            'username': data['username'] if 'username' in data else None,
            # userName of user to whom we are sharing the file
            'File': {},
            'sharedAESKey': data['sharedAESKey'] if 'sharedAESKey' in data else None,
            'signature': data['signature'] if 'signature' in data else None,
            'file_path': data['file_name'] if 'file_name' in data else None
        }
        file_name = data.get('file_name', None)
        ref_key = data.get('ref_key', None)
        iv_value = data.get('iv_value', None)
        shared_by = data.get('shared_by', None)
        if file_name and ref_key and shared_by is not None:
            print("I am none")
            json_obj['File'].update({file_name: {'api_paste_key': ref_key, 'iv': iv_value}})
            json_obj['File'].update({'shared_by': shared_by})
            return json_obj
        else:
            print("I am not none")
            return {}
    except Exception as e:
        print(e)
        return {}


def insert_into_shared_files(data: json):
    json_obj = build_json(data)
    print(json_obj)
    if len(json_obj) == 0:
        return False, "Error saving file to Server"
    try:
        server.insert(json_obj)
        return True, json_obj
    except Exception as e:
        return False, str(e)


def get_all_shared_files_from_db(search_field: str) -> list:
    try:
        results = server.search(Server.username == search_field)
    except Exception as e:
        raise e
    return results


def delete_shared_file_from_db(search_field: str):
    try:
        print(Server.File)
        server.remove(Server.file_path == search_field)
        return True
    except Exception as e:
        raise e
        return False


# def update_user(update_fields: dict, search_field: str):
#     try:
#         server.update(update_fields, Server.file_server_ref_key == search_field)
#     except Exception as e:
#         return False, str(e)

#     updated_user = search_file_in_server(search_field=search_field)
#     return True, updated_user


# 
if __name__ == "__main__":
    data = {
        'username': 'User2',
        'file_name': 'File1',
        'api_paste_key': 'asghwerhe',
        'iv': 'awegwh',
        'shared_by': 'User1',
        'sharedAESKey': 'aegikbwaseigubwegvb ',
        'signature': 'shbrehtjnej'
    }
    # data = {
    #     'fileOwner' : 'User2',
    #     'filePath' : 'root/file1.txt',
    #     'fileData' : 'The new MacBook Pro and AirPods, plus iPhone 13, Apple Watch, iPad, HomePod mini and more. Shop early for the best selection of holiday favorites.'
    # }
    # from PublicFiles import insert_into_public_files,search_file_in_public_files
    # insert_into_public_files(data)
    # results = search_file_in_public_files('User2')
    # print(results)
    insert_into_shared_files(data)
    results = search_file_in_server('User2')
    print(results)
