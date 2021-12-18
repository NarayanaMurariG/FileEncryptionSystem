# create FileServer to store the encrypted messages instead of PasteBin
from tinydb import TinyDB, Query
from Crypto.Random import get_random_bytes
import json

db = TinyDB('PublicFiles.json')

Server = Query()

server = db.table('PublicFiles')


def build_json(data: dict) -> dict:
    try:
        json_obj = {
            'fileOwner': data['username'] if 'username' in data else None,
            # userName of user to whom we are sharing the file
            'filePath': data['filepath'] if 'filepath' in data else None,
            'fileData': data['file_data'] if 'file_data' in data else None
        }
        return json_obj
    except Exception as e:
        print(e)
        return {}


def insert_into_public_files(data: dict):
    json_obj = build_json(data)
    if len(json_obj) == 0:
        return False, "Error saving file to Server"
    try:
        server.insert(json_obj)
        return True, json_obj
    except Exception as e:
        return False, str(e)


def search_file_in_public_files(search_field: str) -> list:
    try:
        results = server.search(Server.filePath == search_field)
    except Exception as e:
        raise e
    return results


def get_all_files_in_public_files():
    try:
        results = server.all()
        return True, results
    except Exception as e:
        return False, str(e)


def delete_public_file_from_db(filePath: str, username: str):
    try:
        a = server.remove((Server.filePath == filePath) & (Server.fileOwner == username))
        if len(a) != 0:
            return True, None
        else:
            return False, "Username: "+username+" don't have Edit/delete access to this file"
    except Exception as e:
        return False, str(e)
