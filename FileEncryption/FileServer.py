# create FileServer to store the encrypted messages instead of PasteBin
from tinydb import TinyDB, Query
from Crypto.Random import get_random_bytes
import json

db = TinyDB('FileServer.json')

Server = Query()

server = db.table('FileServer')


def build_json(data: dict) -> dict:
    try:
        file_server_ref_key = get_random_bytes(10)
        json_obj = {
            'file_server_ref_key': str(file_server_ref_key),
            'file_name': data['file_name'],
            'encrypted_data': data['data']
        }
        return json_obj
    except Exception as e:
        print(e)
        return {}


def insert_into_file_server(data: json):
    json_obj = build_json(data)
    if len(json_obj) == 0:
        return False, "Error saving file to Server"
    results = search_file_in_server(json_obj['file_server_ref_key'])
    if len(results) != 0:
        insert_into_file_server(data)
    try:
        server.insert(json_obj)
        return True, json_obj['file_server_ref_key']
    except Exception as e:
        return False, str(e)


def search_file_in_server(search_field: str) -> list:
    try:
        results = server.search(Server.file_server_ref_key == search_field)
    except Exception as e:
        raise e
    if len(results) > 1:
        return []
    return results


def delete_file(key: str):
    try:
        server.remove(Server.file_server_ref_key == key)
        return True, "Record Deleted !!"
    except Exception as e:
        return False, str(e)

