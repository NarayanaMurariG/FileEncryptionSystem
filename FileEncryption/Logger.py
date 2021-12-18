# create FileServer to store the encrypted messages instead of PasteBin
from tinydb import TinyDB, Query
from Crypto.Random import get_random_bytes
import json

db = TinyDB('Logger.json')

Server = Query()

server = db.table('Logger')


# def build_json(data: dict) -> dict:
#     try:
#         json_obj = {
#             'fileOwner': data['username'] if 'username' in data else None,
#             # userName of user to whom we are sharing the file
#             'filePath': data['filepath'] if 'filepath' in data else None,
#             'fileData': data['file_data'] if 'file_data' in data else None
#         }
#         return json_obj
#     except Exception as e:
#         print(e)
#         return {}


def insert_log_into_logger(data: str):
    data_obj = {'value' : data}
    try:
        server.insert(data_obj)
        return True, data
    except Exception as e:
        return False, str(e)


def get_all_files_in_public_files():
    try:
        results = server.all()
        return True, results
    except Exception as e:
        return False, str(e)
