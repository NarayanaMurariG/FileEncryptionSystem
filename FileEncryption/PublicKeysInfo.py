# create FileServer to store the encrypted messages instead of PasteBin
from tinydb import TinyDB, Query
from Crypto.Random import get_random_bytes
import json

db = TinyDB('PublicKeys.json')

Server = Query()

server = db.table('PublicKeys')


# PublicKeys : {
#     'username' : 'UserY',
#     'RSAPublicKey' : 'PublicKey bytes b64encoded'
# }

def build_json(data: dict) -> dict:
    try:
        json_obj = {
            'username': data['username'] if 'username' in data else None,#userName of user to whom we are sharing the file
            'RSAPublicKey': data['RSAPublicKey'] if 'RSAPublicKey' in data else None
        }
        return json_obj
    except Exception as e:
        print(e)
        return {}


def insert_public_key_to_db(data: json):
    print("Public Key INnse")
    json_obj = build_json(data)
    if len(json_obj) == 0:
        return False, "Error saving file to Server"
    try:
        server.insert(json_obj)
        return True, json_obj
    except Exception as e:
        return False, str(e)


def get_user_public_key(search_field: str) -> list:
    try:
        results = server.search(Server.username == search_field)
        print(results)
    except Exception as e:
        raise e
    return results