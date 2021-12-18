import json
from base64 import b64encode, b64decode
from .database import DatabaseQueries


class Utils(object):

    def __init__(self):
        self.registry = {}

    @staticmethod
    def build_json(data: dict) -> dict:
        if 'username' in data:
            if data['username']:
                json_obj = {
                    'username': str(data['username']),
                    'aes_key': data['aes_key'] if 'aes_key' in data else None,
                    'rsa_public_key': data['rsa_public_key'] if 'rsa_public_key' in data else None,
                    'root': {}
                }
                file_name = data.get('file_name', None)
                ref_key = data.get('api_paste_key', None)
                iv_value = data.get('iv', None)
                if file_name and ref_key is not None:
                    json_obj['root'].update({file_name: {'api_paste_key': ref_key, 'iv': iv_value}})
                return json_obj
            else:
                return {}
        else:
            return {}

    def authenticate_user(self, username, privateKey):
        try:
            from .RSAModule import encryptAESKey, decryptAESKey

            db_object = DatabaseQueries()
            checkString = b'ToCheckUserAuthenticity'
            user_obj = db_object.search_user(username)
            if len(user_obj) > 0:
                publicKey = user_obj[0].get('rsa_public_key', None)
                if publicKey is not None:
                    encryptedCheckString = encryptAESKey(checkString, publicKey)
                    decryptedCheckString = decryptAESKey(encryptedCheckString, privateKey)
                    decryptedCheckString = b64decode(decryptedCheckString)
                    if checkString == decryptedCheckString:
                        # code working correctly returning True
                        return True
                    else:
                        return False
                return False
            else:
                return False
        except Exception as e:
            print(str(e))
            return False

    @staticmethod
    def map_api_paste_key_to_user(userName, filePath, fileName, api_paste_key, iv):
        print("Mapping to user")

    @staticmethod
    def get_file_api_key_and_iv(userName, filePath):
        print("Getting api key to user")

    @staticmethod
    def delete_file_from_db(api_paste_key):
        # delete the key from DB
        return True

    @staticmethod
    def update_deletefile_for_user_in_db(userName, filePath):
        # remove the json object for filepath and update user object
        return True

    @classmethod
    def is_directory(cls, filename: str) -> bool:
        split_list = str(filename).split('.')
        if len(split_list) == 1:
            return True
        elif len(split_list) > 1:
            ext = split_list[-1]
            if len(ext) == 0:
                return True
            else:
                return False

    def getFilesList(self, directory, path):
        keys = directory.keys()
        for key in keys:
            if self.is_directory(key):
                sub_dir = directory.get(key)
                path = path + key + '/'
                self.registry.update({path: {}})
                self.getFilesList(sub_dir, path)
            else:
                fileObject = directory.get(key)
                filePath = path + key
                self.registry.update({filePath: {'key': fileObject.get('api_paste_key'), 'iv': fileObject.get('iv')}})

    def get_root_directory_structure(self, user_name: str):
        db_object = DatabaseQueries()
        user = db_object.search_user(search_field=user_name)
        rootDir = user[0]['root']
        self.getFilesList(rootDir, '/')
        return self.registry
