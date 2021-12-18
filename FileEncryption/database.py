from tinydb import TinyDB, Query
import json


class DatabaseQueries(object):

    def __init__(self):
        db = TinyDB('db.json')

        self.User = Query()

        self.users = db.table('Users')

    @staticmethod
    def extract_data(data: dict):
        filepath = data['filepath']
        api_paste_key = data['api_paste_key']
        iv_value = data['iv']
        access_level = data['access_level']
        return filepath, api_paste_key, iv_value, access_level

    def perform_update(self, obj, username: str):
        try:
            self.users.update(obj[0], self.User.username == username)
            return True, None
        except Exception as e:
            return False, str(e)

    def getUsers(self):
        return self.users.all()

    def insert_user(self, data: json):
        from .utils import Utils
        utils = Utils()
        json_obj = utils.build_json(data)
        if len(json_obj) == 0:
            return False, "Invalid username"
        results = self.search_user(data['username'])
        if len(results) != 0:
            return False, "User already exist with that username !!"
        try:
            self.users.insert(json_obj)
            return True, self.users.all()
        except Exception as e:
            return False, str(e)

    def search_user(self, search_field: str) -> list:
        try:
            results = self.users.search(self.User.username == search_field)
        except Exception as e:
            raise e
        if len(results) > 1:
            return []
        return results

    def update_user(self, update_fields: dict, search_field: str):
        try:
            user_object = self.search_user(search_field=search_field)
            root_dir = user_object[0].get('root')
            filepath, api_paste_key, iv_value, access_level = self.extract_data(update_fields)
            root_dir[filepath] = {'api_paste_key': api_paste_key, 'iv': iv_value, 'access_level': access_level}
            user_object[0]['root'] = root_dir
            # self.users.update(user_object[0], self.User.username == search_field)
            flag, message = self.perform_update(obj=user_object, username=search_field)
            if flag:
                return True, "Updated Successfully !!"
            else:
                return False, message
        except Exception as e:
            return False, str(e)

    def delete_user(self, username: str):
        try:
            self.users.remove(self.User.username == username)
        except Exception as e:
            return False, str(e)

        return True, "Record Deleted !!"
