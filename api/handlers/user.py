from tornado.web import authenticated

from .auth import AuthHandler
from cryptography.fernet import Fernet

class UserHandler(AuthHandler):

    @authenticated
    def get(self):
        key = b'0IcycjHWWQSjB8PjnTFlgjLCwLQqjA3u7MrDGhyrKlA='
        f = Fernet(key)
        
        self.set_status(200)
        self.response['email'] = self.current_user['email']
        #self.response['password'] = self.current_user['password']
        self.response['fullName'] = f.decrypt(self.current_user['fullName']).decode()
        self.response['address'] = f.decrypt(self.current_user['address']).decode()
        self.response['dateOfBirth'] = f.decrypt(self.current_user['dateOfBirth']).decode()
        self.response['phoneNumber'] = f.decrypt(self.current_user['phoneNumber']).decode()
        self.response['disabilities'] = f.decrypt(self.current_user['disabilities']).decode()
        self.response['displayName'] = self.current_user['display_name']
        self.write_json()
