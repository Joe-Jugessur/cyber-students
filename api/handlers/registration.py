from json import dumps
from logging import info
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from cryptography.fernet import Fernet
from .base import BaseHandler
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
#from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class RegistrationHandler(BaseHandler):

    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            if not isinstance(email, str):
                raise Exception()
            password = body['password']
            if not isinstance(password, str):
                raise Exception()  
            full_name = body['fullName']
            if not isinstance(full_name, str):
                raise Exception()
            address = body['address']
            if not isinstance(address, str):
                raise Exception()
            date_of_birth = body['dateOfBirth']
            if not isinstance(date_of_birth, str):
                raise Exception()
            phone_number = body['phoneNumber']
            if not isinstance(phone_number, str):
                raise Exception()
            disabilities = body['disabilities']
            if not isinstance(disabilities, str):
                raise Exception()       
            display_name = body.get('displayName')
            if display_name is None:
                display_name = email
            if not isinstance(display_name, str):
                raise Exception()
        except Exception as e:
            self.send_error(400, message='You must provide an email address, password and display name!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return
        
        if not password:
            self.send_error(400, message='The password is invalid!')
            return
        
        if not full_name:
            self.send_error(400, message='The display name is invalid!')
            return
        
        if not address:
            self.send_error(400, message='The address is invalid!')
            return
        
        if not date_of_birth:
            self.send_error(400, message='The date of birth is invalid!')
            return
        
        if not phone_number:
            self.send_error(400, message='The phone number is invalid!')
            return
        
        if not disabilities:
            self.send_error(400, message='The disabilities is invalid!')
            return
        
        if not display_name:
            self.send_error(400, message='The display name is invalid!')
            return

        user = yield self.db.users.find_one({
          'email': email
        }, {})

        if user is not None:
            self.send_error(409, message='A user with the given email address already exists!')
            return
        
        salt = os.urandom(16)
        
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
        passphrase_bytes = bytes(password, "utf-8")
        hashed_passphrase = kdf.derive(passphrase_bytes)
        
        key = b'0IcycjHWWQSjB8PjnTFlgjLCwLQqjA3u7MrDGhyrKlA='
        f = Fernet(key)

        
        yield self.db.users.insert_one({
            'email': email,
            'password': hashed_passphrase,
            'fullName': f.encrypt(bytes(full_name, "utf-8")),
            'address': f.encrypt(bytes(address, "utf-8")),
            'dateOfBirth': f.encrypt(bytes(date_of_birth, "utf-8")),
            'phoneNumber': f.encrypt(bytes(phone_number, "utf-8")),
            'disabilities': f.encrypt(bytes(disabilities, "utf-8")),
            'displayName': display_name,
            'salt': salt
        })

        self.set_status(200)
        self.response['email'] = email
        self.response['password'] = password
        self.response['fullName'] = full_name
        self.response['address'] = address
        self.response['dateOfBirth'] = date_of_birth
        self.response['phoneNumber'] = phone_number
        self.response['disabilities'] = disabilities
        self.response['displayName'] = display_name
        

        self.write_json()
