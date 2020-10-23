"""
Copyright (C) 2020  Centre for Argument Technology (http://arg.tech)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

from argtech import ws
import random
import hashlib
import pymongo
import os

@ws.group
class Auth:

    """Handles authentication for DGEP"""

    def __init__(self):
        self.mongo = pymongo.MongoClient("mongodb://" + str(os.getenv("MONGO")) + ":27017/")

    @ws.method("/login",methods=["POST"])
    def login(self):
        """
        @/app/docs/auth/login.yml
        """

        return ws.login(self.check_credentials)

    def check_credentials(self, username, password):
        db = self.mongo["dgep"]
        users = db["users"]

        result = users.find_one({"username":username})

        if not result:
            return None

        hashed, salt = self.hash(username, password, result["salt"])

        if hashed != result["password"]:
            return None

        return {"username": username}

    def hash(self, username, password, salt=None):
        if salt is None:
            ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
            chars = []

            for i in range(16):
                chars.append(random.choice(ALPHABET))

            salt = "".join(chars)

        return hashlib.sha224(str(username + password + salt).encode("utf-8")).hexdigest(), salt

    @ws.method("/register",methods=["POST"])
    def register(self):
        """
        @/app/docs/auth/register.yml
        """

        details = ws.request.get_json(force=True)

        if "username" not in details or "password" not in details:
            return "No username and/or password provided", 400

        username = details["username"]

        db = self.mongo["dgep"]
        users = db["users"]

        result = users.find_one({"username": username})

        if result is not None:
            return "User already exists", 403

        password, salt = self.hash(username, details["password"])

        obj = {"username": username, "password": password, "salt": salt}
        users.insert_one(obj)

        return "Success", 200
