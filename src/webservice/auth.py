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
