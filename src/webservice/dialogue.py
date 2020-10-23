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
from dgep import Dialogue as DGEPDialogue
from .protocol import Protocol
import uuid
import os
import pymongo

@ws.group
class Dialogue:

    """Create and manage dialogues"""

    def __init__(self):
        self.mongo = os.getenv("MONGO")

    @ws.method("/new/<protocol>",methods=["POST"])
    def new(self, protocol):
        """
        @/app/docs/dialogue/new.yml
        """

        login = ws.authorise()

        if login is not None:
            data = ws.request.get_json(force=True)
            dgdl = Protocol().get_protocol(protocol)

            if dgdl is not None:
                d = DGEPDialogue()
                response = d.new_dialogue(dgdl, **data)

                if "error" not in response:
                    response, result = self.save_dialogue(d, login["username"])

                    if response == "error" and result == "owner":
                        return ws._401()

                    return {"dialogueID": result, "moves": d.get_available_moves()}, 200
                else:
                    return response, 500
            else:
                return "Protocol not found", 404

            return response
        else:
            return ws._401()

    @ws.method("/<dialogueID>/moves",methods=["GET"])
    def moves(self, dialogueID):
        """
        @/app/docs/dialogue/moves.yml
        """
        login = ws.authorise()

        if login is not None:
            status, d = self.load_dialogue(dialogueID, login["username"])

            if status == "ok":
                return d.get_available_moves(), 200
            elif status == "error":
                if d == "owner":
                    return ws._401()
                else:
                    return d, 404
        else:
            return ws._401()

    @ws.method("/<dialogueID>/interaction/<interactionID>",methods=["POST"])
    def interaction(self, dialogueID, interactionID):
        """
        @/app/docs/dialogue/interaction.yml
        """
        login = ws.authorise()

        if login is not None:
            status, d = self.load_dialogue(dialogueID, login["username"])

            if status == "ok":
                data = ws.request.get_json(force=True)
                result = d.perform_interaction(interactionID, **data)
                self.save_dialogue(d, login["username"], dialogueID)
                return result, 200
            elif status == "error":
                if d == "owner":
                    return ws._401()
                else:
                    return d, 404
        else:
            return ws._401()

        return "DialogueID: {}; interactionID: {}".format(dialogueID,interactionID)

    @ws.method("/<dialogueID>/status",methods=["GET"])
    def status(self, dialogueID):
        """
        @/app/docs/dialogue/status.yml
        """
        login = ws.authorise()

        if login is not None:
            status, d = self.load_dialogue(dialogueID, login["username"])

            if status == "ok":
                return d.save(), 200
            elif status == "error":
                if d == "owner":
                    return ws._401()
                else:
                    return d, 404
        else:
            return ws._401()

    def save_dialogue(self, dialogue, owner, dialogueID=None):
        """
        Save the dialogue with the given ID, or insert a new dialogue
        if no or an unmatched ID is provided
        """

        mongo = pymongo.MongoClient("mongodb://" + self.mongo + ":27017/")
        db = mongo["dgep"]
        dialogues = db["dialogues"]

        if dialogueID is None:
            dialogueID = str(uuid.uuid4())
            query = {"dialogueID": dialogueID}
        else:
            query = {"dialogueID": dialogueID}
            result = dialogues.find_one(query)

            if result is not None:
                if result.get("owner","") != owner:
                    return "error", "owner"

        data = {"dialogueID": dialogueID, "owner": owner, "dialogue": dialogue.save()}
        dialogues.replace_one(query, data, True)

        return "ok", dialogueID


    def load_dialogue(self, dialogueID, user):
        """
        Load the dialogue with the given dialogueID
        """
        mongo = pymongo.MongoClient("mongodb://" + self.mongo + ":27017/")
        db = mongo["dgep"]
        dialogues = db["dialogues"]

        query = {"dialogueID": dialogueID}

        result = dialogues.find_one(query)

        if result is not None:
            if result.get("owner","") != user:
                return "error", "owner"

            return "ok", DGEPDialogue(result.get("dialogue"))
        else:
            return "error", "Dialogue not found"
