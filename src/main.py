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
from webservice import *

description = 'DGEP is a platform for dialogue games'

swagger = {
    "info":{
        "license": {
            "name": "GNU Lesser General Public License v3.0",
            "url": "https://www.gnu.org/licenses/lgpl-3.0.en.html"
        },
        "contact":{
            "email":"mark@arg.tech"
        }
    }
}


app = ws.build(title="Dialogue Game Execution Platform", description=description, **swagger)
