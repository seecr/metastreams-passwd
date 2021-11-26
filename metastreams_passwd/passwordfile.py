## begin license ##
#
# "Metastreams Passwd" is a module for storing passwords using Argon2
#
# Copyright (C) 2021 Seecr (Seek You Too B.V.) https://seecr.nl
#
# This file is part of "Metastreams Passwd"
#
# "Metastreams Passwd" is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# "Metastreams Passwd" is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with "Metastreams Passwd".  If not, see <http://www.gnu.org/licenses/>.
#
## end license ##

import json
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash
from os import chmod, rename
from os.path import isfile
from stat import S_IWRITE, S_IREAD

ph = PasswordHasher()

class PasswordFile(object):
    def __init__(self, filepath):
        self._storage = _Storage(filepath)

    def addUser(self, username, password):
        if self.hasUser(username):
            raise ValueError('User already exists.')
        self._storage.set(username, ph.hash(password))

    def removeUser(self, username):
        self._storage.remove(username)

    def validateUser(self, username, password):
        hashed = self._storage.get(username)
        try:
            result = hashed is not None and ph.verify(hashed, password)
            if result and ph.check_needs_rehash(hashed):
                self.setPassword(username, password)
            return result
        except VerifyMismatchError:
            return False
        except InvalidHash:
            raise ValueError(f'Unexpected hash for user {username}, check file!')

    def setPassword(self, username, password):
        if not self.hasUser(username):
            raise ValueError('User does not exist.')
        self._storage.set(username, ph.hash(password))

    def listUsernames(self):
        return self._storage.listkeys()

    def hasUser(self, username):
        return username in self._storage.listkeys()

class _Storage(object):
    version = 3
    def __init__(self, filepath):
        self._filepath = str(filepath)
        self._loadUsers()

    def set(self, username, hashed):
        d = self._loadUsers()
        d[username] = hashed
        self._storeUsers(d)

    def remove(self, username):
        d = self._loadUsers()
        d.pop(username, None)
        self._storeUsers(d)

    def get(self, username):
        return self._loadUsers().get(username)

    def listkeys(self):
        return list(sorted(self._loadUsers().keys()))

    def _loadUsers(self):
        if not isfile(self._filepath):
            return {}
        with open(self._filepath, 'r') as fp:
            data = json.load(fp)
            if not data.get('version') == self.version:
                raise ValueError("Unexpected version")
            return data['users']

    def _storeUsers(self, users):
        if not isfile(self._filepath):
            with open(self._filepath, 'w') as fp:
                json.dump({'version': self.version, 'users':{}}, fp)
        with open(self._filepath, 'r') as fp:
            data = json.load(fp)
            data['users'] = users
            with open(self._filepath+'~', 'w') as wfp:
                json.dump(data, wfp)
        rename(self._filepath+'~', self._filepath)
        chmod(self._filepath, S_IREAD | S_IWRITE)

__all__ = ['PasswordFile']
