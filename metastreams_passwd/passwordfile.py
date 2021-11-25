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

from autotest import test

@test
def test_addUser(tmp_path):
    pwd = PasswordFile(tmp_path / 'pwd')
    pwd.addUser(username='John', password='password')
    test.truth(pwd.validateUser('John', 'password'))
    # reopen file.
    pwd2 = PasswordFile(tmp_path / 'pwd')
    test.truth(pwd2.validateUser('John', 'password'))

@test
def test_validPassword(tmp_path):
    pwd = PasswordFile(tmp_path / 'pwd')
    pwd.addUser(username='John', password='password')
    test.not_(pwd.validateUser(username='John', password=''))
    test.not_(pwd.validateUser(username='John', password=' '))
    test.not_(pwd.validateUser(username='John', password='abc'))
    test.truth(pwd.validateUser(username='John', password='password'))
    test.not_(pwd.validateUser(username='John', password='password '))

    test.not_(pwd.validateUser(username='', password=''))
    test.not_(pwd.validateUser(username='Piet', password=''))

@test
def test_setPassword(tmp_path):
    pwd = PasswordFile(tmp_path / 'pwd')
    pwd.addUser(username='John', password='password')
    pwd.setPassword(username='John', password='newpasswd')
    test.truth(pwd.validateUser(username='John', password='newpasswd'))

@test
def test_setPasswordWithBadUsername(tmp_path):
    pwd = PasswordFile(tmp_path / 'pwd')
    with test.raises(ValueError):
        pwd.setPassword(username='Harry', password='newpasswd')

@test
def test_addUserWithBadPassword(tmp_path):
    pwd = PasswordFile(tmp_path / 'pwd')
    # Checking was done by meresco.html.password file, not anymore
    pwd.addUser(username='Harry', password='')
    test.eq(['Harry'], pwd.listUsernames())

@test
def test_addUserWithBadname(tmp_path):
    pwd = PasswordFile(tmp_path / 'pwd')
    # Checking was done by meresco.html.password file, not anymore
    pwd.addUser(username='', password='pwd')
    test.eq([''], pwd.listUsernames())

@test
def test_addExistingUser(tmp_path):
    pwd = PasswordFile(tmp_path / 'pwd')
    pwd.addUser(username='John', password='password')
    with test.raises(ValueError):
        pwd.addUser(username='John', password='good')

@test
def test_removeUser(tmp_path):
    pwd = PasswordFile(tmp_path / 'pwd')
    pwd.addUser(username='John', password='password')
    test.truth(pwd.validateUser('John', 'password'))
    pwd.removeUser(username='John')
    test.not_(pwd.validateUser('John', 'password'))

@test
def test_listUsernames(tmp_path):
    pwd = PasswordFile(tmp_path / 'pwd')
    pwd.addUser(username='john', password='password')
    pwd.addUser(username='graham', password='password2')
    pwd.addUser(username='hank', password='password3')
    test.eq(set(['hank', 'graham', 'john']), set(pwd.listUsernames()))

@test
def test_hasUser(tmp_path):
    pwd = PasswordFile(tmp_path / 'pwd')
    pwd.addUser(username='john', password='password')
    test.truth(pwd.hasUser(username='john'))
    test.not_(pwd.hasUser(username='johnny'))

@test
def test_rehashIfNecessary(tmp_path):
    pwd = PasswordFile(tmp_path / 'pwd')
    pwd.addUser(username='one', password='secret')
    myPh = PasswordHasher(parallelism=2, memory_cost=2048)
    hashed2 = myPh.hash('secret2')
    with (tmp_path / 'pwd').open() as f:
        data = json.load(f)
    data['users']['two'] = hashed2
    hashed1 = data['users']['one']
    with (tmp_path / 'pwd').open('w') as f:
        json.dump(data, f)
    test.truth(pwd.validateUser('two', 'secret2'))
    test.truth(pwd.validateUser('one', 'secret'))
    with (tmp_path / 'pwd').open() as f:
        data = json.load(f)
    test.eq(hashed1, data['users']['one'])
    test.ne(hashed2, data['users']['two'])
    test.truth(pwd.validateUser('two', 'secret2'))

@test
def test_conversionNeeded(tmp_path):
    with (tmp_path / 'pwd').open('w') as f:
        json.dump(dict(version=2,users={}), f)
    with test.raises(ValueError):
        PasswordFile(tmp_path / 'pwd')
