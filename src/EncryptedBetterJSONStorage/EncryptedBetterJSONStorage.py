# MIT License

# Copyright (c) 2023 Ankur Grover

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import _thread as Thread
from io import BufferedRandom, BufferedWriter
from pathlib import Path
from typing import Literal, Mapping, Optional, Set, Union

try:
    from blosc2 import compress, decompress
except ImportError as e:
    raise ImportError("Dependencies not satisfied: pip install blosc2") from e

try:
    from orjson import dumps, loads
except ImportError as e:
    raise ImportError("Dependencies not satisfied: pip install orjson") from e

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.hashes import SHA256,Hash
    from cryptography.hazmat.backends import default_backend
except ImportError as e:
    raise ImportError("Dependencies not satisfied: pip install cryptography") from e

class EncryptedBetterJSONStorage:
    """
    A class that represents a storage interface for reading and writing to a file with encryption and compression.


    Attributes
    ----------
    `dbpath: str`
        Path to file, if it does not exist it will be created only if the the 'r+' access mode is set.

    `encryption_key: bytes, Optional`
        These attributes will be passed encryption key to `cryptography.algorithms.AES` if encryption is set to True

    `encryption: bool`
        Set to True if encryption is required
    
    `compression: bool`
        Set to True if compression is required

    `access_mode: str, optional`
        Options are `'r'` for readonly (default), or `'r+'` for writing and reading.

    `kwargs:`
        These attributes will be passed on to `orjson.dumps`

    Methods
    -------
    `read() -> Mapping:`
        Returns the data from memory.

    `write(data: Mapping) -> None:`
        Writes data to file if acces mode is set to `r+`.

    `load() -> None:`
        loads the data from disk. This happens on object creation.
        Can be used when you suspect the data in memory and on disk are not in sync anymore.

    Raises
    ------
    `FileNotFoundError` when the file doesn't exist and `r+` is not set

    Notes
    ----
    If the directory specified in `dbpath` does not exist it will only be created if access_mode is set to `'r+'`.
    """

    __slots__ = (
        "_hash",
        "_access_mode",
        "_dbpath",
        "_data",
        "_kwargs",
        "_changed",
        "_running",
        "_shutdown_lock",
        "_handle",
        "encryption_key",
        "encryption",
        "compression",
    )

    _dbpaths: Set[int] = set()

    def __init__(
        self, dbpath: Path = Path(),encryption_key:Optional[bytes] = None, encryption:bool = False ,compression:bool = False, access_mode: Literal["r", "r+"] = "r", **kwargs
    ):
        # flags
        self._shutdown_lock = Thread.allocate_lock()
        self._running = True
        self._changed = False

        # checks
        self._hash = hash(dbpath)

        # encryption and compression
        if encryption and encryption_key == None:
            raise AttributeError(f'Please provide encryption_key if encryption is set to True')

        self.encryption = encryption
        self.compression = compression
        if self.encryption:
            self.raw_encryption_key = encryption_key
            self._nonce = b"authenticated but unencrypted data"
            self._cipher = Cipher(algorithms.AES(self.raw_encryption_key),modes.GCM(self._nonce),backend=default_backend())
            self.encryptor = self._cipher.encryptor()
            self.decryptor = self._cipher.decryptor()

        self._handle: Optional[Union[BufferedWriter, BufferedRandom]] = None
        if access_mode not in {"r", "r+"}:
            self.close()
            raise AttributeError(
                f'access_mode is not one of ("r", "r+"), :{access_mode}'
            )

        if not isinstance(dbpath, Path):
            self.close()
            raise TypeError("path is not an instance of pathlib.Path")

        if not dbpath.exists():
            if access_mode == "r":
                self.close()
                raise FileNotFoundError(
                    f"""File can't be found, use access_mode='r+' if you wan to create it.
                        dbpath: <{dbpath.absolute()}>,
                        """
                )
            dbpath.parent.mkdir(parents=True, exist_ok=True)
            self._handle = dbpath.open("wb+")
        if not dbpath.is_file():
            self.close()
            raise FileNotFoundError(
                f"""path does not lead to a file: <{dbpath.absolute()}>."""
            )
        else:
            self._handle = dbpath.open("rb+")

        self._access_mode = access_mode
        self._dbpath = dbpath

        # rest
        self._kwargs = kwargs
        self._data: Optional[Mapping]

        # finishing init
        self.load()
        # only start the file write at all if the access mode is not read only
        if access_mode == "r+":
            Thread.start_new_thread(self.__file_writer, ())

    def __new__(cls, dbpath, *args, **kwargs):
        h = hash(dbpath)
        if h in cls._dbpaths:
            raise AttributeError(
                f'A EncryptedBetterJSONStorage object already exists with path < "{dbpath}" >'
            )
        cls._dbpaths.add(h)
        return object.__new__(cls)

    def __repr__(self):
        return (
            f"""BetterEncryptedJSONStorage(encryption_key={self.raw_encryption_key}, encryption={self.encryption},compression={self.compression},path={self._path}, Paths={self.__class__._paths})"""
        )

    def read(self):
        return self._data

    def __file_writer(self):
        self._shutdown_lock.acquire()
        while self._running:

            if self._changed:
                self._changed = False
                self._handle.seek(0)
                if self.compression and self.encryption:
                    self._handle.write(self.encryptor.update(compress(dumps(self._data))))
                elif self.encryption:
                    self._handle.write(self.encryptor.update(dumps(self._data)))
                elif self.compression:
                    self._handle.write(compress(dumps(self._data)))
                else :
                    self._handle.write(dumps(self._data))

        self._shutdown_lock.release()

    def write(self, data: Mapping):
        if self._access_mode != "r+":
            raise PermissionError("Storage is openend as read only")
        self._data = data
        self._changed = True

    def load(self) -> None:
        if len(db_bytes := self._dbpath.read_bytes()):
            if self.compression and self.encryption:
                self._data = loads(decompress(self.decryptor.update(db_bytes)))
            elif self.encryption:
                self._data = loads(self.decryptor.update(db_bytes))
            elif self.compression:
                self._data = loads(decompress(db_bytes))
            else :
                self._data = loads(db_bytes)
        else:
            self._data = None

    def close(self):
        while self._changed:
            ...
        self._running = False
        self._shutdown_lock.acquire()
        if self._handle != None:
            self._handle.flush()
            self._handle.close()
        self.__class__._dbpaths.discard(self._hash)
