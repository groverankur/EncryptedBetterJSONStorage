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
import warnings
from io import BufferedRandom, BufferedWriter, UnsupportedOperation
from os import SEEK_END, fsync, remove
from typing import Literal, Mapping, Optional, Union

from tinydb.storages import Storage, touch

try:
    from blosc2 import compress, decompress
except ImportError as e:
    raise ImportError("Dependencies not satisfied: pip install blosc2") from e

try:
    from orjson import dumps, loads
except ImportError as e:
    raise ImportError("Dependencies not satisfied: pip install orjson") from e

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.hashes import SHA256, Hash
except ImportError as e:
    raise ImportError("Dependencies not satisfied: pip install cryptography") from e


class BetterEncryptedJSONStorage(Storage):
    """
    A class that represents a storage interface for reading and writing to a file with encryption and compression

    Attributes
    ----------
    `path: str`
        Path to file, if it does not exist it will be created only if the the 'r+'/'rb+' access mode is set.

    `create_dirs: bool`
        Whether to create all missing parent directories.

    `encoding: str`
        Encoding of the encrypted file

    `access_mode: str, optional`
        Options are `'r' or 'rb'` for readonly (default), or `'r' or 'rb+'` for writing and reading.if encryption is set, access mode need to either `rb or rb+`

    `encryption_key: bytes, Optional`
        These attributes will be passed encryption key to `cryptography.algorithms.AES` if encryption is set to True

    `encryption: bool`
        Set to True if encryption is required

    `compression: bool`
        Set to True if compression is required

    `kwargs:`
        These attributes will be passed on to `orjson.dumps`

    Methods
    -------
    `read() -> Mapping:`
        Returns the data from memory.

    `write(data: Mapping) -> None:`
        Writes data to file if acces mode is set either  to `r+` or `rb+`.

    `load() -> None:`
        loads the data from disk. This happens on object creation.
        Can be used when you suspect the data in memory and on disk are not in sync anymore.

    Raises
    ------
    `FileNotFoundError` when the file doesn't exist and `r+` is not set

    Notes
    ----
    If the directory specified in `path` does not exist it will only be created if access_mode is set either to `rb or rb+`.
    """

    def __init__(
        self,
        path: str,
        create_dirs=False,
        encoding=None,
        encryption_key: Optional[bytes] = None,
        encryption: bool = False,
        compression: bool = False,
        access_mode: Literal["r", "rb", "r+", "rb+"] = "r",
        **kwargs,
    ):
        """
        Create a new instance.

        Also creates the storage file, if it doesn't exist and the access mode
        is appropriate for writing.
        Parsing, compressing,encryption and writing to the file is done by a seperate thread so reads don't get blocked by slow fileIO.

        Note: Using an access mode other than `r` or `r+` or `rb` or `rb+` will probably lead to data loss or data corruption!

        :param path: Where to store the JSON data.
        :param create_dirs: Whether to create all missing parent directories.
        :param encoding: encoding of the encrypted file.
        :param encryption_key: The encryption / decryption key
        :param encryption: Whether encryption is required
        :param compression: Whether compression is required
        :param access_mode: mode in which the file is opened (r, r+, rb, rb+)
        :type access_mode: str
        """

        super().__init__()

        # flags
        self._shutdown_lock = Thread.allocate_lock()
        self._running = True
        self._changed = False

        # encryption and compression
        if encryption and encryption_key == None:
            raise AttributeError(
                "Please provide encryption_key if encryption is set to True"
            )

        self.encryption = encryption
        self.compression = compression
        if self.encryption:
            self.raw_encryption_key = self.__reset_hash(encryption_key)
            self._nonce = b"authenticated but unencrypted data"
            self._cipher = Cipher(
                algorithms.AES(self.raw_encryption_key),
                modes.GCM(self._nonce),
                backend=default_backend(),
            )
            self.encryptor = self._cipher.encryptor()
            self.decryptor = self._cipher.decryptor()

        self._mode = access_mode
        self.kwargs = kwargs
        self._data: Optional[Mapping] = None
        self._handle: Optional[Union[BufferedWriter, BufferedRandom]] = None
        self._path = path
        self.encoding = encoding
        self._create_dirs = create_dirs

        if self._mode not in ("r", "rb", "r+", "rb+"):
            self.close()
            warnings.warn(
                "Using an `access_mode` other than 'r', 'rb', 'r+' or 'rb+' can cause data loss or corruption"
            )

        # Create the file if it doesn't exist and creating is allowed by the access mode
        if any(
            [character in self._mode for character in ("+", "w", "a")]
        ):  # any of the writing modes
            touch(self._path, create_dirs=self._create_dirs)

        # Open the file for reading/writing
        self.__reset_handle()

        # finishing init
        self.load()
        # only start the file write at all if the access mode is not read only
        if self._mode in ["r+", "rb+"]:
            Thread.start_new_thread(self.__file_writer, ())

    def __repr__(self):
        return f"""BetterEncryptedJSONStorage(path={self._path},create_dirs={self._create_dirs},encoding={self.encoding},encryption_key={self.raw_encryption_key}, encryption={self.encryption},compression={self.compression},access_mode={self._mode})"""

    def close(self) -> None:
        while self._changed:
            ...
        self._running = False
        self._shutdown_lock.acquire()
        if self._handle is not None:
            self._handle.flush()
            self._handle.close()

    def read(self) -> Optional[Mapping]:
        return self._data

    def load(self) -> None:
        # Get the file size by moving the cursor to the file end and reading
        # its location
        self._handle.seek(0, SEEK_END)
        size = self._handle.tell()

        if not size:
            # File is empty, so we return ``None`` so TinyDB can properly
            # initialize the database
            return None
        else:
            # Return the cursor to the beginning of the file
            self._handle.seek(0)

            # Load the JSON contents of the file
            if len(db_bytes := self._handle.read()):
                self._data = loads(
                    decompress(self.decryptor.update(db_bytes))
                    if self.compression and self.encryption
                    else self.decryptor.update(db_bytes)
                    if self.encryption
                    else decompress(db_bytes)
                    if self.compression
                    else db_bytes,
                    **self.kwargs,
                )
            else:
                self._data = None

    def __file_writer(self):
        self._shutdown_lock.acquire()
        while self._running:
            if self._changed:
                self._changed = False
                # Move the cursor to the beginning of the file just in case
                self._handle.seek(0)
                # Serialize the database state using the user-provided arguments
                serialized = (
                    self.encryptor.update(compress(dumps(self._data, **self.kwargs)))
                    if self.compression and self.encryption
                    else self.encryptor.update(dumps(self._data, **self.kwargs))
                    if self.encryption
                    else compress(dumps(self._data, **self.kwargs))
                    if self.compression
                    else dumps(self._data, **self.kwargs)
                )
                # Write the serialized data to the file
                try:
                    self._handle.write(serialized)
                except UnsupportedOperation as exc:
                    raise IOError(
                        f'Cannot write to the database. Access mode is "{0}"'.format(
                            self._mode
                        )
                    ) from exc

                # Ensure the file has been written
                self._handle.flush()
                fsync(self._handle.fileno())
                # Remove data that is behind the new cursor in case the file has gotten shorter
                self._handle.truncate()

        self._shutdown_lock.release()

    def write(self, data: Mapping):
        if self._mode not in ["r+", "rb+"]:
            raise PermissionError("Storage is openend as read only")
        self._data = data
        self._changed = True

    def __reset_handle(self):
        """
        Open/Reopens the file handle with (potentially a new key)
        """
        self._handle = open(self._path, mode=self._mode, encoding=self.encoding)

    def __reset_hash(self, key):
        h = Hash(SHA256, default_backend)
        h.update(key)
        return h.finalize()

    def change_encryption_key(self, new_encryption_key):
        """
        Changes the encryption key of the storage to the new encryption key. Can be called via db.storage.change_encryption_key(...).
        :param new_encryption_key: A string that contains the new encryption key.
        """
        from shutil import copyfile
        from sys import exc_info

        from tinydb import TinyDB

        new_db_path = self._path + "_clone"
        new_encryption_key = self.__reset_hash(new_encryption_key)

        try:
            db_new_pw = TinyDB(
                encryption_key=new_encryption_key,
                path=new_db_path,
                storage=BetterEncryptedJSONStorage,
            )
        except:
            print("Failed opening database with new password, aborting.", exc_info()[0])
            print("Error: ", exc_info()[1])
            return False

        try:
            # copy from old to new
            self._handle.flush()
            db_new_pw.storage.write(self.read())
            self.close()
            db_new_pw.close()

            # copy new over old
            copyfile(new_db_path, self.path)

            # reset encryption handle
            self.raw_encryption_key = new_encryption_key
            self.__reset_handle()

            success = True
        except:
            print("could not write database: ", exc_info()[0])
            print("Error: ", exc_info()[1])
            success = False
        finally:
            remove(new_db_path)
        return success
