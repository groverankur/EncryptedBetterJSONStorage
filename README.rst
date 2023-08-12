.. image:: https://github.com/groverankur/EncryptedBetterJSONStorage/blob/965cbd755a9f1d7c2424c73f2bf659d642c3de67/img/logo.png
    :scale: 100%
    :height: 150px

Introduction
************

.. image:: https://img.shields.io/badge/code%20style-black-000000.svg
    :target: https://github.com/psf/black


EncryptedBetterJSONStorage is a faster 'Storage Type' for TinyDB_  by Adding encryption to BetterJSONStorage_
It uses the faster Orjson_ library for parsing the JSON , BLOSC2_ for compression and cryptography_ for encryption.

Parsing, compressing, and writing to the file is done by a seperate thread so reads don't get blocked by slow fileIO.
Smaller filesizes result in faster reading and writing (less diskIO).
Even Reading is all done from memory.

These optimizations result in much faster reading and writing without loss of functionality.

A goal for the EncryptedBetterJSONStorage project is to provide a drop in replacement for the default JSONStorage with added functionality of encryption and compression.

An example of how to implement EncryptedBetterJSONStorage can be found below.
Anything else can be found in the `TinyDB docs <https://tinydb.readthedocs.io/>`_.

Installing EncryptedBetterJSONStorage
****************************

Install EncryptedBetterJSONStorage as follows

.. code-block:: PowerShell

    python setup.py install

Usage
************

context Manager
===============
.. code-block:: python

    from pathlib import Path
    from tinydb import TinyDB
    from EncryptedBetterJSONStorage import EncryptedBetterJSONStorage

    path = Path('relative/path/to/file.db')

    with TinyDB(path,encryption_key=b"KeY", encryption=True ,compression=True, access_mode="r+", storage=EncryptedBetterJSONStorage) as db:
        db.insert({'int': 1, 'char': 'a'})
        db.insert({'int': 1, 'char': 'b'})

.. _TinyDB: https://github.com/msiemens/tinydb
.. _Orjson: https://github.com/ijl/orjson
.. _BLOSC2: https://github.com/Blosc/python-blosc2
.. _cryptography: https://github.com/pyca/cryptography
.. _BetterJSONStorage :https://github.com/MrPigss/BetterJSONStorage

extra
=====
one difference from TinyDB default JSONStorage is that BetterJSONStorage is ReadOnly by default.
use access_mode='r+' if you want to write as well.

All arguments except for the storage and access_mode argument are forwarded to the underlying storage.
You can use this to pass additional keyword arguments to orjson.dumps(…) method.

For all options see the `orjson documentation <https://github.com/ijl/orjson#option>`_.

.. code-block:: python

    with TinyDB('file.db',encryption_key=b"KeY", encryption=True ,compression=True, option=orjson.OPT_NAIVE_UTC, storage=EncryptedBetterJSONStorage) as db:
