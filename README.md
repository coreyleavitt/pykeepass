# pykeepass

<a href="https://github.com/coreyleavitt/pykeepass/actions/workflows/ci.yaml"><img src="https://github.com/coreyleavitt/pykeepass/actions/workflows/ci.yaml/badge.svg"/></a>
<a href="https://coreyleavitt.github.io/pykeepass"><img src="https://img.shields.io/badge/docs-pdoc-blue"/></a>

This library allows you to read and write KeePass databases (KDBX3 and KDBX4 formats).

# Installation

Requires Python 3.11+

``` bash
pip install pykeepass
```

On Debian/Ubuntu, you may need to install lxml dependencies first:

``` bash
sudo apt install libxml2-dev libxmlsec1-dev
pip install pykeepass
```

# Quickstart

## Creating a Database

``` python
from pykeepass import create_database

# create a new KDBX4 database with default settings (Argon2id, AES-256)
>>> kp = create_database('new.kdbx', password='somePassw0rd')

# create with a keyfile
>>> kp = create_database('new.kdbx', password='somePassw0rd', keyfile='key.key')

# create a KDBX3 database
>>> kp = create_database('new.kdbx', password='somePassw0rd', version=3)
```

### Cipher and KDF Options

``` python
from pykeepass import create_database
from pykeepass.kdbx_parsing import Cipher, Argon2Config, AesKdfConfig

# KDBX4 with ChaCha20 cipher and custom Argon2 settings
>>> kp = create_database(
...     'new.kdbx',
...     password='somePassw0rd',
...     cipher=Cipher.chacha20,
...     kdf=Argon2Config(iterations=5, memory=131072, parallelism=4, variant='id'),
... )

# use preset configurations
>>> kp = create_database('new.kdbx', password='pw', kdf=Argon2Config.high_security())
>>> kp = create_database('new.kdbx', password='pw', kdf=Argon2Config.fast())

# KDBX3 with Twofish cipher and custom AES-KDF rounds
>>> kp = create_database(
...     'new.kdbx',
...     password='somePassw0rd',
...     version=3,
...     cipher=Cipher.twofish,
...     kdf=AesKdfConfig(rounds=100000),
... )
```

Available ciphers: `aes256`, `chacha20`, `twofish`

Available Argon2 variants (KDBX4): `id`, `d`, `i`

## Opening and Manipulating Databases

``` python
from pykeepass import PyKeePass

# load database
>>> kp = PyKeePass('db.kdbx', password='somePassw0rd')

# get all entries
>>> kp.entries
[Entry: "foo_entry (myusername)", Entry: "foobar_entry (myusername)", ...]

# find any group by its name
>>> group = kp.find_groups(name='social', first=True)

# get the entries in a group
>>> group.entries
[Entry: "social/facebook (myusername)", Entry: "social/twitter (myusername)"]

# find any entry by its title
>>> entry = kp.find_entries(title='facebook', first=True)

# retrieve the associated password and OTP information
>>> entry.password
's3cure_p455w0rd'
>>> entry.otp
otpauth://totp/test:lkj?secret=TEST%3D%3D%3D%3D&period=30&digits=6&issuer=test

# update an entry
>>> entry.notes = 'primary facebook account'

# create a new group
>>> group = kp.add_group(kp.root_group, 'email')

# create a new entry
>>> kp.add_entry(group, 'gmail', 'myusername', 'myPassw0rdXX')
Entry: "email/gmail (myusername)"

# save database
>>> kp.save()
```

## Finding and Manipulating Entries

``` python
# add a new entry to the Root group
>>> kp.add_entry(kp.root_group, 'testing', 'foo_user', 'passw0rd')
Entry: "testing (foo_user)"

# add a new entry to the social group
>>> group = kp.find_groups(name='social', first=True)
>>> entry = kp.add_entry(group, 'testing', 'foo_user', 'passw0rd')
Entry: "testing (foo_user)"

# save the database
>>> kp.save()

# delete an entry
>>> kp.delete_entry(entry)

# move an entry
>>> kp.move_entry(entry, kp.root_group)

# save the database
>>> kp.save()

# change creation time
>>> from datetime import datetime, timezone
>>> entry.ctime = datetime(2023, 1, 1, tzinfo=timezone.utc)

# update modification or access time
>>> entry.touch(modify=True)

# save entry history
>>> entry.save_history()
```

## Finding and Manipulating Groups

``` python
>>> kp.groups
[Group: "foo", Group "foobar", Group: "social", Group: "social/foo_subgroup"]

>>> kp.find_groups(name='foo', first=True)
Group: "foo"

>>> kp.find_groups(name='foo.*', regex=True)
[Group: "foo", Group "foobar"]

>>> kp.find_groups(path=['social'], regex=True)
[Group: "social", Group: "social/foo_subgroup"]

>>> kp.find_groups(name='social', first=True).subgroups
[Group: "social/foo_subgroup"]

>>> kp.root_group
Group: "/"

# add a new group to the Root group
>>> group = kp.add_group(kp.root_group, 'social')

# add a new group to the social group
>>> group2 = kp.add_group(group, 'gmail')
Group: "social/gmail"

# save the database
>>> kp.save()

# delete a group
>>> kp.delete_group(group)

# move a group
>>> kp.move_group(group2, kp.root_group)

# save the database
>>> kp.save()

# change creation time
>>> from datetime import datetime, timezone
>>> group.ctime = datetime(2023, 1, 1, tzinfo=timezone.utc)

# update modification or access time
>>> group.touch(modify=True)
```

## Attachments

``` python
>>> e = kp.add_entry(kp.root_group, title='foo', username='', password='')

# add attachment data to the db
>>> binary_id = kp.add_binary(b'Hello world')

>>> kp.binaries
[b'Hello world']

# add attachment reference to entry
>>> a = e.add_attachment(binary_id, 'hello.txt')
>>> a
Attachment: 'hello.txt' -> 0

# access attachments
>>> a
Attachment: 'hello.txt' -> 0
>>> a.id
0
>>> a.filename
'hello.txt'
>>> a.data
b'Hello world'
>>> e.attachments
[Attachment: 'hello.txt' -> 0]

# list all attachments in the database
>>> kp.attachments
[Attachment: 'hello.txt' -> 0]

# search attachments
>>> kp.find_attachments(filename='hello.txt')
[Attachment: 'hello.txt' -> 0]

# delete attachment reference
>>> e.delete_attachment(a)

# or, delete both attachment reference and binary
>>> kp.delete_binary(binary_id)
```

## OTP Codes

``` python
# find an entry which has otp attribute
>>> e = kp.find_entries(otp='.*', regex=True, first=True)
>>> import pyotp
>>> pyotp.parse_uri(e.otp).now()
799270
```

## Modifying KDF Parameters

You can adjust key derivation function parameters on an existing database:

``` python
# KDBX4: Argon2 parameters
>>> kp.argon2_iterations = 10
>>> kp.argon2_memory = 131072  # in KB
>>> kp.argon2_parallelism = 4
>>> kp.argon2_variant = 'id'  # 'id', 'd', or 'i'

# KDBX3: AES-KDF rounds
>>> kp.transform_rounds = 100000

# changes take effect on next save()
>>> kp.save()
```

Note: Changing KDF parameters requires re-encrypting the database with the new settings.


# Tests and Debugging

Run tests with pytest:

``` bash
pytest tests/ -v
pytest tests/ -v -k 'SomeSpecificTest'
```

Enable debugging when doing tests in console:

``` python
>>> from pykeepass.pykeepass import debug_setup
>>> debug_setup()
>>> kp.entries[0]
DEBUG:pykeepass.pykeepass:xpath query: //Entry
DEBUG:pykeepass.pykeepass:xpath query: (ancestor::Group)[last()]
DEBUG:pykeepass.pykeepass:xpath query: (ancestor::Group)[last()]
DEBUG:pykeepass.pykeepass:xpath query: String/Key[text()="Title"]/../Value
DEBUG:pykeepass.pykeepass:xpath query: String/Key[text()="UserName"]/../Value
Entry: "root_entry (foobar_user)"
```

