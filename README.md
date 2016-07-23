# proxy-toggle
A command-line tool to run programs seamlessly behind a proxy.

## Introduction

Many corporate networks use proxies both for network protection and to cache often-used content. This command-line tool allows its users to run programs behind a corporate proxy without the need to constantly set/unset proxy environment variables. It sets the environment variables only when needed and unsets them whenever the program finished its execution.

## Installation

To use proxy-toggle:

```
$ pip install proxy-toggle
```
Head over to [pip-installer](<http://www.pip-installer.org/en/latest/index.html) for instructions on installing pip.

To run from source, you can [download the source code](https://github.com/beylsp/proxy-toggle) for proxy-toggle, and then run:

```
$ python setup.py install
```

## Usage

Before you can start using proxy-toggle, you must initialize the application:

```
$ px --init
```

This will prompt for your proxy settings: proxy server URL and user account/password. A secure keyring (to encrypt the password) will be generated. This might take a while.

After successful initialization, run:

```
$ px <program>
```

If your proxy does not require user authentication, run:

```
$ px --nouser <program>
```

## Examples

```
$ px git clone https://github.com/beylsp/proxy-toggle

$ px --nouser wget http://github.com/beylsp/archive/master.zip
```
