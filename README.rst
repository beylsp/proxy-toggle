************
proxy-toggle
************
.. image:: https://img.shields.io/pypi/v/proxy-toggle.svg
    :target: https://pypi.python.org/pypi/proxy-toggle
    :alt: PyPi Version

.. image:: https://travis-ci.org/beylsp/proxy-toggle.svg?branch=master
    :target: https://travis-ci.org/beylsp/proxy-toggle
    :alt: Build Status

.. image:: https://coveralls.io/repos/github/beylsp/proxy-toggle/badge.svg?branch=master
     :target: https://coveralls.io/github/beylsp/proxy-toggle?branch=master
     :alt: Coverage report

.. image:: https://readthedocs.org/projects/proxy-toggle/badge
      :target: https://proxy-toggle.readthedocs.io/en/latest/
      :alt: Documentation

.. image:: https://requires.io/github/beylsp/proxy-toggle/requirements.svg?branch=master
     :target: https://requires.io/github/beylsp/proxy-toggle/requirements/?branch=master
     :alt: Requirements Status

.. role:: bash(code)
   :language: bash

A command-line tool to run programs seamlessly behind a proxy.

Introduction
------------

Many corporate networks use proxies both for network protection and to cache often-used content. This command-line tool allows you to run programs behind a corporate proxy without the need to constantly set/unset proxy environment variables. It sets the environment variables only when needed and unsets them whenever the program finished its execution. Currently, proxy-toggle only supports *Basic Access Authentication* as the authentication scheme to the proxy.

Deployment Requirements
-------------------------

In order to use this module you need to have access to a compatible version of the :bash:`GnuPG` executable. On a Linux platform, this will typically be installed via your distribution's package manager (e.g. :bash:`apt-get` on Debian/Ubuntu). Windows binaries are available `here <http://goo.gl/P8mxi>`_ - use one of the :bash:`gnupg-w32cli-1.4.x.exe` installers for the simplest deployment options.

Installation
------------

To use proxy-toggle:

.. code-block:: bash

    $ pip install proxy-toggle


Head over to `pip-installer <http://www.pip-installer.org/en/latest/index.html>`_ for instructions on installing pip.

To run from source, you can `download the source code <https://github.com/beylsp/proxy-toggle>`_ for proxy-toggle, and then run:

.. code-block:: bash

    $ python setup.py install


Usage
-----

Before you can start using proxy-toggle, you must initialize the application:

.. code-block:: bash

    $ px --init


This will prompt for your proxy settings: proxy server URL and user account/password. A secure keyring (to encrypt the password) will be generated. This might take a while.

You can test your proxy settings with following command:

.. code-block:: bash

    $ px --test


After successful initialization, run:

.. code-block:: bash

    $ px <program>

If your proxy doesn't require user authentication, run it with :bash:`--nouser` option:

.. code-block:: bash

    $ px --nouser <program>

When you want to renew your proxy password, run it with :bash:`--renew` option:

.. code-block:: bash

    $ px --renew

You can clear your proxy settings with :bash:`--clear` option:

.. code-block:: bash

    $ px --clear


Examples
--------

.. code-block:: bash

    $ px git clone https://github.com/beylsp/proxy-toggle

    $ px --nouser wget https://github.com/beylsp/archive/master.zip


Contributing
------------

We love contributions. If you've found a bug in the tool or would like new features added, go ahead and open issues or pull requests against this repo. Write a test to show your bug was fixed or the feature works as expected.
