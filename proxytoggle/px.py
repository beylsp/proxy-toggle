"""A command-line tool to run programs seamlessly behind a proxy."""
import argparse
import ConfigParser
import getpass
import gnupg
import os
import shutil
import string
import struct
import subprocess
import sys
import urllib
import urlparse

PX_DIR = os.path.join(os.path.expanduser('~'), '.px')


def normalize(s):
    """Convert unsafe ascii characters into a valid URL ascii format.

    Args:
      s: string, string to be URL encoded.

    Returns:
      Normalized string.
    """
    return urllib.quote_plus(s)


class ProxyStore(object):
    """Secure store for proxy settings.

    This class generates a gnupg keyring to keep an RSA key pair. The RSA key
    is used to encrypt the user's proxy password.
    """
    def __init__(self, renew=False):
        """Constructor of ProxyStore.

        Creates directory structure, sets up a gnupg keyring and initializes
        the proxy toggle application. When a renew is requested, the new
        password is encrypted with the previously generated key.

        Args:
          renew: boolean, just renew password (default: False).
        """
        if renew:
            self._renew_app()
        else:
            self._init_app()

    def _init_app(self):
        """Initialize proxy application.

        Creates proxy configuration file ('px.conf') and hidden password file
        that stores the encrypted proxy password.
        """
        try:
            if os.path.exists(PX_DIR):
                shutil.rmtree(PX_DIR)
            os.makedirs(PX_DIR, 0700)
        except IOError, err:
            print 'Error initializing proxy store.'
            print err
            sys.exit(err.errno)

        host, user, password = self._get_user_input()

        try:
            gpg = gnupg.GPG(homedir=PX_DIR)
        except RuntimeError, err:
            print 'Error initializing keyring.'
            print err
            sys.exit(err.errno)
        else:
            passphrase = self._passphrase()
            key = self._generate_key(gpg, passphrase)

        self._write_config(passphrase, host, user)
        self._write_pass(str(gpg.encrypt(normalize(password),
                                         key.fingerprint)))

    def _renew_app(self):
        """Renew proxy application with new password."""
        try:
            gpg = gnupg.GPG(homedir=PX_DIR)
        except RuntimeError, err:
            print 'Error renewing password. Try to run "px --init".'
            print err
            sys.exit(err.errno)
        else:
            keys = gpg.list_keys()
            if not keys:
                print 'No keys found. Please run "px --init" first.'
                sys.exit()
            else:
                password = self._ask('Please enter new proxy password: ',
                                     mask=True)
                self._write_pass(str(gpg.encrypt(normalize(password),
                                                 keys[0]['fingerprint'])))

    def _write_pass(self, password):
        """Write password file ('.pass').

        Args:
          password: string, proxy user password.
        """
        try:
            fd = os.open(os.path.join(PX_DIR, '.pass'),
                         os.O_WRONLY | os.O_CREAT, 0600)
            with os.fdopen(fd, 'wb') as passfile:
                passfile.write(password)
        except IOError, err:
            print err
            sys.exit(err.errno)

    def _write_config(self, passphrase, host, user):
        """Write config file ('px.conf').

        Args:
          passphrase: string, passphrase to lock keyring.
          host: string, proxy host URL.
          user: string, proxy user account.
        """
        config = ConfigParser.ConfigParser()
        config.add_section('proxy')
        config.set('proxy', 'host', host)
        config.set('proxy', 'user', normalize(user))
        config.set('proxy', 'passphrase', passphrase)

        try:
            fd = os.open(os.path.join(PX_DIR, 'px.conf'),
                         os.O_WRONLY | os.O_CREAT, 0600)
            with os.fdopen(fd, 'wb') as configfile:
                config.write(configfile)
        except IOError, err:
            print err
            sys.exit(err.errno)

    def _get_user_input(self):
        """Retrieve proxy settings from user.

        Returns:
          Generator yielding proxy settings from user input.
        """
        d = [
            ('host', {'validator': bool}),
            ('user', {}),
            ('password', {'mask': True, 'validator': bool})]
        for field, kwargs in d:
            yield self._ask('Please enter proxy %s: ' % field, **kwargs)

    def _ask(self, question, mask=False, validator=bool):
        """Ask a question to standard input and validate answer.

        This question is repeatedly asked until successfully validated.

        Args:
          question: string, question to be asked.
          mask: boolean, whether or not to mask answer,
            e.g. password field (default: False).
          validator: function, invoked to validate answer (default: bool).

        Returns:
          The answer to the question.
        """
        try:
            if mask:
                _input = getpass.getpass(question)
            else:
                _input = raw_input(question)
        except KeyboardInterrupt:
            print
            sys.exit()

        if not validator(_input):
            self._ask(question, validator)
        return _input

    def _generate_key(self, gpg, passphrase):
        """Create batch file for input to key generation.

        Args:
          gpg: gnupg object, interface to gnupg keyring.
          passphrase: string, passphrase used to lock keyring.

        Returns:
          The gnupg GenKey object.
        """
        batch = {
            'name_real': 'px',
            'name_email': 'px@px',
            'key_type': 'RSA',
            'key_length': 1024,
            'passphrase': passphrase}
        key_settings = gpg.gen_key_input(**batch)

        print 'Generating a basic OpenPGP RSA key. This might take a while...'
        return gpg.gen_key(key_settings)

    def _passphrase(self, length=8):
        """Generate random passphrase.

        Args:
          length: integer, length of passphrase.

        Returns:
          The random generated passphrase.
        """
        alpha = (string.ascii_lowercase +
                 string.ascii_uppercase +
                 string.digits + '#+')
        phrase = []
        for i in range(length):
            index = struct.unpack('b', os.urandom(1))[0] % 64
            phrase.append(alpha[index])
        return ''.join(phrase)


class ProxyExec(object):
    """Execute shell command in a new process.

    The new process uses proxy environment variables instead of inheriting the
    current process' environment: 'http_proxy', 'https_proxy' and 'ftp_proxy'.
    """
    def env(self):
        """Create environment mappings based on proxy settings.

        Returns:
          Dictionary with environment variables.
        """
        myenv = {}
        user, pwd, urlo = self.get_proxy_settings()
        if self.nouser:
            env = urlo.geturl()
        else:
            env = '%s://%s:%s@%s' % (urlo.scheme, user, pwd, urlo.netloc)
        for protocol in ['http', 'https', 'ftp']:
            myenv['%s_proxy' % protocol] = env
        return myenv

    def get_password(self, passphrase):
        """Retrieve user password from passfile.

        Args:
          passphrase: string, passphrase needed to unlock RSA key.

        Returns:
          Decrypted user password.
        """
        passfile = os.path.join(PX_DIR, '.pass')
        try:
            with open(passfile) as fd:
                password = fd.read()
        except IOError, err:
            print err
            print 'No passfile found. Please run "px --init" first.'
            sys.exit(err.errno)
        else:
            gpg = gnupg.GPG(homedir=PX_DIR)
            return str(gpg.decrypt(password, passphrase=passphrase))

    def get_proxy_settings(self):
        """Retrieve proxy settings from configuration and pass file.

        Returns:
          user name, decrypted user password and urlparsed proxy host.
        """
        configfile = os.path.join(PX_DIR, 'px.conf')
        config = ConfigParser.ConfigParser()
        try:
            with open(configfile) as fd:
                config.readfp(fd)
                host = config.get('proxy', 'host')
                user = config.get('proxy', 'user')
                passphrase = config.get('proxy', 'passphrase')
        except IOError, err:
            print err
            print 'No proxy settings found. Please run "px --init" first.'
            sys.exit(err.errno)
        except ConfigParser.Error, err:
            print 'Error proxy settings (%s)' % configfile
            print err
            print 'Please run "px --init" again.'
            sys.exit(1)

        return user, self.get_password(passphrase), urlparse.urlparse(host)

    def __call__(self, nouser, cmd):
        """Execute child process with proxy environment.

        Args:
          nouser: boolean, whether or not to provide user name/password
            to proxy host.
          cmd: string, shell command to be executed.
        """
        self.nouser = nouser
        if nouser:
            cmd = cmd[1:]
        proc = subprocess.Popen(' '.join(cmd), shell=True, env=self.env())
        proc.wait()


def _parse_command_line():
    """Configure and parse our command line flags.

    Returns:
      Parsed known command line arguments.
    """
    parser = argparse.ArgumentParser(description=__doc__, usage=usage())
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--init',
                       action='store_true',
                       default=False,
                       help='Initialize proxy toggle.')
    group.add_argument('--nouser',
                       action='store_true',
                       default=False,
                       help='Proxy does not require a username and password.')
    group.add_argument('--renew',
                       action='store_true',
                       default=False,
                       help='Renew password.')
    return parser.parse_known_args(sys.argv[1:])


def usage():
    return '''px --help | --init | --renew | [--nouser] program'''


init_proxy_store = ProxyStore
_exec = ProxyExec()


def main():
    config, _ = _parse_command_line()
    if config.init or config.renew:
        init_proxy_store(config.renew)
    else:
        _exec(config.nouser, sys.argv[1:])


if __name__ == '__main__':
    main()
