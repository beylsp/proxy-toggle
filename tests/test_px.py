import base64
import errno
import getpass
import mock
import os
import string
import shutil
import subprocess
import sys
import tempfile
import unisquid
import unittest

from six.moves import configparser
from six.moves import urllib

from proxytoggle import px
from proxytoggle.px import ProxyStore
from proxytoggle.px import ProxyExec


class TestProxyStore(unittest.TestCase):
    def setUp(self):
        self.store = ProxyStore.__new__(ProxyStore)

    def test_passphrase_with_default_length_returns_length_8(self):
        self.assertEquals(len(self.store._passphrase()), 8)

    def test_passphrase_with_length_returns_length_4(self):
        self.assertEquals(len(self.store._passphrase(length=4)), 4)

    def test_passphrase_returns_alpha_chars(self):
        alpha = (string.ascii_lowercase +
                 string.ascii_uppercase +
                 string.digits + '#+')
        passphrase = self.store._passphrase()
        self.assertTrue(all([x in alpha for x in passphrase]))

    def test_ask_question_with_default_bool_validator_success(self):
        q = 'Do you feel lucky?'
        a = 'Yes'
        answer = self.store._ask(q, input_function=lambda x: a)
        self.assertEquals(answer, a)

    def test_ask_question_with_default_bool_validator_failed(self):
        def input(question):
            self.count += 1
            if self.first:
                self.first = False
                return ''
            return 'Yes'

        self.first = True
        self.count = 0

        q = 'Do you feel lucky?'
        answer = self.store._ask(q, input_function=input)
        self.assertEquals(self.count, 2)

    def test_ask_question_with_my_validator_success(self):
        q = 'Do you feel lucky?'
        a = 'Yes'
        answer = self.store._ask(q, input_function=lambda x: a,
                                 validator=lambda x: True)
        self.assertEquals(answer, a)

    def test_ask_question_with_my_validator_failed(self):
        def validate(input):
            self.count += 1
            if self.first:
                self.first = False
                return False
            return True

        self.first = True
        self.count = 0

        q = 'Do you feel lucky?'
        answer = self.store._ask(q, input_function=lambda x: 'Yes',
                                 validator=validate)
        self.assertEquals(self.count, 2)

    def test_ask_question_keyboard_interrupt(self):
        def input(question):
            raise KeyboardInterrupt

        sys.stdout = mock.MagicMock()
        q = 'Do you feel lucky?'
        with self.assertRaises(SystemExit) as e_cm:
            self.store._ask(q, input_function=input)
        self.assertIsInstance(e_cm.exception, SystemExit)

    def test_get_user_input_calls_for_correct_input(self):
        prefix = 'Please enter proxy'
        expected_questions = [mock.call('%s host: ' % prefix),
                              mock.call('%s user: ' % prefix),
                              mock.call('%s password: ' % prefix,
                                  input_function=getpass.getpass)]
        self.store._ask = mock.MagicMock()
        # eat results yielded by generator
        _ = list(self.store._get_user_input())
        self.assertEquals(self.store._ask.call_args_list, expected_questions)

    def test_write_config_prog_exits_if_permission_denied(self):
        sys.stdout = mock.MagicMock()

        # generate 'permission denied' error
        oserr = OSError()
        oserr.errno = errno.EACCES
        oserr.strerror = 'Permission denied'
        oserr.filename = 'px.conf'

        with mock.patch('os.open', side_effect=oserr) as mock_open:
            with self.assertRaises(SystemExit) as e_cm:
                self.store._write_config('doe', 'http://corporate.proxy.com', 'john')

        self.assertEquals(e_cm.exception.code, errno.EACCES)

    def test_write_config_prog_exits_if_bad_file_descriptor(self):
        os.open = mock.MagicMock()
        sys.stdout = mock.MagicMock()

        # generate 'bad file descriptor' error
        oserr = OSError()
        oserr.errno = errno.EBADF
        oserr.strerror = 'Bad file descriptor'

        with mock.patch('os.fdopen', side_effect=oserr) as mock_open:
            with self.assertRaises(SystemExit) as e_cm:
                self.store._write_config('doe', 'http://corporate.proxy.com', 'john')

        self.assertEquals(e_cm.exception.code, errno.EBADF)

    def test_write_config_creates_file_with_correct_permission(self):
        cfg_file = os.path.join(os.path.expanduser('~'), '.px', 'px.conf')
        os.open = mock.MagicMock()
        os.fdopen = mock.MagicMock()

        self.store._write_config('doe', 'http://corporate.proxy.com', 'john')
        os.open.assert_called_once_with(cfg_file, os.O_WRONLY | os.O_CREAT, 0o600)

    def test_write_config_gives_correct_data_to_configparser(self):
        section = 'proxy'
        host = 'http://corporate.proxy.com'
        user = 'john'
        passphrase = 'doe'
        expected_args = [mock.call(section, 'host', host),
                         mock.call(section, 'user', user),
                         mock.call(section, 'passphrase', passphrase)]
        os.open = mock.MagicMock()
        os.fdopen = mock.MagicMock()

        with mock.patch('proxytoggle.px.configparser.ConfigParser.set') as mock_config_set:
            self.store._write_config(passphrase, host, user)

        self.assertEquals(mock_config_set.call_args_list, expected_args)

    def test_write_pass_prog_exits_if_permission_denied(self):
        sys.stdout = mock.MagicMock()

        # generate 'permission denied' error
        oserr = OSError()
        oserr.errno = errno.EACCES
        oserr.strerror = 'Permission denied'
        oserr.filename = '.pass'

        with mock.patch('os.open', side_effect=oserr) as mock_open:
            with self.assertRaises(SystemExit) as e_cm:
                self.store._write_pass('mysecretpassword')

        self.assertEquals(e_cm.exception.code, errno.EACCES)

    def test_write_pass_prog_exits_if_bad_file_descriptor(self):
        os.open = mock.MagicMock()
        sys.stdout = mock.MagicMock()

        # generate 'bad file descriptor' error
        oserr = OSError()
        oserr.errno = errno.EBADF
        oserr.strerror = 'Bad file descriptor'

        with mock.patch('os.fdopen', side_effect=oserr) as mock_open:
            with self.assertRaises(SystemExit) as e_cm:
                self.store._write_pass('mysecretpassword')

        self.assertEquals(e_cm.exception.code, errno.EBADF)

    def test_write_pass_creates_file_with_correct_permission(self):
        pass_file = os.path.join(os.path.expanduser('~'), '.px', '.pass')
        os.open = mock.MagicMock()
        os.fdopen = mock.MagicMock()

        self.store._write_pass('mysecretpassword')
        os.open.assert_called_once_with(pass_file, os.O_WRONLY | os.O_CREAT, 0o600)

    def test_write_pass_writes_correct_password(self):
        password = 'mysecretpassword'
        os.open = mock.MagicMock(return_value=4)
        m = mock.mock_open()

        with mock.patch('os.fdopen', m):
            self.store._write_pass(password)

        m.return_value.write.assert_called_once_with(password)

    def test_renew_app_called_if_renew_flag_is_set(self):
        self.store._renew_app = mock.MagicMock()
        self.store.__init__(renew=True)

        self.store._renew_app.assert_called_once()

    def test_init_app_called_if_renew_flag_is_not_set(self):
        self.store._init_app = mock.MagicMock()
        self.store.__init__(renew=False)

        self.store._init_app.assert_called_once()

    def test_generate_key_with_correct_input(self):
        passphrase = 'mypassphrase'
        batch = {
            'name_real': 'px',
            'name_email': 'px@px',
            'key_type': 'RSA',
            'key_length': 1024,
            'passphrase': passphrase}
        sys.stdout = mock.MagicMock()
        gpg_mock = mock.MagicMock(spec=['gen_key_input', 'gen_key'])
        self.store._generate_key(gpg_mock, passphrase)

        gpg_mock.gen_key_input.assert_called_once_with(**batch)


class TestProxyExec(unittest.TestCase):
    def setUp(self):
        self.executor = ProxyExec.__new__(ProxyExec)

    def test_env_returns_correct_environment(self):
        path = '/usr/local/sbin'
        user = 'john'
        password = 'doe'
        os.environ.get = mock.MagicMock(return_value=path)
        urlo = urllib.parse.urlparse('http://corporate.proxy.com')
        env = 'http://john:doe@corporate.proxy.com'
        expected_dict = {
            'PATH': path,
            'http_proxy': env,
            'https_proxy': env,
            'ftp_proxy': env,
            'all_proxy': env}

        settings = (user, password, urlo)
        self.executor.get_proxy_settings = mock.MagicMock(
            return_value=(user, password, urlo))

        self.assertEquals(self.executor.env(), expected_dict)

    def test_env_nouser_returns_correct_environment(self):
        path = '/usr/local/sbin'
        user = 'john'
        password = 'doe'
        os.environ.get = mock.MagicMock(return_value=path)
        urlo = urllib.parse.urlparse('http://corporate.proxy.com')
        env = 'http://corporate.proxy.com'
        expected_dict = {
            'PATH': path,
            'http_proxy': env,
            'https_proxy': env,
            'ftp_proxy': env,
            'all_proxy': env}

        settings = (user, password, urlo)
        self.executor.get_proxy_settings = mock.MagicMock(
            return_value=(user, password, urlo))

        self.assertEquals(self.executor.env(nouser=True), expected_dict)

    def test_call_executes_child_process(self):
        cmd = ['arg1', 'arg2', 'arg3']
        expected_args = [mock.call(' '.join(cmd),
                                   shell=True,
                                   env={})]
        subprocess.Popen = mock.MagicMock()
        with mock.patch('proxytoggle.px.ProxyExec.env', return_value={}):
            self.executor(nouser=False, cmd=cmd)
        self.assertEquals(subprocess.Popen.call_args_list, expected_args)

    def test_call_with_nouser_flag_executes_child_process(self):
        cmd = ['arg1', 'arg2', 'arg3']
        expected_args = [mock.call(' '.join(cmd[1:]),
                                   shell=True,
                                   env={})]
        subprocess.Popen = mock.MagicMock()
        with mock.patch('proxytoggle.px.ProxyExec.env', return_value={}):
            self.executor(nouser=True, cmd=cmd)
        self.assertEquals(subprocess.Popen.call_args_list, expected_args)

class TestArgumentParser(unittest.TestCase):
    def test_init_command_line_argument(self):
        sys.argv = ['px', '--init']
        config, remainder = px._parse_command_line()
        self.assertTrue(config.init)

    def test_nouser_command_line_argument(self):
        sys.argv = ['px', '--nouser']
        config, remainder = px._parse_command_line()
        self.assertTrue(config.nouser)

    def test_renew_command_line_argument(self):
        sys.argv = ['px', '--renew']
        config, remainder = px._parse_command_line()
        self.assertTrue(config.renew)

    def test_version_command_line_argument(self):
        sys.stderr = mock.MagicMock()
        sys.argv = ['px', '--version']
        with self.assertRaises(SystemExit) as e_cm:
            config, remainder = px._parse_command_line()
            self.assertTrue(config.version)
        self.assertIsInstance(e_cm.exception, SystemExit)

    def test_test_command_line_argument(self):
        sys.stdout = mock.MagicMock()
        sys.argv = ['px', '--test']
        config, remainder = px._parse_command_line()
        self.assertTrue(config.test)

    def test_clear_command_line_argument(self):
        sys.stdout = mock.MagicMock()
        sys.argv = ['px', '--clear']
        config, remainder = px._parse_command_line()
        self.assertTrue(config.clear)

    def test_some_command_line_argument(self):
        command = 'wget http://google.com'
        sys.argv = ['px', command]
        config, remainder = px._parse_command_line()
        self.assertEquals(remainder, [command])

    def test_mutual_exclusive_options(self):
        sys.stderr = mock.MagicMock()
        sys.argv = ['px', '--init', '--renew']
        with self.assertRaises(SystemExit) as e_cm:
            config, remainder = px._parse_command_line()
        self.assertIsInstance(e_cm.exception, SystemExit)


class TestFunctional(unisquid.LiveServerTestCase):
    def setUp(self):
        unisquid.LiveServerTestCase.setUp(self)

        # copy template keyring to tempdir and update
        # host url in px.conf with live server url
        curdir = os.path.dirname(__file__)
        keydir = os.path.join(curdir, 'keyring')
        self.px_dir = tempfile.mkdtemp(dir=curdir)
        for _file in os.listdir(keydir):
            shutil.copy(os.path.join(keydir, _file), self.px_dir)
        self.update_configfile()

    def tearDown(self):
        unisquid.LiveServerTestCase.tearDown(self)
        if os.path.exists(self.px_dir):
            shutil.rmtree(self.px_dir)

    def update_configfile(self):
        configfile = os.path.join(self.px_dir, 'px.conf')
        parser = configparser.SafeConfigParser()
        parser.read(configfile)
        parser.set('proxy', 'host', self.live_server_url)
        with open(configfile, 'w') as cfg:
            parser.write(cfg)

    def create_app(self):
        self.http_status_mock = '200 OK'
        def response(environ, start_response):
            # put environment to queue
            self.q.put(environ)
            start_response(self.http_status_mock,
                           [( 'Content-Type', 'text/html')])
            return ''
        return response

    def get_proxy_auth_from_env(self, env):
        auth = env.get('HTTP_PROXY_AUTHORIZATION', '')
        if auth:
            _, enc = auth.split()
            return base64.b64decode(enc).decode('utf-8').split(':')
        return None, None

    def test_px_basic_access_auth_user(self):
        sys.argv = ['px', 'wget', '-qO-', 'http://google.com']
        with mock.patch('proxytoggle.px.PX_DIR', self.px_dir):
            px.main()
            # consume the environment from queue
            environ = self.q.get()

        user, _ = self.get_proxy_auth_from_env(environ)
        self.assertEquals(user, 'john')

    def test_px_basic_access_auth_password(self):
        sys.argv = ['px', 'wget', '-qO-', 'http://google.com']
        with mock.patch('proxytoggle.px.PX_DIR', self.px_dir):
            px.main()
            # consume the environment from queue
            environ = self.q.get()

        _, password = self.get_proxy_auth_from_env(environ)
        self.assertEquals(password, 'doe')

    def test_px_basic_access_auth_password_after_renew(self):
        getpass.getpass = mock.MagicMock(return_value='roe')
        sys.argv = ['px', '--renew']
        with mock.patch('proxytoggle.px.PX_DIR', self.px_dir):
            px.main()

            sys.argv = ['px', 'wget', '-qO-', 'http://google.com']
            px.main()
            # consume the environment from queue
            environ = self.q.get()

        _, password = self.get_proxy_auth_from_env(environ)
        self.assertEquals(password, 'roe')

    def test_px_clear_proxy_settings(self):
        sys.argv = ['px', '--clear']
        with mock.patch('proxytoggle.px.PX_DIR', self.px_dir):
            px.main()

        self.assertFalse(os.path.exists(self.px_dir))

    def test_px_test_ok(self):
        with mock.patch('proxytoggle.px.PX_DIR', self.px_dir):
            status = px.test()

        self.assertEquals(status, 'OK')

    def test_px_test_failed(self):
        self.http_status_mock = '407 Proxy Authentication Required'
        with mock.patch('proxytoggle.px.PX_DIR', self.px_dir):
            status = px.test()

        self.assertEquals(status, 'FAILED')
