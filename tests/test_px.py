import errno
import getpass
import mock
import os
import string
import sys
import unittest

from proxytoggle.px import ProxyStore


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
