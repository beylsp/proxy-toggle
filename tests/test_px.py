import errno
import getpass
import mock
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

    def test_aks_question_keyboard_interrupt(self):
        def input(question):
            raise KeyboardInterrupt

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
        oserr.errno = errno.EACCESS
        oserr.strerror = 'Permission denied'
        oserr.filename = 'px.conf'

        with mock.patch('os.open', side_effect=oserr) as mock_open:
            with self.assertRaises(SystemExit) as e_cm:
                self.store._write_config('http://corporate.proxy.com', 'john', 'doe')

        self.assertEquals(e_cm.exception.code, errno.EACCESS)
