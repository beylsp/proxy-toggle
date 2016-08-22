import proxytoggle

short_description = 'A command-line tool to run programs seamlessly behind a proxy.'


try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read()

with open('requirements.txt') as req_file:
    requirements = req_file.read().split('\n')

with open('dev-requirements.txt') as devreq_file:
    test_requirements = devreq_file.read().split('\n')


setup(
    name = 'proxy-toggle',
    version = proxytoggle.__version__,
    description = short_description,
    long_description = readme + '\n\n' + history,
    author = "Patrik Beyls",
    documentation = "http://proxy-toggle.readthedocs.io/en/stable/",
    url = 'https://github.com/beylsp/proxy-toggle',
    packages = [
        'proxytoggle',
    ],
    install_requires = requirements,
    license = "MIT",
    classifiers = [
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Operating System :: POSIX',
        'Operating System :: Unix',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
    ],
    test_suite = 'tests',
    tests_require = test_requirements,
    entry_points = {
        'console_scripts': ['px=proxytoggle.px:main'],
    }
)
