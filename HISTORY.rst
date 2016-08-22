1.0.0
-----

Original open source release

1.0.1
-----

Unstable release

1.0.2
-----

First stable release

1.0.3
-----

- Add new positional command-line arguments: '--version', '--test'
- Add full support for python 3.x
- Set 'all_proxy' environment variable as understood by curl

1.0.4
-----

- Add missing dependency (six) to setuptools script
- Subprocess inherits parent's 'PATH' environment variable
- Add new positional command-line argument: '--clear'

1.0.5
-----

- Bugfix: no error reported when 'px --test' fails

1.0.6
-----
- Fix #1: Raise SystemExit with error message when RuntimeError occurs as it doesn't have errno attribute
