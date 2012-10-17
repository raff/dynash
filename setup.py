#!/usr/bin/env python
# -*- coding: utf-8 -*-

from dynash import __version__
import sys

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

if sys.version_info <= (2, 5):
    error = "ERROR: dynash %s requires Python Version 2.6 or above...exiting." % __version__
    print >> sys.stderr, error
    sys.exit(1)

SETUP_OPTIONS = dict(
    name='dynash',
    version=__version__,
    description='Command line client for DynamoDB',
    long_description = open("README.md").read(),
    author='Raffaele Sena',
    author_email='raff367@gmail.com',
    url='https://github.com/raff/dynash',
    license = "MIT",
    platforms = "Posix; MacOS X; Windows",
    classifiers = [
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Topic :: Internet',
        'Topic :: Utilities',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7'
    ],

    packages=['dynash'
              ],

    data_files=[('.', ['README.md'])
               ],

    install_requires=['boto >= 2.6.0',
                      'cmd2',
                      ],

    entry_points="""
    [console_scripts]
    dynash=dynash.dynash:run_command
    """
    )

def do_setup():
    setup(**SETUP_OPTIONS)

if __name__ == '__main__':
    do_setup()
