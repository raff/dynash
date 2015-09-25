#!/usr/bin/env python
# -*- coding: utf-8 -*-

from dynash import __version__
import os
import sys

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

if sys.version_info <= (2, 5):
    error = "ERROR: dynash %s requires Python Version 2.6 or above...exiting." % __version__
    print >> sys.stderr, error
    sys.exit(1)

def read_file(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

SETUP_OPTIONS = dict(
    name='dynash',
    version=__version__,
    description='Command line client for DynamoDB',
    long_description = read_file("README.md"),
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

    packages=['dynash',
              'dynash2',
              ],

    data_files=[('.', ['README.md'])
               ],

    install_requires=['boto >= 2.32.0',
                      'cmd2',
                      ],

    entry_points="""
    [console_scripts]
    dynash=dynash.dynash:run_command
    dynash2=dynash2.dynash2:run_command
    """
    )

def do_setup():
    setup(**SETUP_OPTIONS)

if __name__ == '__main__':
    do_setup()
