#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup
from dynash import __version__

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

    packages=['dynash'
              ],

    data_files=[('.', ['README.md'])
               ],

    install_requires=['distribute',
                      'setuptools >= 0.6c11',
                      'boto >= 2.6.0',
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
