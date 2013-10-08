#!/usr/bin/python
from distutils.core import setup, Command
from unittest import TextTestRunner, TestLoader
from glob import glob
from os.path import splitext, basename, join as pjoin
import os

class TestCommand(Command):
    user_options = [ ]

    def initialize_options(self):
        self._dir = os.getcwd()

    def finalize_options(self):
        pass

    def run(self):
        '''
        Finds all the tests modules in tests/, and runs them.
        '''
        tests = TestLoader().loadTestsFromName('tests.api')
        t = TextTestRunner(verbosity = 1)
        t.run(tests)

setup(name='rfc3161',
        version='0.1.7',
        license='MIT',
        description='Python implementation of the RFC3161 specification, using pyasn1',
        author='Benjamin Dauvergne',
        author_email='bdauvergne@entrouvert.com',
        packages=['rfc3161'],
        requires=['pyasn1'],
        cmdclass={'test': TestCommand})
