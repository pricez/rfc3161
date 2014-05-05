#!/usr/bin/python
from setuptools import setup
from distutils.cmd import Command
from unittest import TextTestRunner, TestLoader
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
        version='1.0.4',
        license='MIT',
        url='https://dev.entrouvert.org/projects/python-rfc3161',
        description='Python implementation of the RFC3161 specification, using pyasn1',
        long_description=file('README').read(),
        author='Benjamin Dauvergne',
        author_email='bdauvergne@entrouvert.com',
        packages=['rfc3161'],
        install_requires=[
            'pyasn1', 
            'pyasn1_modules', 
            'M2Crypto'],
        cmdclass={'test': TestCommand})
