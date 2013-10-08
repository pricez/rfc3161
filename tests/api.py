import unittest
import os.path
import datetime

from pyasn1.type import univ

import rfc3161

class Rfc3161(unittest.TestCase):
    PUBLIC_TSA_SERVER = 'http://time.certum.pl'
    CERTIFICATE = os.path.join(os.path.dirname(__file__),
            '../data/certum_certificate.crt')

    def test_timestamp(self):
        certificate = file(self.CERTIFICATE).read()
        value, substrate = rfc3161.RemoteTimestamper(
                self.PUBLIC_TSA_SERVER, certificate=certificate)(data='xx')
        self.assertIsInstance(rfc3161.get_timestamp(value), datetime.datetime)
        self.assertNotEqual(value, None)
        self.assertEqual(substrate, '')
