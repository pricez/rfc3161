import unittest
import os.path
import datetime

from pyasn1.type import univ

import rfc3161

class Rfc3161(unittest.TestCase):

    def test_time_certum_pl(self):
        PUBLIC_TSA_SERVER = 'http://time.certum.pl'
        CERTIFICATE = os.path.join(os.path.dirname(__file__),
                '../data/certum_certificate.crt')
        data = 'xx'
        certificate = file(CERTIFICATE).read()
        value, substrate = rfc3161.RemoteTimestamper(
                PUBLIC_TSA_SERVER, certificate=certificate)(data=data)
        self.assertIsInstance(rfc3161.get_timestamp(value), datetime.datetime)
        self.assertNotEqual(value, None)
        self.assertEqual(substrate, '')

    def test_teszt_e_szigno_hu(self):
        PUBLIC_TSA_SERVER = 'https://teszt.e-szigno.hu:440/tsa'
        USERNAME = 'teszt'
        PASSWORD = 'teszt'
        CERTIFICATE = os.path.join(os.path.dirname(__file__),
                '../data/e_szigno_test_tsa2.crt')
        data = '{"comment": "Envoi en Commission", "to": "Benjamin Dauvergne", "filetype": "Arr\u00eat CC", "from": "Benjamin Dauvergne", "files": [{"name": "affectations_ange1d.xlsx", "digest": "ce57e4ba353107dddaab91b9ad26c0569ffe0f94", "size": 16279}]}'
        certificate = file(CERTIFICATE).read()
        value, substrate = rfc3161.RemoteTimestamper(
                PUBLIC_TSA_SERVER, certificate=certificate, username=USERNAME,
                password=PASSWORD, hashname='sha256')(data=data)
        self.assertIsInstance(rfc3161.get_timestamp(value), datetime.datetime)
        self.assertNotEqual(value, None)
        self.assertEqual(substrate, '')

    def test_teszt_e_szigno_hu_with_nonce(self):
        PUBLIC_TSA_SERVER = 'https://teszt.e-szigno.hu:440/tsa'
        USERNAME = 'teszt'
        PASSWORD = 'teszt'
        CERTIFICATE = os.path.join(os.path.dirname(__file__),
                '../data/e_szigno_test_tsa2.crt')
        data = 'xx'
        certificate = file(CERTIFICATE).read()
        value, substrate = rfc3161.RemoteTimestamper(
                PUBLIC_TSA_SERVER, certificate=certificate, username=USERNAME,
                password=PASSWORD, hashname='sha256')(data=data, nonce=2)
        self.assertIsInstance(rfc3161.get_timestamp(value), datetime.datetime)
        self.assertNotEqual(value, None)
        self.assertEqual(substrate, '')
