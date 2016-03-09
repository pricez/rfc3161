import datetime
import hashlib
import requests
import base64

from pyasn1.codec.der import encoder, decoder
from pyasn1_modules import rfc2459
from pyasn1.type import univ
from pyasn1.error import PyAsn1Error
import M2Crypto.X509 as X509
import socket

from types import TSAPolicyId

import rfc3161

__all__ = ('RemoteTimestamper','check_timestamp','get_hash_oid',
    'TimestampingError', 'get_timestamp')

id_attribute_messageDigest = univ.ObjectIdentifier((1,2,840,113549,1,9,4,))

def get_hash_oid(hashname):
    return rfc3161.__dict__['id_'+hashname]

def get_hash_from_oid(oid):
    h = rfc3161.oid_to_hash.get(oid)
    if h is None:
        raise ValueError('unsupported hash algorithm', oid)
    return h

def get_hash_class_from_oid(oid):
    h = get_hash_from_oid(oid)
    return getattr(hashlib, h)

def _get_gen_time(tstinfo):
    formats = ['%Y%m%d%H%M%S.%fZ', '%Y%m%d%H%M%SZ']
    genTime = tstinfo.getComponentByName('genTime')
    for f in formats:
        try:
            return datetime.datetime.strptime(str(genTime), f)
        except ValueError:
            pass
    else:
        raise ValueError("not a valid genTime: %s" % genTime)

class TimestampingError(RuntimeError):
    pass

def get_timestamp(tst):
    try:
        if not isinstance(tst, rfc3161.TimeStampToken):
            tst, substrate = decoder.decode(tst, asn1Spec=rfc3161.TimeStampToken())
            if substrate:
                raise ValueError("extra data after tst")

        tstinfo = tst.getComponentByName('content').getComponentByPosition(2).getComponentByPosition(1)
        tstinfo, substrate = decoder.decode(tstinfo, asn1Spec=univ.OctetString())
        if substrate:
            raise ValueError("extra data after tst")
        tstinfo, substrate = decoder.decode(tstinfo, asn1Spec=rfc3161.TSTInfo())
        if substrate:
            raise ValueError("extra data after tst")
        return _get_gen_time(tstinfo)
    except PyAsn1Error, e:
        raise ValueError('not a valid TimeStampToken', e)

def check_timestamp(tst, certificate, data=None, digest=None, hashname=None, nonce=None):
    if tst is None:
        return False, "TimeStampToken is null"
    hashname = hashname or 'sha1'
    hashobj = hashlib.new(hashname)
    if digest is None:
        if not data:
            raise ValueError("check_timestamp requires data or digest argument")
        hashobj.update(data)
        digest = hashobj.digest()

    if not isinstance(tst, rfc3161.TimeStampToken):
        tst, substrate = decoder.decode(tst, asn1Spec=rfc3161.TimeStampToken())
        if substrate:
            return False, "extra data after tst"
    signed_data = tst.content
    if certificate == "":
        return False, "missing certificate"
    if nonce is not None and int(tst.tst_info['nonce']) != int(nonce):
        return False, 'nonce is different or missing'
    # check message imprint with respect to locally computed digest
    message_imprint = tst.tst_info.message_imprint
    if message_imprint.hash_algorithm[0] != get_hash_oid(hashname) or \
        str(message_imprint.hashed_message) != digest:
            return False, 'Message imprint mismatch'
    #
    if not len(signed_data['signerInfos']):
        return False, 'No signature'
    # We validate only one signature
    signer_info = signed_data['signerInfos'][0]
    # check content type
    if tst.content['contentInfo']['contentType'] != rfc3161.id_ct_TSTInfo:
        return False, "Signed content type is wrong: %s != %s" % (
            tst.content['contentInfo']['contentType'], rfc3161.id_ct_TSTInfo)

    # check signed data digest
    content = str(decoder.decode(str(tst.content['contentInfo']['content']),
        asn1Spec=univ.OctetString())[0])
    # if there is authenticated attributes, they must contain the message
    # digest and they are the signed data otherwise the content is the
    # signed data
    if len(signer_info['authenticatedAttributes']):
        authenticated_attributes = signer_info['authenticatedAttributes']
        signer_digest_algorithm = signer_info['digestAlgorithm']['algorithm']
        signer_hash_class = get_hash_class_from_oid(signer_digest_algorithm)
        signer_hash_name = get_hash_from_oid(signer_digest_algorithm)
        content_digest = signer_hash_class(content).digest()
        for authenticated_attribute in authenticated_attributes:
            if authenticated_attribute[0] == id_attribute_messageDigest:
                try:
                    signed_digest = str(decoder.decode(str(authenticated_attribute[1][0]),
                            asn1Spec=univ.OctetString())[0])
                    if signed_digest != content_digest:
                        return False, 'Content digest != signed digest'
                    s = univ.SetOf()
                    for i, x in enumerate(authenticated_attributes):
                        s.setComponentByPosition(i, x)
                    signed_data = encoder.encode(s)
                    break
                except PyAsn1Error:
                    raise
                    pass
        else:
            return False, 'No signed digest'
    else:
        signed_data = content
    # check signature
    if isinstance(certificate, basestring):
        certificate = [certificate]
    for cert in certificate:
        try:
            cert = X509.load_cert_string(cert, X509.FORMAT_PEM)
        except:
            cert = X509.load_cert_string(cert, X509.FORMAT_DER)
        signature = signer_info['encryptedDigest']
        pub_key = cert.get_pubkey()
        pub_key.reset_context(signer_hash_name)
        pub_key.verify_init()
        pub_key.verify_update(signed_data)
        if pub_key.verify_final(str(signature)) == 1:
            return True, ''
    return False, 'Bad signature'


class RemoteTimestamper(object):
    def __init__(self, url, certificate=None, capath=None, cafile=None,
                 username=None, password=None, hashname=None,
                 include_tsa_certificate=False, tsa_policy_id=None, timeout=10):
        self.url = url
        self.certificate = certificate
        self.capath = capath
        self.cafile = cafile
        self.username = username
        self.password = password
        self.hashname = hashname or 'sha1'
        self.include_tsa_certificate = include_tsa_certificate
        self.tsa_policy_id = tsa_policy_id
        self.timeout = timeout

    def check_response(self, response, digest, nonce=None):
        '''
           Check validity of a TimeStampResponse
        '''
        tst = response.time_stamp_token
        return self.check(tst, digest=digest, nonce=nonce)

    def check(self, tst, data=None, digest=None, nonce=None):
        return check_timestamp(tst, digest=digest, data=data, nonce=nonce,
                certificate=self.certificate, hashname=self.hashname)

    def timestamp(self, data=None, digest=None, include_tsa_certificate=None, nonce=None):
        return self(data=data, digest=digest,
                include_tsa_certificate=include_tsa_certificate, nonce=nonce)

    def _make_request(self, url, data, timeout, headers):
        try:
            return requests.post(self.url, data=data, timeout=self.timeout,
                                 headers=headers)
        except requests.RequestException, e:
            raise TimestampingError('Unable to send the request to %r' %
                                    self.url, e)

    def __call__(self, data=None, digest=None, include_tsa_certificate=None, nonce=None):
        algorithm_identifier = rfc2459.AlgorithmIdentifier()
        algorithm_identifier.setComponentByPosition(0, get_hash_oid(self.hashname))
        message_imprint = rfc3161.MessageImprint()
        message_imprint.setComponentByPosition(0, algorithm_identifier)
        hashobj = hashlib.new(self.hashname)
        if data:
            hashobj.update(data)
            digest = hashobj.digest()
        elif digest:
            assert len(digest) == hashobj.digest_size, 'digest length is wrong'
        else:
            raise ValueError('You must pass some data to digest, or the digest')
        message_imprint.setComponentByPosition(1, digest)
        request = rfc3161.TimeStampReq()
        request.setComponentByPosition(0, 'v1')
        request.setComponentByPosition(1, message_imprint)
        if self.tsa_policy_id:
            policy = TSAPolicyId(self.tsa_policy_id)
            request.setComponentByPosition(2, policy)
        if nonce is not None:
            request.setComponentByPosition(3, int(nonce))
        request.setComponentByPosition(4, include_tsa_certificate if include_tsa_certificate is not None else self.include_tsa_certificate)
        binary_request = encoder.encode(request)
        headers = { 'Content-Type': 'application/timestamp-query' }
        if self.username != None:
            base64string = base64.standard_b64encode('%s:%s' % (self.username, self.password))
            headers['Authorization'] = "Basic %s" % base64string
        response = self._make_request(self.url, binary_request, self.timeout,
                                      headers)
        tst_response, substrate = decoder.decode(response.content, asn1Spec=rfc3161.TimeStampResp())
        if substrate:
            return False, 'Extra data returned'
        result, message = self.check_response(tst_response, digest, nonce=nonce)
        if result:
            return encoder.encode(tst_response.time_stamp_token), ''
        else:
            return False, message


