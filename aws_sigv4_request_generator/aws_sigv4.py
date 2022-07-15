import os
import hmac
import hashlib
import datetime

from requests.auth import AuthBase
from urllib.parse import quote, urlparse


class AWSSigV4RequestGenerator(AuthBase):

    def __init__(self, **kwargs):
        """
        :param aws_service='es',
        :param aws_access_key_id='YOUR_KEY_ID',
        :param aws_secret_access_key='YOUR_SECRET',
        :param aws_session_token='YOUR_SESSION_TOKEN'
        :param aws_region='us-east-1',
        :param aws_host='search-service.us-east-1.es.amazonaws.com',
        """

        self.aws_service = kwargs.get('aws_service')
        self.aws_access_key_id = kwargs.get('aws_access_key_id')
        self.aws_secret_access_key = kwargs.get('aws_secret_access_key')
        self.aws_session_token = kwargs.get('aws_session_token')
        self.aws_region = kwargs.get('aws_region')
        self.aws_host = kwargs.get('aws_host')

        if self.aws_service is None:
            raise KeyError("Service is required")

        if self.aws_access_key_id is None or self.aws_secret_access_key is None:
            self.aws_access_key_id = os.environ.get('AWS_ACCESS_KEY_ID')
            self.aws_secret_access_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
            self.aws_session_token = os.environ.get('AWS_SESSION_TOKEN') or os.environ.get('AWS_SECURITY_TOKEN')

        if self.aws_access_key_id is None or self.aws_secret_access_key is None:
            raise KeyError("AWS Access Key ID and Secret Access Key are required")

        if self.aws_region is None:
            raise KeyError("Region is required")


    def __call__(self, request):
        """
        Adds the authorization headers required by Amazon's signature
        version 4 signing process to the request.
        Adapted from https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html
        """

        self.amzdate, self.datestamp = self.get_headers_and_credential_date()
        aws_sigv4_headers = self.get_aws_sigv4_headers(request)
        request.headers.update(aws_sigv4_headers)

        return request


    def get_aws_sigv4_headers(self, request):
        """
        Returns a dictionary containing the necessary headers for Amazon's
        signature version 4 signing process.
        """

        canonical_querystring, canonical_uri, canonical_headers = self.get_canonical_data(request)
        payload_hash = self.get_payload_hash(request)
        signed_headers = 'host;x-amz-date;x-amz-security-token' if self.aws_session_token else 'host;x-amz-date'

        canonical_request = '\n'.join([request.method, canonical_uri, canonical_querystring,
                                       canonical_headers, signed_headers, payload_hash])

        authorization_header = self.get_authorization_header(canonical_request, signed_headers)

        headers = {
            'Authorization':        authorization_header,
            'X-AMZ-Date':           self.amzdate,
            'x-amz-content-sha256': payload_hash,
        }

        if self.aws_session_token:
            request.headers['x-amz-security-token'] = self.aws_session_token

        return headers


    @staticmethod
    def sign(key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


    def get_signature_key(self):
        """
        Key derivation functions. See:
        http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-python
        """
        k_date = self.sign(('AWS4' + self.aws_secret_access_key).encode('utf-8'), self.datestamp)
        k_region = self.sign(k_date, self.aws_region)
        k_service = self.sign(k_region, self.aws_service)
        k_signing = self.sign(k_service, 'aws4_request')

        return k_signing


    def get_canonical_data(self, request):
        """
        Create the canonical query string. According to AWS, by the
        end of this function our query string values must
        be URL-encoded (space=%20) and the parameters must be sorted
        by name.
        Create canonical URI--the part of the URI from domain to query
        string (use '/' if no path)
        Create the canonical headers and signed headers. Header names
        must be trimmed and lowercase, and sorted in code point order from
        low to high. Note that there is a trailing \n.
        """

        parsed_url = urlparse(request.url)
        querystring = dict(map(lambda i: i.split('='), parsed_url.query.split('&'))) if len(
                parsed_url.query) else dict()
        canonical_querystring = "&".join(map(lambda parsed_url: "=".join(parsed_url), sorted(querystring.items())))

        # safe chars adapted from boto's use of urllib.parse.quote
        # https://github.com/boto/boto/blob/d9e5cfe900e1a58717e393c76a6e3580305f217a/boto/auth.py#L393
        canonical_uri = quote(parsed_url.path if parsed_url.path else '/', safe='/-_.~')
        host = self.aws_host or request.headers.get('Host') or parsed_url.hostname

        # We check if we get host from kwargs than in request headers and the last chance to hostname of parsed url
        canonical_headers = ('host:' + host + '\n' + 'x-amz-date:' + self.amzdate + '\n')

        if self.aws_session_token:
            canonical_headers += 'x-amz-security-token:' + self.aws_session_token + '\n'

        return canonical_querystring, canonical_uri, canonical_headers


    @staticmethod
    def get_headers_and_credential_date():
        """
        Create a date for headers and the credential string
        """

        date_utc_now = datetime.datetime.utcnow()
        amzdate = date_utc_now.strftime('%Y%m%dT%H%M%SZ')
        datestamp = date_utc_now.strftime('%Y%m%d')

        return amzdate, datestamp


    @staticmethod
    def get_payload_hash(request):
        """
        Create payload hash. For GET requests, the payload is an empty string ("")
        """

        if request.method == 'GET':
            payload_hash = hashlib.sha256(''.encode('utf-8')).hexdigest()
        else:
            if request.body:
                if isinstance(request.body, bytes):
                    payload_hash = hashlib.sha256(request.body).hexdigest()
                else:
                    payload_hash = hashlib.sha256(request.body.encode('utf-8')).hexdigest()
            else:
                payload_hash = hashlib.sha256(b'').hexdigest()

        return payload_hash


    def get_authorization_header(self, canonical_request, signed_headers):
        """
        Create authorization header and add to request headers
        """

        credential_scope = '/'.join([self.datestamp, self.aws_region, self.aws_service, 'aws4_request'])
        string_to_sign = '\n'.join(['AWS4-HMAC-SHA256', self.amzdate,
                                    credential_scope, hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()])
        signing_key = self.get_signature_key()
        signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
        authorization_header = "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}".format(
                self.aws_access_key_id, credential_scope, signed_headers, signature)

        return authorization_header
