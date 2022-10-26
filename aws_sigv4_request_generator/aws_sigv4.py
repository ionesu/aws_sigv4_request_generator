import os
import hmac
import hashlib
import logging
import datetime

from urllib.parse import quote, urlparse


class AWSSigV4RequestGenerator():

    def __init__(self, **kwargs):
        """
        :param aws_service='es',
        :param aws_access_key_id='YOUR_KEY_ID',
        :param aws_secret_access_key='YOUR_SECRET',
        :param aws_session_token='YOUR_SESSION_TOKEN'
        :param aws_region='us-east-1',
        :param aws_host='search-service.us-east-1.es.amazonaws.com',
        """


        if not kwargs.get('aws_service'):
            raise KeyError("Service is required")

        self.__dict__.update(kwargs)

        if not all(getattr(self, attr, None) for attr in ["aws_access_key_id", "aws_secret_access_key"]):
            logging.debug("Checking environment for credentials")
            self.aws_access_key_id = os.getenv('AWS_ACCESS_KEY_ID')
            self.aws_secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY')
            self.aws_session_token = os.getenv('AWS_SESSION_TOKEN') or os.getenv('AWS_SECURITY_TOKEN')

        if any(True for x in (self.aws_access_key_id, self.aws_secret_access_key) if x is None):
            raise KeyError("AWS Access Key ID and Secret Access Key are required")

        if not getattr(self, 'aws_region', None):
            logging.debug("Checking environment for region")
            self.aws_region = os.getenv('AWS_DEFAULT_REGION')

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

        parsed_url = urlparse(request.url)
        logging.debug("Request URL: %s", parsed_url)

        canonical_querystring = self.get_canonical_querystring(parsed_url)
        canonical_uri = self.get_canonical_uri(parsed_url)
        canonical_headers = self.get_canonical_headers(parsed_url)

        payload_hash = self.get_payload_hash(request)
        signed_headers = 'host;x-amz-date;x-amz-security-token' if self.aws_session_token else 'host;x-amz-date'

        canonical_request = '\n'.join([request.method, canonical_uri, canonical_querystring,
                                       canonical_headers, signed_headers, payload_hash])
        logging.debug("Canonical Request: '%s'", canonical_request)

        authorization_header = self.get_authorization_header(canonical_request, signed_headers)

        headers = {
            'Authorization':        authorization_header,
            'X-AMZ-Date':           self.amzdate,
            'x-amz-content-sha256': payload_hash,
        }

        if self.aws_session_token:
            request.headers['x-amz-security-token'] = self.aws_session_token

        logging.debug("Generated Request Headers: %s", headers)

        return headers


    @staticmethod
    def sign(key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


    @staticmethod
    def get_headers_and_credential_date():
        """
        Create a date for headers and the credential string
        """

        date_utc_now = datetime.datetime.utcnow()
        amzdate = date_utc_now.strftime('%Y%m%dT%H%M%SZ')
        datestamp = date_utc_now.strftime('%Y%m%d')
        logging.debug("Starting authentication with amzdate=%s and datestamp=%s", amzdate, datestamp)

        return amzdate, datestamp


    @staticmethod
    def get_payload_hash(request):
        """
        Create payload hash. For GET requests, the payload is an empty string ("")
        """

        if request.method == 'GET':
            payload = ''.encode('utf-8')

        else:
            if request.body:
                payload = request.body if isinstance(request.body, bytes) else request.body.encode('utf-8')

            else:
                payload = b''

        logging.debug("Request Body: <bytes> %s", payload)

        return hashlib.sha256(payload).hexdigest()


    @staticmethod
    def get_canonical_querystring(parsed_url):
        """
        Create the canonical query string. According to AWS, by the
        end of this function our query string values must
        be URL-encoded (space=%20) and the parameters must be sorted
        by name.
        """

        querystring = dict(map(lambda i: i.split('='), parsed_url.query.split('&'))) if len(
                parsed_url.query) else dict()
        canonical_querystring = "&".join(map(lambda parsed_url: "=".join(parsed_url), sorted(querystring.items())))

        return canonical_querystring


    @staticmethod
    def get_canonical_uri(parsed_url):
        """
        Create canonical URI--the part of the URI from domain to query
        string (use '/' if no path)
        """

        canonical_uri = quote(parsed_url.path if parsed_url.path else '/', safe='/-_.~')

        return canonical_uri


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


    def get_canonical_headers(self, parsed_url):
        """
        Create the canonical headers and signed headers. Header names
        must be trimmed and lowercase, and sorted in code point order from
        low to high. Note that there is a trailing \n.
        """

        # We check if we get host from kwargs than hostname of parsed url
        host = getattr(self, 'aws_host', None) or parsed_url.hostname
        canonical_headers = ('host:' + host + '\n' + 'x-amz-date:' + self.amzdate + '\n')

        if self.aws_session_token:
            canonical_headers += 'x-amz-security-token:' + self.aws_session_token + '\n'

        return canonical_headers


    def get_authorization_header(self, canonical_request, signed_headers):
        """
        Create authorization header and add to request headers
        """

        credential_scope = '/'.join([self.datestamp, self.aws_region, self.aws_service, 'aws4_request'])
        string_to_sign = '\n'.join(['AWS4-HMAC-SHA256', self.amzdate,
                                    credential_scope, hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()])
        logging.debug("String-to-Sign: %s", string_to_sign)

        signing_key = self.get_signature_key()
        signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
        logging.debug("Signature: %s", signature)

        authorization_header = "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}".format(
                self.aws_access_key_id, credential_scope, signed_headers, signature)

        return authorization_header
