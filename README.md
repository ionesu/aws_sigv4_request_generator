# AWS Signature Version 4 signing process (Python)

This package allows you to add the authorization headers to your request required by Amazon's 
[signature version 4](https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html)

Tested with python 3.9

# Usage

```python
import requests
from aws_sigv4_request_generator.aws_sigv4 import AWSSigV4RequestGenerator

auth = AWSSigV4RequestGenerator(
        aws_access_key_id='YOUR_KEY',
        aws_secret_access_key='YOUR_SECRET',
        aws_session_token='YOUR_SESSION_TOKEN',
        aws_region='us-east-1',
        aws_service='execute-api'
        )

response = requests.request('GET', 'https://api.domain.com/path', auth=auth)
```

# Thanks to
[AWS Examples of the complete Signature Version 4 signing process](https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html)

[GitHub user DavidMuller and his package aws-requests-auth](https://github.com/andrewjroth/requests-auth-aws-sigv4)

[GitHub user andrewjroth and his package requests-auth-aws-sigv4](https://github.com/andrewjroth/requests-auth-aws-sigv4)