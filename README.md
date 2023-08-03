# aws-proxy

A very simple version of aws-es-kibina but implemented in python/boto to make it more easily understandable and
maintainable for python developers.

It basically decorates HTTP requests with the required IAM stuff to make the requests work with AWS's OpenSearch setup.
It's down to you to tunnel to the OpenSearch cluster yourself.

## Setting up

1. Make a virtualenv if you wish
1. `pip install -r requirements.txt`

## Usage

```
usage: aws_es_proxy.py [-h] [--region REGION] [--port PORT] [--assumed-role ASSUMED_ROLE] endpoint

positional arguments:
  endpoint              Opensearch endpoint to proxy to

options:
  -h, --help            show this help message and exit
  --region REGION, -r REGION
                        AWS region to use
  --port PORT, -p PORT  Port for proxy to run on
  --assumed-role ASSUMED_ROLE
                        Assumed role to use
```

## Example

```
python aws_es_proxy.py 127.0.0.1:8157 --region <region> --assumed-role <assumed-role>
```

You can use with or without an assumed role depending on your needs
