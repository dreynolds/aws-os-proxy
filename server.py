import argparse
import http.server
import logging
import socketserver

import boto3
import requests
import urllib3
from requests_aws4auth import AWS4Auth

LOG = logging.getLogger(__name__)
# Don't bother me with insecure SSL issues - they're because we're tunneling and not using the domain
urllib3.disable_warnings()


def get_creds(region, assumed_role=None):
    """
    Get AWS creds to add to ES requests
    """
    LOG.info("getting creds in region: %s", region)
    client = boto3.client("sts")
    if assumed_role is not None:
        resp = client.assume_role(RoleArn=assumed_role, RoleSessionName="test_session")
        LOG.debug(resp)
        session_kwargs = {
            "aws_access_key_id": resp["Credentials"]["AccessKeyId"],
            "aws_secret_access_key": resp["Credentials"]["SecretAccessKey"],
            "aws_session_token": resp["Credentials"]["SessionToken"],
        }
    else:
        session_kwargs = {}
    LOG.info(session_kwargs)

    session = boto3.Session(**session_kwargs)
    credentials = session.get_credentials()
    return AWS4Auth(
        credentials.access_key,
        credentials.secret_key,
        region,
        "es",
        session_token=credentials.token,
    )


class AwsAuthProxy(http.server.SimpleHTTPRequestHandler):
    region = None
    upstream = None
    creds = None

    def do_POST(self):
        self._self_authed_request("post")

    def do_GET(self):
        self._self_authed_request("get")

    def _self_authed_request(self, method):
        if not self.creds:
            LOG.error("No creds found")
            self.send_error(401)
            self.end_headers()
        else:
            path = self.path[1:]
            url = "https://%s/%s" % (self.upstream, path)
            LOG.info("URL %s", url)

            request_kwargs = {
                "auth": self.creds,
                "verify": False,
                "headers": {"osd-xsrf": "true"},
            }
            if method == "get":
                resp = requests.get(url, **request_kwargs)
            elif method == "post":
                content_length = int(self.headers["Content-Length"])
                body = self.rfile.read(content_length)
                resp = requests.post(url, **request_kwargs, data=body)
            self.send_response(resp.status_code)
            self.end_headers()
            self.wfile.write(resp.content)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "endpoint", nargs=1, default="127.0.0.1:8157", help="Endpoint to proxy to"
    )
    parser.add_argument(
        "--region", "-r", required=False, default="us-east-1", help="AWS region to use"
    )
    parser.add_argument(
        "--port",
        "-p",
        required=False,
        default=5000,
        type=int,
        help="Port for proxy to run on",
    )
    parser.add_argument("--assumed-role", required=False, help="Assumed role to use")

    args = parser.parse_args()

    AwsAuthProxy.upstream = args.endpoint[0]
    AwsAuthProxy.region = args.region
    AwsAuthProxy.creds = get_creds(args.region, args.assumed_role)

    with socketserver.ForkingTCPServer(("", args.port), AwsAuthProxy) as httpd:
        LOG.info("Now serving at %s", str(args.port))
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            httpd.server_close()
