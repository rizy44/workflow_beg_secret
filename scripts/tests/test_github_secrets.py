import base64

from nacl import public

from beg_secret.config import GitHubTarget
from beg_secret.github_secrets import GitHubSecretsClient, encrypt_secret


def test_encrypt_roundtrip():
    sk = public.PrivateKey.generate()
    pk_b64 = base64.b64encode(bytes(sk.public_key)).decode()
    sealed = encrypt_secret(pk_b64, "s3cr3t")
    assert public.SealedBox(sk).decrypt(base64.b64decode(sealed)) == b"s3cr3t"


def test_base_paths():
    bp = GitHubSecretsClient.base_path
    assert bp(GitHubTarget(kind="repo", repo="o/r")) == "/repos/o/r/actions/secrets"
    assert (
        bp(GitHubTarget(kind="environment", repo="o/r", environment="prod eu"))
        == "/repos/o/r/environments/prod%20eu/secrets"
    )
    assert bp(GitHubTarget(kind="org", org="acme")) == "/orgs/acme/actions/secrets"
