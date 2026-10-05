import base64
import xml.etree.ElementTree as ET

from beg_secret.config import JenkinsCredential, JenkinsStore
from beg_secret.jenkins_credentials import FILE_CLASS, SSH_CLASS, JenkinsClient, build_credential_xml


def _cred(t, **kw):
    return JenkinsCredential(id="c1", type=t, description="d <&>", refs={}, **kw)


def test_string_xml_escapes():
    root = ET.fromstring(build_credential_xml(_cred("string"), {"secret": "a<b>&c"}))
    assert root.findtext("secret") == "a<b>&c"
    assert root.findtext("description") == "d <&>"
    assert root.findtext("scope") == "GLOBAL"


def test_file_xml_base64():
    root = ET.fromstring(build_credential_xml(_cred("file", file_name="kc"), {"content": "hello"}))
    assert root.tag == FILE_CLASS
    assert base64.b64decode(root.findtext("secretBytes")) == b"hello"
    assert root.findtext("fileName") == "kc"


def test_ssh_xml():
    xml = build_credential_xml(_cred("sshPrivateKey"), {"username": "git", "private_key": "KEY", "passphrase": "pp"})
    root = ET.fromstring(xml)
    assert root.tag == SSH_CLASS
    assert root.find("privateKeySource").get("class").endswith("$DirectEntryPrivateKeySource")
    assert root.find("privateKeySource").findtext("privateKey") == "KEY"
    assert root.findtext("passphrase") == "pp"


def test_store_paths():
    sp = JenkinsClient.store_path
    assert sp(JenkinsStore(None, "_", [])) == "/credentials/store/system/domain/_"
    assert sp(JenkinsStore("team/my app", "_", [])) == "/job/team/job/my%20app/credentials/store/folder/domain/_"
