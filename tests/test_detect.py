import pytest

from osintcrawler.detect import DetectionError, detect, refang
from osintcrawler.models import IType


@pytest.mark.parametrize(
    "raw, itype, value",
    [
        ("8.8.8.8", IType.IP, "8.8.8.8"),
        ("2001:4860:4860::8888", IType.IP, "2001:4860:4860::8888"),
        ("8.8.8[.]8", IType.IP, "8.8.8.8"),
        ("10.0.0.0/8", IType.CIDR, "10.0.0.0/8"),
        ("as15169", IType.ASN, "AS15169"),
        ("Example.COM.", IType.DOMAIN, "example.com"),
        ("evil[.]example[.]org", IType.DOMAIN, "evil.example.org"),
        ("bücher.de", IType.DOMAIN, "xn--bcher-kva.de"),
        ("hxxps://evil[.]com/login", IType.URL, "https://evil.com/login"),
        ("evil.com/path?a=1", IType.URL, "http://evil.com/path?a=1"),
        ("44D88612FEA8A8F36DE82E1278ABB02F", IType.HASH, "44d88612fea8a8f36de82e1278abb02f"),
        ("3395856ce81f2b7382dee72602f798b642f14140", IType.HASH, "3395856ce81f2b7382dee72602f798b642f14140"),
        ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", IType.HASH,
         "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"),
        ("John.Doe@Example.com", IType.EMAIL, "john.doe@example.com"),
        ("john[at]example[.]com", IType.EMAIL, "john@example.com"),
        ("+254 712 345678", IType.PHONE, "+254712345678"),
        ("cve-2021-44228", IType.CVE, "CVE-2021-44228"),
        ("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", IType.BTC, "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"),
        ("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", IType.BTC, "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"),
        ("0x742d35Cc6634C0532925a3b844Bc454e4438f44e", IType.ETH, "0x742d35cc6634c0532925a3b844bc454e4438f44e"),
        ("@johndoe", IType.USERNAME, "johndoe"),
        ("user:jane_doe", IType.USERNAME, "jane_doe"),
        ("10 Downing Street, London", IType.ADDRESS, "10 Downing Street, London"),
        ("address: 1600 Pennsylvania Ave", IType.ADDRESS, "1600 Pennsylvania Ave"),
    ],
)
def test_detect(raw, itype, value):
    ind = detect(raw)
    assert ind.type is itype
    assert ind.value == value


def test_private_ip_flagged():
    assert detect("192.168.1.10").meta["is_private"] is True


def test_hash_type_meta():
    assert detect("a" * 64).meta["hash_type"] == "sha256"


def test_phone_needs_region():
    with pytest.raises(DetectionError):
        detect("0712345678")
    assert detect("0712345678", phone_region="KE").value == "+254712345678"


def test_forced_type():
    assert detect("15169", forced=IType.ASN).value == "AS15169"
    with pytest.raises(DetectionError):
        detect("not-an-ip", forced=IType.IP)


def test_refang():
    assert refang("hxxp://a[.]b[.]c[/]x") == "http://a.b.c/x"


def test_garbage_rejected():
    with pytest.raises(DetectionError):
        detect("!!!")
