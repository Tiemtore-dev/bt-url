"""Protection SSRF — ne nécessite aucun réseau (IP littérales / localhost)."""

import pytest

from bt_url import netguard as ng


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1",
                                "169.254.169.254", "::1", "0.0.0.0", "fc00::1", "100.64.0.1"])
def test_non_public_ips_rejected(ip):
    assert not ng.is_public_ip(ip)


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_ips_accepted(ip):
    assert ng.is_public_ip(ip)


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "169.254.169.254", "[::1]", "", "10.1.2.3"])
def test_private_hosts_not_public(host):
    assert ng.host_is_public_sync(host) is False


def test_public_ip_literal_is_public():
    assert ng.host_is_public_sync("8.8.8.8") is True


async def test_follow_redirects_blocks_internal_target_without_request():
    out = await ng.follow_redirects("http://169.254.169.254/latest/meta-data/")
    assert out["blocked"] == "http://169.254.169.254/latest/meta-data/"
    assert out["chain"] == ["http://169.254.169.254/latest/meta-data/"]


async def test_resolver_rejects_loopback():
    with pytest.raises(OSError):
        await ng.PublicOnlyResolver().resolve("localhost", 80)
