"""Testy generatora konfiguracji nginx: pytest -q"""
from pathlib import Path

from fpscanner.tools.nginx_conf import render

KW = dict(server_cert="/s.pem", server_key="/s.key", client_ca="/ca.pem")
ROOT = Path(__file__).resolve().parent.parent


def test_committed_prod_config_matches_generator():
    expected = render(**{**KW, "server_cert": "/etc/fp/tls/server.pem",
                         "server_key": "/etc/fp/tls/server.key",
                         "client_ca": "/etc/fp/tls/client-ca.pem", "server_name": "fp.example.com"})
    assert (ROOT / "deploy" / "nginx.conf").read_text(encoding="utf-8") == expected, \
        "deploy/nginx.conf jest nieaktualny: python -m fpscanner.tools.nginx_conf --prod > deploy/nginx.conf"


def test_security_critical_directives_present_in_both_variants():
    for conf in (render(**KW), render(**KW, run_dir="/run")):
        assert "ssl_protocols           TLSv1.3;" in conf
        assert "ssl_verify_client       on;" in conf
        assert "proxy_set_header        X-Forwarded-For $remote_addr;" in conf   # nadpisanie
        assert "$proxy_add_x_forwarded_for" not in conf                           # nie dopisujemy
        assert "$ssl_client_escaped_cert" in conf and "$ssl_client_verify" in conf
        assert "limit_except POST" in conf and "client_max_body_size    64k;" in conf
        assert "location / { return 404; }" in conf


def test_dev_variant_is_self_contained_and_prod_has_no_header_logging():
    dev = render(**KW, run_dir="/run")
    assert "pid /run/nginx.pid;" in dev and "access_log off;" in dev and "events {" in dev
    prod = render(**KW)
    assert "events" not in prod and "pid " not in prod                    # fragment do conf.d/
    assert "log_format fp" in prod and "$http_" not in prod               # log bez nagłówków
