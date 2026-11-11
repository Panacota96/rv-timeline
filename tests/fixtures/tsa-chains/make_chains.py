#!/usr/bin/env python3
"""TSA certificate-path fixtures for the chain validation in src/core/src/trust.rs (test keys only).

  python3 tests/fixtures/tsa-chains/make_chains.py        rewrites cases/ and expected.json

Every case is a folder cases/<name>/ with leaf.pem (the TSA certificate), chain.pem (the certificates a token
would carry, in token order; absent when there are none) and anchors.pem (the --tsa-ca bundle, in bundle order).
expected.json gives, per case, the genTime to validate at, the verdict the Rust validator must reach ("ok" or a
fragment of its error message) and the verdict of an independent validator, recorded when the fixtures are made:

  openssl verify -purpose timestampsign -attime <genTime> -CAfile anchors.pem [-untrusted chain.pem] leaf.pem

The Rust test (trust::tests::chain_fixtures_match_expected_and_openssl) requires the two verdicts to agree (both
"ok", or both rejected) unless the case carries a "deliberate_difference" saying why the tool is stricter. The
expected verdicts are written here by hand, before and independently of the validator, and OpenSSL checks them.
"""

from __future__ import annotations

import datetime as dt
import json
import shutil
import subprocess
from pathlib import Path

from asn1crypto import keys as a_keys
from asn1crypto import x509 as a_x509
from cryptography import x509 as cx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

HERE = Path(__file__).resolve().parent
GEN_TIME = dt.datetime(2026, 6, 1, tzinfo=dt.UTC)
NB = dt.datetime(2020, 1, 1, tzinfo=dt.UTC)
NA = dt.datetime(2040, 1, 1, tzinfo=dt.UTC)
_keys: dict[str, rsa.RSAPrivateKey] = {}


def key(label: str) -> rsa.RSAPrivateKey:
    if label not in _keys:
        _keys[label] = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return _keys[label]


def nm(cn: str, o: str = "Rakvor TEST") -> cx.Name:
    """O first, then CN: a directoryName constraint on O=… is then a prefix of the subject's RDN sequence."""
    return cx.Name([cx.NameAttribute(NameOID.ORGANIZATION_NAME, o), cx.NameAttribute(NameOID.COMMON_NAME, cn)])


def cert(subject, issuer, k, issuer_k, *, ca=False, pathlen=None, ku=None, eku=(ExtendedKeyUsageOID.TIME_STAMPING,),
         eku_critical=True, extra=(), nb=NB, na=NA, bc=True):
    b = (cx.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(k.public_key())
         .serial_number(cx.random_serial_number()).not_valid_before(nb).not_valid_after(na)
         .add_extension(cx.SubjectKeyIdentifier.from_public_key(k.public_key()), critical=False)
         .add_extension(cx.AuthorityKeyIdentifier.from_issuer_public_key(issuer_k.public_key()), critical=False))
    if bc:
        b = b.add_extension(cx.BasicConstraints(ca=ca, path_length=pathlen if ca else None), critical=True)
    if ca:
        b = b.add_extension(cx.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                        data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                        crl_sign=True, encipher_only=False, decipher_only=False)
                            if ku is None else ku, critical=True)
    elif ku is not None:
        b = b.add_extension(ku, critical=True)
    if not ca and eku:
        b = b.add_extension(cx.ExtendedKeyUsage(list(eku)), critical=eku_critical)
    for ext, crit in extra:
        b = b.add_extension(ext, critical=crit)
    return b.sign(issuer_k, hashes.SHA256())


def ca(subject, issuer, k, issuer_k, **kw):
    return cert(subject, issuer, k, issuer_k, ca=True, **kw)


def root(cn="Rakvor TEST Root", label="root", **kw):
    return ca(nm(cn), nm(cn), key(label), key(label), **kw)


def tsa(issuer_cert, issuer_label, cn="Rakvor TEST TSA", o="Rakvor TEST", label="tsa", **kw):
    return cert(nm(cn, o), issuer_cert.subject, key(label), key(issuer_label), **kw)


def v1_root(cn: str, label: str) -> cx.Certificate:
    """X.509 v1 self-signed root (no extensions), as some legacy TSA hierarchies still use."""
    k = key(label)
    name = a_x509.Name.build({"organization_name": "Rakvor TEST", "common_name": cn})
    tbs = a_x509.TbsCertificate({
        "version": "v1", "serial_number": 4242, "signature": {"algorithm": "sha256_rsa"}, "issuer": name,
        "validity": {"not_before": a_x509.Time({"utc_time": NB}), "not_after": a_x509.Time({"utc_time": NA - dt.timedelta(days=1)})},
        "subject": name,
        "subject_public_key_info": a_keys.PublicKeyInfo.load(k.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)),
    })
    sig = k.sign(tbs.dump(), padding.PKCS1v15(), hashes.SHA256())
    c = a_x509.Certificate({"tbs_certificate": tbs, "signature_algorithm": {"algorithm": "sha256_rsa"},
                            "signature_value": sig})
    return cx.load_der_x509_certificate(c.dump())


def dirname_nc(permitted=None, excluded=None):
    return cx.NameConstraints(permitted_subtrees=permitted, excluded_subtrees=excluded)


def build() -> dict[str, dict]:
    cases: dict[str, dict] = {}

    def add(name, leaf, chain, anchors, expect, diff=None):
        cases[name] = {"leaf": leaf, "chain": chain, "anchors": anchors, "expect": expect}
        if diff:
            cases[name]["deliberate_difference"] = diff

    r = root()
    i = ca(nm("Rakvor TEST Intermediate"), r.subject, key("int"), key("root"))
    add("ok_root_issues_tsa", tsa(r, "root"), [], [r], "ok")
    add("ok_intermediate", tsa(i, "int"), [i], [r], "ok")

    # RFC 3161 §2.3: the EKU is critical and contains only id-kp-timeStamping.
    add("eku_noncritical", tsa(i, "int", eku_critical=False), [i], [r], "must be critical")
    add("eku_multipurpose", tsa(i, "int", eku=(ExtendedKeyUsageOID.TIME_STAMPING, ExtendedKeyUsageOID.SERVER_AUTH)),
        [i], [r], "only id-kp-timeStamping")
    add("eku_missing", tsa(i, "int", eku=()), [i], [r], "lacks the timeStamping extended key usage")

    # pathLenConstraint.
    i0 = ca(nm("Rakvor TEST Int pathlen0"), r.subject, key("int0"), key("root"), pathlen=0)
    sub = ca(nm("Rakvor TEST Sub CA"), i0.subject, key("sub"), key("int0"))
    add("pathlen0_violated", tsa(sub, "sub"), [sub, i0], [r], "pathLenConstraint")
    i1 = ca(nm("Rakvor TEST Int pathlen1"), r.subject, key("int1"), key("root"), pathlen=1)
    sub1 = ca(nm("Rakvor TEST Sub CA 1"), i1.subject, key("sub1"), key("int1"))
    add("pathlen1_ok", tsa(sub1, "sub1"), [sub1, i1], [r], "ok")
    r0 = root("Rakvor TEST Root pathlen0", "root0", pathlen=0)
    i_r0 = ca(nm("Rakvor TEST Int under pathlen0 root"), r0.subject, key("int_r0"), key("root0"))
    add("root_pathlen0_violated", tsa(i_r0, "int_r0"), [i_r0], [r0], "pathLenConstraint")
    # Key rollover: a self-issued intermediate (same name, new key, signed with the old key) does not count.
    roll = ca(i0.subject, i0.subject, key("int0_new"), key("int0"))
    add("pathlen0_selfissued_rollover_ok", tsa(roll, "int0_new"), [roll, i0], [r], "ok")

    # keyUsage of issuers.
    no_cs = ca(nm("Rakvor TEST Int no keyCertSign"), r.subject, key("int_nocs"), key("root"),
               ku=cx.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                              data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=True,
                              encipher_only=False, decipher_only=False))
    add("issuer_keyusage_without_keycertsign", tsa(no_cs, "int_nocs"), [no_cs], [r], "keyCertSign")
    not_ca = cert(nm("Rakvor TEST Int not a CA"), r.subject, key("int_notca"), key("root"), eku=())
    add("issuer_not_a_ca", tsa(not_ca, "int_notca"), [not_ca], [r], "not a CA")
    r_nobc = root("Rakvor TEST Root without basicConstraints", "root_nobc", bc=False)
    add("anchor_without_basicconstraints_with_keycertsign_ok", tsa(r_nobc, "root_nobc"), [], [r_nobc], "ok")
    r_bare = cert(nm("Rakvor TEST Root without CA marks"), nm("Rakvor TEST Root without CA marks"), key("root_bare"),
                  key("root_bare"), bc=False, eku=())
    add("anchor_without_basicconstraints_or_keyusage", tsa(r_bare, "root_bare"), [], [r_bare], "not a CA")
    rv1 = v1_root("Rakvor TEST v1 Root", "root_v1")
    i_v1 = ca(nm("Rakvor TEST Int under v1 root"), rv1.subject, key("int_v1"), key("root_v1"))
    add("anchor_v1_ok", tsa(i_v1, "int_v1"), [i_v1], [rv1], "ok")

    # Critical extensions: unknown ones fail closed, on any certificate of the path.
    unk = cx.UnrecognizedExtension(ObjectIdentifier("1.3.6.1.4.1.55555.1.1"), b"\x05\x00")
    i_unk = ca(nm("Rakvor TEST Int unknown critical"), r.subject, key("int_unk"), key("root"), extra=[(unk, True)])
    add("unknown_critical_on_intermediate", tsa(i_unk, "int_unk"), [i_unk], [r], "unsupported critical extension")
    add("unknown_critical_on_tsa", tsa(i, "int", extra=[(unk, True)]), [i], [r], "unsupported critical extension")
    i_unk_nc = ca(nm("Rakvor TEST Int unknown non-critical"), r.subject, key("int_unknc"), key("root"),
                  extra=[(unk, False)])
    add("unknown_noncritical_ok", tsa(i_unk_nc, "int_unknc"), [i_unk_nc], [r], "ok")
    i_pc = ca(nm("Rakvor TEST Int policyConstraints"), r.subject, key("int_pc"), key("root"),
              extra=[(cx.PolicyConstraints(require_explicit_policy=0, inhibit_policy_mapping=None), True)])
    add("policy_constraints_critical", tsa(i_pc, "int_pc"), [i_pc], [r], "unsupported critical extension",
        diff="certificate-policy processing (RFC 5280 §6.1.3(d)-(f), §6.1.4(a)-(j)) is not implemented, so critical "
             "policyConstraints, policyMappings and inhibitAnyPolicy fail closed; OpenSSL processes them.")
    i_cp = ca(nm("Rakvor TEST Int critical policies"), r.subject, key("int_cp"), key("root"),
              extra=[(cx.CertificatePolicies([cx.PolicyInformation(ObjectIdentifier("2.5.29.32.0"), None)]), True)])
    add("certificate_policies_critical_ok", tsa(i_cp, "int_cp"), [i_cp], [r], "ok")

    # nameConstraints (directoryName evaluated; other name forms only when the path carries such names).
    perm = dirname_nc(permitted=[cx.DirectoryName(cx.Name([cx.NameAttribute(NameOID.ORGANIZATION_NAME, "Rakvor TEST")]))])
    r_nc = root("Rakvor TEST Root constrained", "root_nc", extra=[(perm, True)])
    i_nc = ca(nm("Rakvor TEST Int constrained"), r_nc.subject, key("int_nc"), key("root_nc"))
    add("nc_dirname_permitted_ok", tsa(i_nc, "int_nc"), [i_nc], [r_nc], "ok")
    add("nc_dirname_permitted_violated", tsa(i_nc, "int_nc", o="Other Org"), [i_nc], [r_nc], "name constraints")
    excl = dirname_nc(excluded=[cx.DirectoryName(nm("Evil TSA"))])
    i_ex = ca(nm("Rakvor TEST Int excluding"), r.subject, key("int_ex"), key("root"), extra=[(excl, True)])
    add("nc_dirname_excluded", tsa(i_ex, "int_ex", cn="Evil TSA", label="tsa_evil"), [i_ex], [r], "name constraints")
    add("nc_dirname_excluded_other_name_ok", tsa(i_ex, "int_ex"), [i_ex], [r], "ok")
    # Excluded base in another string type, case and spacing: RFC 5280 §7.1 matching still excludes it.
    excl2 = dirname_nc(excluded=[cx.DirectoryName(cx.Name([
        cx.NameAttribute(NameOID.ORGANIZATION_NAME, "RAKVOR  test", _type=cx.name._ASN1Type.PrintableString),
        cx.NameAttribute(NameOID.COMMON_NAME, "evil tsa", _type=cx.name._ASN1Type.PrintableString)]))])
    i_ex2 = ca(nm("Rakvor TEST Int excluding (printable)"), r.subject, key("int_ex2"), key("root"),
               extra=[(excl2, True)])
    add("nc_dirname_excluded_case_and_spacing", tsa(i_ex2, "int_ex2", cn="Evil TSA", label="tsa_evil"), [i_ex2], [r],
        "name constraints")
    dns = dirname_nc(permitted=[cx.DNSName("rakvor.test")])
    i_dns = ca(nm("Rakvor TEST Int DNS constrained"), r.subject, key("int_dns"), key("root"), extra=[(dns, True)])
    add("nc_dns_without_dns_names_ok", tsa(i_dns, "int_dns"), [i_dns], [r], "ok")
    san = cx.SubjectAlternativeName([cx.DNSName("tsa.rakvor.test")])
    add("nc_dns_with_dns_san_not_evaluated", tsa(i_dns, "int_dns", extra=[(san, False)]), [i_dns], [r],
        "cannot be evaluated",
        diff="dNSName constraints are not evaluated: a path whose certificates carry dNSName names under a dNSName "
             "constraint is rejected (fail closed); OpenSSL evaluates it and accepts.")

    # Path building: the first candidate issuer or anchor is not always the right one.
    other = root("Rakvor TEST Other Root", "root_other")
    i_x_other = ca(i.subject, other.subject, key("int"), key("root_other"))
    t = tsa(i, "int")
    add("cross_signed_good_candidate_first", t, [i, i_x_other], [r], "ok")
    add("cross_signed_first_candidate_untrusted", t, [i_x_other, i], [r], "ok",
        diff="the path search backtracks over every candidate issuer; OpenSSL 3.0 keeps the first untrusted candidate "
             "and fails (the same certificates in the other order verify: cross_signed_good_candidate_first).")
    i_expired = ca(i.subject, r.subject, key("int"), key("root"), nb=dt.datetime(2015, 1, 1, tzinfo=dt.UTC),
                   na=dt.datetime(2025, 1, 1, tzinfo=dt.UTC))
    add("cross_signed_first_candidate_expired", tsa(i, "int"), [i_expired, i], [r], "ok")
    r_old = ca(r.subject, r.subject, key("root"), key("root"), nb=dt.datetime(2010, 1, 1, tzinfo=dt.UTC),
               na=dt.datetime(2025, 1, 1, tzinfo=dt.UTC))
    add("renewed_anchor_after_expired_one", tsa(i, "int"), [i], [r_old, r], "ok")
    add("only_expired_anchor", tsa(i, "int"), [i], [r_old], "not valid at the token's genTime")
    add("untrusted_root", tsa(i, "int"), [i], [other], "no trusted issuer")
    # A loop (A issued by B, B issued by A) ends; so does a path longer than the depth limit.
    a = ca(nm("Rakvor TEST Loop A"), nm("Rakvor TEST Loop B"), key("loop_a"), key("loop_b"))
    b = ca(nm("Rakvor TEST Loop B"), nm("Rakvor TEST Loop A"), key("loop_b"), key("loop_a"))
    add("issuer_loop", tsa(a, "loop_a"), [a, b], [r], "no trusted issuer")
    chain, up, up_label = [], r, "root"
    for n in range(10):
        c = ca(nm(f"Rakvor TEST Deep {n}"), up.subject, key(f"deep{n}"), key(up_label))
        chain.insert(0, c)
        up, up_label = c, f"deep{n}"
    add("path_too_long", tsa(up, up_label), chain, [r], "too long",
        diff="paths are limited to 8 certificates below the anchor (bounded search); OpenSSL's default depth is 100.")
    return cases


def pem(certs) -> bytes:
    return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs)


def openssl_verdict(d: Path) -> str:
    cmd = ["openssl", "verify", "-purpose", "timestampsign", "-attime", str(int(GEN_TIME.timestamp())),
           "-CAfile", str(d / "anchors.pem")]
    if (d / "chain.pem").exists():
        cmd += ["-untrusted", str(d / "chain.pem")]
    out = subprocess.run(cmd + [str(d / "leaf.pem")], capture_output=True, text=True)
    if out.returncode == 0:
        return "ok"
    lines = [l.strip() for l in (out.stdout + out.stderr).splitlines() if l.strip().startswith("error ")]
    return lines[0].split(": ", 1)[-1] if lines else "rejected"


def main() -> None:
    cases_dir = HERE / "cases"
    shutil.rmtree(cases_dir, ignore_errors=True)
    expected = {"gen_time": GEN_TIME.strftime("%Y-%m-%dT%H:%M:%SZ"), "openssl": subprocess.run(
        ["openssl", "version"], capture_output=True, text=True).stdout.strip(), "cases": {}}
    for name, c in build().items():
        d = cases_dir / name
        d.mkdir(parents=True)
        (d / "leaf.pem").write_bytes(pem([c["leaf"]]))
        if c["chain"]:
            (d / "chain.pem").write_bytes(pem(c["chain"]))
        (d / "anchors.pem").write_bytes(pem(c["anchors"]))
        entry = {"expect": c["expect"], "openssl": openssl_verdict(d)}
        if "deliberate_difference" in c:
            entry["deliberate_difference"] = c["deliberate_difference"]
        agree = (entry["expect"] == "ok") == (entry["openssl"] == "ok")
        if not agree and "deliberate_difference" not in entry:
            raise SystemExit(f"{name}: expected {entry['expect']!r} but OpenSSL says {entry['openssl']!r}")
        expected["cases"][name] = entry
    (HERE / "expected.json").write_text(json.dumps(expected, indent=2) + "\n")
    print(f"{len(expected['cases'])} cases written to {cases_dir}")


if __name__ == "__main__":
    main()
