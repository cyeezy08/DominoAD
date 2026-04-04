"""
smb_collector.py
----------------
Enumerates live sessions and local admins via SMB/RPC.
Uses impacket under the hood.

Collects:
  - Active sessions on each computer (who is logged in where)
  - Local group memberships (who is local admin on what)

Usage:
    collector = SMBCollector(config)
    sessions  = collector.get_sessions(computers)
    admins    = collector.get_local_admins(computers)
"""

import logging
from dataclasses import dataclass
from typing import Optional

from impacket.dcerpc.v5 import transport, srvs, samr, scmr
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.smbconnection import SMBConnection, SessionError

logger = logging.getLogger(__name__)


@dataclass
class SMBConfig:
    domain: str
    username: str
    password: str
    lm_hash: str = ""      # for pass-the-hash (leave empty if using password)
    nt_hash: str = ""      # for pass-the-hash
    timeout: int = 5


@dataclass
class Session:
    source_host: str       # computer we queried
    logged_on_user: str    # who is logged in
    client_name: str       # remote client name


@dataclass
class LocalAdmin:
    computer: str
    member_dn: str         # DN if resolvable, else raw name
    member_name: str
    is_group: bool


class SMBCollector:
    def __init__(self, config: SMBConfig):
        self.config = config

    # ------------------------------------------------------------------ #
    #  Sessions via NetSessionEnum (SRVSVC)                               #
    # ------------------------------------------------------------------ #

    def get_sessions(self, computers: list[dict]) -> list[Session]:
        """
        Query each computer for active sessions.
        Returns list of Session objects.
        """
        all_sessions = []
        for computer in computers:
            host = computer.get("dns_hostname") or computer.get("sam", "").rstrip("$")
            if not host:
                continue

            sessions = self._enum_sessions(host)
            all_sessions.extend(sessions)
            if sessions:
                logger.info(f"  [>] {host}: {len(sessions)} session(s)")

        logger.info(f"[+] Total sessions found: {len(all_sessions)}")
        return all_sessions

    def _enum_sessions(self, host: str) -> list[Session]:
        """NetSessionEnum against a single host."""
        sessions = []
        try:
            rpctransport = transport.SMBTransport(
                host,
                filename=r"\srvsvc",
                username=self.config.username,
                password=self.config.password,
                domain=self.config.domain,
                lmhash=self.config.lm_hash,
                nthash=self.config.nt_hash
            )
            rpctransport.set_connect_timeout(self.config.timeout)

            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(srvs.MSRPC_UUID_SRVS)

            resp = srvs.hNetrSessionEnum(dce, "\x00", NULL, 10)

            for session in resp["InfoStruct"]["SessionInfo"]["Level10"]["Buffer"]:
                user = session["sesi10_username"][:-1]   # strip null
                client = session["sesi10_cname"][:-1]
                if user and not user.startswith("$"):    # skip machine accounts
                    sessions.append(Session(
                        source_host=host,
                        logged_on_user=user,
                        client_name=client.lstrip("\\")
                    ))

            dce.disconnect()

        except (DCERPCException, SessionError, Exception) as e:
            logger.debug(f"  [-] Session enum failed on {host}: {e}")

        return sessions

    # ------------------------------------------------------------------ #
    #  Local admins via SAMR                                              #
    # ------------------------------------------------------------------ #

    def get_local_admins(self, computers: list[dict]) -> list[LocalAdmin]:
        """
        Enumerate local Administrators group on each computer via SAMR.
        Returns list of LocalAdmin objects.
        """
        all_admins = []
        for computer in computers:
            host = computer.get("dns_hostname") or computer.get("sam", "").rstrip("$")
            if not host:
                continue

            admins = self._enum_local_admins(host)
            all_admins.extend(admins)
            if admins:
                logger.info(f"  [>] {host}: {len(admins)} local admin(s)")

        logger.info(f"[+] Total local admin relationships: {len(all_admins)}")
        return all_admins

    def _enum_local_admins(self, host: str) -> list[LocalAdmin]:
        """Enumerate local Administrators group via SAMR on a single host."""
        admins = []
        try:
            rpctransport = transport.SMBTransport(
                host,
                filename=r"\samr",
                username=self.config.username,
                password=self.config.password,
                domain=self.config.domain,
                lmhash=self.config.lm_hash,
                nthash=self.config.nt_hash
            )
            rpctransport.set_connect_timeout(self.config.timeout)

            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)

            # Connect to server
            resp = samr.hSamrConnect(dce)
            server_handle = resp["ServerHandle"]

            # Open built-in domain (local groups live here)
            resp = samr.hSamrLookupDomainInSamServer(
                dce, server_handle, "Builtin"
            )
            domain_sid = resp["DomainId"]

            resp = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_sid)
            domain_handle = resp["DomainHandle"]

            # Look up Administrators group (RID 544)
            resp = samr.hSamrOpenAlias(dce, domain_handle, aliasId=544)
            alias_handle = resp["AliasHandle"]

            # Enumerate members
            resp = samr.hSamrGetMembersInAlias(dce, alias_handle)
            for member in resp["Members"]["Sids"]:
                sid_str = member["SidPointer"].formatCanonical()
                admins.append(LocalAdmin(
                    computer=host,
                    member_dn=sid_str,    # will be resolved later
                    member_name=sid_str,
                    is_group=False        # refined in graph builder
                ))

            dce.disconnect()

        except (DCERPCException, SessionError, Exception) as e:
            logger.debug(f"  [-] Local admin enum failed on {host}: {e}")

        return admins

    # ------------------------------------------------------------------ #
    #  Reachability check                                                  #
    # ------------------------------------------------------------------ #

    def check_smb_access(self, host: str) -> dict:
        """
        Quick SMB connectivity + auth check.
        Returns dict with host, accessible, writable_shares.
        """
        result = {"host": host, "accessible": False, "shares": []}
        try:
            conn = SMBConnection(host, host, timeout=self.config.timeout)
            conn.login(
                self.config.username,
                self.config.password,
                self.config.domain,
                lmhash=self.config.lm_hash,
                nthash=self.config.nt_hash
            )
            result["accessible"] = True

            shares = conn.listShares()
            for share in shares:
                share_name = share["shi1_netname"][:-1]
                result["shares"].append(share_name)

            conn.logoff()

        except (SessionError, Exception) as e:
            logger.debug(f"  [-] SMB check failed on {host}: {e}")

        return result


# Sentinel for SAMR NULL pointer
NULL = None
