"""
ldap_collector.py
-----------------
Enumerates Active Directory objects via LDAP.
Collects: users, groups, computers, OUs, GPOs, memberships.

Usage:
    collector = LDAPCollector(config)
    collector.connect()
    data = collector.collect_all()
"""

import logging
from dataclasses import dataclass, field
from typing import Optional
from ldap3 import (
    Server, Connection, ALL, NTLM, SIMPLE,
    SUBTREE, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES
)
from ldap3.core.exceptions import LDAPException

logger = logging.getLogger(__name__)


@dataclass
class LDAPConfig:
    host: str
    domain: str                        # e.g. "corp.local"
    username: str                      # e.g. "corp\\administrator"
    password: str
    port: int = 389
    use_ssl: bool = False
    auth_method: str = "NTLM"         # NTLM or SIMPLE


@dataclass
class ADData:
    users: list = field(default_factory=list)
    groups: list = field(default_factory=list)
    computers: list = field(default_factory=list)
    ous: list = field(default_factory=list)
    gpos: list = field(default_factory=list)
    memberships: list = field(default_factory=list)  # (member_dn, group_dn)


class LDAPCollector:
    def __init__(self, config: LDAPConfig):
        self.config = config
        self.conn: Optional[Connection] = None
        self.base_dn = self._domain_to_dn(config.domain)

    # ------------------------------------------------------------------ #
    #  Connection                                                          #
    # ------------------------------------------------------------------ #

    def connect(self) -> bool:
        """Establish LDAP connection. Returns True on success."""
        try:
            server = Server(
                self.config.host,
                port=self.config.port,
                use_ssl=self.config.use_ssl,
                get_info=ALL
            )

            auth = NTLM if self.config.auth_method == "NTLM" else SIMPLE

            self.conn = Connection(
                server,
                user=self.config.username,
                password=self.config.password,
                authentication=auth,
                auto_bind=True
            )

            logger.info(f"[+] Connected to {self.config.host} as {self.config.username}")
            return True

        except LDAPException as e:
            logger.error(f"[-] LDAP connection failed: {e}")
            return False

    def disconnect(self):
        if self.conn:
            self.conn.unbind()

    # ------------------------------------------------------------------ #
    #  Core collector                                                      #
    # ------------------------------------------------------------------ #

    def collect_all(self) -> ADData:
        """Run all collection modules. Returns ADData."""
        if not self.conn:
            raise RuntimeError("Not connected. Call connect() first.")

        data = ADData()
        data.users = self.get_users()
        data.groups = self.get_groups()
        data.computers = self.get_computers()
        data.ous = self.get_ous()
        data.gpos = self.get_gpos()
        data.memberships = self.get_memberships()

        logger.info(
            f"[+] Collection complete: "
            f"{len(data.users)} users, "
            f"{len(data.groups)} groups, "
            f"{len(data.computers)} computers"
        )
        return data

    # ------------------------------------------------------------------ #
    #  LDAP query helpers                                                  #
    # ------------------------------------------------------------------ #

    def _search(self, search_filter: str, attributes: list) -> list:
        """Generic paged LDAP search against base DN."""
        results = []
        try:
            self.conn.search(
                search_base=self.base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=attributes,
                paged_size=1000         # handle large directories
            )
            for entry in self.conn.entries:
                results.append(entry)

            # Handle paged results
            cookie = self.conn.result.get("controls", {}).get(
                "1.2.840.113556.1.4.319", {}
            ).get("value", {}).get("cookie")

            while cookie:
                self.conn.search(
                    search_base=self.base_dn,
                    search_filter=search_filter,
                    search_scope=SUBTREE,
                    attributes=attributes,
                    paged_size=1000,
                    paged_cookie=cookie
                )
                for entry in self.conn.entries:
                    results.append(entry)
                cookie = self.conn.result.get("controls", {}).get(
                    "1.2.840.113556.1.4.319", {}
                ).get("value", {}).get("cookie")

        except LDAPException as e:
            logger.warning(f"[-] Search failed ({search_filter}): {e}")

        return results

    # ------------------------------------------------------------------ #
    #  Object collectors                                                   #
    # ------------------------------------------------------------------ #

    def get_users(self) -> list[dict]:
        """Enumerate all user accounts."""
        entries = self._search(
            search_filter="(&(objectCategory=person)(objectClass=user))",
            attributes=[
                "sAMAccountName", "distinguishedName", "displayName",
                "mail", "memberOf", "userAccountControl",
                "lastLogonTimestamp", "pwdLastSet", "adminCount",
                "servicePrincipalName", "description"
            ]
        )

        users = []
        for e in entries:
            uac = self._get_attr(e, "userAccountControl", 0)
            users.append({
                "type": "user",
                "sam": self._get_attr(e, "sAMAccountName"),
                "dn": self._get_attr(e, "distinguishedName"),
                "display_name": self._get_attr(e, "displayName"),
                "email": self._get_attr(e, "mail"),
                "member_of": self._get_attr_list(e, "memberOf"),
                "enabled": not bool(uac & 0x2),
                "admin_count": self._get_attr(e, "adminCount", 0),
                "spns": self._get_attr_list(e, "servicePrincipalName"),
                "description": self._get_attr(e, "description"),
                # Derived flags
                "is_kerberoastable": len(self._get_attr_list(e, "servicePrincipalName")) > 0,
                "password_never_expires": bool(uac & 0x10000),
                "no_preauth_required": bool(uac & 0x400000),   # ASREPRoastable
            })

        logger.info(f"  [>] Users: {len(users)}")
        return users

    def get_groups(self) -> list[dict]:
        """Enumerate all groups."""
        entries = self._search(
            search_filter="(objectClass=group)",
            attributes=[
                "sAMAccountName", "distinguishedName",
                "member", "memberOf", "adminCount", "description",
                "groupType"
            ]
        )

        groups = []
        for e in entries:
            groups.append({
                "type": "group",
                "sam": self._get_attr(e, "sAMAccountName"),
                "dn": self._get_attr(e, "distinguishedName"),
                "members": self._get_attr_list(e, "member"),
                "member_of": self._get_attr_list(e, "memberOf"),
                "admin_count": self._get_attr(e, "adminCount", 0),
                "description": self._get_attr(e, "description"),
                "group_type": self._get_attr(e, "groupType"),
            })

        logger.info(f"  [>] Groups: {len(groups)}")
        return groups

    def get_computers(self) -> list[dict]:
        """Enumerate all computer accounts."""
        entries = self._search(
            search_filter="(objectClass=computer)",
            attributes=[
                "sAMAccountName", "distinguishedName", "dNSHostName",
                "operatingSystem", "operatingSystemVersion",
                "lastLogonTimestamp", "userAccountControl",
                "servicePrincipalName", "memberOf"
            ]
        )

        computers = []
        for e in entries:
            uac = self._get_attr(e, "userAccountControl", 0)
            computers.append({
                "type": "computer",
                "sam": self._get_attr(e, "sAMAccountName"),
                "dn": self._get_attr(e, "distinguishedName"),
                "dns_hostname": self._get_attr(e, "dNSHostName"),
                "os": self._get_attr(e, "operatingSystem"),
                "os_version": self._get_attr(e, "operatingSystemVersion"),
                "enabled": not bool(uac & 0x2),
                "spns": self._get_attr_list(e, "servicePrincipalName"),
                "member_of": self._get_attr_list(e, "memberOf"),
            })

        logger.info(f"  [>] Computers: {len(computers)}")
        return computers

    def get_ous(self) -> list[dict]:
        """Enumerate Organizational Units."""
        entries = self._search(
            search_filter="(objectClass=organizationalUnit)",
            attributes=["distinguishedName", "name", "description", "gpLink"]
        )

        ous = []
        for e in entries:
            ous.append({
                "type": "ou",
                "dn": self._get_attr(e, "distinguishedName"),
                "name": self._get_attr(e, "name"),
                "description": self._get_attr(e, "description"),
                "gp_link": self._get_attr(e, "gpLink"),
            })

        logger.info(f"  [>] OUs: {len(ous)}")
        return ous

    def get_gpos(self) -> list[dict]:
        """Enumerate Group Policy Objects."""
        entries = self._search(
            search_filter="(objectClass=groupPolicyContainer)",
            attributes=["distinguishedName", "displayName", "gPCFileSysPath", "versionNumber"]
        )

        gpos = []
        for e in entries:
            gpos.append({
                "type": "gpo",
                "dn": self._get_attr(e, "distinguishedName"),
                "name": self._get_attr(e, "displayName"),
                "path": self._get_attr(e, "gPCFileSysPath"),
                "version": self._get_attr(e, "versionNumber"),
            })

        logger.info(f"  [>] GPOs: {len(gpos)}")
        return gpos

    def get_memberships(self) -> list[tuple]:
        """
        Returns flat list of (member_dn, group_dn) edges.
        Used by graph builder to create memberOf edges.
        """
        entries = self._search(
            search_filter="(|(objectClass=user)(objectClass=group)(objectClass=computer))",
            attributes=["distinguishedName", "memberOf"]
        )

        edges = []
        for e in entries:
            member_dn = self._get_attr(e, "distinguishedName")
            for group_dn in self._get_attr_list(e, "memberOf"):
                edges.append((member_dn, group_dn))

        logger.info(f"  [>] Membership edges: {len(edges)}")
        return edges

    # ------------------------------------------------------------------ #
    #  Utilities                                                           #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _domain_to_dn(domain: str) -> str:
        """Convert 'corp.local' → 'DC=corp,DC=local'"""
        return ",".join(f"DC={part}" for part in domain.split("."))

    @staticmethod
    def _get_attr(entry, attr: str, default=None):
        """Safely get a single attribute value from an ldap3 entry."""
        try:
            val = getattr(entry, attr).value
            return val if val is not None else default
        except Exception:
            return default

    @staticmethod
    def _get_attr_list(entry, attr: str) -> list:
        """Safely get a multi-value attribute as a list."""
        try:
            val = getattr(entry, attr).values
            return list(val) if val else []
        except Exception:
            return []
