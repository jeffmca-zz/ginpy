import os
import sys
from lxml import etree
from jnpr.junos import Device
import ipaddress


class InterfaceUnitCFG:
    """A class providing a programatic interface to individual units of network interfaces defined in a Juniper config XML file.

    The class essentially wraps an etree Element of a Juniper "interfaces { interface { <intname> { unit { <unitnum }}}}".  Methods are
    provided to inspect what the current configuration is, and to modify it.
    """

    def __init__(self, intobj, unitnum):
        self.unitnum = unitnum
        self.parent = intobj
        for unit in intobj.xmlconfig.findall("./unit"):
            if unit.find("name").text == unitnum:
                    self.xmlconfig = unit

    def is_switchport(self):
        return self.has_ethernet_switching()

    def is_trunk(self):
        if not is_switchport():
            return False
        else:
            if self.xmlconfig.find(".//family/ethernet-switching/interface-mode").text == "trunk":
                return True
            else:
                return False

    def has_ccc(self):
        if self.xmlconfig.find(".//family/ccc") != None:
            return True
        else:
            return False

    def has_ethernet_switching(self):
        if self.xmlconfig.find(".//family/ethernet-switching") != None:
            return True
        else:
            return False

    def has_ipv4(self):
        if self.xmlconfig.find(".//family/inet") != None:
            return True
        else:
            return False

    def has_ipv6(self):
        if self.xmlconfig.find(".//family/inet6") != None:
            return True
        else:
            return False

    def has_ip(self):
        if self.has_ipv4() or self.has_ipv6():
            return True
        else:
            return False

    def has_mpls(self):
        if self.xmlconfig.find(".//family/mpls") != None:
            return True
        else:
            return False
        
    def has_vpls(self):
        if self.xmlconfig.find(".//family/vpls") != None:
            return True
        else:
            return False
    
    def get_vlans(self):
        """
        Returns a list of vlan names configured on the unit "family ethernet-switching vlan members <list>
        """
        if self.has_ethernet_switching():
            vlans = []
            elements = self.xmlconfig.findall(".//family/ethernet-switching/vlan/members")
            for vlan in elements:
                vlans.append(vlan.text)
            return vlans
        else:
            pass

    def add_vlan(self, vlan_name):
        if not self.has_ethernet_switching():
            raise ValueError("Unit isn't configured for ethernet_switching")
        else:
            if vlan_name in self.get_vlans():
                raise ValueError("Unit already configured for vlan {}".format(vlan_name))
            else:
                vlanelement = self.xmlconfig.find("./family/ethernet-switching/vlan")
                etree.SubElement(vlanelement, "members").text = vlan_name

    def remove_vlan(self, vlan_name):
        if not self.has_ethernet_switching():
            raise ValueError("Unit isn't configured for ethernet_switching")
        else:
            if vlan_name not in self.get_vlans():
                raise ValueError("Unit doesn't have vlan {} configured".format(vlan_name))
            else:
                vlancfg = self.xmlconfig.find("./family/ethernet-switching/vlan")
                for member in self.xmlconfig.findall("./family/ethernet-switching/vlan/members"):
                    if member.text == vlan_name:
                        vlancfg.remove(member)


    def get_ipv4(self):
        """
        Returns a list of ipaddress.IPv4Interface objects for each IPv4 address defined on an interface unit (each
        "family inet address" entry.
        """
        faminet = self.xmlconfig.find(".//family/inet")
        v4addrs = []
        if len(faminet) == 0:
            pass
        else:
            for child in faminet.findall("./address"):
                v4addrs.append(ipaddress.IPv4Interface(child.find("./name").text))
        return v4addrs

    def get_ipv6(self):
        """
        Returns a list of ipaddress.IPv6Interface objects for each IPv6 address defined on an interface unit (each
        "family inet address" entry.
        """
        faminet = self.xmlconfig.find(".//family/inet6")
        v6addrs = []
        if len(faminet) == 0:
            pass
        else:
            for child in faminet.findall("./address"):
                v6addrs.append(ipaddress.IPv6Interface(child.find("./name").text))
        return v6addrs

    def get_ip(self):
        """
        Returns a list of ipaddress.IPv4Interface and ipaddress.IPv6Interface objects for each IP address defined on
        an interface unit (each "family inet address" and "family inet6 address" entry)
        """
        return self.get_ipv6() + self.get_ipv4()

    def add_ipv4(self, ipv4str):
        """
        Adds an IPv4 address on an interface.
        """
        v4addr = ipaddress.IPv4Interface(ipv4str)
        if v4addr in self.get_ipv4():
            raise ValueError("IPv4 address already exists on interface unit")
        else:
            inetfam = self.xmlconfig.find("./family/inet")
            etree.SubElement(etree.SubElement(inetfam, "address"), "name").text = v4addr.with_prefixlen

    def add_ipv6(self, ipv6str):
        """
        Adds an IPv6 address on an interface.
        """
        v6addr = ipaddress.IPv6Interface(ipv6str)
        if v6addr in self.get_ipv6():
            raise ValueError("IPv6 address already exists on interface unit")
        else:
            inetfam = self.xmlconfig.find("./family/inet6")
            etree.SubElement(etree.SubElement(inetfam, "address"), "name").text = v6addr.with_prefixlen

    def add_ip(self,ipstr):
        """
        Adds either an IPv4 or IPv6 address to an interface unit.  Attempts to autodetect which address family to use based
        on Python's ipaddress library.
        """
        addr = ipaddress.ip_interface(ipstr)
        if addr.version == 4:
            self.add_ipv4(addr.with_prefixlen)
        elif addr.version == 6:
            self.add_ipv6(addr.with_prefixlen)

    def remove_ipv4(self, ipv4str):
        v4addr = ipaddress.IPv4Interface(ipv4str)
        if not self.has_ipv4():
            raise ValueError("Unit isn't configured for family inet (IPv4)")
        else:
            if v4addr not in self.get_ipv4():
                raise ValueError("Unit doesn't have inet (IPv4) address {} configured".format(v4addr.with_prefixlen))
            else:
                faminetcfg = self.xmlconfig.find("./family/inet")
                for addrcfg in self.xmlconfig.findall("./family/inet/address"):
                    if addrcfg.find("./name").text == v4addr.with_prefixlen:
                        faminetcfg.remove(addrcfg)

    def remove_ipv6(self, ipv6str):
        v6addr = ipaddress.IPv6Interface(ipv6str)
        if not self.has_ipv6():
            raise ValueError("Unit isn't configured for family inet6 (IPv6)")
        else:
            if v6addr not in self.get_ipv6():
                raise ValueError("Unit doesn't have inet6 (IPv6) address {} configured".format(v6addr.with_prefixlen))
            else:
                faminetcfg = self.xmlconfig.find("./family/inet6")
                for addrcfg in self.xmlconfig.findall("./family/inet6/address"):
                    if addrcfg.find("./name").text == v6addr.with_prefixlen:
                        faminetcfg.remove(addrcfg)

    def remove_ip(self,ipstr):
        """
        Removes either an IPv4 or IPv6 address to an interface unit.  Attempts to autodetect which address family to use based
        on Python's ipaddress library.
        """
        addr = ipaddress.ip_interface(ipstr)
        if addr.version == 4:
            self.remove_ipv4(addr.with_prefixlen)
        elif addr.version == 6:
            self.remove_ipv6(addr.with_prefixlen)

    def get_ipv4_mtu_setting(self):
        if self.xmlconfig.find("./family/inet/mtu") == None:
            return 0
        else:
            return int(self.xmlconfig.find("./family/inet/mtu").text)

    def get_ipv6_mtu_setting(self):
        if self.xmlconfig.find("./family/inet6/mtu") == None:
            return 0
        else:
            return int(self.xmlconfig.find("./family/inet6/mtu").text)

    def set_ipv4_mtu(self, mtu):
        faminet = self.xmlconfig.find("./family/inet")
        if mtu == 0:
            if faminet.find("./mtu") == None:
                pass
            else:
                faminet.remove(faminet.find("./mtu"))
        else:
            if faminet.find("./mtu") == None:
                etree.SubElement(faminet, "mtu").text = str(mtu)
            else:
                faminet.find("./mtu").text = str(mtu)

    def set_ipv6_mtu(self, mtu):
        faminet6 = self.xmlconfig.find("./family/inet6")
        if mtu == 0:
            if faminet6.find("./mtu") == None:
                pass
            else:
                faminet6.remove(faminet6.find("./mtu"))
        else:
            if faminet6.find("./mtu") == None:
                etree.SubElement(faminet6, "mtu").text = str(mtu)
            else:
                faminet6.find("./mtu").text = str(mtu)

    @classmethod
    def get_unit_nums(cls, intcfg):
        """
        Returns a list of unit numbers (as integers) defined on an interface passed into the method.
        """
        pass

class InterfaceCFG:
    """A class providing a programatic interface to network interfaces defined in a Juniper config XML file.

    The class essentially wraps an etree Element of a Juniper "interfaces { interface { <intname> }}".  Methods are provided to inspect
    what the current configuration is, and to modify it.
    """

    def __init__(self, junosdevcfg, intname):
        """Create an Interface Object.  Pass in a top-level JConfig Object, and a
        name of an interface.
        """
        self.name = intname
        self.parent = junosdevcfg
        for interface in junosdevcfg.xmlconfig.findall("./interfaces/interface"):
            if interface.find("name").text == intname:
                self.xmlconfig = interface

    def has_vlan_tagging(self):
        if self.xmlconfig.find("./vlan-tagging") != None:
            return True
        else:
            return False
            
    def has_flexible_vlan_tagging(self):
        if self.xmlconfig.find("./flexible-vlan-tagging") != None:
            return True
        else:
            return False

    def get_mtu_setting(self):
        if self.xmlconfig.find("./mtu") == None:
            return 0
        else:
            return int(self.xmlconfig.find("./mtu").text)

    def set_mtu(self, mtu):
        if mtu == 0:
            if self.xmlconfig.find("./mtu") == None:
                pass
            else:
                self.xmlconfig.remove(faminet6.find("./mtu"))
        else:
            if self.xmlconfig.find("./mtu") == None:
                etree.SubElement(self.xmlconfig, "mtu").text = str(mtu)
            else:
                faminet6.find("./mtu").text = str(mtu)

    def is_tagged(self):
        if self.has_vlan_tagging():
            return True
        elif self.has_flexible_vlan_tagging():
            return True
        else:
            """
            This really should return True if the interface has only a single unit, that has family ethernet-switching, 
            with interface-mode trunk.  It's possible there are some other scenarios possible.
            """
            return False
    @classmethod
    def get_int_names(cls,junosdevcfg):
        """Return a list of interface names defined in a JunosDevCFG"""
        pass


class VlanCFG:
    """A class providing a programatic interface to network interfaces defined in a Juniper config XML file.

    The class essentially wraps an etree Element of a Juniper "interfaces { interface { <intname> }}".  Methods are provided to inspect
    what the current configuration is, and to modify it.
    """
    def __init__(self, junosdevcfg, vlan_name ):
        """Create an VlanCFG Object.  Pass in a top-level JunosDevConfig Object, and a
        name of a vlan.
        """
        self.name = vlan_name
        self.parent = junosdevcfg
        for vlan in junosdevcfg.xmlconfig.findall("./vlans"):
            if vlan.find("name").text == vlan_name:
                self.xmlconfig = vlan

    @classmethod
    def get_vlan_by_id(cls, junosdevcfg, vlan_id):
        pass


class SystemUserCFG:
    """
    A class providing a programatic interface to user's defined in a Juniper config XML file.

    The class essentially wraps etree Elements of Juniper "system login user"s.

    Methods are provided to inspect the configuration of current users and to modify them.
    """
    def __init__(self, junossystemcfg, username):
        self.name = username
        self.parent = junossystemcfg
        for userentry in junossystemcfg.xmlconfig.findall("./login/user"):
            if userentry.find("./name").text == username:
                self.xmlconfig = userentry

    def get_uid(self):
        if self.xmlconfig.find("./uid") == None:
            return 0
        else:
            return self.xmlconfig.find("./uid").text

    def get_full_name(self):
        if self.xmlconfig.find("./full-name") == None:
            return ""
        else:
            return self.xmlconfig.find("./full-name").text

    def get_class(self):
        if self.xmlconfig.find("./class") == None:
            return ""
        else:
            return self.xmlconfig.find("./class").text


class SystemCFG:
    """
    A class providing a programatic interface to common system parameters
    defined in a Juniper config XML file.

    The class essentially wraps etree Elements of a Juniper "system" and "snmp"
    hierarchy.  Methods are provided to inspect what the current configuration
    is, and to modify it.
    """
    def __init__(self, junosdevcfg):
        """Create an VlanCFG Object.  Pass in a top-level JunosDevConfig Object, and a
        name of a vlan.
        """
        self.name = "system"
        self.parent = junosdevcfg
        self.xmlconfig = junosdevcfg.xmlconfig.find("./system")
        self.snmpconfig = junosdevcfg.xmlconfig.find("./snmp")

    def has_snmpcfg(self):
        if self.snmpconfig == None:
            return False
        else:
            return True

    def get_hostname(self):
        if self.xmlconfig.find("./host-name") == None:
            return ""
        else:
            return self.xmlconfig.find("./host-name").text

    def get_domainname(self):
        if self.xmlconfig.find("./domain-name") == None:
            return ""
        else:
            return self.xmlconfig.find("./domain-name").text

    def get_timezone(self):
        if self.xmlconfig.find("./time-zone") == None:
            return ""
        else:
            return self.xmlconfig.find("./time-zone").text

    def get_authentication_order(self):
        auth_order = []
        if self.xmlconfig.find("./authentication-order") == None:
            pass
        else:
            for auths in self.xmlconfig.findall("./authentication-order"):
                auth_order.append(auths.text)
        return auth_order

    def get_nameservers(self):
        nameservers = []
        if self.xmlconfig.find("./name-server") == None:
            pass
        else:
            for ns in self.xmlconfig.findall("./name-server"):
                nameservers.append(ns.find("./name").text)
        return nameservers


class JunosDevCFG:
    """A class providing a programatic interface to a JunOS Device configuration.

    The class essentially wraps an etree Element of a JunOS device configuration.  Methods are provided to inspect what the current
    configuration is, and to modify it.

    Pass a JunosDev object into the constructor.  The constructor will retrieve the configuration and store it as self.xmlconfig
    """
    def __init__(self, junosdev):
        self.name = junosdev.name
        with junosdev.handle as conn:
            self.xmlconfig = conn.rpc.get_config()


class JunosDev:
    """A class providing a programatic interface to a JunOS Device.

    The class, on instantiation, creates and holds a pyez handle as self.handle to be used in interacting with the JunOS Device.
    """

    def __init__(self, hostname, username):
        self.name = hostname
        self.handle = Device(host=hostname, user=username)


def main():
    print("Something should probably happen here in main().")


if __name__ == "__main__":
    main()
