#
# Typofinder for domain typo discovery
# 
# Released as open source by NCC Group Plc - http://www.nccgroup.com/
# 
# Developed by Ollie Whitehouse, ollie dot whitehouse at nccgroup dot com
#
# http://www.github.com/nccgroup/typofinder
#
# Released under AGPL see LICENSE for more information#
#

import dns.resolver
import pygeoip
from py2neo import neo4j
from py2neo import node, rel

graph_db = neo4j.GraphDatabaseService("http://localhost:7474/db/data/")

class hostinfo(object):
    """Host information class"""

    A_type = dns.rdatatype.from_text('A')
    AAAA_type = dns.rdatatype.from_text('AAAA')

    def __init__(self):
        self._resolver = dns.resolver.Resolver()
        self._resolver.Timeout = 2.0
        self._resolver.lifetime = 2.0
        self._resolver.cache = dns.resolver.LRUCache()
        self._resolver.search = list() #Ensure no search suffixes
        self._gi = pygeoip.GeoIP('GeoIP.dat')
        self._giv6 = pygeoip.GeoIP('GeoIPv6.dat')

    def do_query(self, prefix, sHostname, rdatatype):
        try:
            domains_index = graph_db.get_or_create_index(neo4j.Node, "Domains")
            orig_node = domains_index.get_or_create("domain", sHostname, {"domain": sHostname})

            if prefix:
                domainname = dns.name.from_text(prefix + '.' + sHostname, origin=dns.name.root)
                lookup_node = domains_index.get_or_create("domain", domainname.to_text(), {"domain": domainname.to_text()})
                subs_index = graph_db.get_or_create_index(neo4j.Relationship, "Subs")
                subs_index.get_or_create("subdomain", domainname.to_text() + " " + sHostname, (orig_node, "SUBS", lookup_node))
            else:
                domainname = dns.name.from_text(sHostname, origin=dns.name.root)
                lookup_node = orig_node

            dnsAnswers = self._resolver.query(domainname, rdatatype)

            for answer in dnsAnswers:
                answer = str(answer)

                ip_index = graph_db.get_or_create_index(neo4j.Node, "IPs")
                ip_node = ip_index.get_or_create("ip", answer, {"ip":answer})

                resolutions_index = graph_db.get_or_create_index(neo4j.Relationship, "Resolutions")
                resolutions_index.get_or_create("resolution", domainname.to_text() + " " + dns.rdatatype.to_text(rdatatype) + " " + answer, (lookup_node, dns.rdatatype.to_text(rdatatype), ip_node))

            return dnsAnswers
        except dns.exception.Timeout:
            return None
        except dns.resolver.NoAnswer:
            return None
        except dns.resolver.NoNameservers:
            print("[!] No working DNS servers.")
            return None

    def getWWW(self, sHostname):
        return self.do_query('www', sHostname, self.A_type)

    def getWWWv6(self, sHostname):
        return self.do_query('www', sHostname, self.AAAA_type)

    def getM(self, sHostname):
        return self.do_query('m', sHostname, self.A_type)

    def getMv6(self, sHostname):
        return self.do_query('m', sHostname, self.AAAA_type)

    def getWEBMail(self, sHostname):
        return self.do_query('webmail', sHostname, self.A_type)

    def getWEBMailv6(self, sHostname):
        return self.do_query('webmail', sHostname, self.AAAA_type)

    def getMX(self, sHostname):
        # MX
        try:
            return self.do_query(None, sHostname, dns.rdatatype.from_text('MX'))
        except dns.resolver.NXDOMAIN:   #Special case, return None rather than throwing NXDOMAIN (TODO figure out why!)
            return None

    def getIPv4(self, sHostname):
        return self.do_query(None, sHostname, self.A_type)

    def getIPv6(self, sHostname):
        return self.do_query(None, sHostname, self.AAAA_type)

    def getGeobyIP(self, sIP):
        try:
            # Geo Location
            return self._gi.country_code_by_addr(sIP)
        except Exception:
            pass
    
    def getGeobyIPv6(self, sIP):
        try:
            # Geo Location
            return self._giv6.country_code_by_addr(sIP)
        except Exception:
            pass

    #
    # these are used by the v2 AJAX API
    #
    def getGeoImagebyIPv4new(self, sIP):
        try:
            countrycode = self.getGeobyIP(sIP)
            if countrycode:
                return "/flags/flags-iso/shiny/16/"+ countrycode + ".png"
        except Exception:
            pass
        return "/flags/flags-iso/shiny/16/_unknown.png"

    def getGeoImagebyIPv6new(self, sIP):
        try:
            countrycode = self.getGeobyIPv6(sIP)
            if countrycode:
                return "/flags/flags-iso/shiny/16/"+ countrycode + ".png"
        except Exception:
            pass
        return "/flags/flags-iso/shiny/16/_unknown.png"
