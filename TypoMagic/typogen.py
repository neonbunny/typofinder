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

import re
import copy
import codecs
from py2neo import neo4j
from py2neo import node, rel

graph_db = neo4j.GraphDatabaseService("http://localhost:7474/db/data/")

class typogen(object):
    """generate typo"""

    def __init__(self):
        #Load up the list of TLDs
        self.lstTlds = list()
        filename = "./tlds.txt"
        with open(filename) as f:
            for line in f:
                if not line.lstrip().startswith('#'):
                    self.lstTlds.append(line.rstrip().lower())
        print("Loading confusables...", end=" ", flush=True)
        self.loadconfusables()
        print("Done.")

    @staticmethod
    def loadkeyb(strCountry):
        keyDict = dict()

        # obviously you can have other maps here
        # I've only included this one
        filename = "./keyb" + strCountry + ".txt"
        with open(filename) as f:
            for line in f:
                split = line.rstrip().split(',')
                if split[0] in keyDict:
                    keyDict[split[0]].append(split[1])
                else:
                    keyDict[split[0]] = [split[1]]

        return keyDict

    @staticmethod
    def loadadditionalhomoglyphs():
        homoglyphs = dict()
        with open("homoglyphs.txt", "r", encoding="utf8") as f:
            for line in f:
                if not line.startswith("#"):
                    split = line.rstrip().split(',')
                    key = split[0]
                    #filter out any glyphs which are the same as the key (case insensitive)
                    tempvalues = [glyph for glyph in split[1].split(' ') if glyph.lower() != key]
                    #filter out glyphs which do not survive round trip conversion, e.g. ß -> ss -> ss
                    values = list()
                    for glyph in tempvalues:
                        try:
                            if 'a' + glyph + 'b' == codecs.decode(codecs.encode('a' + glyph + 'b', "idna"), "idna"):
                                values.append(glyph)
                        except UnicodeError:
                            #Some characters/combinations will fail the nameprep stage
                            pass
                    homoglyphs[key] = values

        return homoglyphs

    @staticmethod
    def loadconfusables():
        global _homoglyphs_confusables
        _homoglyphs_confusables = dict()
        rejected_sequences = set()

        #'utf_8_sig' swallows the BOM at start of file
        with open("confusables.txt", "r", encoding="'utf_8_sig") as f:
            for line in f:
                #If line contains more than whitespace and isn't a comment
                if line.strip() and not line.startswith("#"):
                    split = line.split(';', maxsplit=2)
                    #parse the left hand side of the pairing
                    unihex = split[0].split(' ')[0]
                    part0 = (chr(int(unihex, 16)))

                    if part0 in rejected_sequences:
                        continue

                    #parse the right hand side of the pairing
                    part1 = ''
                    for unihex in split[1].strip().split(' '):
                        part1 += (chr(int(unihex, 16)))

                    if part1 in rejected_sequences:
                        continue

                    #Skip pairs already in the _homoglyphs dict
                    if part0 in _homoglyphs_confusables and part1 in _homoglyphs_confusables[part0]:
                        continue

                    try:
                        #filter out glyphs which do not survive round trip conversion, e.g. ß -> ss -> ss
                        if 'a' + part0 + 'b' != codecs.decode(codecs.encode('a' + part0 + 'b', "idna"), "idna"):
                            rejected_sequences.add(part0)
                            continue
                    except UnicodeError:
                        #Some characters/combinations will fail the nameprep stage
                        rejected_sequences.add(part0)
                        continue

                    try:
                        #filter out glyphs which do not survive round trip conversion, e.g. ß -> ss -> ss
                        if 'a' + part1 + 'b' != codecs.decode(codecs.encode('a' + part1 + 'b', "idna"), "idna"):
                            rejected_sequences.add(part1)
                            continue
                    except UnicodeError:
                        #Some characters/combinations will fail the nameprep stage
                        rejected_sequences.add(part1)
                        continue

                    #Include left to right pair mapping in the dict
                    if part0 not in _homoglyphs_confusables:
                        _homoglyphs_confusables[part0] = set()
                    _homoglyphs_confusables[part0].add(part1)

                    #Include right to left pair mapping in the dict
                    if part1 not in _homoglyphs_confusables:
                        _homoglyphs_confusables[part1] = set()
                    _homoglyphs_confusables[part1].add(part0)

    def is_domain_valid(self, domain):
        #Ensure its in the correct character set
        if not re.match('^[a-z0-9.-]+$', domain):
            return False
        #Ensure the TLD is sane
        elif domain[domain.rfind(".") + 1:] not in self.lstTlds:
            return False
        # hostnames can't start or end with a -
        elif ".-" in domain or "-." in domain or domain.startswith("-"):
            return False
        #Ensure the location of dots are sane
        elif ".." in domain or domain.startswith("."):
            return False
        else:
            return True

    @staticmethod
    def bitflipbyte(inputbyte):
        """
        Flips the lowest 7 bits in the given input byte/int to build a list of mutated values.

        @param inputbyte: The byte/int to bit flip
        @return: A list of the mutated values.
        """
        result = list()
        mask = 1
        #As we know we're flipping ASCII, only do the lowest 7 bits
        for i in range(0, 7):
            result.append(inputbyte ^ mask)
            mask <<= 1
        return result

    @staticmethod
    def generate_country_code_doppelgangers(strHost):
        result = list()
        with open("countrynames.txt", 'r', encoding="UTF-8") as countrynames:
            for line in countrynames:
                if not line.startswith('#'):
                    parts = line.split(';', maxsplit=2)
                    # 2 letter country code subdomain, but without the dot
                    result.append(parts[0].strip().lower() + strHost)
                    # 3 letter country code subdomain, but without the dot
                    result.append(parts[1].strip().lower() + strHost)
        return result

    @staticmethod
    def generate_subdomain_doppelgangers(strHost):
        result = list()
        with open("subdomains.txt", 'r') as subdomains:
            for subdomain in subdomains:
                result.append(subdomain.strip() + strHost)
        return result

    @staticmethod
    def generate_extra_dot_doppelgangers(strHost):
        result = list()
        for idx, char in enumerate(strHost):
            #A dot instead of a character
            result.append(strHost[:idx] + '.' + strHost[idx + 1:])
            #A dot inserted between characters
            result.append(strHost[:idx] + '.' + strHost[idx:])
        return result

    @staticmethod
    def bitflipstring(strInput):
        """
        Flips the lowest 7 bits in each character of the given string to build a list of mutated values.

        @param strInput: The string to bit flip
        @return: A list of the mutated values.
        """
        result = list()
        i = 0
        for character in strInput:
            flippedchars = typogen.bitflipbyte(character.encode("UTF-8")[0])
            for flippedchar in flippedchars:
                result.append(strInput[:i] + chr(flippedchar) + strInput[i + 1:])
            i += 1
        return result

    @staticmethod
    def generate_missing_character_typos(strHost):
        # missing characters

        result = list()
        idx = 0
        while idx < len(strHost):
            strTypo = strHost[0:idx] + strHost[idx + 1:]
            idx += 1
            result.append(strTypo)
        return result

    @staticmethod
    def generate_duplicate_character_typos(strHost):
        # duplicate characters

        result = list()
        idx = 0
        while idx < len(strHost):
            strHostList = list(strHost)
            if strHostList[idx] != '.':
                strHostList.insert(idx, strHostList[idx])
                strTypo = "".join(strHostList)
                result.append(strTypo)
            idx += 1
        return result

    @staticmethod
    def generate_miskeyed_typos(strHost, strCountry):
        # swap to a surrounding key for each character

        result = list()
        # load keyboard mapping
        typoDict = typogen.loadkeyb(strCountry)

        for idx, char in enumerate(strHost):
            if char in typoDict:
                for replacement_char in typoDict[char]:
                    result.append(strHost[:idx] + replacement_char + strHost[idx + 1:])
        return result

    @staticmethod
    def generate_homoglyph_confusables_typos(strHost):
        # swap characters to similar looking characters, based on Unicode's confusables.txt

        result = list()
        global _homoglyphs_confusables
        #Replace each homoglyph subsequence in the strHost with each replacement subsequence associated with the homoglyph subsequence
        for homoglyph_subsequence in _homoglyphs_confusables:
            idx = 0
            while 1:
                idx = strHost.find(homoglyph_subsequence, idx)
                if idx > -1:
                    for replacement_subsequence in _homoglyphs_confusables[homoglyph_subsequence]:
                        newhostname = strHost[:idx] + replacement_subsequence + strHost[idx + len(homoglyph_subsequence):]
                        result.append(str(codecs.encode(newhostname, "idna"), "ascii"))
                    idx += len(homoglyph_subsequence)
                else:
                    break

        return result

    @staticmethod
    def generate_additional_homoglyph_typos(strHost):
        # swap characters to similar looking characters, based on homoglyphs.txt

        result = list()
        # load homoglyph mapping
        homoglyphs = typogen.loadadditionalhomoglyphs()

        for idx, char in enumerate(strHost):
            if char in homoglyphs:
                for replacement_char in homoglyphs[char]:
                    newhostname = strHost[:idx] + replacement_char + strHost[idx + 1:]
                    result.append(str(codecs.encode(newhostname, "idna"), "ascii"))

        return result

    @staticmethod
    def generate_miskeyed_addition_typos(strHost, strCountry):
        # add a surrounding key either side of each character

        result = list()
        # load keyboard mapping
        typoDict = typogen.loadkeyb(strCountry)

        for idx, char in enumerate(strHost):
            if char in typoDict:
                for replacement_char in typoDict[char]:
                    result.append(strHost[:idx + 1] + replacement_char + strHost[idx + 1:])
                    result.append(strHost[:idx] + replacement_char + strHost[idx:])
        return result

    @staticmethod
    def generate_miskeyed_sequence_typos(strHost, strCountry):
        # repeated surrounding keys for any character sequences in the string

        result = list()
        # load keyboard mapping
        typoDict = typogen.loadkeyb(strCountry)

        idx = 0
        while idx < len(strHost):
            char = strHost[idx]
            #Loop through sequences of the same character, counting the sequence length
            sequence_len = 1
            while idx+1 < len(strHost) and strHost[idx+1] == char:
                sequence_len += 1
                idx += 1

            #Increment the index at this point to make the maths easier if we found a sequence
            idx += 1

            #Replace the whole sequence
            if sequence_len > 1:
                if char in typoDict:
                    for replacement_char in typoDict[char]:
                        result.append(strHost[:idx - sequence_len] + (replacement_char * sequence_len) + strHost[idx:])

        return result

    @staticmethod
    def generate_transposed_character_typos(strHost):
        result = list()
        for idx in range(0, len(strHost) - 1):
            result.append(strHost[:idx] + strHost[idx+1:idx+2] + strHost[idx:idx+1] + strHost[idx+2:])
        return result

    def generatetyposv2(self, strHost, strCountry, bTypos, iTypoIntensity, bTLDS, bBitFlip, bHomoglyphs, bDoppelganger):
        """
        generate the typos

        @param strHost The hostname to generate typos for
        @param strCountry The country code of the keyboard to use when generating miskeyed typos
        @param bTypos Flag to indicate that typos should be generated
        @param iTypoIntensity A percentage of how intense the typo generation should be.
        @param bTLDS Flag to indicate that the TLDs should be swapped
        @param bBitFlip Flag to indicate that the hostname should be bitflipped
        """

        # result list of typos
        lstTypos = []

        if bBitFlip:
            lstTypos += self.bitflipstring(strHost)

        if bTypos:
            #Quick:
            lstTypos += self.generate_missing_character_typos(strHost)
            lstTypos += self.generate_duplicate_character_typos(strHost)
            #Balanced:
            if iTypoIntensity > 0:
                lstTypos += self.generate_miskeyed_typos(strHost, strCountry)
                lstTypos += self.generate_miskeyed_sequence_typos(strHost, strCountry)
            #Rigorous:
            if iTypoIntensity > 50:
                lstTypos += self.generate_transposed_character_typos(strHost)
                lstTypos += self.generate_miskeyed_addition_typos(strHost, strCountry)

        if bTLDS:
            lastdot = strHost.rfind(".")
            # tld swap out
            for gtld in self.lstTlds:
                newHost = strHost[:lastdot] + "." + gtld
                lstTypos.append(newHost)

        if bHomoglyphs:
            lstTypos += self.generate_homoglyph_confusables_typos(strHost)
            lstTypos += self.generate_additional_homoglyph_typos(strHost)

        if bDoppelganger:
            #Commented out until a slider is put in - this following line results in Ssssllloooowwww searches
            #lstTypos += self.generate_country_code_doppelgangers(strHost)
            lstTypos += self.generate_subdomain_doppelgangers(strHost)
            lstTypos += self.generate_extra_dot_doppelgangers(strHost)

        uniqueTypos = set(lstTypos)

        # Add the original domain 
        try:
            uniqueTypos.add(strHost)
        except KeyError:
            pass

        graph_db.clear()
        domains_index = graph_db.get_or_create_index(neo4j.Node, "Domains")
        typos_index = graph_db.get_or_create_index(neo4j.Relationship, "Typos")

        # create the original node
        orig_node = domains_index.get_or_create("domain", strHost, {"domain": strHost})

        # Remove any invalid typos
        for typo in copy.copy(uniqueTypos):
            if not self.is_domain_valid(typo):
                uniqueTypos.remove(typo)
            elif not typo is strHost:
                typo_node, = node(domainname=typo)
                typo_node = domains_index.get_or_create("domain", typo, {"domain": typo})

                typo_rel = typos_index.get_or_create("typo", strHost + " " + typo, (orig_node, "TYPO", typo_node))

        return sorted([codecs.decode(asciiHost.encode(), "idna") for asciiHost in uniqueTypos])
