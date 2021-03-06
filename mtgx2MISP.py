#!/usr/bin/env python
from lxml import etree
from lxml.builder import E
import zipfile
import sys
from pymisp import MISPServer
import pdb
import time
from datetime import date

MISP_URL = "http(s)://yourmisp.com"
API_KEY = "y0uR@p1K3y"
ORG = "Your Organisation"

file_ = sys.argv[1]
zp = zipfile.ZipFile(file_)
path = "Graphs/Graph1.graphml"
data = zp.read(path)
xml = etree.fromstring(data)
NS_GRAPHML = "http://graphml.graphdrawing.org/xmlns"
NS_MTG = "http://maltego.paterva.com/xml/mtgx"
CURRENT_TIMESTAMP = str(time.time())
nodes = xml.findall('.//{%s}node' % NS_GRAPHML)


class Attribute:
    def __init__(self, type_, category, timestamp, comment, value):
        self.type_ = type_
        self.category = category
        self.timestamp = timestamp
        self.comment = comment
        self.value = value
        self.misp_xml = self._make_xml()

    def _make_xml(self,):
        misp_xml = E.Attribute(
            E.id(),
            E.type(self.type_),
            E.category(self.category),
            E.to_ids("0"),
            E.uuid(),
            E.event_id(),
            E.distribution("0"),
            E.timestamp(self.timestamp),
            E.comment(self.comment),
            E.value(self.value),
            E.ShadowAttribute() 
        )
        return misp_xml


def make_ip_address(ip_entity):
    ip = ip_entity.xpath(".//mtg:Properties/mtg:Property[@displayName='IP Address']/mtg:Value/text()", namespaces={'mtg': NS_MTG})[0]
    text = node.xpath(".//mtg:Notes/text()", namespaces={'mtg': NS_MTG})
    comment = "Malicious ip from maltego" if len(text) == 0 else text[0]
    attribute = Attribute("ip-dst", "Network activity", CURRENT_TIMESTAMP, comment, ip)
    return attribute.misp_xml


def make_domain(domain_entity):
    domain = domain_entity.xpath(".//mtg:Properties/mtg:Property[@displayName='Domain Name']/mtg:Value/text()", namespaces={'mtg': NS_MTG})[0]
    text = node.xpath(".//mtg:Notes/text()", namespaces={'mtg': NS_MTG})
    comment = "Malicious domain from maltego" if len(text) == 0 else text[0]
    attribute = Attribute("domain", "Network activity", CURRENT_TIMESTAMP, comment, domain)
    return attribute.misp_xml


def make_url(url_entity):
    url = url_entity.xpath(".//mtg:Properties/mtg:Property[@displayName='URL']/mtg:Value/text()", namespaces={'mtg': NS_MTG})[0]
    text = node.xpath(".//mtg:Notes/text()", namespaces={'mtg': NS_MTG})
    comment = "Malicious url from maltego" if len(text) == 0 else text[0]
    attribute = Attribute("url", "Network activity", CURRENT_TIMESTAMP, comment, url)
    return attribute.misp_xml


def make_filename(filename_entity):
    filename = filename_entity.xpath(".//mtg:Properties/mtg:Property[@displayName='Filename']/mtg:Value/text()", namespaces={'mtg': NS_MTG})[0]
    text = node.xpath(".//mtg:Notes/text()", namespaces={'mtg': NS_MTG})
    comment = "Suspicious filename from maltego" if len(text) == 0 else text[0]
    attribute = Attribute("filename", "Artifacts dropped", CURRENT_TIMESTAMP, comment, filename)
    return attribute.misp_xml


def sha256(hash):
    hs = '2c740d20dab7f14ec30510a11f8fd78b82bc3a711abe8a993acdb323e78e6d5e'
    if len(hash) == len(hs) and hash.isdigit() is False and hash.isalpha() is False and hash.isalnum() is True:
        return True
    else:
        return False


def sha1(hash):
    hs = '4a1d4dbc1e193ec3ab2e9213876ceb8f4db72333'
    if len(hash) == len(hs) and hash.isdigit() is False and hash.isalpha() is False and hash.isalnum() is True:
        return True
    else:
        return False


def md5(hash):
    hs = 'ae11fd697ec92c7c98de3fac23aba525'
    if len(hash) is len(hs) and hash.isdigit() is False and hash.isalpha() is False and hash.isalnum() is True:
        return True
    else:
        return False


def make_hash(hash_entity):
    hash_ = hash_entity.xpath(".//mtg:Properties/mtg:Property[@displayName='Hash']/mtg:Value/text()", namespaces={'mtg': NS_MTG})[0]
    text = node.xpath(".//mtg:Notes/text()", namespaces={'mtg': NS_MTG})
    comment = "Suspicious hash from maltego" if len(text) == 0 else text[0]
    if sha256(hash_):
        hash_type = "sha256"
    elif sha1(hash_):
        hash_type = "sha1"
    elif md5(hash_):
        hash_type = "md5"
    else:
        return None
    attribute = Attribute(hash_type, "External analysis", CURRENT_TIMESTAMP, comment, hash_)
    return attribute.misp_xml


def make_email(email_entity):
    email = email_entity.xpath(".//mtg:Properties/mtg:Property[@displayName='Email Address']/mtg:Value/text()", namespaces={'mtg': NS_MTG})[0]
    text = node.xpath(".//mtg:Notes/text()", namespaces={'mtg': NS_MTG})
    comment = "Malicious email from maltego" if len(text) == 0 else text[0]
    attribute = Attribute("email-src", "Payload delivery", CURRENT_TIMESTAMP, comment, email)
    return attribute.misp_xml


convert_entity = {
    "maltego.IPv4Address": make_ip_address,
    "maltego.Domain": make_domain,
    "maltego.URL": make_url,
    "malformity.Filename": make_filename,
    "malformity.Hash": make_hash,
    "maltego.EmailAddress": make_email,
}

misp_entities = []

for node in nodes:
    mtg_entities = node.findall('.//{%s}MaltegoEntity' % NS_MTG)
    for entity in mtg_entities:
        try:
            new_entity = convert_entity[entity.attrib["type"]](entity)
            if new_entity is not None:
                misp_entities.append(new_entity)
        except:
            pass


misp = MISPServer(MISP_URL, API_KEY)
today = date.today().strftime("%Y-%m-%d")

misp_event = E.Event(
    E.id(),
    E.org(ORG),
    E.date(today),
    E.threat_level_id("4"),
    E.info("Imported graph elements from maltego"),
    E.published("0"),
    E.uuid(),
    E.attribute_count(str(len(misp_entities))),
    E.analysis("0"),
    E.timestamp(str(time.time())),
    E.distribution("0"),
    E.proposal_email_lock("0"),
    E.orgc(ORG),
    E.locked("0"),
    E.publish_timestamp(),
    E.ShadowAttribute(),
    E.RelatedEvent()
)

for entity in misp_entities:
    misp_event.append(entity)

res = misp.post(etree.tostring(misp_event))
#pdb.set_trace()

# import pprint
# pp = pprint.PrettyPrinter(indent=4)
# pp.pprint(res.text)

text_ = res.text.encode('utf-8')

xml_response = etree.tostring(etree.fromstring(text_), pretty_print=True)
print(xml_response)