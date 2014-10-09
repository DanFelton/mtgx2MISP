from lxml import etree
from lxml.builder import E
import zipfile
import sys
from pymisp import MISPServer
import pdb
import time
from datetime import date

MISP_URL = "https://54.76.164.83"
API_KEY = "6180Chk5oIKak0dKZDqmCodjR0IuLruStCT5Tdbi"

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


def make_hash(hash_entity):
    hash_ = hash_entity.xpath(".//mtg:Properties/mtg:Property[@displayName='Hash']/mtg:Value/text()", namespaces={'mtg': NS_MTG})[0]
    text = node.xpath(".//mtg:Notes/text()", namespaces={'mtg': NS_MTG})
    comment = "Suspicious hash from maltego" if len(text) == 0 else text[0]
    attribute = Attribute("md5", "External analysis", CURRENT_TIMESTAMP, comment, hash_)
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
        #try:
        new_entity = convert_entity[entity.attrib["type"]](entity)
        misp_entities.append(new_entity)
        #except:
        #    pass


misp = MISPServer(MISP_URL, API_KEY)
today = date.today().strftime("%Y-%m-%d")

misp_event = E.Event(
    E.id(),
    E.org("BAE AI"),
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
    E.orgc("BAE AI"),
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