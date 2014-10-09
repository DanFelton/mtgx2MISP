import requests
import json
from lxml import etree

class MISPServer(object):

    def __init__(self, url, key, default_output_type='xml'):
        self.url = url + '/events'
        self.key = key
        self.output_type = default_output_type

    def _session(self, overridden_output_type=None):
        if overridden_output_type is not None:
            output_type = overridden_output_type
        else:
            output_type = self.output_type
        headers = {
                'content-type': 'text/' + self.output_type,
                'Accept': 'application/' + self.output_type,
                'Authorization': self.key
            }
        session = requests.Session()
        session.verify = False
        session.headers.update(headers)
        return session

    '''get a specified event, or get index if event_id omitted'''
    def get(self, event_id=None):
        if(event_id is not None):
            url = self.url + "/{}".format(str(event_id))
        else:
            url = self.url
        return self._session().get(url)

    '''event_detail = file/string containing xml or json for event to be edited/created'''
    def post(self, event_detail, edit=False):
        xml_content = None
        json_content = None
        try:
            xml_content = etree.parse(event_detail)
        except: #etree.XMLSyntaxError, e:
            #print(e)
            try:
                xml_content = etree.fromstring(event_detail)
            except etree.XMLSyntaxError, e:
                print(e)
                ##########################
                try:
                    json_content = json.load(open(event_detail))
                except:
                    #to-do
                    import pdb; pdb.set_trace()
        if xml_content is not None:
            if edit:
                event_id = xml_content.find("id").text
                url = self.url + "/{}".format(event_id)
            else:
                url = self.url
            payload = etree.tostring(xml_content)
            return self._session().post(url, data=payload)
        if json_content is not None:
            #to-do handle json posts
            return json_content
        return None

    def delete(self, event_id):
        return self._session().delete(self.url + "/{}".format(str(event_id)))

    #search fields are lists of strings or single string
    #all fields can be negated with '!' except for type
    def search(self, value, type_="null", category="null", org="null", tag="null", attribute_search=False):
        if attribute_search:
            search_url = self.url[:-7] + "/attributes"
        else:
            search_url = self.url
        search_url = search_url + "/restSearch/download/{}/{}/{}/{}/{}"
        def process_arg(arg_value):
            if isinstance(arg_value, list):
                processed_string = "&&".join(arg_value)
            else:
                processed_string = str(arg_value)
            return processed_string
        prepped_value = process_arg(value)
        prepped_type = process_arg(type_)
        prepped_category =  process_arg(category)
        prepped_org = process_arg(org)
        prepped_tag = process_arg(tag)
        return self._session().get(search_url.format(prepped_value, prepped_type, prepped_category, prepped_org, prepped_tag))

    #todo
    def get_attachment(self, event_id):
        pass
