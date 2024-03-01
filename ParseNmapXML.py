# Get a list of all open ports
import xml.etree.ElementTree as ElementTree


class ParseNmapXML:
    def __init__(self, file_path):
        self.ports_list = list()
        self.file_path = file_path
        self._has_http_server = False
        self.xml_data = self.get_xml_data()
        self.open_ports = self.parse_nmap_open_ports()

    def get_xml_data(self):
        return ElementTree.parse(self.file_path).getroot()

    def parse_nmap_open_ports(self):
        parsed_data = []

        for _port in self.xml_data.findall('./host/ports/port'):
            data = {
                'protocol': _port.get('protocol'),
                'portid': _port.get('portid')
            }
            # Fill list of ports
            self.ports_list.append(_port.get('portid'))

            for _service in _port.findall('./service'):
                # TODO - Should get 'ostype'
                for _key in ['name', 'product', 'version']:
                    if _service.get(_key) is not None:
                        data[_key] = _service.get(_key)
                    else:
                        data[_key] = 'Unknown'

                    if self._has_http_server is False and _key is 'name' and _service.get(_key) == 'http':
                        self._has_http_server = True

            parsed_data.append(data)

        return parsed_data

    def get_nmap_parsed_open_ports(self):
        return self.open_ports

    def get_has_http_server(self):
        return self._has_http_server

    def get_open_ports_list(self):
        return self.ports_list
