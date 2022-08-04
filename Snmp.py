from pysnmp.hlapi import *
from ncs_udm import UDM
import json, time, csv

class Snmp_Model(UDM):
    def __init__(self):
        super().__init__()
        with open('config/udm.json') as udm_file:
            self.udm_config = json.load(udm_file)
        self.udm_id = self.udm_config['id']
        self.data_ver = self.udm_config['ver']
        self.current_point_value = dict()
        self.csv_config_list = list()
    
    def snmp_get(self, community, ip, port, oid):
        get_respond = getCmd(SnmpEngine(),
                             CommunityData(community),
                             UdpTransportTarget((ip, port)),
                             ContextData(),
                             ObjectType(ObjectIdentity(oid)))
        return get_respond

    def snmp_set(self, community, ip, port, oid, change_value):
        set_respond = setCmd(SnmpEngine(),
                             CommunityData(community),
                             UdpTransportTarget((ip, port)),
                             ContextData(),
                             ObjectType(ObjectIdentity(oid), change_value))
        return set_respond
    
    def create_config_csv(self):
        with open('config/config.csv', 'w', newline='') as csvFile:
            writer = csv.DictWriter(csvFile, ["Name", "community", "ip", "port", "oid","FunID(hex.xxxx)", "DataType", "Type(0~2:R、W、R/W)", "Unit", "range", "setrange", "tag"])
            writer.writeheader()
            count = int()
            for os_name in self.udm_config['udm']:
                for oid_name, oid in self.udm_config['udm'][os_name]['oid'].items():
                    writer.writerow({"Name": f"{os_name}_{oid_name}", "community": self.udm_config['udm'][os_name]['community'], "ip": self.udm_config['udm'][os_name]['ip'], "port": self.udm_config['udm'][os_name]['port'], "oid": oid, "FunID(hex.xxxx)": f"{'%04x' %count}", "Type(0~2:R、W、R/W)": 2})
                    count += 1
        with open('config/config.csv', newline='',) as point_config_file:
            csv_to_dict = csv.DictReader(point_config_file)
            for dict_count in csv_to_dict:
                self.csv_config_list.append(dict_count)
    
    def register_config(self):
        payload_data_dict = dict()
        payload_fun_data_list = list()
        for point_dict in self.csv_config_list:
            payload_data_dict['id'] = point_dict['FunID(hex.xxxx)']
            payload_data_dict['name'] = point_dict['Name']
            payload_data_dict['type'] = point_dict['Type(0~2:R、W、R/W)']
            payload_fun_data_list.append(payload_data_dict)
            payload_data_dict = {}
        return payload_fun_data_list
    
    def make_config(self):
        payload_data_dict = dict()
        payload_fun_data_list = list()
        for point_dict in self.csv_config_list:
            payload_data_dict['id'] = point_dict['FunID(hex.xxxx)']
            payload_data_dict['name'] = point_dict['Name']
            payload_data_dict['type'] = point_dict['Type(0~2:R、W、R/W)']
            payload_fun_data_list.append(payload_data_dict)
            payload_data_dict = {}
        return payload_fun_data_list
    
    def make_status(self):
        payload_status_data_list = list()
        for point_dict in self.csv_config_list:
            fun_id = point_dict['FunID(hex.xxxx)']
            connect_community = point_dict['community']
            connect_ip = point_dict['ip']
            connect_port = int(point_dict['port'])
            oid = point_dict['oid']
            get_respond = self.snmp_get(connect_community, connect_ip, connect_port, oid)
            for (error_indication, error_status, error_index, var_binds) in get_respond:
                if error_indication:
                    print(error_indication)
                elif error_status:
                    print(error_status)
                else:
                    value = var_binds[0][1]
            payload_status_data_list.append(f"UDM|{self.udm_id}|{fun_id}|{value}|{int(time.time()*1000)}")
            self.current_point_value[f"{fun_id}"] = value
        return payload_status_data_list

    def exec_control(self, code3_payload_list):
        command_count = int()
        for payload_command in code3_payload_list[0]:
            payload_command_list = payload_command.split("|")
            if payload_command_list[0] == "UDM" and int(payload_command_list[1]) == self.udm_id:
                command_count += 1
                for point_dict in self.csv_config_list:
                    if payload_command_list[2] == point_dict['FunID(hex.xxxx)']:
                        community = point_dict['community']
                        ip = point_dict['ip']
                        port = int(point_dict['port'])
                        oid = point_dict['oid']
                        set_respond = self.snmp_set(community, ip, port, oid, payload_command_list[3])
                        for (error_indication, error_status, error_index, value) in set_respond:
                            if error_indication:
                                self.Main.error(f"Snmp error : {point_dict['FunID(hex.xxxx)']} {error_indication}")
                            elif error_status:
                                self.Main.error(f"Snmp error : {point_dict['FunID(hex.xxxx)']} {error_status}")
                            else:
                                command_count -= 1
        if command_count == 0:
            return 0
        else:
            return 1
    
    def exec_update(self):
        return 0
    
    def change_detect(self):
        check_point_value = dict()
        change_data_list = list()
        for point_dict in self.csv_config_list:
            fun_id = point_dict['FunID(hex.xxxx)']
            connect_community = point_dict['community']
            connect_ip = point_dict['ip']
            connect_port = int(point_dict['port'])
            oid = point_dict['oid']
            get_respond = self.snmp_get(connect_community, connect_ip, connect_port, oid)
            for (error_indication, error_status, error_index, var_binds) in get_respond:
                if error_indication:
                    self.Main.error(f"Snmp error {error_indication}")
                elif error_status:
                    self.Main.error(f"Snmp error {error_status}")
                else:
                    value = var_binds[0][1]
            check_point_value[f"{fun_id}"] = value
        if check_point_value != self.current_point_value:
            for different_point in check_point_value:
                if check_point_value[different_point] != self.current_point_value[different_point]:
                    change_data_list.append(f"UDM|{self.udm_id}|{different_point}|{check_point_value[different_point]}|{int(time.time()*1000)}")
            self.current_point_value = check_point_value
        return change_data_list
    
a = Snmp_Model()
a.create_config_csv()
a.start