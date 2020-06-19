import logging
from logging.handlers import SysLogHandler
from LogStream import storage_engine


class RemoteSyslog(storage_engine.DatabaseFormat):
    def __init__(self, ip_address, logger, port=514):
        super(RemoteSyslog, self).__init__(logger)
        # Table
        self.type = 'syslog'
        # Primary key
        self.id = ip_address + ':' + str(port)
        self.handler = logging.handlers.SysLogHandler(address=(ip_address, port))

    def emit(self, messages):
        for message in messages:
            struct_message = [
                'attack_types=' + str(message['attack_types']),
                'category=' + str(message['category']),
                'cloud_provider=' + str(message['cloud_provider']),
                'date_time=' + str(message['date_time']),
                'detection_events=' + str(message['detection_events']),
                'geo_city=' + str(message['geo_city']),
                'geo_country=' + str(message['geo_country']),
                'geo_country_code=' + str(message['geo_country_code']),
                'geo_latitude=' + str(message['geo_latitude']),
                'geo_longitude=' + str(message['geo_longitude']),
                'geo_state=' + str(message['geo_state']),
                'header=' + str(message['header']),
                'ip_address_intelligence=' + str(message['ip_address_intelligence']),
                'method=' + str(message['method']),
                'protocol=' + str(message['protocol']),
                'query_string=' + str(message['query_string']),
                'region=' + str(message['region']),
                'request_status=' + str(message['request_status']),
                'response_code=' + str(message['response_code']),
                'severity=' + str(message['severity']),
                'sig_ids=' + str(message['sig_ids']),
                'sig_names=' + str(message['sig_names']),
                'source_ip=' + str(message['source_ip']),
                'src_port=' + str(message['src_port']),
                'sub_violations=' + str(message['sub_violations']),
                'support_id=' + str(message['support_id']),
                'threat_campaign_ids=' + str(message['threat_campaign_ids']),
                'threat_campaign_names=' + str(message['threat_campaign_names']),
                'violation_details_json=' + str(message['violation_details_json']),
                'violation_rating=' + str(message['violation_rating']),
            ]
            struct_message = ';'.join(struct_message)
            self.logger.debug("%s::%s: SEND LOG: %s" %
                         (__class__.__name__, __name__, struct_message))
            record = logging.makeLogRecord({
                'msg': struct_message,
            })
            self.handler.emit(record)

    def get_json(self):
        return {
            'id': self.id
        }


class LogCollectorDB(storage_engine.DatabaseFormat):
    def __init__(self, logger):
        super(LogCollectorDB, self).__init__(logger)
        self.handlers = {}
        # Relationship with other tables
        self.children['syslog'] = {}

    def add(self, log_instance):
        if log_instance.id not in self.children[log_instance.type].keys():
            self.create_child(log_instance)

    def remove(self, log_instance):
        if log_instance.id in self.children[log_instance.type].keys():
            log_instance.delete()

    def get(self):
        data_all_types = {}

        # syslog
        type = 'syslog'
        data = []
        for log_instance in self.children[type].values():
            data.append(log_instance.get_json())
        data_all_types[type] = data

        return data_all_types

    def emit(self, messages):
        # syslog
        type = 'syslog'
        for log_instance in self.children[type].values():
            log_instance.emit(messages)



