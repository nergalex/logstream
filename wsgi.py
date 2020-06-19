from flask import (Flask, request)
from flask_restful import (Api, Resource)
from flasgger import Swagger
from LogStream import f5cloudservices, logcollector, local_file_manager
import logging
import threading
import uuid
import time

application = Flask(__name__)
api = Api(application)
swagger = Swagger(application)


def setup_logging(log_level, log_file):
    if log_level == 'debug':
        log_level = logging.DEBUG
    elif log_level == 'verbose':
        log_level = logging.INFO
    else:
        log_level = logging.WARNING

    logging.basicConfig(filename=log_file, format='%(asctime)s %(levelname)s %(message)s', level=log_level)
    return logging.getLogger(__name__)


@swagger.definition('f5cs', tags=['v2_model'])
class ConfigF5CS:
    """
    Configure F5 Cloud Services
    ---
    required:
      - username
      - password
    properties:
      username:
        type: string
        description: F5 CS user account
      password:
        type: string
        description: password
    """

    @staticmethod
    def prepare(data_json):
        if 'username' in data_json and 'password' in data_json:
            result = {
                'code': 200,
                'object': data_json
            }
        else:
            result = {
                'code': 400,
                'msg': 'parameters: username, password must be set'
            }
        return result

    @staticmethod
    def set(data_json):
        f5cs.username = data_json['object']['username']
        f5cs.password = data_json['object']['password']
        f5cs.enable()
        f5cs.fecth_subscriptions()

    @staticmethod
    def get():
        if f5cs is not None:
            return f5cs.get_json()
        else:
            return None


@swagger.definition('logcollector', tags=['v2_model'])
class ConfigLogCollector:
    """
    Configure remote logging servers
    ---
    required:
      - syslog
    properties:
        syslog:
          type: array
          items:
            type: object
            schema:
            $ref: '#/definitions/syslog_server'
    """

    @staticmethod
    def prepare(data_json):
        if 'syslog' in data_json.keys():
            result = []
            code = 0
            for instance in data_json['syslog']:
                data = ConfigSyslogServer.prepare(instance)
                result.append(data)
                code = max(code, data['code'])
            result = {
                'code': code,
                'syslog': result
            }
        else:
            result = {
                'code': 400,
                'msg': 'parameters: syslog must be set'
            }
        return result

    @staticmethod
    def set(data_json):
        for instance in data_json['syslog']:
            ConfigSyslogServer.set(instance)

    @staticmethod
    def get():
        return logcol_db.get()


@swagger.definition('syslog_server', tags=['v2_model'])
class ConfigSyslogServer:
    """
    Configure a syslog server
    ---
    required:
      - ip_address
      - port
    properties:
      ip_address:
        type: string
        pattern: '^\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}$'
        description: ipv4 address
        example:
          1.1.1.1
      port:
        type: integer
        description: port listener
        default: 514
    """

    @staticmethod
    def prepare(data_json):
        if 'ip_address' in data_json.keys():
            result = {
                'code': 200,
                'object': {
                    'ip_address': data_json['ip_address']
                }
            }
            if 'port' in data_json.keys():
                result['object']['port'] = data_json['port']
            else:
                result['object']['port'] = 514
        else:
            result = {
                'code': 400,
                'msg': 'parameters: log_level, log_file must be set'
            }
        return result

    @staticmethod
    def set(data_json):
        logcol_db.add(logcollector.RemoteSyslog(
            ip_address=data_json['object']['ip_address'],
            port=data_json['object']['port'],
            logger=logger)
        )


class Declare(Resource):
    def get(self):
        """
        Get LogStream current declaration
        ---
        tags:
          - F5 Cloud Services LogStream
        responses:
          200:
            schema:
              required:
                - f5cs
                - logcollector
              properties:
                f5cs:
                  type: object
                  schema:
                  $ref: '#/definitions/f5cs'
                logcollector:
                  type: object
                  schema:
                  $ref: '#/definitions/logcollector'
        """
        return {
            'f5cs': ConfigF5CS.get(),
            'logcollector': ConfigLogCollector.get(),
        }, 200

    def post(self):
        """
        Configure LogStream in one declaration
        ---
        tags:
          - F5 Cloud Services LogStream
        consumes:
          - application/json
        parameters:
          - in: body
            name: body
            schema:
              required:
                - f5cs
                - logcollector
              properties:
                f5cs:
                  type: object
                  schema:
                  $ref: '#/definitions/f5cs'
                logcollector:
                  type: object
                  schema:
                  $ref: '#/definitions/logcollector'
        responses:
          200:
            description: Deployment done
         """
        data_json = request.get_json()
        clean_data = Declare.clean(declaration=data_json)

        # data malformated
        if 'code' in clean_data.keys():
            return clean_data

        # clean data
        else:
            Declare.deploy(declaration=clean_data)
            Declare.save(declaration=data_json)

        return "Configuration done", 200

    @staticmethod
    def clean(declaration):
        result = {}
        cur_class = 'f5cs'
        if cur_class in declaration.keys():
            result[cur_class] = ConfigF5CS.prepare(declaration[cur_class])
            if result[cur_class]['code'] not in (200, 201, 202):
                return result, result[cur_class]['code']
        else:
            return {
                'code': 400,
                'msg': 'parameters: ' + cur_class + ' must be set'
            }

        cur_class = 'logcollector'
        if cur_class in declaration.keys():
            result[cur_class] = ConfigLogCollector.prepare(declaration[cur_class])
            if result[cur_class]['code'] not in (200, 201, 202):
                return result, result[cur_class]['code']
        else:
            return {
                'code': 400,
                'msg': 'parameters: ' + cur_class + ' must be set'
            }

        return result

    @staticmethod
    def deploy(declaration):
        cur_class = 'f5cs'
        if cur_class in declaration.keys():
            ConfigF5CS.set(declaration[cur_class])

        cur_class = 'logcollector'
        if cur_class in declaration.keys():
            ConfigLogCollector.set(declaration[cur_class])
    @staticmethod
    def save(declaration):
        local_config.set_json(declaration)
        local_config.save()


class EngineThreading(Resource):
    @staticmethod
    def start_main():
        """
        Start threads. One thread per EAP instance.
        :return:
        """
        if len(thread_manager['thread_queue'].keys()) == 0 and \
                thread_manager['event'].is_set():
            thread_manager['event'].clear()
            for eap_instance in f5cs.get_eap_instances():
                thread_name = str(uuid.uuid4())
                t = threading.Thread(
                    target=EngineThreading.task_producer_consumer,
                    name=thread_name,
                    args=(thread_manager['event'], thread_name, eap_instance)
                )
                thread_manager['thread_queue'][thread_name] = t
                print("%s::%s: NEW THREAD: id=%s;eap_instance:%s" %
                            (__class__.__name__, __name__, t.name, eap_instance.id))
                logger.debug("%s::%s: NEW THREAD: id=%s;eap_instance:%s" %
                            (__class__.__name__, __name__, t.name, eap_instance.id))
                t.start()
            return "Engine started", 200
        else:
            return "Engine already started", 202

    @staticmethod
    def stop_main():
        """
        Stop gracefully threads
        :return:
        """
        if not thread_manager['event'].is_set():
            # set flag as a signal to threads for stop processing their next fetch logs iteration
            thread_manager['event'].set()
            print("%s::%s: Main - event set" %
                         (__class__.__name__, __name__))
            logger.debug("%s::%s: Main - event set" %
                         (__class__.__name__, __name__))

            # wait for threads to stop processing their current fetch logs iteration
            while len(thread_manager['thread_queue'].keys()) > 0:
                print("%s::%s: Main - wait for dying thread" %
                             (__class__.__name__, __name__))
                logger.debug("%s::%s: Main - wait for dying thread" %
                             (__class__.__name__, __name__))
                time.sleep(thread_manager['update_interval'])

            print("%s::%s: Main - all thread died" %
                         (__class__.__name__, __name__))
            logger.debug("%s::%s: Main - all thread died" %
                         (__class__.__name__, __name__))
            return "Engine stopped", 200
        else:
            return "Engine already stopped", 202

    @staticmethod
    def restart_main():
        EngineThreading.stop_main()
        return EngineThreading.start_main()

    @staticmethod
    def task_producer_consumer(thread_flag, thread_name, eap_instance):
        """
        fetch security events and send them on remote logging servers
        :param thread_flag:
        :param thread_name:
        :param eap_instance:
        :return:
        """
        while not thread_flag.is_set():
            eap_instance.get_token()
            eap_instance.fetch_security_events()
            logcol_db.emit(eap_instance.pop_security_events())

            print("%s::%s: THREAD SENT LOGS: name=%s;eap_instance:%s" %
                         (__class__.__name__, __name__, thread_name, eap_instance.id))
            logger.debug("%s::%s: THREAD SENT LOGS: name=%s;eap_instance:%s" %
                         (__class__.__name__, __name__, thread_name, eap_instance.id))
            time.sleep(thread_manager['update_interval'])
            print("%s::%s: THREAD AWAKE: name=%s;eap_instance:%s" %
                         (__class__.__name__, __name__, thread_name, eap_instance.id))
            logger.debug("%s::%s: THREAD AWAKE: name=%s;eap_instance:%s" %
                         (__class__.__name__, __name__, thread_name, eap_instance.id))

        print("%s::%s: EXIT THREAD: name=%s;eap_instance:%s" %
                     (__class__.__name__, __name__, thread_name, eap_instance.id))
        logger.debug("%s::%s: EXIT THREAD: name=%s;eap_instance:%s" %
                     (__class__.__name__, __name__, thread_name, eap_instance.id))
        thread_manager['thread_queue'].pop(thread_name, None)


class Engine(Resource):
    def get(self):
        """
        Get engine status
        ---
        tags:
          - F5 Cloud Services LogStream
        responses:
          200:
            schema:
              required:
                - status
              properties:
                status:
                  type: string
                  description: status
                threads:
                  type: integer
                  description: number of running threads
        """
        data = {}
        if len(thread_manager['thread_queue'].keys()) > 0:
            data['status'] = 'sync processing'
            data['threads'] = len(thread_manager['thread_queue'].keys())
        else:
            data['status'] = 'no sync process'
        return data

    def post(self):
        """
            Start/Stop engine
            ---
            tags:
              - F5 Cloud Services LogStream
            consumes:
              - application/json
            parameters:
              - in: body
                name: body
                schema:
                  required:
                    - action
                  properties:
                    action:
                      type: string
                      description : Start/Stop engine
                      enum: ['start', 'stop', 'restart']
            responses:
              200:
                description: Action done
        """
        data_json = request.get_json()

        # Sanity check
        cur_class = 'action'
        if cur_class not in data_json.keys():
            return {
                'code': 400,
                'msg': 'parameters: ' + cur_class + ' must be set'
            }
        else:
            # Sanity check
            if data_json[cur_class].lower() == 'start':
                return EngineThreading.start_main()
            elif data_json[cur_class].lower() == 'stop':
                return EngineThreading.stop_main()
            elif data_json[cur_class].lower() == 'restart':
                return EngineThreading.restart_main()
            else:
                return "Unknown action", 400

# Global var
logger = setup_logging(
    log_level='debug',
    log_file='logs/log.txt'
)
logcol_db = logcollector.LogCollectorDB(logger)
thread_manager = {
    'event': threading.Event(),
    'thread_queue': {},
    'update_interval': 10,
}

# event = True == engine stopped
thread_manager['event'].set()

f5cs = f5cloudservices.F5CSEAP(
    username=None,
    password=None,
    logger=logger
)

# load local configuration
local_config = local_file_manager.Configuration(backup_file='declaration.json')
if local_config.get_json() is not None:
    clean_data = Declare.clean(declaration=local_config.get_json())
    # malformed declaration
    if 'code' in clean_data.keys():
        raise Exception('Local configuration file is malformated', clean_data)

    # deploy
    Declare.deploy(declaration=clean_data)

# API
api.add_resource(Declare, '/declare')
api.add_resource(Engine, '/engine')

# Start program
if __name__ == '__main__':
    print("Dev Portal: http://127.0.0.1:5000/apidocs/")
    application.run(
        host="0.0.0.0",
        debug=True,
        use_reloader=True,
        port=5000
    )

