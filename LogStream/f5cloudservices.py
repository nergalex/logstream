import requests
from LogStream import storage_engine
import pytz
import datetime


class F5CSGeneric (storage_engine.DatabaseFormat):
    def __init__(self, username, password, logger):
        super(F5CSGeneric, self).__init__(logger)
        # Table
        self.type = 'f5_cloud_services'
        # Primary key
        self.id = username
        # Attribute
        self.host = 'api.cloudservices.f5.com'
        self.username = username
        self.password = password
        self.session = None
        self.access_token = None
        self.refresh_token = None
        self.primary_account_id = None
        self.catalog_id = None
        self.service_type = None

    def enable(self):
        self.get_token()
        self.get_account_user()

    def generate_error(self, r):
        if self.logger:
            self.logger.error('%s::%s: code %s; %s' %
                              (__class__.__name__, __name__, r.status_code, r.text))
        raise ConnectionError('%s::%s: code %s; %s' %
                              (__class__.__name__, __name__, r.status_code, r.text))

    def _get(self, path, parameters=None):
        # URL builder
        if parameters and len(parameters) > 0:
            uri = path + '?' + '&'.join(parameters)
        else:
            uri = path

        url = 'https://' + self.host + uri
        headers = {
            'Authorization': 'Bearer ' + self.access_token,
            'Content-Type': 'application/json'
        }
        r = self.session.get(
            url,
            headers=headers,
            verify=False)
        if r.status_code not in (200, 201, 202, 204):
            self.generate_error(r)

        return r.json()

    def _post(self, path, data):
        url = 'https://' + self.host + path
        headers = {
            'Authorization': 'Bearer ' + self.access_token,
            'Content-Type': 'application/json'
        }
        r = self.session.post(
            url,
            headers=headers,
            json=data,
            verify=False)
        if r.status_code not in (200, 201, 202, 204):
            self.generate_error(r)

        if r.text == '':
            return {}
        else:
            return r.json()

    def get_token(self):
        self.session = requests.session()
        url = 'https://' + self.host + '/v1/svc-auth/login'
        headers = {
            'Content-Type': 'application/json'
        }
        data = {
            'username': self.username,
            'password': self.password
        }
        r = self.session.post(
            url,
            headers=headers,
            data=str(data).replace("\'", "\""),
            verify=False)
        self.logger.info('Create Token for an Application using Password grant type associated to username %s' % (
            self.username))
        if r.status_code != requests.codes.ok:
            self.logger.error('%s::%s: code %s; %s' %
                (__class__.__name__, __name__, r.status_code, r.text))
            raise
        else:
            self.access_token = r.json()['access_token']
            self.refresh_token = r.json()['refresh_token']

    def get_account_user(self):
        path = '/v1/svc-account/user'
        parameters = []
        self.primary_account_id = self._get(path, parameters)['primary_account_id']

    def get_subscription(self):
        path = '/v1/svc-subscription/subscriptions'
        parameters = [
            'catalogId=' + self.catalog_id,
            'account_id=' + self.primary_account_id,
            'service_type=' + self.service_type,
        ]
        return self._get(path, parameters)


class F5CSEAPInstance (F5CSGeneric):
    def __init__(self, subscription, username, password, logger):
        super(F5CSEAPInstance, self).__init__(username, password, logger)
        # Table
        self.type = 'eap_instance'
        # Primary key
        self.id = subscription['subscription_id']
        # Attribute
        self.subscription_id = subscription['subscription_id']
        self.service_instance_id = subscription['service_instance_id']
        self.service_instance_name = subscription['service_instance_name']
        self.time_fetch_security_events = self._update_time()
        self.events = []
        self.get_token()
        self.get_account_user()

    def _update_time(self):
        return datetime.datetime.now(tz=pytz.timezone("America/New_York")).strftime("%Y-%m-%dT%H:%M:%SZ")

    def fetch_security_events(self):
        url = '/waf/v1/analytics/security/events'
        data = {
            'service_instance_id': self.service_instance_id,
            'subscription_id': self.subscription_id,
            'since': self.time_fetch_security_events
        }
        self.time_fetch_security_events = self._update_time()
        self.events += self._post(url, data)['events']

    def pop_security_events(self):
        data = self.events
        self.events = []
        return data

    def get_json(self):
        return {
            'service_instance_name': self.service_instance_name,
            'last_time_fetch_security_events': self.time_fetch_security_events,
        }


class F5CSEAP (F5CSGeneric):
    def __init__(self, username, password, logger):
        super(F5CSEAP, self).__init__(username, password, logger)
        # Table
        self.type = 'eap'
        # Primary key
        self.id = username
        # Relationship with other tables
        self.children['eap_instance'] = {}
        self.eap_instance_ids = self.children['eap_instance'].keys()
        self.eap_instances = self.children['eap_instance'].values()
        # Attribute
        self.service_type = 'waf'
        self.catalog_id = 'c-aa9N0jgHI4'

    def fecth_subscriptions(self):
        subscriptions = self.get_subscription()['subscriptions']
        cur_subscription_ids = []

        # CREATE new eap_instance
        for subscription in subscriptions:
            if subscription['subscription_id'] not in self.eap_instance_ids:
                eap_instance = F5CSEAPInstance(
                    subscription=subscription,
                    username=self.username,
                    password=self.password,
                    logger=self.logger)
                self.create_child(eap_instance)
            cur_subscription_ids.append(subscription['subscription_id'])

        # DELETE old eap_instance
        for eap_instance_id in self.eap_instance_ids:
            if eap_instance_id not in cur_subscription_ids:
                self.children['eap_instance'][eap_instance_id].delete()

    def fetch_security_events(self):
        for eap_instance in self.eap_instances:
            eap_instance.fetch_security_events()

    def pop_security_events(self):
        events = []
        for eap_instance in self.eap_instances:
            events.append(eap_instance.pop_security_events())
        return events

    def get_json(self):
        data = {
            'username': self.username
        }
        for eap_instance_id, eap_instance in self.children['eap_instance'].items():
            data[eap_instance_id] = eap_instance.get_json()
        return data

    def get_eap_instances(self):
        return self.eap_instances



