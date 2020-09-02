# F5 Cloud Services - LogStream App
## Use Case
[F5 Cloud Services Essential App Protect](https://clouddocs.f5.com/cloud-services/latest/f5-cloud-services-Essential.App.Protect-About.html) is a Web Application Firewall in SaaS mode
Security event logs can be pulled through API.

LogStream App pulls event logs regularly from EAP and forwards them to remote syslog servers (log collector, SIEM)

![alt text][logstream_schema]

[logstream_schema]: https://github.com/nergalex/logstream/blob/master/image/EAP_LogStream.png "logstream_schema"

## Security consideration
* In the `declaration`, set a user account with limited access (Read)
* No logs are stored on the system. LogStream PULL logs from F5 CS EAP and then PUSH them directly to remote log collector server(s).

## Pre-requisites
* Deploy a Linux VM. Example: `CentOS 7.5`
* In F5 CS, create a user account with limited access (Read)

## Install via Ansible
Use Ansible role for CentOS 7.x with extra variables below.

| Job template  | playbook      | activity      | inventory     | limit         | credential   |
| ------------- | ------------- | ------------- | ------------- | ------------- |------------- |
| `onboard`  | `playbooks/f5cs.yaml`    | `unit_onboarding`    | `localhost`  | `localhost` | `my_vm_credential` |
| `deploy_app_service`  | `playbooks/f5cs.yaml`    | `unit_app_service-logstream`    | `localhost`  | `localhost` | `my_vm_credential` |

| Extra variable| Description | Example of value      |
| ------------- | ------------- | ------------- |
| `activity` | cf. activity value per Job Template | `unit_onboarding` |
| `extra_vm_name` | VM hostname | `vm-logstream` |
| `extra_vm_ip_mgt` | VM management IP | `10.100.0.5` |

## Install manually
Example below for CentOS.
Please refer to [NGINX Unit](https://unit.nginx.org/installation/#centos) web site for another OS.

### INSTALL NGINX Unit
* CREATE repo info
```bash
sudo vi /etc/yum.repos.d/unit.repo
[unit]
name=unit repo
baseurl=https://packages.nginx.org/unit/centos/$releasever/$basearch/
gpgcheck=0
enabled=1
```
* INSTALL packages. Example: use `yum -y install`
```bash
sudo yum -y install python3 \
    python-setuptools \
    git \
    unit \
    unit-python36
```
* Start NGINX Unit
```bash
sudo service unit start
```

### COPY LogStream sources
* CREATE F5 Cloud Services apps directory
```bash
sudo mkdir /etc/f5-cs-apps
sudo cd /etc/f5-cs-apps/
sudo git clone https://github.com/nergalex/logstream.git
sudo chmod 777 /etc/f5-cs-apps/logstream
sudo chmod 777 /etc/f5-cs-apps/logstream/declaration.json
sudo chmod 777 /etc/f5-cs-apps/logstream/logstream.log
```
* CREATE virtual environment
```bash
sudo pip3.6 install virtualenv
sudo /usr/local/bin/virtualenv -p python3.6 /etc/f5-cs-apps/venv/
sudo source /etc/f5-cs-apps/venv/bin/activate
sudo pip install -r /etc/f5-cs-apps/logstream/requirements.txt
sudo deactivate
```

### Configure FaaS (NGINX Unit)
Follow the NGINX Unit guide for [flask](https://unit.nginx.org/howto/flask/)
* GET configuration
```bash
cd ~
curl --unix-socket /var/run/unit/control.sock http://localhost/config/ > config.json
```
* EDIT configuration
```bash
vi config.json
```
```json
{
    "listeners": {
        "*:8080": {
            "pass": "applications/logstream"
        }
    },
    "applications": {
        "logstream": {
            "type": "python 3",
            "working_directory": "/etc/f5-cs-apps/logstream",
            "home": "/etc/f5-cs-apps/venv",
            "path": "/etc/f5-cs-apps/logstream",
            "module": "wsgi"
        }
    }
}
```
* SET configuration
```bash
curl -X PUT --data-binary @config.json --unix-socket /var/run/unit/control.sock http://localhost/config
```
* TEST configuration
```bash
curl http://127.0.0.1:8080/declare
```

## Configuration guide
2 ways to configure LogStream:
* Access to API Dev Portal with your browser `http://<extra_vm_ip_mgt>:8080/apidocs/`
* Use Postman. Import collection LogStream.postman_collection.json

Configuration workflow:
* First time, use `declare` entry point to configure entirely LogStream. Refer to API Dev Portal for parameter and allowed values.
* Then use `action` entry point to start/stop the engine.
* Use `declare` anytime you need to reconfigure LogStream and launch `restart` `action` to apply the new configuration.
* The last `declaration` is saved locally.





