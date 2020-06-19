# F5 Cloud Services - LogStream App
## Pre-requisites
Deploy a Linux VM.
Example: `CentOS 7.5`

## Install via Ansible
Use Ansible rolefor CentOS 7.x with extra variables below.

## Install manually
### INSTALL packages
Install packages.
Example: use `yum -y install`
```yaml
- name: INSTALL package
  package:
    name:
      - python3
      - python-setuptools
      - git
```

Start NGINX Unit
`sudo service unit start`

### INSTALL NGINX Unit
Install NGINX Unit and its python module.
More information about the chosen OS: [CentOS](https://unit.nginx.org/installation/#centos)
```yaml
- name: COPY unit repo
  copy:
    content:
        [unit]
        name=unit repo
        baseurl=https://packages.nginx.org/unit/centos/$releasever/$basearch/
        gpgcheck=0
        enabled=1
    dest: /etc/yum.repos.d/unit.repo
```
```yaml
- name: INSTALL package
  package:
    name:
      - unit
      - unit-python36
```

### COPY StreamLog
```yaml
- name: CREATE F5 Cloud Services apps directoty
  file:
    path: /etc/f5-cs-apps
    state: directory
```
```yaml
- name: CREATE log directoty
  file:
    path: /etc/f5-cs-apps/log/
```
```yaml
- name: GIT CLONE StreamLog sources
  git:
    repo: 'https://github.com/nergalex/logstream.git'
    dest: /etc/f5-cs-apps/
```

### COPY StreamLog
```yaml
- name: INSTALL virtualenv
  pip:
    name:
      - pip
      - virtualenv
    executable: pip3.6
```
Example:
```bash
pip3.6 install virtualenv
/usr/local/bin/virtualenv -p python3.6 /etc/f5-cs-apps/venv/
source /etc/f5-cs-apps/venv/bin/activate
pip install -r /etc/f5-cs-apps/logstream/requirements.txt
deactivate
```

### Configure UNIT
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
            "working_directory": "/etc/f5-cs-apps/",
            "home": "venv",
            "path": "logstream",
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

# https://unit.nginx.org/configuration/#python
- name: UPDATE Unit configuration
  uri:
    unix_socket: /var/run/unit/control.sock
    url: "http://{{ inventory_hostname }}/config/"
    method: PUT
    headers:
        Content-Type: application/json
    body: "{{ lookup('template', 'nginx_unit_webhook.json') }}"
    body_format: json
    timeout: 60
    status_code: 200, 202
    validate_certs: false
  register: config_json

- debug:
    var: config_json





