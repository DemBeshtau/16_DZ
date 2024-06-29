# Основы сбора и хранения логов #
1. В Vagrant развернуть 2 виртуальные машины (ВМ) web и log;
2. На ВМ web настроить веб-сервер NGINX;
3. На ВМ log настроить центральный сервер сбора логов на любой из систем:<br/>
   - journald;
   - rsyslog;
   - ELK;
4. Настроить аудит, следящий за изменение конфигураций NGINX.
&ensp;&ensp;Все критичные логи с ВМ web должны собираться и локально и удалённо. Все логи с NGINX должны уходить на удалённый сервер (локально только критичные логи). Логи аудита должны также уходить на удалённую систему.
#### Дополнительное задание ####
- развернуть допольнительную ВМ с ELK;
- в ELK должны уходить только логи NGINX;
- в во вторую систему всё остальное.
### Исходные данные ###
&ensp;&ensp;ПК на Linux c 8 ГБ ОЗУ или виртуальная машина (ВМ) с включенной Nested Virtualization.<br/>
&ensp;&ensp;Предварительно установленное и настроенное ПО:<br/>
&ensp;&ensp;&ensp;Hashicorp Vagrant (https://www.vagrantup.com/downloads);<br/>
&ensp;&ensp;&ensp;Oracle VirtualBox (https://www.virtualbox.org/wiki/Linux_Downloads).<br/>
&ensp;&ensp;&ensp;Ansible (https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html).<br/>
&ensp;&ensp;Все действия проводились с использованием Vagrant 2.4.0, VirtualBox 7.0.18, Ansible 9.4.0 и образа CentOS 7 версии 1804_2.<br/>
&ensp;&ensp;ПО стека ELK устанавливалось локально из rpm-пакетов. Указанные пакеты можно получить по ссылкам:<br/>
&ensp;&ensp;https://disk.yandex.ru/d/y1once01GzoGqQ<br/>
&ensp;&ensp;https://disk.yandex.ru/d/KaXobFakzLMIMw
### Ход решения ###
#### 1. Конфигурирование ВМ web
- Установка веб-сервера NGINX и проверка его работоспособности:
```shell
[root@web ~]# yum install epel-release -y
...
[root@web ~]# yum install -y nginx
...
[root@web ~]# systemctl status nginx
● nginx.service - The nginx HTTP and reverse proxy server
   Loaded: loaded (/usr/lib/systemd/system/nginx.service; enabled; vendor preset: disabled)
   Active: active (running) since Sat 2024-06-29 19:58:42 MSK; 8min ago
  Process: 885 ExecStart=/usr/sbin/nginx (code=exited, status=0/SUCCESS)
  Process: 874 ExecStartPre=/usr/sbin/nginx -t (code=exited, status=0/SUCCESS)
  Process: 870 ExecStartPre=/usr/bin/rm -f /run/nginx.pid (code=exited, status=0/SUCCESS)
 Main PID: 887 (nginx)
   CGroup: /system.slice/nginx.service
           ├─887 nginx: master process /usr/sbin/nginx
           ├─888 nginx: worker process
           └─889 nginx: worker process
...
```
![изображение](https://github.com/DemBeshtau/16_DZ/assets/149678567/64775b64-48f6-43ef-b8e5-c63ffbaf08d4)
- Настройка отправки логов NGINX на централизованный сервер:
```shell
[root@web ~]# nano /etc/nginx/nginx.conf
...
[root@web ~]# cat /etc/nginx/nginx.conf
# Логи пересылаются на сервер ELK
error_log /var/log/nginx/error.log;
error_log syslog:server=192.168.56.11:514,tag=nginx_error;
...
http {
    access_log syslog:server=192.168.56.11:514,tag=nginx_access,severity=info combined;
...
```
- Настройка аудита файлов конфигурации NGINX - добавление правил /etc/audit/rules.d/audit.rules:
```shell
[root@web ~] cd /etc/audit/rules.d/
[root@web rules.d]# echo "-w /etc/nginx/nginx.conf -p wa -k nginx_cfg" >> audit.rules
[root@web rules.d]# echo "-w /etc/nginx/default.d/ -p wa -k nginx_cfg" >> audit.rules
[root@web rules.d]# echo "-w /etc/nginx/conf.d/ -p wa -k nginx_cfg" >> audit.rules
[root@web rules.d]# cat audit.rules
#Осуществляется аудит файлов nginx.conf, содежимого директорий default.d и conf.d
-w /etc/nginx/nginx.conf -p wa -k nginx_cfg
-w /etc/nginx/default.d/ -p wa -k nginx_cfg
-w /etc/nginx/conf.d/ -p wa -k nginx_cfg
[root@web rules.d]# systemctl restart auditd
[root@web rules.d]# systemctl status auditd
● auditd.service - Security Auditing Service
   Loaded: loaded (/usr/lib/systemd/system/auditd.service; enabled; vendor preset: enabled)
   Active: active (running) since Sat 2024-06-29 19:58:39 MSK; 1h 19min ago
     Docs: man:auditd(8)
           https://github.com/linux-audit/audit-documentation
  Process: 535 ExecStartPost=/sbin/augenrules --load (code=exited, status=0/SUCCESS)
  Process: 522 ExecStart=/sbin/auditd (code=exited, status=0/SUCCESS)
 Main PID: 526 (auditd)
   CGroup: /system.slice/auditd.service
           ├─526 /sbin/auditd
           ├─531 /sbin/audispd
           └─533 /sbin/audisp-remote 
```
- Настройка сервиса rsyslog на отправку логов на сервер централихованного сбора логов log:
```shell
[root@web ~]# nano /etc/rsyslog.conf
[root@web ~]# cat /etc/rsyslog.conf
...
*.* @@192.168.56.15:514
```
- Установка и настройка плагина audispd-plugins для пересылки логов аудита централизованный сервер сбора логов:
```shell
[root@web ~]# yum -y install audispd-plugins
...
[root@web ~]# nano /etc/audit/auditd.conf
...
[root@web ~]# cat /etc/audit/auditd.conf
...
#Передача логов в формате RAW и отображение в логах имени хоста
log_format = RAW
name_format = HOSTNAME
...
[root@web ~]# nano /etc/audisp/plugins.d/au-remote.conf
...
[root@web ~]# cat /etc/audisp/plugins.d/au-remote.conf
# включение плагина active = yes
active = yes
direction = out
path = /sbin/audisp-remote
type = always
#args =
format = string
[root@web ~]# nano /etc/audisp/audisp-remote.conf
...
[root@web ~]# nano /etc/audisp/audisp-remote.conf
# Адрес и порт сервера, принимающего аудит логи 
remote_server = 192.168.56.15
port = 60
...
[root@web rules.d]# systemctl restart auditd
```  
#### 2. Конфигурирование ВМ log (сервер централизованного сбора логов)
- Настройка rsyslog для приёма логов с удалённых хостов:
```shell
[root@log ~]# nano /etc/rsyslog.conf
...
[root@log ~]# cat /etc/rsyslog.conf
...
# Приём логов по UDP
$ModLoad imudp
$UDPServerRun 514

# Приём логов по TCP
$ModLoad imtcp
$InputTCPServerRun 514
...
# Правила приёма логов от удалённых хостов
$template RemoteLogs,"/var/log/rsyslog/%HOSTNAME%/%PROGRAMNAME%.log
*.* ?RemoteLogs
& stop
[root@log ~]# systemctl restart rsyslog
```
- Настройка auditd для приёма логов аудита с удалённых хостов:
```shell
[root@log ~]# nano /etc/audit/auditd.conf
...
[root@log ~]# cat /etc/audit/auditd.conf
...
#Открытие порта 60 для сервиса auditd 
tcp_listen_port = 60
...
[root@log ~]# systemctl restart auditd
```
#### 3. Конфигурирование ВМ elk (сервер централизованного сбора логов со стеком ELK)
- Настройка сервиса rsyslog производится аналогично серверу log.
- Установка и настройка ПО составляющего ELK-стек: java-11-openjdk.x86_64, filebeat, logstash, elasticsearch, kibana:
```shell
[root@elk ~]# yum install java-11-openjdk.x86_64
...
[root@elk ~]# yum localinstall /vagrant/filebeat-8.14.1-x86_64.rpm
...
[root@elk ~]# nano /etc/filebeat/filebeat.yml
...
[root@elk ~]# cat /etc/filebeat/filebeat.yml
# ============================== Filebeat inputs ===============================
...
# filestream is an input for collecting log messages from files.
- type: log

  # Unique ID among all inputs, an ID is required.
  id: my-filestream-id

  # Change to true to enable this input configuration.
  enabled: true

  # Paths that should be crawled and fetched. Glob based paths.
  paths:
    - /var/log/rsyslog/web/*.log
...
# ------------------------------ Logstash Output -------------------------------
output.logstash:
  # The Logstash hosts
  hosts: ["192.168.56.11:5044"]
...
[root@elk ~]# systemctl enable --now filebeat.service

[root@elk ~]# yum localinstall /vagrant/logstash-8.14.1-x86_64.rpm
...
[root@elk ~]# nano /etc/logstash/logstash.yml
...
[root@elk ~]# cat /etc/logstash/logstash.yml
...
# ------------ Data path ------------------
#
# Which directory should be used by logstash and its plugins
# for any persistent needs. Defaults to LOGSTASH_HOME/data
#
path.data: /var/lib/logstash
...
# ------------ Pipeline Configuration Settings --------------
#
# Where to fetch the pipeline configuration for the main pipeline
#
path.config: /etc/logstash/conf.d
...
[root@elk ~]# cd /etc/logstash/conf.d

[root@elk conf.d]# nano logstash-nginx-es.conf
...
[root@elk conf.d]# cat logstash-nginx-es.conf
input {
    beats {
        port => 5044
    }
}

filter {
 grok {
   match => [ "message" , "%{COMBINEDAPACHELOG}+%{GREEDYDATA:extra_fields}"]
   overwrite => [ "message" ]
 }
 mutate {
   convert => ["response", "integer"]
   convert => ["bytes", "integer"]
   convert => ["responsetime", "float"]
 }
 date {
   match => [ "timestamp" , "dd/MMM/YYYY:HH:mm:ss Z" ]
   remove_field => [ "timestamp" ]
 }
 useragent {
   source => "agent"
 }
}

output {
 elasticsearch {
   hosts => ["http://192.168.56.11:9200"]
   #cacert => '/etc/logstash/certs/http_ca.crt'
   #ssl => true
   index => "weblogs-%{+YYYY.MM.dd}"
   document_type => "nginx_logs"
 }
 stdout { codec => rubydebug }
}

[root@elk ~]# systemctl enable --now logstash.service

[root@elk ~]# yum localinstall /vagrant/elasticsearch-8.14.1-x86_64.rpm
...
[root@elk ~]# nano /etc/elasticsearch/elasticsearch.yml
...
[root@elk ~]# cat /etc/elasticsearch/elasticsearch.yml
...
# ----------------------------------- Paths ------------------------------------
#
# Path to directory where to store the data (separate multiple locations by comma):
#
path.data: /var/lib/elasticsearch
#
# Path to log files:
#
path.logs: /var/log/elasticsearch
#
...
#----------------------- BEGIN SECURITY AUTO CONFIGURATION -----------------------
#
# The following settings, TLS certificates, and keys have been automatically      
# generated to configure Elasticsearch security features on 26-06-2024 11:47:00
#
# --------------------------------------------------------------------------------

# Enable security features
xpack.security.enabled: false

xpack.security.enrollment.enabled: false

# Enable encryption for HTTP API client connections, such as Kibana, Logstash, and Agents
xpack.security.http.ssl:
  enabled: false
  keystore.path: certs/http.p12

# Enable encryption and mutual authentication between cluster nodes
xpack.security.transport.ssl:
  enabled: false
  verification_mode: certificate
  keystore.path: certs/transport.p12
  truststore.path: certs/transport.p12
# Create a new cluster with the current node only
# Additional nodes can still join the cluster later
cluster.initial_master_nodes: ["elk"]

# Allow HTTP API connections from anywhere
# Connections are encrypted and require user authentication
http.host: 0.0.0.0
...
[root@elk ~]# nano /etc/elasticsearch/jvm.options
...
[root@elk ~]# cat /etc/elasticsearch/jvm.options
...
# Установка максимума занимаемой ява-машиной оперативной памяти 
-Xms1g
-Xmx1g
...
[root@elk ~]# systemctl enable --now elasticsearch.service

[root@elk ~]# yum localinstall /vagrant/kibana-8.14.1-x86_64.rpm
...
[root@elk ~]# nano /etc/kibana/kibana.yml
...
[root@elk ~]# cat /etc/kibana/kibana.yml
...
# =================== System: Kibana Server ===================
# Kibana is served by a back end server. This setting specifies the port to use.
server.port: 5601

# Specifies the address to which the Kibana server will bind. IP addresses and host names are both valid values.
# The default is 'localhost', which usually means remote machines will not be able to connect.
# To allow connections from remote users, set this parameter to a non-loopback address.
server.host: "0.0.0.0"
...
[root@elk ~]# systemctl enable --now kibana.service
```   
#### 3. Проверка работоспособности системы централизованного сбора логов
- Проверка работы связки веб-сервер (web) - сервер централизованного сбора логов (log). Для этого внесём изменения в конфигурационный файл /etc/nginx/nginx.conf и просмотрим локальные логи аудита и эти же логи на сервере log:
```shell
[root@web ~]# nano /etc/nginx/nginx.conf
...
[root@web ~]# cat /etc/nginx/nginx.conf
# This is the test message
# For more information on configuration, see:
#   * Official English Documentation: http://nginx.org/en/docs/
#   * Official Russian Documentation: http://nginx.org/ru/docs/
...
[root@web ~]# grep nginx_cfg /var/log/audit/audit.log 
node=web type=CONFIG_CHANGE msg=audit(1719617742.214:1625): auid=4294967295 ses=4294967295 subj=system_u:system_r:unconfined_service_t:s0 op=add_rule key="nginx_cfg" list=4 res=1
node=web type=CONFIG_CHANGE msg=audit(1719617742.218:1626): auid=4294967295 ses=4294967295 subj=system_u:system_r:unconfined_service_t:s0 op=add_rule key="nginx_cfg" list=4 res=1
node=web type=CONFIG_CHANGE msg=audit(1719617742.221:1627): auid=4294967295 ses=4294967295 subj=system_u:system_r:unconfined_service_t:s0 op=add_rule key="nginx_cfg" list=4 res=1
node=web type=CONFIG_CHANGE msg=audit(1719680319.566:5): auid=4294967295 ses=4294967295 subj=system_u:system_r:unconfined_service_t:s0 op=add_rule key="nginx_cfg" list=4 res=1
node=web type=CONFIG_CHANGE msg=audit(1719680319.571:6): auid=4294967295 ses=4294967295 subj=system_u:system_r:unconfined_service_t:s0 op=add_rule key="nginx_cfg" list=4 res=1
node=web type=CONFIG_CHANGE msg=audit(1719680319.576:7): auid=4294967295 ses=4294967295 subj=system_u:system_r:unconfined_service_t:s0 op=add_rule key="nginx_cfg" list=4 res=1
node=web type=SYSCALL msg=audit(1719683635.836:751): arch=c000003e syscall=2 success=yes exit=3 a0=145bec0 a1=441 a2=1b6 a3=63 items=2 ppid=2860 pid=3136 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=4 comm="nano" exe="/usr/bin/nano" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="nginx_cfg"
node=web type=SYSCALL msg=audit(1719692241.619:2536): arch=c000003e syscall=2 success=yes exit=3 a0=22438a0 a1=441 a2=1b6 a3=63 items=2 ppid=2860 pid=6986 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=4 comm="nano" exe="/usr/bin/nano" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="nginx_cfg"
node=web type=SYSCALL msg=audit(1719692266.391:2537): arch=c000003e syscall=2 success=yes exit=3 a0=22479a0 a1=241 a2=1b6 a3=7ffc6f8fd420 items=2 ppid=2860 pid=6986 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=4 comm="nano" exe="/usr/bin/nano" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="nginx_cfg"

#Просмотр аудит логов веб-сервера web на сервере централизованного сбора логов log
[root@log ~]# grep nginx_cfg /var/log/audit/audit.log 
node=web type=CONFIG_CHANGE msg=audit(1719680319.566:5): auid=4294967295 ses=4294967295 subj=system_u:system_r:unconfined_service_t:s0 op=add_rule key="nginx_cfg" list=4 res=1
node=web type=CONFIG_CHANGE msg=audit(1719680319.571:6): auid=4294967295 ses=4294967295 subj=system_u:system_r:unconfined_service_t:s0 op=add_rule key="nginx_cfg" list=4 res=1
node=web type=CONFIG_CHANGE msg=audit(1719680319.576:7): auid=4294967295 ses=4294967295 subj=system_u:system_r:unconfined_service_t:s0 op=add_rule key="nginx_cfg" list=4 res=1
node=web type=SYSCALL msg=audit(1719683635.836:751): arch=c000003e syscall=2 success=yes exit=3 a0=145bec0 a1=441 a2=1b6 a3=63 items=2 ppid=2860 pid=3136 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=4 comm="nano" exe="/usr/bin/nano" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="nginx_cfg"
node=web type=SYSCALL msg=audit(1719692241.619:2536): arch=c000003e syscall=2 success=yes exit=3 a0=22438a0 a1=441 a2=1b6 a3=63 items=2 ppid=2860 pid=6986 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=4 comm="nano" exe="/usr/bin/nano" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="nginx_cfg"
node=web type=SYSCALL msg=audit(1719692266.391:2537): arch=c000003e syscall=2 success=yes exit=3 a0=22479a0 a1=241 a2=1b6 a3=7ffc6f8fd420 items=2 ppid=2860 pid=6986 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=4 comm="nano" exe="/usr/bin/nano" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="nginx_cfg"

#Просмотров лог-файлов, переданных с веб-сервера web
[root@log ~]# ll /var/log/rsyslog/web/
total 36
-rw-------. 1 root root 4376 Jun 30 00:35 audisp-remote.log
-rw-------. 1 root root  750 Jun 30 00:35 audispd.log
-rw-------. 1 root root  223 Jun 30 00:34 polkitd.log
-rw-------. 1 root root  273 Jun 30 00:34 rsyslogd.log
-rw-------. 1 root root  879 Jun 30 00:35 sshd.log
-rw-------. 1 root root  604 Jun 30 00:34 sudo.log
-rw-------. 1 root root  177 Jun 30 00:35 systemd-logind.log
-rw-------. 1 root root  504 Jun 30 00:34 systemd.log 
```
- Проверка работы связки веб-сервер (web) - сервер централизованного сбора логов со стеком ELK (elk). В качестве демонстрации работоспособности
системы приводится скрины работы сервиса Kibanа с настроенным источником данных, содержащим индексы, полученные из логов NGINX на сервере централизованного
сбора логов elk.<br/>

![изображение](https://github.com/DemBeshtau/16_DZ/assets/149678567/c173a2ee-9cf6-4c38-9cef-2a45e02410b7)

![изображение](https://github.com/DemBeshtau/16_DZ/assets/149678567/66ab5611-d765-4691-8b29-76afd278cd72)


