#!/bin/bash

#           Setup Script for  Redis + Elasticsearch + logstash + Kibana
#                            [ A R C H I T E C T U R E ]
#   Sheeper(Logstash) ---> Redis --> Logsatash-Indexer --> Elasticsearch --> Kibana
#
#

########## GET IP ADDRESS ##########
#export IP_ADD=$(ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1')
export IP_ADD="0.0.0.0"

########## INSTALL JAVA & REQUIRED APPs ##########
sudo add-apt-repository -y ppa:webupd8team/java
sudo apt-get update
echo debconf shared/accepted-oracle-license-v1-1 select true | sudo debconf-set-selections
echo debconf shared/accepted-oracle-license-v1-1 seen true | sudo debconf-set-selections
sudo apt-get -y install oracle-java8-installer
sudo apt-get -y install build-essential tcl
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/5.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-5.x.list
sudo apt-get update

########## INSTALLL REDIS ##########
cd /tmp
curl -O http://download.redis.io/redis-stable.tar.gz
tar xzvf redis-stable.tar.gz
cd redis-stable
make
sudo make install
sudo mkdir /etc/redis
sudo cp /tmp/redis-stable/redis.conf /etc/redis
sed -i 's&^supervised no&supervised systemd&g' /etc/redis/redis.conf
sed -i 's&^bind 127.0.0.1&bind 0.0.0.0&g' /etc/redis/redis.conf
sed -i 's&^dir ./&dir /var/lib/redis&g' /etc/redis/redis.conf

cat > /etc/systemd/system/redis.service <<EOL

[Unit]
Description=Redis In-Memory Data Store
After=network.target

[Service]
User=redis
Group=redis
ExecStart=/usr/local/bin/redis-server /etc/redis/redis.conf
ExecStop=/usr/local/bin/redis-cli shutdown
Restart=always

[Install]
WantedBy=multi-user.target
EOL

sudo adduser --system --group --no-create-home redis
sudo mkdir /var/lib/redis
sudo chown redis:redis /var/lib/redis
sudo chmod 770 /var/lib/redis
sudo systemctl start redis
sudo systemctl enable redis

########## INSTALL ELASTICSEARCH ##########
sudo apt-get -y install elasticsearch

cat > /etc/elasticsearch/elasticsearch.yml <<EOL
# ======================== Elasticsearch Configuration =========================
#
# NOTE: Elasticsearch comes with reasonable defaults for most settings.
#       Before you set out to tweak and tune the configuration, make sure you
#       understand what are you trying to accomplish and the consequences.
#
# The primary way of configuring a node is via this file. This template lists
# the most important settings you may want to configure for a production cluster.
#
# Please consult the documentation for further information on configuration options:
# https://www.elastic.co/guide/en/elasticsearch/reference/index.html
#
# ---------------------------------- Cluster -----------------------------------
#
# Use a descriptive name for your cluster:
#
#cluster.name: my-application
#
# ------------------------------------ Node ------------------------------------
#
# Use a descriptive name for the node:
#
#node.name: node-1
#
# Add custom attributes to the node:
#
#node.attr.rack: r1
#
# ----------------------------------- Paths ------------------------------------
#
# Path to directory where to store the data (separate multiple locations by comma):
#
#path.data: /path/to/data
#
# Path to log files:
#
#path.logs: /path/to/logs
#
# ----------------------------------- Memory -----------------------------------
#
# Lock the memory on startup:
#
#bootstrap.memory_lock: true
#
# Make sure that the heap size is set to about half the memory available
# on the system and that the owner of the process is allowed to use this
# limit.
#
# Elasticsearch performs poorly when the system is swapping the memory.
#
# ---------------------------------- Network -----------------------------------
#
# Set the bind address to a specific IP (IPv4 or IPv6):
#
network.host: $IP_ADD
#
# Set a custom port for HTTP:
#
#http.port: 9200
#
# For more information, consult the network module documentation.
#
# --------------------------------- Discovery ----------------------------------
#
# Pass an initial list of hosts to perform discovery when new node is started:
# The default list of hosts is ["127.0.0.1", "[::1]"]
#
#discovery.zen.ping.unicast.hosts: ["host1", "host2"]
#
# Prevent the "split brain" by configuring the majority of nodes (total number of master-eligible nodes / 2 + 1):
#
#discovery.zen.minimum_master_nodes: 3
#
# For more information, consult the zen discovery module documentation.
#
# ---------------------------------- Gateway -----------------------------------
#
# Block initial recovery after a full cluster restart until N nodes are started:
#
#gateway.recover_after_nodes: 3
#
# For more information, consult the gateway module documentation.
#
# ---------------------------------- Various -----------------------------------
#
# Require explicit names when deleting indices:
#
#action.destructive_requires_name: true
EOL
sudo service elasticsearch restart

########## INSTALL LOGSTASH ##########
sudo apt-get update && sudo apt-get install logstash
sudo apt-get install -y haveged
sed -i 's/^# config.reload.automatic: false/config.reload.automatic: true/g' /etc/logstash/logstash.yml

cat > /etc/logstash/conf.d/apache-filter.conf <<EOL
filter {
if [type] == "apache" {
 grok {
        match => [ "message", "%{URIHOST} %{COMBINEDAPACHELOG}" ] }
      }
else if [type] == "apache-server-home" {
grok {
        match => [ "message", "%{COMMONAPACHELOG} %{QS}" ] }
     }
}
EOL

cat > /etc/logstash/conf.d/logstash-indexer.conf <<EOL
input {
  file {
    type => "syslog"
    path => [ "/var/log/auth.log", "/var/log/messages", "/var/log/syslog" ]
  }
  tcp {
    port => "5145"
    type => "syslog-network"
  }
  udp {
    port => "5145"
    type => "syslog-network"
  }
  redis {
    host => "127.0.0.1"
    data_type => "list"
    key => "logstash"
    codec => json
  }
}
EOL

cat > /etc/logstash/conf.d/syslog-filter.conf <<EOL
filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "%
      {SYSLOGTIMESTAMP:syslog_timestamp} %
      {SYSLOGHOST:syslog_hostname} %
      {DATA:syslog_program}(?:\[%
      {POSINT:syslog_pid}\])?: %
      {GREEDYDATA:syslog_message}" }
      add_field => [ "received_at", "%{@timestamp}" ]
      add_field => [ "received_from", "%{host}" ]
    }
  syslog_pri { }
  date { match => [ "syslog_timestamp", "MMM d HH:mm:ss", "MMM dd HH:mm:ss" ]}
  }
}
EOL

cat /etc/logstash/conf.d/syslog-network-filter.conf <<EOL
filter {
if [type] == "syslog-network" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp}%{GREEDYDATA:syslog_message}" }
      add_field => [ "received_at", "%{@timestamp}" ]
      add_field => [ "received_from", "%{host}" ]
    }
    syslog_pri { }
    date {
      match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
  }
}
EOL

cat > /etc/logstash/conf.d/30-elasticsearch-output.conf <<EOL
output {
  elasticsearch {
    hosts => ["127.0.0.1:9200"]
    document_type => "%{[@metadata][type]}"
  }
}
EOL

sudo usermod -a -G adm logstash
sudo service logstash configtest
sudo service logstash restart
sudo update-rc.d logstash defaults 96 9



########## INSTALL KIBANA ##########
sudo apt-get -y install kibana

cat > /etc/kibana/kibana.yml <<EOL
# The default is 'localhost', which usually means remote machines will not be able to connect.
server.host: localhost

# Kibana is served by a back end server. This setting specifies the port to use.
#server.port: 5601

# Specifies the address to which the Kibana server will bind. IP addresses and host names are both valid values.
# The default is 'localhost', which usually means remote machines will not be able to connect.
# To allow connections from remote users, set this parameter to a non-loopback address.
#server.host: "localhost"

# Enables you to specify a path to mount Kibana at if you are running behind a proxy. This only affects
# the URLs generated by Kibana, your proxy is expected to remove the basePath value before forwarding requests
# to Kibana. This setting cannot end in a slash.
#server.basePath: ""

# The maximum payload size in bytes for incoming server requests.
#server.maxPayloadBytes: 1048576

# The Kibana server's name.  This is used for display purposes.
#server.name: "your-hostname"

# The URL of the Elasticsearch instance to use for all your queries.
#elasticsearch.url: "http://localhost:9200"

# When this setting's value is true Kibana uses the hostname specified in the server.host
# setting. When the value of this setting is false, Kibana uses the hostname of the host
# that connects to this Kibana instance.
#elasticsearch.preserveHost: true

# Kibana uses an index in Elasticsearch to store saved searches, visualizations and
# dashboards. Kibana creates a new index if the index doesn't already exist.
#kibana.index: ".kibana"

# The default application to load.
#kibana.defaultAppId: "discover"

# If your Elasticsearch is protected with basic authentication, these settings provide
# the username and password that the Kibana server uses to perform maintenance on the Kibana
# index at startup. Your Kibana users still need to authenticate with Elasticsearch, which
# is proxied through the Kibana server.
#elasticsearch.username: "user"
#elasticsearch.password: "pass"

# Paths to the PEM-format SSL certificate and SSL key files, respectively. These
# files enable SSL for outgoing requests from the Kibana server to the browser.
#server.ssl.cert: /path/to/your/server.crt
#server.ssl.key: /path/to/your/server.key

# Optional settings that provide the paths to the PEM-format SSL certificate and key files.
# These files validate that your Elasticsearch backend uses the same key files.
#elasticsearch.ssl.cert: /path/to/your/client.crt
#elasticsearch.ssl.key: /path/to/your/client.key

# Optional setting that enables you to specify a path to the PEM file for the certificate
# authority for your Elasticsearch instance.
#elasticsearch.ssl.ca: /path/to/your/CA.pem

# To disregard the validity of SSL certificates, change this setting's value to false.
#elasticsearch.ssl.verify: true

# Time in milliseconds to wait for Elasticsearch to respond to pings. Defaults to the value of
# the elasticsearch.requestTimeout setting.
#elasticsearch.pingTimeout: 1500

# Time in milliseconds to wait for responses from the back end or Elasticsearch. This value
# must be a positive integer.
#elasticsearch.requestTimeout: 30000

# List of Kibana client-side headers to send to Elasticsearch. To send *no* client-side
# headers, set this value to [] (an empty list).
#elasticsearch.requestHeadersWhitelist: [ authorization ]

# Header names and values that are sent to Elasticsearch. Any custom headers cannot be overwritten
# by client-side headers, regardless of the elasticsearch.requestHeadersWhitelist configuration.
#elasticsearch.customHeaders: {}

# Time in milliseconds for Elasticsearch to wait for responses from shards. Set to 0 to disable.
#elasticsearch.shardTimeout: 0

# Time in milliseconds to wait for Elasticsearch at Kibana startup before retrying.
#elasticsearch.startupTimeout: 5000

# Specifies the path where Kibana creates the process ID file.
#pid.file: /var/run/kibana.pid

# Enables you specify a file where Kibana stores log output.
#logging.dest: stdout

# Set the value of this setting to true to suppress all logging output.
#logging.silent: false

# Set the value of this setting to true to suppress all logging output other than error messages.
#logging.quiet: false

# Set the value of this setting to true to log all events, including system usage information
# and all requests.
#logging.verbose: false

# Set the interval in milliseconds to sample system and process performance
# metrics. Minimum is 100ms. Defaults to 5000.
#ops.interval: 5000
EOL

sudo update-rc.d kibana defaults 96 9
sudo service kibana start

########## INSTALL NGNIX ##########
sudo apt-get install -y nginx apache2-utils
sudo htpasswd -cb /etc/nginx/htpasswd.users kibanaadmin kibanaadmin

cat > /etc/nginx/sites-available/default <<EOL
server {
  listen 80;
  #server_name example.com;
  auth_basic "Restricted Access";
  auth_basic_user_file /etc/nginx/htpasswd.users;
  location / {
    proxy_pass http://localhost:5601;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection 'upgrade';
    proxy_set_header Host \$host;
    proxy_cache_bypass \$http_upgrade;
  }
}
EOL
sudo service nginx restart

########## SHEEPER ##########

sudo cp -R /etc/logstash /etc/logsheeper
sudo rm /etc/logsheeper/conf.d/*
sudo mkdir /var/lib/logsheeper
sudo mkdir /var/log/logsheeper

sed -i 's&^/var/log/logstash/gc.log&/var/log/logsheeper/gc.log&g' /etc/logsheeper/startup.options
sed -i 's&^/etc/logstash&/etc/logsheeper&g' /etc/logsheeper/startup.options
sed -i 's&^/var/run/logstash.pid.log&/var/run/logsheeper.pid&g' /etc/logsheeper/startup.options

sed -i 's&^/var/log/logstash&/var/log/logsheepers&g' /etc/logsheeper/logstash.yml
sed -i 's&^/var/lib/logstashs&/var/lib/logsheeper&g' /etc/logsheeper/logstash.yml

cat > /etc/logsheeper/conf.d/input.conf <<EOL
input {
  beats {
    port => 5044
  }
}
EOL

cat > /etc/logsheeper/conf.d/output.conf <<EOL
output {
  redis {
    host => "127.0.0.1:6379"
    data_type => "list"
    key => "sheeper"
  }
}
EOL
cat > /etc/systemd/system/logsheeper.service <<EOL
[Unit]
Description=logsheepr

[Service]
Type=simple
User=logstash
Group=logstash
# Load env vars from /etc/default/ and /etc/sysconfig/ if they exist.
# Prefixing the path with '-' makes it try to load, but if the file doesn't
# exist, it continues onward.
EnvironmentFile=-/etc/default/logstash
EnvironmentFile=-/etc/sysconfig/logstash
ExecStart=/usr/share/logstash/bin/logstash "--path.settings" "/etc/logsheepr"
Restart=always
WorkingDirectory=/
Nice=19
LimitNOFILE=16384

[Install]
WantedBy=multi-user.target
EOL

########## Sample Kibana dashboards ##########
cd ~
curl -L -O https://download.elastic.co/beats/dashboards/beats-dashboards-1.1.0.zip
unzip -o beats-dashboards-*.zip
cd beats-dashboards-*
./load.sh


echo "====================== Test Elasticsearch ==============================="
curl -XGET "http://localhost:9200/filebeat-*/_search?pretty"
