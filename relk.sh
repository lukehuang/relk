#!/bin/bash

#           Setup Script for  Redis + Elasticsearch + logstash + Kibana
#                            [ A R C H I T E C T U R E ]
#   Sheeper(Logstash) ---> Redis --> Logsatash-Indexer --> Elasticsearch --> Kibana
#
#
set -x
set -e
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CONFIG_PATH=$DIR/config
OS_VERSION=$(awk '/DISTRIB_RELEASE=/' /etc/*-release | sed 's/DISTRIB_RELEASE=//' | sed 's/[.]0/./')
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

sudo cp $CONFIG_PATH/redis/redis.service /etc/systemd/system/redis.service

sudo adduser --system --group --no-create-home redis
sudo mkdir /var/lib/redis
sudo chown redis:redis /var/lib/redis
sudo chmod 770 /var/lib/redis
sudo systemctl start redis
sudo systemctl enable redis

########## INSTALL ELASTICSEARCH ##########
sudo apt-get -y install elasticsearch

sudo cp $CONFIG_PATH/elasticsearch/elasticsearch.yml /etc/elasticsearch/elasticsearch.yml

sudo service elasticsearch restart

########## INSTALL LOGSTASH ##########
sudo apt-get update && sudo apt-get install logstash
sudo apt-get install -y haveged
sed -i 's/^# config.reload.automatic: false/config.reload.automatic: true/g' /etc/logstash/logstash.yml

sudo cp $CONFIG_PATH/logstash/apache-filter.conf /etc/logstash/conf.d/apache-filter.conf
sudo cp $CONFIG_PATH/logstash/logstash-indexer.conf /etc/logstash/conf.d/logstash-indexer.conf
sudo cp $CONFIG_PATH/logstash/syslog-filter.conf /etc/logstash/conf.d/syslog-filter.conf
sudo cp $CONFIG_PATH/logstash/syslog-network-filter.conf /etc/logstash/conf.d/syslog-network-filter.conf
sudo cp $CONFIG_PATH/logstash/30-elasticsearch-output.conf /etc/logstash/conf.d/30-elasticsearch-output.conf

sudo usermod -a -G adm logstash
sudo service logstash restart
if [OS_VERSION = "16.04"]; then
  chmod 664 /etc/systemd/system/logstash.service
  systemctl daemon-reload
  systemctl enable logstash.service
fi
if [OS_VERSION = "14.04"]; then
  sudo update-rc.d logstash defaults 96 9
fi

########## INSTALL KIBANA ##########
sudo apt-get -y install kibana

sudo cp $CONFIG_PATH/kibana/kibana.yml /etc/kibana/kibana.yml
sudo service kibana restart

if [OS_VERSION = "16.04"]; then
  sudo chmod 664 /etc/systemd/system/kibana.service
  sudo systemctl daemon-reload
  sudo systemctl enable kibana.service
fi
if [OS_VERSION = "14.04"]; then
  sudo update-rc.d kibana defaults 96 9
fi


########## INSTALL NGNIX ##########
sudo apt-get install -y nginx apache2-utils
sudo htpasswd -cb /etc/nginx/htpasswd.users kibanaadmin kibanaadmin

sudo cp $CONFIG_PATH/nginx/default /etc/nginx/sites-available/default
sudo service nginx restart

########## SHEEPER ##########

sudo cp -R /etc/logstash /etc/logsheeper
sudo rm /etc/logsheeper/conf.d/*
sudo mkdir /var/lib/logsheeper

sed -i 's&^/var/log/logstash/gc.log&/var/log/logsheeper/gc.log&g' /etc/logsheeper/startup.options
sed -i 's&^/etc/logstash&/etc/logsheeper&g' /etc/logsheeper/startup.options
sed -i 's&^/var/run/logstash.pid.log&/var/run/logsheeper.pid&g' /etc/logsheeper/startup.options

sed -i 's&^/var/log/logstash&/var/log/logsheepers&g' /etc/logsheeper/logstash.yml
sed -i 's&^/var/lib/logstashs&/var/lib/logsheeper&g' /etc/logsheeper/logstash.yml

sudo cp $CONFIG_PATH/logsheeper/input.conf /etc/logsheeper/conf.d/input.conf
sudo cp $CONFIG_PATH/logsheeper/output.conf /etc/logsheeper/conf.d/output.conf

sudo cp $CONFIG_PATH/logsheeper/logsheeper.service /etc/systemd/system/logsheeper.service
sudo service logsheeper restart

if [OS_VERSION = "16.04"]; then
  sudo chmod 664 /etc/systemd/system/logsheeper.service
  sudo systemctl daemon-reload
  sudo systemctl enable logsheeper.service
fi
if [OS_VERSION = "14.04"]; then
  sudo update-rc.d logsheeper defaults 96 9
fi


########## Sample Kibana dashboards ##########
cd ~
curl -L -O https://download.elastic.co/beats/dashboards/beats-dashboards-1.1.0.zip
unzip -o beats-dashboards-*.zip
cd beats-dashboards-*
./load.sh


echo "====================== Test Elasticsearch ==============================="
curl -XGET "http://localhost:9200/filebeat-*/_search?pretty"
