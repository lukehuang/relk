#!/bin/bash
set -x
set -e
# This script opens 4 terminal windows.

i="0"
echo $1
sed -i "s/benchmark: \(.*\)/benchmark: $1/g" "/etc/filebeat/filebeat.yml"
sed -i "s/id: \(.*\)/id: $2/g" "/etc/filebeat/filebeat.yml"
service filebeat restart
while [ $i -lt 1500 ]
do
echo "$(date) $i message$i" >> /var/log/custom.log
i=$[$i+1]
sleep 1
done
