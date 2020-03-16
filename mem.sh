#!/bin/bash
USEDMEMORY=$(free -m | awk 'NR==2{printf "%.2f	", $3*100/$2 }')
TCP_CONN=$(netstat -an | wc -l)
TCP_CONN_PORT_80=$(netstat -an | grep 80 | wc -l)
USERS=$(uptime |awk '{ print $6 }')
IO_WAIT=$(iostat | awk 'NR==4 {print $5}')
instance_id=i-01b0860b3f7cb31fd
aws cloudwatch put-metric-data --metric-name memory-usage --dimensions Instance=$instance_id  --namespace "Custom" --value $USEDMEMORY
aws cloudwatch put-metric-data --metric-name Tcp_connections --dimensions Instance=$instance_id  --namespace "Custom" --value $TCP_CONN
aws cloudwatch put-metric-data --metric-name TCP_connection_on_port_80 --dimensions Instance=$instance_id  --namespace "Custom" --value $TCP_CONN_PORT_80
aws cloudwatch put-metric-data --metric-name IO_WAIT --dimensions Instance=$instance_id --namespace "Custom" --value $IO_WAIT
