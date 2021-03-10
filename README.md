# Suricata plugin for stenographer integration


## Installation
Build using 
```bash
CPPFLAGS="-I/opt/suricata/src" make
```

where ```/opt/suricata/src``` is a path to suricata source code.

## Usage 

Change suricata configuration file like this to enable eve logging using stenographer 

```
 plugins:
  - /Suricata-stenographer-plugin/eve-stenographer.so

outputs:
...
  - eve-log:
      enabled: yes
      filetype: stenographer-plugin #regular|syslog|unix_dgram|unix_stream|redis
      filename: eve.json

      stenographer-plugin:
        enabled: yes
        filename: /var/log/stenographer.log
        pcap-dir: /tmp/pcaps/
        before-time: 30
        after-time: 5
        compression: no
        no-overlapping: no
        cleanup:
          enabled: no
          script: /home/vadym/script.sh
          expiry-time: 0
          min-disk-space-left: 4000000000
```


Where  ```/Suricata-stenographer-plugin/eve-stenographer.so``` is a path to installed plugin, ```filename``` is a path to file, where stenographer events will be logged, ```pcap-dir``` is a path to directory, where pcap files will be saved, ```before-time``` and ```after-time``` are the amount of seconds to save packets before and after alert occured, ```compression``` is an ability to save compressed pcap files, ```no-overlapping``` is an option to disable saving same packets more than 1 time (if there are many alerts at the same time), ```cleanup``` is an option to clean pcap's folder if more than ```min-disk-space-left``` left on device or pcap file is older than ```expiry-time``` seconds, ```script``` option will be executed before cleanup code. 

You can specify time measurment units for ```before-time```, ```after-time```, ```expiry-time```  and memory units for ```min-disk-space-left```. For example:
```
      before-time: 30s
      after-time: 5m
      expiry-time: 2h
      min-disk-space-left: 4gb
``` 

| Units | Description | Units | Description |   
| :---: | :---: | :---: | :---:|
|```s```|```second```| ```kb```| ```Kilobytes``` |
|```m```|```minutes```|```mb```| ```Megabytes``` |
|```h```|```hours```| ```gb```| ```Gigabytes``` |
|```d```|```days```|
|```w```|```week```|

Without any of these specfiers **default values would be** set  - ```s``` for time units and ```kb``` for memory units. 

You can add alert by your hands using ```named pipe```. 

First of all you need to add line ```command-pipe: <filename>``` to your configuration file, like this:
```
      stenographer-plugin:
        enabled: yes
        filename: /var/log/stenographer.log
        pcap-dir: /tmp/pcaps/
        cert-dir: /etc/stenographer/certs/
        before-time: 30
        after-time: 5
        compression: no
        no-overlapping: no
        command-pipe: external_alerts
        cleanup:
          enabled: yes
          script: /home/vadym/script.sh
          expiry-time: 1m
          min-disk-space-left: 4000000000
```
**Plagin can create named pipe file by himself** when it does not exist. In this case it would be ```external_alerts```. Mention that **root** would be owner of created named pipe.

You can write something to named pipe under root using this syntax:
```echo <message> > <name of named pipe> &```.
The ```&``` puts this into the background so you can continue to type commands in the same shell.
