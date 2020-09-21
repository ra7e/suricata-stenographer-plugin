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