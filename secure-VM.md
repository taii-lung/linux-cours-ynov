# On va secure un VM 

## On commence par enlever totes les tolls inutile d'nginx qui nous rende plus vulnérable
### 1
```http {

        ##
        # Basic Settings
        ##

        sendfile on;
        tcp_nopush on;
        types_hash_max_size 2048;
        server_tokens off;```

