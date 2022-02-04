# JMS

#### JMS = 10.100.120.122 / lbmeet.company.lan
#### JVB = 10.100.120.123
#### coturn = 10.100.120.111 / coturn.company.lan


## Repository download


```
curl https://download.jitsi.org/jitsi-key.gpg.key | sudo sh -c 'gpg --dearmor > /usr/share/keyrings/jitsi-keyring.gpg'
echo 'deb [signed-by=/usr/share/keyrings/jitsi-keyring.gpg] https://download.jitsi.org stable/' | sudo tee /etc/apt/sources.list.d/jitsi-stable.list > /dev/null

apt update
```



## Debconf setup


```
apt install debconf-utils
```


Configuration Deb package


```
cat << EOF | sudo debconf-set-selections
jitsi-videobridge2      jitsi-videobridge/jvb-hostname  string  lbmeet.company.lan
jitsi-meet-prosody      jitsi-videobridge/jvbsecret     password        Ztr0ngP4ssw!ord
jitsi-meet              jitsi-meet/jvb-serve    boolean false
jitsi-meet-prosody      jitsi-videobridge/jvb-hostname  string  lbmeet.company.lan
jitsi-meet-prosody      jitsi-meet-prosody/jvb-hostname string  lbmeet.company.lan
jitsi-meet-web-config   jitsi-meet/cert-choice select I want to use my own certificate
jitsi-meet-web-config   jitsi-meet/cert-path-crt        string  /etc/ssl/lbmeet_cert.pem
jitsi-meet-web-config   jitsi-meet/cert-path-key        string  /etc/ssl/lbmeet_pvkey.pem
EOF
```



## Firewall port


```
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 10000/udp
sudo ufw allow 22/tcp
sudo ufw allow 3478/udp
sudo ufw allow 5347/tcp
sudo ufw allow 9090/tcp
sudo ufw allow 5349/tcp
sudo ufw allow 34522/tcp
sudo ufw enable
```



## Certificate for JMS

Create cert and key pem in /etc/ssl/


```
nano /etc/ssl/lbmeet_pvkey.pem
nano /etc/ssl/lbmeet_cert.pem
```


And copy cert and key inside


## Installation of packages

Install all package except jitsi-videobridge2


```
apt install -y nginx nginx-full prosody jicofo jitsi-meet-web jitsi-meet-prosody jitsi-meet-web-config
```



## Check debconf configuration: 


```
debconf-get-selections | grep -P "(jibri|jicofo|jigasi|jitsi)"
```



## **Jicofo**

/etc/jitsi/jicofo/config


```
JICOFO_HOST=lbmeet.company.lan
JICOFO_HOSTNAME=lbmeet.company.lan
JICOFO_AUTH_DOMAIN=auth.lbmeet.company.lan
JICOFO_AUTH_USER=focus
JICOFO_AUTH_PASSWORD=NEfeCQhD6cBrsh4l
JICOFO_OPTS=""

JAVA_SYS_PROPS="-Dconfig.file=/etc/jitsi/jicofo/jicofo.conf -Dnet.java.sip.communicator.SC_HOME_DIR_LOCATION=/etc/jitsi -Dnet.java.sip.communicator.SC_HOME_DIR_NAME=jicofo -Dnet.java.sip.communicator.SC_LOG_DIR_LOCATION=/var/log/jitsi -Djava.util.logging.config.file=/etc/jitsi/jicofo/logging.properties"
```


/etc/jitsi/jicofo/jicofo.conf


```
jicofo {
  xmpp: {
    client: {
      client-proxy: focus.lbmeet.company.lan
    }
    trusted-domains: [ "recorder.lbmeet.company.lan" ]
  }
  bridge: {
    brewery-jid: "JvbBrewery@internal.auth.lbmeet.company.lan"
  }
}
```



## **Prosody**

/etc/prosody/conf.avail/lbmeet.company.lan.cfg.lua

```
plugin_paths = { "/usr/share/jitsi-meet/prosody-plugins/" }

-- domain mapper options, must at least have domain base set to use the mapper
muc_mapper_domain_base = "lbmeet.company.lan";

external_service_secret = "9fl567cbb7bb4232593f564409gh4jj0d85322057485c27b5";
external_services = {
     { type = "stun", host = "coturn.company.lan", port = 3478 },
     { type = "turn", host = "coturn.company.lan", port = 3478, transport = "udp", secret = true, ttl = 86400, algorithm = "turn" },
     { type = "turns", host = "coturn.company.lan", port = 5349, transport = "tcp", secret = true, ttl = 86400, algorithm = "turn" }
};

cross_domain_bosh = false;
consider_bosh_secure = true;
-- https_ports = { }; -- Remove this line to prevent listening on port 5284

-- https://ssl-config.mozilla.org/#server=haproxy&version=2.1&config=intermediate&openssl=1.1.0g&guideline=5.4
ssl = {
    protocol = "tlsv1_2+";
    ciphers = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384"
}

unlimited_jids = {
    "focus@auth.lbmeet.company.lan",
    "jvb@auth.lbmeet.company.lan"
}

VirtualHost "lbmeet.company.lan"
    -- enabled = false -- Remove this line to enable this host
    authentication = "anonymous"
    -- Properties below are modified by jitsi-meet-tokens package config
    -- and authentication above is switched to "token"
    --app_id="example_app_id"
    --app_secret="example_app_secret"
    -- Assign this host a certificate for TLS, otherwise it would use the one
    -- set in the global section (if any).
    -- Note that old-style SSL on port 5223 only supports one certificate, and will always
    -- use the global one.
    ssl = {
        key = "/etc/prosody/certs/lbmeet.company.lan.key";
        certificate = "/etc/prosody/certs/lbmeet.company.lan.crt";
    }
    av_moderation_component = "avmoderation.lbmeet.company.lan"
    speakerstats_component = "speakerstats.lbmeet.company.lan"
    conference_duration_component = "conferenceduration.lbmeet.company.lan"
    -- we need bosh
    modules_enabled = {
        "bosh";
        "pubsub";
        "ping"; -- Enable mod_ping
        "speakerstats";
        "external_services";
        "conference_duration";
        "muc_lobby_rooms";
        "muc_breakout_rooms";
        "av_moderation";
    }
    c2s_require_encryption = false
    lobby_muc = "lobby.lbmeet.company.lan"
    breakout_rooms_muc = "breakout.lbmeet.company.lan"
    main_muc = "conference.lbmeet.company.lan"
    -- muc_lobby_whitelist = { "recorder.lbmeet.company.lan" } -- Here we can whitelist jibri to enter lobby enabled rooms

Component "conference.lbmeet.company.lan" "muc"
    restrict_room_creation = true
    storage = "memory"
    modules_enabled = {
        "muc_meeting_id";
        "muc_domain_mapper";
        "polls";
        --"token_verification";
        "muc_rate_limit";
    }
    admins = { "focus@auth.lbmeet.company.lan" }
    muc_room_locking = false
    muc_room_default_public_jids = true

Component "breakout.lbmeet.company.lan" "muc"
    restrict_room_creation = true
    storage = "memory"
    modules_enabled = {
        "muc_meeting_id";
        "muc_domain_mapper";
        --"token_verification";
        "muc_rate_limit";
    }
    admins = { "focus@auth.lbmeet.company.lan" }
    muc_room_locking = false
    muc_room_default_public_jids = true

-- internal muc component
Component "internal.auth.lbmeet.company.lan" "muc"
    storage = "memory"
    modules_enabled = {
        "ping";
    }
    admins = { "focus@auth.lbmeet.company.lan", "jvb@auth.lbmeet.company.lan" }
    muc_room_locking = false
    muc_room_default_public_jids = true

VirtualHost "auth.lbmeet.company.lan"
    ssl = {
        key = "/etc/prosody/certs/auth.lbmeet.company.lan.key";
        certificate = "/etc/prosody/certs/auth.lbmeet.company.lan.crt";
    }
    modules_enabled = {
        "limits_exception";
    }
    authentication = "internal_hashed"

-- Proxy to jicofo's user JID, so that it doesn't have to register as a component.
Component "focus.lbmeet.company.lan" "client_proxy"
    target_address = "focus@auth.lbmeet.company.lan"

Component "speakerstats.lbmeet.company.lan" "speakerstats_component"
    muc_component = "conference.lbmeet.company.lan"

Component "conferenceduration.lbmeet.company.lan" "conference_duration_component"
    muc_component = "conference.lbmeet.company.lan"

Component "avmoderation.lbmeet.company.lan" "av_moderation_component"
    muc_component = "conference.lbmeet.company.lan"

Component "lobby.lbmeet.company.lan" "muc"
    storage = "memory"
    restrict_room_creation = true
    muc_room_locking = false
    muc_room_default_public_jids = true
    modules_enabled = {
        "muc_rate_limit";
        "polls";
    }
```



## **Meet**

/etc/jitsi/meet/lbmeet.company.lan-config.js


```
var config = {
    hosts: {
        domain: 'lbmeet.company.lan',
        muc: 'conference.<!--# echo var="subdomain" default="" -->lbmeet.company.lan'
    },
    testing: {
    },
    flags: {
    },
    enableNoAudioDetection: true,
    enableNoisyMicDetection: true,
    channelLastN: -1,
    enableWelcomePage: true,
    p2p: {
        enabled: true,
        stunServers: [
            { urls: 'stun:coturn.company.lan:3478' }
        ]
    },
    analytics: {
    },
    deploymentInfo: {
    },
    mouseMoveCallbackInterval: 1000,
    makeJsonParserHappy: 'even if last key had a trailing comma'
};
```



## **NGINX**

/etc/nginx/site-available/lbmeet.company.lan.conf


```
server_names_hash_bucket_size 64;

types {
# nginx's default mime.types doesn't include a mapping for wasm
    application/wasm     wasm;
}
server {
    listen 80;
    listen [::]:80;
    server_name lbmeet.company.lan;

    location ^~ /.well-known/acme-challenge/ {
        default_type "text/plain";
        root         /usr/share/jitsi-meet;
    }
    location = /.well-known/acme-challenge/ {
        return 404;
    }
    location / {
        return 301 https://$host$request_uri;
    }
}
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name lbmeet.company.lan;

    # Mozilla Guideline v5.4, nginx 1.17.7, OpenSSL 1.1.1d, intermediate configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;  # about 40000 sessions
    ssl_session_tickets off;

    add_header Strict-Transport-Security "max-age=63072000" always;
    set $prefix "";

    ssl_certificate /etc/ssl/lbmeet_cert.pem;
    ssl_certificate_key /etc/ssl/lbmeet_pvkey.pem;

    root /usr/share/jitsi-meet;

    # ssi on with javascript for multidomain variables in config.js
    ssi on;
    ssi_types application/x-javascript application/javascript;

    index index.html index.htm;
    error_page 404 /static/404.html;

    gzip on;
    gzip_types text/plain text/css application/javascript application/json image/x-icon application/octet-stream application/wasm;
    gzip_vary on;
    gzip_proxied no-cache no-store private expired auth;
    gzip_min_length 512;

    location = /config.js {
        alias /etc/jitsi/meet/lbmeet.company.lan-config.js;
    }

    location = /external_api.js {
        alias /usr/share/jitsi-meet/libs/external_api.min.js;
    }

    # ensure all static content can always be found first
    location ~ ^/(libs|css|static|images|fonts|lang|sounds|connection_optimization|.well-known)/(.*)$
    {
        add_header 'Access-Control-Allow-Origin' '*';
        alias /usr/share/jitsi-meet/$1/$2;

        # cache all versioned files
        if ($arg_v) {
            expires 1y;
        }
    }

    # BOSH
    location = /http-bind {
        proxy_pass http://127.0.0.1:5280/http-bind?prefix=$prefix&$args;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header Host $http_host;
    }

    # xmpp websockets
    location = /xmpp-websocket {
        proxy_pass http://127.0.0.1:5280/xmpp-websocket?prefix=$prefix&$args;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $http_host;
        tcp_nodelay on;
    }

    # colibri (JVB) websockets for jvb1
    #location ~ ^/colibri-ws/default-id/(.*) {
    #    proxy_pass http://127.0.0.1:9090/colibri-ws/default-id/$1$is_args$args;
    #    proxy_http_version 1.1;
    #    proxy_set_header Upgrade $http_upgrade;
    #    proxy_set_header Connection "upgrade";
    #    tcp_nodelay on;
    #}

    # colibri (JVB) websockets for additional JVBs
    #location ~ ^/colibri-ws/([0-9.]*)/(.*) {
    #    proxy_pass http://$1:9090/colibri-ws/$1/$2$is_args$args;
    #    proxy_http_version 1.1;
    #    proxy_set_header Upgrade $http_upgrade;
    #    proxy_set_header Connection "upgrade";
    #    tcp_nodelay on;
    #}
    
    # colibri (JVB) websockets for additional JVBs at 10.100.120.123
    location ~ ^/colibri-ws/10.100.120.123/(.*) {
        proxy_pass http://10.100.120.123:9090/colibri-ws/10.100.120.123/$1$is_args$args;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        tcp_nodelay on;
    }



    # load test minimal client, uncomment when used
    #location ~ ^/_load-test/([^/?&:'"]+)$ {
    #    rewrite ^/_load-test/(.*)$ /load-test/index.html break;
    #}
    #location ~ ^/_load-test/libs/(.*)$ {
    #    add_header 'Access-Control-Allow-Origin' '*';
    #    alias /usr/share/jitsi-meet/load-test/libs/$1;
    #}

    location ~ ^/([^/?&:'"]+)$ {
        try_files $uri @root_path;
    }

    location @root_path {
        rewrite ^/(.*)$ / break;
    }

    location ~ ^/([^/?&:'"]+)/config.js$
    {
        set $subdomain "$1.";
        set $subdir "$1/";

        alias /etc/jitsi/meet/lbmeet.company.lan-config.js;
    }

    # BOSH for subdomains
    location ~ ^/([^/?&:'"]+)/http-bind {
        set $subdomain "$1.";
        set $subdir "$1/";
        set $prefix "$1";

        rewrite ^/(.*)$ /http-bind;
    }

    # websockets for subdomains
    location ~ ^/([^/?&:'"]+)/xmpp-websocket {
        set $subdomain "$1.";
        set $subdir "$1/";
        set $prefix "$1";

        rewrite ^/(.*)$ /xmpp-websocket;
    }

    # Anything that didn't match above, and isn't a real file, assume it's a room name and redirect to /
    location ~ ^/([^/?&:'"]+)/(.*)$ {
        set $subdomain "$1.";
        set $subdir "$1/";
        rewrite ^/([^/?&:'"]+)/(.*)$ /$2;
    }
}
```



# JVB


## Basic install


```
curl https://download.jitsi.org/jitsi-key.gpg.key | sudo sh -c 'gpg --dearmor > /usr/share/keyrings/jitsi-keyring.gpg'
echo 'deb [signed-by=/usr/share/keyrings/jitsi-keyring.gpg] https://download.jitsi.org stable/' | sudo tee /etc/apt/sources.list.d/jitsi-stable.list > /dev/null

apt update
```



## Debconf setup


```
apt install debconf-utils

cat << EOF | sudo debconf-set-selections
jitsi-videobridge       jitsi-videobridge/jvb-hostname  string  lbmeet.company.lan
jitsi-meet              jitsi-meet/jvb-serve    boolean false
jitsi-meet-prosody      jitsi-videobridge/jvb-hostname  string  lbmeet.company.lan
jitsi-meet-web-config   jitsi-meet/cert-choice select I want to use my own certificate
jitsi-meet-web-config   jitsi-meet/cert-path-crt        string  /etc/ssl/lbmeet_cert.pem
jitsi-meet-web-config   jitsi-meet/cert-path-key        string  /etc/ssl/lbmeet_pvkey.pem
jitsi-meet-prosody      jitsi-videobridge/jvbsecret     password        Ztr0ngP4ssw!ord
EOF
```

## Firewall
```
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 10000/udp
sudo ufw allow 22/tcp
sudo ufw allow 3478/udp
sudo ufw allow 5349/tcp
sudo ufw allow 5347/tcp
sudo ufw allow 34522/tcp
ufw allow 5222/tcp
ufw allow 9090/tcp
ufw allow 4096/udp
sudo ufw enable
```



## **Install JVB only**


```
apt install jitsi-videobridge2
```



## **Configuration file**

/etc/jitsi/videobridge/config


```
JVB_HOSTNAME=lbmeet.company.lan
JVB_HOST=lbmeet.company.lan
JVB_PORT=5347
JVB_SECRET=9cNUuCaG
JAVA_SYS_PROPS="-Dconfig.file=/etc/jitsi/videobridge/jvb.conf -Dnet.java.sip.communicator.SC_HOME_DIR_LOCATION=/etc/jitsi -Dnet.java.sip.communicator.SC_HOME_DIR_NAME=videobridge -Dnet.java.sip.communicator.SC_LOG_DIR_LOCATION=/var/log/jitsi -Djava.util.logging.config.file=/etc/jitsi/videobridge/logging.properties"
```


/etc/jitsi/videobridge/jvb.conf


```
videobridge {
    http-servers {
        public {
            port = 9090
        }
    }
    websockets {
        enabled = true
        server-id = "10.100.120.123"
        domain = "lbmeet.company.lan:443"
        tls = true
    }
}
```


/etc/jitsi/videobridge/sip-communicator.properties


```
org.ice4j.ice.harvest.DISABLE_AWS_HARVESTER=true
org.ice4j.ice.harvest.STUN_MAPPING_HARVESTER_ADDRESSES=coturn.company.lan:3478
org.jitsi.videobridge.ENABLE_STATISTICS=true
org.jitsi.videobridge.STATISTICS_TRANSPORT=muc
org.jitsi.videobridge.xmpp.user.shard.HOSTNAME=lbmeet.company.lan
org.jitsi.videobridge.xmpp.user.shard.DOMAIN=auth.lbmeet.company.lan
org.jitsi.videobridge.xmpp.user.shard.USERNAME=jvb
org.jitsi.videobridge.xmpp.user.shard.PASSWORD=9cNUuCaG
org.jitsi.videobridge.xmpp.user.shard.MUC_JIDS=JvbBrewery@internal.auth.lbmeet.company.lan
org.jitsi.videobridge.xmpp.user.shard.MUC_NICKNAME=6c7ebce4-b7cc-464e-a6c6-bb0a67746442
org.jitsi.jicofo.auth.URL=XMPP:lbmeet.company.lan
org.jitsi.videobridge.DISABLE_TCP_HARVESTER=true
org.jitsi.videobridge.xmpp.user.shard.DISABLE_CERTIFICATE_VERIFICATION=true
