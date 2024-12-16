# On va secure un VM 

## On commence par enlever totes les tolls inutile d'nginx qui nous rende plus vulnérable
### 1- on cache la version d'nginx
```http {

        ##
        # Basic Settings
        ##

        sendfile on;
        tcp_nopush on;
        types_hash_max_size 2048;
        server_tokens off; \\ et la on a retiré le # pour activé cette conf
```
### 2-on affiche un server web different au yeux des hacker
```
root@debian:/etc/nginx# sudo apt update; sudo apt install nginx-extras -y
```
```
http {

        ##
        # Basic Settings
        ##

        sendfile on;
        tcp_nopush on;
        types_hash_max_size 2048;
        server_tokens off;
        more_set_headers 'Caddy server'; // Caddy c'est le nom d'un autre server, il va se casser la tete à pour le mauvais du coup
```

## il me faut un firewall !!! //firewalld
```
root@debian:/etc/nginx# sudo apt install firewalld
```
```
root@debian:/etc/nginx# sudo systemctl enable firewalld
root@debian:/etc/nginx# sudo systemctl start firewalld
```

## Je m'occupe des users pour plus de sécurité
### nouvel user ajouté
```
adduser will
Adding user `will' ...
Adding new group `will' (1000) ...
Adding new user `will' (1000) with group `will (1000)' ...
Creating home directory `/home/will' ...
Copying files from `/etc/skel' ...
New password:
Retype new password:
passwd: password updated successfully
Changing the user information for will
Enter the new value, or press ENTER for the default
        Full Name []:
        Room Number []:
        Work Phone []:
        Home Phone []:
        Other []:
Is the information correct? [Y/n] y
Adding new user `will' to supplemental / extra groups `users' ...
Adding user `will' to group `users' ...
```
### on lui donne les permissions root
```
root@debian:/etc# sudo usermod -aG sudo will
```
### on s'y connecte puis on interdit la connexion ssh en root dans le fichier /etc/ssh/sshd.conf
```
PermitRootLogin no
```

## on configure Fail2ban
```
will@debian:/etc/ssh$ sudo apt install fail2ban
```
### dans /etc/fail2ban/jail.local on le config pour ssh
```
[sshd]
enabled = true
port = ssh
logpath = /var/log/secure
maxretry = 5
```
### et on peut démarrer fail2ban chill
```
will@debian:/etc$ sudo systemctl enable fail2ban
Synchronizing state of fail2ban.service with SysV service script with /lib/systemd/systemd-sysv-install.
Executing: /lib/systemd/systemd-sysv-install enable fail2ban
will@debian:/etc$ sudo systemctl start fail2ban
will@debian:/etc$
```





