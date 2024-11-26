# TP 1
## Étape 1 : Analyse et nettoyage du serveur
### Lister les tâches cron pour détecter des backdoors 
```
[root@localhost ~]# cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:65534:65534:Kernel Overflow User:/:/sbin/nologin
tss:x:59:59:Account used for TPM access:/:/usr/sbin/nologin
systemd-coredump:x:999:997:systemd Core Dumper:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
sssd:x:998:996:User for sssd:/:/sbin/nologin
chrony:x:997:995:chrony system user:/var/lib/chrony:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/usr/share/empty.sshd:/usr/sbin/nologin
attacker:x:1000:1000::/home/attacker:/bin/bash

[root@localhost ~]# sudo crontab -u attacker -l
*/10 * * * * /tmp/.hidden_script
```

### Identifier et supprimer les fichiers cachés :
```
[root@localhost ~]# cd /tmp/
[root@localhost tmp]# ls -a
.             .hidden_script
..            malicious.sh
.ICE-unix     systemd-private-438372070bdc43e3978370ece47c744e-chronyd.service-lBLUzH
.X11-unix     systemd-private-438372070bdc43e3978370ece47c744e-dbus-broker.service-1WFA6d
.XIM-unix     systemd-private-438372070bdc43e3978370ece47c744e-irqbalance.service-46ggjN
.font-unix    systemd-private-438372070bdc43e3978370ece47c744e-kdump.service-bi0Kbs
.hidden_file  systemd-private-438372070bdc43e3978370ece47c744e-systemd-logind.service-ZTkaoX
[root@localhost tmp]# rm .hidden_script malicious.sh .hidden_file 
rm: remove regular file '.hidden_script'? y
rm: remove regular file 'malicious.sh'? y
rm: remove regular file '.hidden_file'? y

[root@localhost tmp]# ls -a
.           systemd-private-438372070bdc43e3978370ece47c744e-chronyd.service-lBLUzH
..          systemd-private-438372070bdc43e3978370ece47c744e-dbus-broker.service-1WFA6d
.ICE-unix   systemd-private-438372070bdc43e3978370ece47c744e-irqbalance.service-46ggjN
.X11-unix   systemd-private-438372070bdc43e3978370ece47c744e-kdump.service-bi0Kbs
.XIM-unix   systemd-private-438372070bdc43e3978370ece47c744e-systemd-logind.service-ZTkaoX
.font-unix
```

### Analyser les connexions réseau actives :
```
[root@localhost ~]# sudo ss -tunap
Netid      State       Recv-Q      Send-Q                   Local Address:Port              Peer Address:Port       Process                                                                                                             
udp        ESTAB       0           0                192.168.56.101%enp0s8:68              192.168.56.100:67          users:(("NetworkManager",pid=845,fd=36))                                                                           
udp        ESTAB       0           0                     10.0.2.15%enp0s3:68                    10.0.2.2:67          users:(("NetworkManager",pid=845,fd=26))                                                                           
udp        UNCONN      0           0                            127.0.0.1:323                    0.0.0.0:*           users:(("chronyd",pid=836,fd=5))                                                                                   
udp        UNCONN      0           0                                [::1]:323                       [::]:*           users:(("chronyd",pid=836,fd=6))                                                                                   
tcp        LISTEN      0           128                            0.0.0.0:22                     0.0.0.0:*           users:(("sshd",pid=868,fd=3))                                                                                      
tcp        ESTAB       0           0                       192.168.56.101:22                192.168.56.1:34030       users:(("sshd",pid=1726,fd=4),("sshd",pid=1722,fd=4))                                                              
tcp        LISTEN      0           128                               [::]:22                        [::]:*           users:(("sshd",pid=868,fd=4))  
```

## Étape 2 : Configuration avancée de LVM
### Créer un snapshot de sécurité pour /mnt/secure_data :
```
[root@localhost secure_data]# sudo lvcreate --snapshot --name mylv_snapshot --size 500M /dev/vg_secure/secure_data 
```

### Tester la restauration du snapshot :
```
[root@localhost secure_data]# sudo mkdir /mnt/mylv_snapshot
[root@localhost secure_data]# sudo mount /dev/vg_secure/mylv_snapshot /mnt/mylv_snapshot
[root@localhost secure_data]# ls /mnt/mylv_snapshot
lost+found  sensitive1.txt  sensitive2.txt
[root@localhost secure_data]# sudo cp /mnt/mylv_snapshot/sensitive1.txt /mnt/secure_data/
[root@localhost secure_data]# ls /mnt/secure_data
lost+found  sensitive1.txt  sensitive2.txt
```

### Optimiser l’espace disque :
```
[root@localhost ~]# sudo lvchange -an /dev/vg_secure/secure_data 
  Logical volume vg_secure/secure_data contains a filesystem in use.

[root@localhost ~]# mount | grep secure_data
/dev/mapper/vg_secure-secure_data on /mnt/secure_data type ext4 (rw,relatime,seclabel)
[root@localhost ~]# sudo umount /mnt/secure_data

[root@localhost ~]# sudo lvchange -an /dev/vg_secure/secure_data

[root@localhost ~]# sudo lvextend -L +3M /dev/vg_secure/secure_data
  Rounding size to boundary between physical extents: 4.00 MiB.
  Size of logical volume vg_secure/secure_data changed from 500.00 MiB (125 extents) to 504.00 MiB (126 extents).
  Logical volume vg_secure/secure_data successfully resized.

```

## Étape 3 : Automatisation avec un script de sauvegarde
### Créer un script secure_backup.sh :
```
#!/bin/bash

# Variables
SOURCE_DIR="/mnt/secure_data"
BACKUP_DIR="/backup"
DATE=$(date +"%Y%m%d")
BACKUP_FILE="${BACKUP_DIR}/secure_data_${DATE}.tar.gz"

# Exclusion des fichiers .tmp, .log et fichiers cachés
EXCLUDE_PATTERN="--exclude=*.tmp --exclude=*.log --exclude=.*"

# Vérification que le répertoire source existe
if [ ! -d "$SOURCE_DIR" ]; then
    echo "Erreur : Le répertoire source ${SOURCE_DIR} n'existe pas."
    exit 1
fi

# Création du répertoire de sauvegarde s'il n'existe pas
if [ ! -d "$BACKUP_DIR" ]; then
    echo "Création du répertoire de sauvegarde ${BACKUP_DIR}..."
    mkdir -p "$BACKUP_DIR"
fi

# Création de l'archive
echo "Création de la sauvegarde dans ${BACKUP_FILE}..."
tar czf "$BACKUP_FILE" $EXCLUDE_PATTERN -C "$SOURCE_DIR" .

# Vérification du succès
if [ $? -eq 0 ]; then
    echo "Sauvegarde réussie : ${BACKUP_FILE}"
else
    echo "Erreur lors de la création de la sauvegarde."
    exit 2
fi
```

### Ajoutez une fonction de rotation des sauvegardes :  
```
#!/bin/bash

# Variables
SOURCE_DIR="/mnt/secure_data"
BACKUP_DIR="/backup"
DATE=$(date +"%Y%m%d")
BACKUP_FILE="${BACKUP_DIR}/secure_data_${DATE}.tar.gz"
MAX_BACKUPS=7 

[...]

# Fonction pour effectuer la rotation des sauvegardes 
rotate_backups() {   
    echo "Rotation des sauvegardes..."   
    # Liste des sauvegardes triées par date   
    BACKUP_FILES=$(ls -1t ${BACKUP_DIR}/secure_data_*.tar.gz 2>/dev/null)   
    BACKUP_COUNT=$(echo "$BACKUP_FILES" | wc -l)   
    
    # Supprimer les sauvegardes en excès   
    if [ "$BACKUP_COUNT" -gt "$MAX_BACKUPS" ]; then   
        FILES_TO_DELETE=$(echo "$BACKUP_FILES" | tail -n +$((MAX_BACKUPS + 1)))   
        echo "$FILES_TO_DELETE" | while read -r FILE; do   
            echo "Suppression de l'ancienne sauvegarde : $FILE"   
            rm -f "$FILE"   
        done   
    else   
        echo "Aucune rotation nécessaire. Nombre actuel de sauvegardes : $BACKUP_COUNT."  
    fi   
}  

# Vérification que le répertoire source existe
if [ ! -d "$SOURCE_DIR" ]; then


[...]


    exit 2
fi

# Appeler la fonction de rotation des sauvegardes  
rotate_backups   
```

### Testez le script :
```
[root@localhost ~]# /root/secure_backup.sh 
Création de la sauvegarde dans /backup/secure_data_20241125.tar.gz...
Sauvegarde réussie : /backup/secure_data_20241125.tar.gz
Rotation des sauvegardes...
Aucune rotation nécessaire. Nombre actuel de sauvegardes : 1.


[root@localhost ~]# ls -l /backup/
total 4
-rw-r--r--. 1 root root 45 Nov 25 21:31 secure_data_20241125.tar.gz
```

### Automatisez avec une tâche cron :
```
[root@localhost ~]# sudo crontab -e

j'ajoute dans l'éditeur:
0 3 * * * /root/secure_backup.sh

je sauvegarde et je quitte.
```

## Étape 4 : Surveillance avancée avec auditd
### Configurer auditd pour surveiller /etc :
```
[root@localhost ~]# sudo auditctl -a always,exit -F arch=b64 -S open,openat,creat,unlink,rename -F dir=/etc -F perm=wa -k etc_changes
[root@localhost ~]# sudo nano /etc/audit/rules.d/audit.rules
[root@localhost ~]# sudo cat /etc/audit/rules.d/audit.rules 
-a always,exit -F arch=b64 -S open,openat,creat,unlink,rename -F dir=/etc -F perm=wa -k etc_changes
## First rule - delete all
-D

## Increase the buffers to survive stress events.
## Make this bigger for busy systems
-b 8192

## This determine how long to wait in burst of events
--backlog_wait_time 60000

## Set failure mode to syslog
-f 1


```

### Tester la surveillance :
```
[root@localhost ~]# sudo touch /etc/test_audit
[root@localhost ~]# echo "Test auditd" | sudo tee -a /etc/test_audit
Test auditd
[root@localhost ~]# sudo rm /etc/test_audit

[root@localhost ~]# sudo ausearch -k etc_changes | grep etc_changes
type=SYSCALL msg=audit(1732568925.388:540): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7fff63e798ea a2=941 a3=1b6 items=2 ppid=2561 pid=2563 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="touch" exe="/usr/bin/touch" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="etc_changes"
type=SYSCALL msg=audit(1732568935.358:547): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7ffe099738eb a2=441 a3=1b6 items=2 ppid=2567 pid=2569 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="tee" exe="/usr/bin/tee" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="etc_changes"
type=SYSCALL msg=audit(1732568941.067:554): arch=c000003e syscall=263 success=yes exit=0 a0=ffffff9c a1=562c075f0c20 a2=0 a3=100 items=2 ppid=2570 pid=2572 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="rm" exe="/usr/bin/rm" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="etc_changes"
```

### Analyser les événements :
```
[root@localhost ~]# sudo ausearch -k etc_changes

[root@localhost ~]# sudo ausearch -k etc_changes > /var/log/audit_etc.log

```

## Étape 5 : Sécurisation avec Firewalld
### Configurer un pare-feu pour SSH et HTTP/HTTPS uniquement :
```
[root@localhost ~]# sudo firewall-cmd --permanent --add-service=ssh
Warning: ALREADY_ENABLED: ssh
success

[root@localhost ~]# sudo firewall-cmd --permanent --add-service=http
success

[root@localhost ~]# sudo firewall-cmd --permanent --add-service=https
Warning: ALREADY_ENABLED: https
success

[root@localhost ~]# sudo firewall-cmd --list-all
public (active)
  target: default
  icmp-block-inversion: no
  interfaces: enp0s3 enp0s8
  sources: 
  services: cockpit dhcpv6-client https ssh
  ports: 2222/tcp
  protocols: 
  forward: yes
  masquerade: no
  forward-ports: 
  source-ports: 
  icmp-blocks: 
  rich rules: 

[root@localhost ~]# sudo firewall-cmd --permanent --remove-service=cockpit
success

[root@localhost ~]# sudo firewall-cmd --permanent --remove-service=dhcpv6-client
success

```

### Bloquer des IP suspectes :
```
[root@localhost ~]# sudo ausearch -k etc_changes | grep "addr="
type=SOCKADDR msg=audit(1732567969.535:403): saddr=100000000000000000000000
type=SOCKADDR msg=audit(1732568096.822:428): saddr=100000000000000000000000
type=SOCKADDR msg=audit(1732568170.373:453): saddr=100000000000000000000000
type=SOCKADDR msg=audit(1732568517.482:486): saddr=100000000000000000000000
type=SOCKADDR msg=audit(1732568553.595:493): saddr=100000000000000000000000
[root@localhost ~]# sudo ss -tupn | grep ESTAB
udp   ESTAB 0      0      192.168.56.101%enp0s8:68   192.168.56.100:67    users:(("NetworkManager",pid=860,fd=36))
udp   ESTAB 0      0           10.0.2.15%enp0s3:68         10.0.2.2:67    users:(("NetworkManager",pid=860,fd=26))
tcp   ESTAB 0      0             192.168.56.101:22     192.168.56.1:37484 users:(("sshd",pid=1524,fd=4),("sshd",pid=1520,fd=4))

il n'y a pas d'adresse IP malveillantes
```

### Restreindre SSH à un sous-réseau spécifique :
```
[root@localhost ~]# sudo firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='192.168.1.0/24' service name='ssh' accept"
success

[root@localhost ~]# sudo firewall-cmd --reload
success

[root@localhost ~]# sudo firewall-cmd --list-rich-rules
rule family="ipv4" source address="192.168.1.0/24" service name="ssh" accept

```



# DLC
## Étape 1 : Analyse avancée et suppression des traces suspectes
### Rechercher des utilisateurs récemment ajoutés :
```
[root@localhost secure_data]# sudo cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:65534:65534:Kernel Overflow User:/:/sbin/nologin
tss:x:59:59:Account used for TPM access:/:/usr/sbin/nologin
systemd-coredump:x:999:997:systemd Core Dumper:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
sssd:x:998:996:User for sssd:/:/sbin/nologin
chrony:x:997:995:chrony system user:/var/lib/chrony:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/usr/share/empty.sshd:/usr/sbin/nologin
attacker:x:1000:1000::/home/attacker:/bin/bash

il y a un utilisateur attacker, surement malveillant
```

### Trouver les fichiers récemment modifiés dans des répertoires critiques :
```
[root@localhost ~]# sudo find /etc /usr/local/bin /var -type f -mtime -7 | grep secure
/etc/lvm/backup/vg_secure
/etc/lvm/archive/vg_secure_00001-428914066.vg
/etc/lvm/archive/vg_secure_00003-423511421.vg
/etc/lvm/archive/vg_secure_00000-1860456324.vg
/etc/lvm/archive/vg_secure_00002-656608851.vg
/var/log/secure
```

### Lister les services suspects activés :
``` 
[root@localhost ~]# sudo systemctl list-unit-files --state=enabled
UNIT FILE                          STATE   PRESET  
auditd.service                     enabled enabled 
chronyd.service                    enabled enabled 
crond.service                      enabled enabled 
dbus-broker.service                enabled enabled 
firewalld.service                  enabled enabled 
getty@.service                     enabled enabled 
irqbalance.service                 enabled enabled 
kdump.service                      enabled enabled 
lvm2-monitor.service               enabled enabled 
microcode.service                  enabled enabled 
NetworkManager-dispatcher.service  enabled enabled 
NetworkManager-wait-online.service enabled disabled
NetworkManager.service             enabled enabled 
nis-domainname.service             enabled enabled 
rsyslog.service                    enabled enabled 
selinux-autorelabel-mark.service   enabled enabled 
sshd.service                       enabled enabled 
sssd.service                       enabled enabled 
systemd-boot-update.service        enabled enabled 
systemd-network-generator.service  enabled enabled 
dbus.socket                        enabled enabled 
dm-event.socket                    enabled enabled 
lvm2-lvmpolld.socket               enabled enabled 
sssd-kcm.socket                    enabled enabled 
reboot.target                      enabled enabled 
remote-fs.target                   enabled enabled 
dnf-makecache.timer                enabled enabled 
logrotate.timer                    enabled enabled 

je ne vois pas quel service est senser etre malveillant.
```

### Supprimer une tâche cron suspecte : 
``` 
[root@localhost ~]# ls /var/spool/cron/
attacker
[root@localhost ~]# sudo crontab -u attacker -r
[root@localhost ~]# ls /var/spool/cron/
```

## Étape 2 : Configuration avancée de LVM
### Créer un snapshot du volume logique :
``` 
[root@localhost ~]# sudo lvcreate --snapshot --name secure_data_snapshot --size 500M /dev/vg_secure/secure_data
  Rounding up size to full physical extent 500.00 MiB
  Logical volume "secure_data_snapshot" created.
```

### Tester le snapshot :
``` 
[root@localhost ~]# sudo mount /dev/vg_secure/secure_data_snapshot /mnt/secure_data_snapshot

[root@localhost ~]# sudo ls /mnt/secure_data_snapshot
lost+found  sensitive1.txt  sensitive2.txt

```

### Simuler une restauration :
``` 
[root@localhost ~]# sudo rm /mnt/secure_data/sensitive2.txt

[root@localhost ~]# sudo cp /mnt/secure_data_snapshot/sensitive2.txt /mnt/secure_data/

[root@localhost secure_data]# ls
sensitive1.txt  sensitive2.txt  testfile1.txt  testfile2.txt
```

## Étape 3 : Renforcement du pare-feu avec des règles dynamiques
### Bloquer les attaques par force brute :  
``` 
[root@localhost secure_data]# sudo firewall-cmd --permanent --add-rich-rule="rule family='ipv4' service name='ssh' limit value='2/m' accept"
success

[root@localhost secure_data]# sudo firewall-cmd --reload
success

[root@localhost secure_data]# sudo firewall-cmd --list-all
public (active)
  target: default
  icmp-block-inversion: no
  interfaces: enp0s3 enp0s8
  sources: 
  services: http https ssh
  ports: 2222/tcp
  protocols: 
  forward: yes
  masquerade: no
  forward-ports: 
  source-ports: 
  icmp-blocks: 
  rich rules: 
        rule family="ipv4" source address="192.168.1.0/24" service name="ssh" accept
        rule family="ipv4" service name="ssh" accept limit value="2/m"

```

### Restreindre l’accès SSH à une plage IP spécifique :
``` 
deja fait

[root@localhost secure_data]# sudo firewall-cmd --list-all
public (active)
  target: default
  icmp-block-inversion: no
  interfaces: enp0s3 enp0s8
  sources: 
  services: http https ssh
  ports: 2222/tcp
  protocols: 
  forward: yes
  masquerade: no
  forward-ports: 
  source-ports: 
  icmp-blocks: 
  rich rules: 
        rule family="ipv4" source address="192.168.1.0/24" service name="ssh" accept
        rule family="ipv4" source address="192.168.0.0/16" service name="ssh" accept
        rule family="ipv4" service name="ssh" accept limit value="2/m"

```

### Créer une zone sécurisée pour un service web :
``` 
[root@localhost secure_data]# sudo firewall-cmd --permanent --new-zone=web_zone
success

[root@localhost secure_data]# sudo firewall-cmd --permanent --zone=web_zone --add-service=http
success

[root@localhost secure_data]# sudo firewall-cmd --permanent --zone=web_zone --add-service=https
success

[root@localhost secure_data]# sudo firewall-cmd --permanent --zone=web_zone --set-target=DROP
success


[root@localhost secure_data]# sudo firewall-cmd --permanent --zone=web_zone --change-interface=enp0s8
success

[root@localhost secure_data]# sudo firewall-cmd --reload
success

[root@localhost secure_data]# sudo firewall-cmd --zone=web_zone --list-all
web_zone
  target: DROP
  icmp-block-inversion: no
  interfaces: 
  sources: 
  services: http https
  ports: 
  protocols: 
  forward: no
  masquerade: no
  forward-ports: 
  source-ports: 
  icmp-blocks: 
  rich rules: 

```

## Étape 4 : Création d'un script de surveillance avancé
### Écrivez un script monitor.sh :
``` 
[root@localhost secure_data]# sudo cat /usr/local/bin/monitor.sh
#!/bin/bash

# Chemin du fichier de log
LOG_FILE="/var/log/monitor.log"

# Fonction pour surveiller les connexions réseau
monitor_connections() {
    echo "=== [$(date)] Connexions actives ===" >> "$LOG_FILE"
    ss -tuna | grep -v "State" >> "$LOG_FILE"
    echo "" >> "$LOG_FILE"
}

# Fonction pour surveiller les modifications dans /etc
monitor_file_changes() {
    echo "=== [$(date)] Modifications dans /etc ===" >> "$LOG_FILE"
    inotifywait -r -e modify,create,delete,move --format '%T %w%f %e' --timefmt '%Y-%m-%d %H:%M:%S' /etc >> "$LOG_FILE" &
    INOTIFY_PID=$!
}

# Fonction principale
main() {
    echo "=== Surveillance démarrée à $(date) ===" >> "$LOG_FILE"
    monitor_connections
    monitor_file_changes

    # Surveillance continue (Ctrl+C pour quitter)
    while true; do
        sleep 60  # Intervalle de mise à jour
        monitor_connections
    done
}

# Nettoyage en cas d'arrêt du script
cleanup() {
    echo "=== Surveillance arrêtée à $(date) ===" >> "$LOG_FILE"
    kill "$INOTIFY_PID" 2>/dev/null
    exit 0
}

# Gestion du signal Ctrl+C
trap cleanup SIGINT SIGTERM

# Exécution
main

```

### Ajoutez une alerte par e-mail :
```
[root@localhost secure_data]# sudo cat /usr/local/bin/monitor.sh 
#!/bin/bash

# Chemin du fichier de log
LOG_FILE="/var/log/monitor.log"
EMAIL="maitre_adam@jsp.com" 
SUBJECT="ALERTE : Modification dans /etc"  

# Fonction pour surveiller les connexions réseau
monitor_connections() {
[...]

 while read event; do
        echo "$event" >> "$LOG_FILE"

        
        echo "Un changement a été détecté : $event" | mailx -s "$SUBJECT" "$EMAIL"
    done &
    INOTIFY_PID=$!  
}

# Fonction principale
main() {
    echo "=== Surveillance démarrée à $(date) ===" >> "$LOG_FILE"
    monitor_connections
    monitor_file_changes 

[...]

# Nettoyage en cas d'arrêt du script
cleanup() {
    echo "=== Surveillance arrêtée à $(date) ===" >> "$LOG_FILE"
    kill "$INOTIFY_PID" 2>/dev/null 
    exit 0
}

# Gestion du signal Ctrl+C
trap cleanup SIGINT SIGTERM

# Exécution
main
```

### Automatisez le script :
``` 
[root@localhost ~]# sudo crontab -e

j'ajoute dans l'éditeur:
*/5 * * * * /usr/local/bin/monitor.sh >> /var/log/monitor_cron.log 2>&1

je sauvegarde et je quitte.
```


## Étape 5 : Mise en place d’un IDS (Intrusion Detection System)
### Installer et configurer AIDE :
``` 
[root@localhost ~]# aide --version

[root@localhost ~]# sudo aide --init

[root@localhost ~]# sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db

[root@localhost ~]# sudo nano /etc/aide.conf

j'y ajoute:

/etc           p+i+n+u+g+s+b+m+c+md5+sha512
/bin           p+i+n+u+g+s+b+m+c+md5+sha512
/sbin          p+i+n+u+g+s+b+m+c+md5+sha512
/usr/bin       p+i+n+u+g+s+b+m+c+md5+sha512
/usr/sbin      p+i+n+u+g+s+b+m+c+md5+sha512
```

### Tester AIDE :
``` 
[root@localhost ~]# sudo touch /etc/testfile

[root@localhost ~]# sudo aide --check

la modification est signalée dans la sortie.
```