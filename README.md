mtgx2MISP
=========

script to parse mtgx files and insert them into MISP as events.

requires misp api (included).

requires lxml (http://lxml.de/installation.html).

helper script to automatically process files requires inotify-tools

run chmod u+x on mtgx2MISP.py and helpers/gobble.sh

cd to helpers and run gobble.sh from there. It is recommended to either add to crontab to run automatically (@reboot) or to run in the background in a detached screen, or using nohup.
the script will monitor the 'files_to_gobble' directory and will process any files dropped there with mtgx2MISP, save maltego files here that you want to import into MISP.

currently mtgx2MISP supports the following maltego entity types:
maltego.IPv4Address": make_ip_address,
    maltego.Domain
    maltego.URL
    malformity.Filename
    malformity.Hash (MISP only supports md5, sha1 & sha256, other hash types will be silently ignored)
    maltego.EmailAddress