docker for SIP Sysrepo plugin.

## build dockerfile

```
$ docker build -t sysrepo/sysrepo-netopeer2:sip -f Dockerfile .
```

## run dockerfile with supervisor

```
$ docker run -i -t -v /opt/yang:/opt/fork --name sip -p 830:830 --rm sysrepo/sysrepo-netopeer2:sip
```

## run dockerfile without supervisor

```
$ docker run -i -t -v /opt/yang:/opt/fork --name sip --rm sysrepo/sysrepo-netopeer2:sip bash
$ ubusd &
$ rpcd &
$ sysrepod
$ sysrepo-plugind
$ netopeer2-server
```
