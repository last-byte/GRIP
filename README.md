# GRIP v0.1
Golang RIP Injection Program allows you to inject fake routes in a RIPv2 environment.

Installing requisites:
```
$ go get github.com/miekg/rip
$ go get golang.org/x/net/ipv4
```

Building:
```
$ go build main.go -o grip
```
Usage:
```
$ ./grip -h
Usage of ./grip:
  -dst string
    	the destination IP address, default value is multicast (default "224.0.0.9")
  -metric int
    	the metric for the route (default 1)
  -netmask string
    	the subnet mask for the advertised network (default "255.255.255.0")
  -network string
    	the network address to advertise
  -src string
    	the source IP address to spoof
```
