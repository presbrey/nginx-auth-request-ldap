# nginx-auth-request-ldap

This service provides LDAP authentication for nginx via the [http_auth_request API](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html).

## Installation

`go get -u github.com/presbrey/nginx-auth-request-ldap`

Use systemd or [supervisord](supervisord.org) to daemonize `nginx-auth-request-ldap`.

## Features

* authentication cache w/ configurable TTL
* bind DN template integrates with any LDAP provider/schema

## Options

```
Usage of ./nginx-auth-request-ldap:
  -U="uid=%s,cn=users,cn=accounts,dc=example,dc=com": username template
  -h="ldap.example.com": LDAP server host
  -p=636: LDAP server port
  -r="EXAMPLE.COM": authentication realm
  -t=1m0s: cache TTL
```
