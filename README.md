# netdata-unbound
netdata python plugin for unbound dns server monitoring

[Unbound](https://www.unbound.net/) is a validating, recursive, and caching DNS resolver. 

Work in progress

Current approach use `unbound-control stats_noreset` command to gather data.

## TODO
* define all charts
* organize charts to provide most meaningful results
* screenshots
* documentation

## Configure unbound
In order for monitoring to work, unbound must be configured with remote-control enabled
https://unbound.net/documentation/howto_setup.html