## Json Web Tokens (JWT) to provide auth for c-lightning plugins

1. https://github.com/nettijoe96/c-lightning-graphql is the only plugin that currently uses these tokens

## Process for token auth

### Server

1. Build: `go build`
2. Add plugin to plugin library through symlink: 

    `ln -s <path to jwt-factory> .`

    `cd <path to c-lightning source>/plugins`

3. Create openssl rsa key and self signed cert

    `openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyin key.pem -out cert.pem`

4. Start c-lightning command line options --certfile and --keyfile: 

    `./lightningd --certfile=/path/to/cert --keyfile=path/to/key`

5. Trust the raw hex public key and attach privileges to it. Different applications will provide the raw pub key in different ways. Since the only application right now is graphql plugin, see that [readme](https://github.com/nettijoe96/c-lightning-graphql/blob/master/README.md) for more details. 

    `./lightning-cli trustkey <raw hex pub key> privilegeA,privilegeB,...,privilegeN`


### Client

The client side is expected to only be used for developers.

1. Create an openssl cert for the client and expose raw hex public key to the user so that the user can run trustkey to add privileges
2. Connect to the server using tls and the self signed certificate. Make sure that the server cert is part of a trust chain if api is exposed on the web or remotely. However, many plugins and browser extensions might use this on the same machine, in which case a self-signed server certificate works. 
3. Collect the json token as a response. It is in the body of the https response if the status is OK 

