# ACME Client

This Automatic Certificate Management Environment (ACME) client can be used to get X.509 certificates signed by Let’s 
Encrypt.

## Running Test for the ACME Client
The testing setup can be run using the script `project/run`. In this section we describe the command-line arguments:

- Challenge type\
(required, {dns01 | http01}) indicates which ACME challenge type the client
should perform. Valid options are dns01 and http01 for the dns-01 and http-01
challenges, respectively.

- --dir DIR URL\
(required) DIR URL is the directory URL of the ACME server that should be used.

- --domain DOMAIN\
(required, multiple) DOMAIN is the domain for which to request the certificate. If
multiple --domain flags are present, a single certificate for multiple domains 
is requested. Wildcard domains have no special flag and are simply denoted by,
e.g., *.example.net.

- --revoke\
(optional) If present, the application immediately revokes the certificate
after obtaining it. In both cases, the application starts its HTTPS server
and sets it up to use the newly obtained certificate.

Here is an example:

`./run dns01 --dir https://localhost:14000/dir --record 127.0.0.2 --domain acme.good.ch --revoke`

When invoked like this, the application obtains a certificate valid for acme.good.ch. It uses the ACME server at the
URL https://localhost:14000/dir and perform the dns-01 challenge. The DNS server
of the application responds with 127.0.0.2 to all requests for A records. Once the
certificate has been obtained, the application starts its certificate HTTPS server
and installs the obtained certificate on this server.

Note: One way to make this work is to run Pebble (a local ACME server designed for tests) on localhost port 14000.

Download Pebble: https://github.com/letsencrypt/pebble


## Theory
X.509 certificates are used in the public key infrastructure for authentication and encryption. In order to get a 
certificate signed for a certain domain you first has to prove that the domain truly belongs to you. This is done by 
proving that you have control over the domain. For this project we use two different approaches to achieve this.
1) DNS: Upload a DNS record for the domain. 
2) HTTP: Upload a file directly to the server that hosts the domain.

Here is a rough overview of the certificate negotiation:
1. The ACME client creates a X.509 certificate for a domain.
2. The client contacts the ACME server requesting for the created certificate to be signed.
3. The ACME server replies with a challenge. The challenge consists of uploading a random token to the DNS or HTTP 
sever.
4. The ACME client completes the challenge.
5. The ACME server checks if the challenge is completed. If that is the case, it signs the X.509 certificate and sends 
it back to the ACME client.

Now that the client has a certificate signed by a trusted authority, it can install it on its server. The server 
can now support authenticated and encrypted protocols, such as TLS.