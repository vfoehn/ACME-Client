import requests
import json
import time
import os
import sys
import subprocess
from binascii import unhexlify, b2a_base64
from hashlib import sha256
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID
from cryptography import x509


HEADERS = {"Accept-Language": "en-US,en;q=0.5"}
ACME_SERV_CERT = 'pebble_https_ca.pem'
RSA_E = 65537
DIR_PREFIX = '.well-known/acme-challenge'
DNS_PORT = 5004


# Create an RSA key pair in the PEM format
def init_keys():
    print(os.path.dirname(os.path.realpath(__file__)))
    private_key = rsa.generate_private_key(public_exponent=RSA_E, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    private_key_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                format=serialization.PrivateFormat.PKCS8,
                                                encryption_algorithm=serialization.NoEncryption())
    public_key_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                             format=serialization.PublicFormat.SubjectPublicKeyInfo)
    print('private_key_pem:')
    print(private_key_pem.decode())
    with open('./keys/private_key.pem', 'wb+') as f:
        f.write(private_key_pem)
    with open('./keys/public_key.pem', 'wb+') as f:
        f.write(public_key_pem)

    return private_key, public_key


# Encode messages
def format_text(text):
    formatted_text = b2a_base64(text).decode()
    return formatted_text.replace('\n', '').replace('=', '').replace('+', '-').replace('/', '_')


# Create a message that follows the JWS format
def get_protected(nonce, url, key_type, key):
    if key_type == 'kid':
        protected = {
            'alg': 'RS256',
            'kid': key,
            'nonce': nonce,
            'url': url
        }
    else:
        protected = {
            'alg': 'RS256',
            'jwk': key,
            'nonce': nonce,
            'url': url
        }
    return format_text(json.dumps(protected).encode())


# Correctly format the payload of a packet
def get_payload(payload):
    if payload == None:
        return ""
    else:
        return format_text(json.dumps(payload).encode())


# Sign the message using the private key
def get_signature(protected_str, payload_str):
    signature_input = "{0}.{1}".format(protected_str, payload_str).encode()  # signature_input must be of type bytes
    signature = private_key.sign(signature_input, padding.PKCS1v15(), hashes.SHA256())
    return format_text(signature)


# Send a packet in the correct format to the ACME server.
def send_pkt(url, key_type, key, payload, expect_json=True):
    print(dir['newNonce'])
    r_nonce = requests.head(dir['newNonce'], headers=HEADERS, verify=ACME_SERV_CERT)
    nonce = r_nonce.headers['replay-nonce']
    protected_str = get_protected(nonce, url, key_type, key)
    payload_str = get_payload(payload)
    signature_str = get_signature(protected_str, payload_str)

    data = {
        'protected': protected_str,
        'payload': payload_str,
        'signature': signature_str
    }
    data_str = json.dumps(data)
    headers = {
        'Accept-Language': 'en-US,en;q=0.5',
        'Content-Type': 'application/jose+json'
    }

    r = requests.post(url, data=data_str, headers=headers, verify=ACME_SERV_CERT)

    # Requests for certificate download are not JSON compatible
    if not expect_json:
        if r.status_code == 200:
            print(str(r.content.decode()) + '\n\n\n')
            return r
        else:
            print('Warning: POST-as-GET request was not successful. (Status code ' + str(r.status_code) + ')')
            return send_pkt(url, key_type, key, payload, expect_json)
    print(str(r.json()) + '\n')
    if r.json()['status'] == 400:
        return send_pkt(url, key_type, key, payload)
    else:
        return r


# Safely parse the challenge JSON to get the challenge token
def get_challenge(challenges, type):
    for c in challenges:
        if c['type'] == type:
            return c


# Request an HTTP challenge from the ACME server
def attempt_http_challenge(record, challenge, jwk):
    token = challenge['token']
    account_key = json.dumps(jwk).replace(' ', '')
    thumbprint = sha256(account_key.encode()).digest()
    key_authorization = token + '.' + format_text(thumbprint)
    if not os.path.exists(DIR_PREFIX):
        os.makedirs(DIR_PREFIX)
    with open(DIR_PREFIX + '/' + token, 'w+') as f:
        f.write(key_authorization)


# Request a DNS challenge from the ACME server
def attempt_dns_challenge(record, challenge, jwk):
    token = challenge['token']
    account_key = json.dumps(jwk).replace(' ', '')
    thumbprint = sha256(account_key.encode()).digest()
    key_authorization = token + '.' + format_text(thumbprint)
    msg = format_text(sha256(key_authorization.encode()).digest())
    requests.post('http://' + record + ':' + str(DNS_PORT) + '/key_authorization', data=msg)


# Delete the challenge tokens (i.e., proof) on the servers
def remove_proof(challenge_type, challenge):
    token = challenge['token']
    if challenge_type == 'http-01' and os.path.exists(DIR_PREFIX):
        os.remove(DIR_PREFIX + '/' + token)
    elif challenge_type == 'dns-01':
        msg = ''
        requests.post('http://' + record + ':' + str(DNS_PORT) + '/remove_key_authorization', data=msg)


# Contact the ACME server to find out about the state of the certificate request
def poll_for_status(url, kid):
    r_poll = send_pkt(url, 'kid', kid, None)
    while True:
        print('***Poll for Status***')
        r_poll = send_pkt(url, 'kid', kid, None)
        status = r_poll.json()['status']
        if status != 'pending' and status != 'processing':
            return status
        time.sleep(3)


# Create a Certificate Signing Request (CSR) and write it to disk
def get_csr(domains):
    domain_list = []
    for domain in domains:
        domain_list.append(x509.DNSName(domain))

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"CH")
        ])).add_extension(
            x509.SubjectAlternativeName(domain_list),
            critical=False, ).sign(private_key, hashes.SHA256(), default_backend())

    with open("keys/csr.pem", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    return csr.public_bytes(serialization.Encoding.DER)


# Contact ACME server to revoke a certificate
def revoke_certificate(revoke_url, jwk, cert_str):
    # Convert certificate from PEM to DER
    cert = x509.load_pem_x509_certificate(cert_str.encode(), default_backend())
    der_cert = cert.public_bytes(serialization.Encoding.DER)
    payload = {
        "certificate": format_text(der_cert),
        "reason": 4
    }
    print('Revoking certificate')
    r_revoke = send_pkt(revoke_url, 'jwk', jwk, payload, expect_json=False)


def main(challenge_type, dir_url, record, domains, revoke):
    global private_key, public_key, dir
    private_key, public_key = init_keys()

    # Dir
    r_dir = requests.get(dir_url, headers=HEADERS, verify=ACME_SERV_CERT)
    dir = r_dir.json()

    # Account
    print('***Create Account***')
    encoded_e = '0' + '{0:x}'.format(public_key.public_numbers().e)
    encoded_e = format_text(unhexlify(encoded_e))
    encoded_n = '{:0x}'.format(public_key.public_numbers().n)
    encoded_n = format_text(unhexlify(encoded_n))

    jwk = {
        "e": encoded_e,
        "kty": "RSA",
        "n": encoded_n
    }

    payload = {"termsOfServiceAgreed": True}
    r_account = send_pkt(dir['newAccount'], 'jwk', jwk, payload)
    kid = r_account.headers['location']

    # Submit order
    print('***Submit Order***')
    identifiers = []
    for domain in domains:
        identifiers.append({"type": "dns", "value": domain})
    payload = {'identifiers': identifiers}

    r_order = send_pkt(dir['newOrder'], 'kid', kid, payload)
    order = r_order.json()
    order_url = r_order.headers['location']
    finalize_url = order['finalize']
    authorization_urls = order['authorizations']
    counter = 0

    for authorization_url in authorization_urls:
        # Fetch challenges
        print('***Fetch Challenge***')
        r_author = send_pkt(authorization_url, 'kid', kid, None)
        challenges = r_author.json()['challenges']
        challenge = get_challenge(challenges, challenge_type)

        # Attempt challenges
        if challenge_type == 'http-01':
            attempt_http_challenge(record, challenge, jwk)
        elif challenge_type == 'dns-01':
            attempt_dns_challenge(record, challenge, jwk)
        else:
            raise Exception('Invalid challenge type.')

        # Challenge (Possibly redundant)
        print('***Respond to Challenge***')
        payload = {}  # Payload is supposed to be empty
        r_chal = send_pkt(challenge['url'], 'kid', kid, payload)
        challenge_status = poll_for_status(authorization_url, kid)

        remove_proof(challenge_type, challenge)
        counter += 1

    # Poll for challenge status
    status = poll_for_status(order_url, kid)
    if os.path.exists(DIR_PREFIX + '/' + challenge['token']):
        os.remove(DIR_PREFIX + '/' + challenge['token'])

    if status == 'valid':
        pass
    elif status == 'invalid':
        pass

    # Finalize order
    print('***Finalize Order***')
    csr = get_csr(domains)
    payload = {"csr": format_text(csr)}
    r_fin = send_pkt(finalize_url, 'kid', kid, payload)

    # Poll for CSR status
    poll_for_status(order_url, kid)
    r_poll = send_pkt(order_url, 'kid', kid, None)
    cert_url = r_poll.json()['certificate']

    # Download certificate
    print('***Download Certificate***')
    r_cert = send_pkt(cert_url, 'kid', kid, None, expect_json=False)
    obtained_cert = r_cert.content.decode()
    with open('keys/obtained_cert.pem', 'w+') as f:
        delimiter = '-----BEGIN CERTIFICATE-----'
        split_obtained_cert = obtained_cert.split(delimiter)
        f.write(delimiter + split_obtained_cert[1])

    # Create certificate chain
    intermeadiates_cert_url = core_pebble_url + '15000/intermediates/0'
    root_cert_url = core_pebble_url + '15000/roots/0'
    intermediates_cert = requests.get(intermeadiates_cert_url, verify=ACME_SERV_CERT).content.decode()
    root_cert = requests.get(root_cert_url, verify=ACME_SERV_CERT).content.decode()

    with open('keys/chained_cert.pem', 'w+') as f:
        # Avoid duplicate intermediate certificates
        delimiter = '-----BEGIN CERTIFICATE-----'
        split_obtained_cert = obtained_cert.split(delimiter)
        f.write(delimiter + split_obtained_cert[1])

        f.write(intermediates_cert)
        f.write(root_cert)

    if revoke:
        revoke_certificate(dir['revokeCert'], jwk, obtained_cert)

    # Run HTTPS certificate server
    print('***Launching Certificate Server***')
    cert_server_proc = subprocess.Popen(['python3', 'certificate_server.py', record])
    cert_server_proc.wait()


if __name__ == "__main__":
    # Parse the arguments
    global core_pebble_url
    args = sys.argv
    if len(args) == 1:
        dir = 'https://localhost:14000/dir'
        core_pebble_url = dir.replace('14000/dir', '')
        main('dns-01', 'https://localhost:14000/dir', 'localhost', ['*.example.org'], False)
    else:
        challenge_type = args[1]
        if challenge_type == 'http01':
            challenge_type = 'http-01'
        if challenge_type == 'dns01':
            challenge_type = 'dns-01'
        dir = args[3]
        core_pebble_url = dir.replace('14000/dir', '')

        record = args[5]
        domains = []
        i = 6
        while i < len(args) and args[i] == '--domain':
            domains.append(args[i + 1])
            i += 2

        revoke = False
        if i < len(args) and args[i] == '--revoke':
            revoke = True
        main(challenge_type, dir, record, domains, revoke)