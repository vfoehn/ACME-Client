import requests



r = requests.head('https://127.0.0.2:5001', verify='project/keys/chained_cert.pem')
r = requests.get('https://127.0.0.2:5001', verify='project/keys/chained_cert.pem')
#requests.get('http://127.0.0.2:5003/shutdown')