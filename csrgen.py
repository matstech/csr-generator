import sys
import configparser
import time
import inquirer
import os

from OpenSSL import crypto
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from subprocess import run

def create_csr(attrs):
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    country = attrs.get('country','')
    state = attrs.get('state','')
    locality = attrs.get('locality','')
    organization_name = attrs.get('organization_name','')
    organization_unit = attrs.get('organization_unit','')
    common_name = attrs.get('common_name', '')
    sans = attrs.get('sans','').split(',')

    x509sans = []    
    for s in sans:
      x509sans.append(x509.DNSName(s.strip()))

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organization_unit),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        
    ])).add_extension(
        x509.SubjectAlternativeName(x509sans),
        critical=False,
    ).add_extension(
        x509.BasicConstraints(ca=False,path_length=None),critical=False,
    ).add_extension(
        x509.KeyUsage(content_commitment=False,
                      crl_sign=False,
                      data_encipherment=False,
                      decipher_only=False,
                      digital_signature=True,
                      encipher_only=False,
                      key_agreement=False,
                      key_cert_sign=False,
                      key_encipherment=True), critical=False
    ).sign(key, hashes.SHA256())

    return {'key': key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()).decode('utf-8'), 'csr': csr.public_bytes(
            encoding=serialization.Encoding.PEM).decode('utf-8')}

def prompt(defaults):
    country = input("Country (C): (Default: {df})".format(df=defaults.get('DEFAULT','IT'))) or defaults.get('DEFAULT','IT')
    state = input('State Name (ST): (Default: {df})'.format(df=defaults.get('DEFAULT','ST'))) or defaults.get('DEFAULT','ST')
    locality = input('Locality Name (L): (Default: {df})'.format(df=defaults.get('DEFAULT','L'))) or defaults.get('DEFAULT','L')
    organization_unit = input('Organization Unit (OU): (Default: {df})'.format(df=defaults.get('DEFAULT','OU'))) or defaults.get('DEFAULT','OU')
    organization_name = input('Organization Name (O): (Default: {df})'.format(df=defaults.get('DEFAULT','O'))) or defaults.get('DEFAULT','O')
    common_name = input('Common Name (CN):')
    if common_name == '':
       print('Common Name cannot be empty')
       sys.exit(1)
    sans = input('Subject Alternative Names (SAN):')

    return {
        'country': country,
        'state': state,
        'locality': locality,
        'organization_unit': organization_unit,
        'organization_name': organization_name,
        'common_name': common_name,
        'sans': sans
    }

def in_dir(attrs):
   # write csr
   timestamp = int(time() * 1000)
   csr = open("{timestamp}_csr.pem".format(timestamp=timestamp), "a")
   csr.write(attrs.get('csr',''))
   csr.close()
   # write key
   key = open("{timestamp}_key.pem".format(timestamp=timestamp), "a")
   key.write(attrs.get('key',''))
   key.close()

def verify(attrs):
    with open(attrs.get('key',''), "r") as f:
        key = f.read()
    with open(attrs.get('cert',''), "r") as f:
        cert = f.read()
    with open(attrs.get('csr',''), "r") as f:
        csr = f.read()

    pub_key_obj = crypto.load_certificate(crypto.FILETYPE_PEM, cert).get_pubkey()
    pub_key = crypto.dump_publickey(crypto.FILETYPE_PEM, pub_key_obj)
    pub_key_modulus = pub_key_obj.to_cryptography_key().public_numbers().n

    private_key_obj = crypto.load_privatekey(crypto.FILETYPE_PEM, key)
    pvt_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, private_key_obj)
    p_key_modulus = private_key_obj.to_cryptography_key().private_numbers().public_numbers.n
    
    csr_obj = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr)
    csr = crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr_obj)
    csr_modulus = csr_obj.get_pubkey().to_cryptography_key().public_numbers().n

    return p_key_modulus == pub_key_modulus == csr_modulus
   

if __name__ == "__main__":
    config = configparser.ConfigParser()
    config.read('defaults.ini')
    quest_map = {
       'Generate new CSR':'generate', 
       'Verify yor credentials':'verify'
    }
    
    questions = [
        inquirer.List('command',
                        message="Choose a command to run",
                        choices=quest_map.keys(),
                        carousel=True
                    ),
    ]
    answers = inquirer.prompt(questions)
    command = quest_map[answers["command"]]

    if command == 'verify':
      key_path = './pkey.pem'
      csr_path = './cert_request.csr'
      cert_path = './cert.crt'
      v = verify({
         'key':key_path,
         'cert':cert_path,
         'csr':csr_path
      })
      print('------------------------- Match: ', v)
    elif command == 'generate':
      attrs = prompt(config)
      r = create_csr(attrs)
      in_dir(r)
