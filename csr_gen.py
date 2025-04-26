import time
import inquirer

from OpenSSL import crypto
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

def create_csr():
    """Function generating csr file."""
    key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        csr_names()).add_extension(
            x509.SubjectAlternativeName(csr_sans()),critical=False
    ).add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=False, # no CA type
    ).add_extension(key_usages(), critical=True).sign(key, hashes.SHA256())

    return {'key': key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()).decode('utf-8'),
            'csr': csr.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')}

def key_usages():
    """Function asking user about key usage to set in CSR and build object."""
    print("\n--- Key Usage Configuration ---\n")
    key_usage_questions = [
        inquirer.Confirm("content_commitment", message="nonRepudiation", default=False),
        inquirer.Confirm("crl_sign", message="cRLSign", default=False),
        inquirer.Confirm("data_encipherment", message="dataEncipherment", default=False),
        inquirer.Confirm("decipher_only", message="decipherOnly", default=False),
        inquirer.Confirm("digital_signature", message="digitalSignature", default=True),
        inquirer.Confirm("encipher_only", message="encipherOnly", default=False),
        inquirer.Confirm("key_agreement", message="keyAgreement", default=False),
        inquirer.Confirm("key_cert_sign", message="keyCertSign", default=False),
        inquirer.Confirm("key_encipherment", message="keyEncipherment", default=True),
    ]

    answers = inquirer.prompt(key_usage_questions)

    return x509.KeyUsage(content_commitment=answers['content_commitment'],
                         crl_sign=answers['crl_sign'],
                         data_encipherment=answers['data_encipherment'],
                         decipher_only=answers['decipher_only'],
                         digital_signature=answers['digital_signature'],
                         encipher_only=answers['encipher_only'],
                         key_agreement=answers['key_agreement'],
                         key_cert_sign=answers['key_cert_sign'],
                         key_encipherment=answers['key_encipherment'])

def csr_names():
    """Function asking user about CSR names and build object."""
    print("\n--- Names Configuration ---\n")
    csr_questions = [
        inquirer.Text("country", message="Country (C)", default='IT'),
        inquirer.Text("state", message="State Name (ST)", default='Italy'),
        inquirer.Text("locality", message="Locality Name (L)", default='Rome'),
        inquirer.Text("organization_name", message="Organization Name (O)"),
        inquirer.Text("organization_unit", message="Organization Unit (OU)"),
        inquirer.Text("common_name", message="Common Name (CN)",
                      validate=lambda _, x: len(str(x))),
    ]

    answers =  inquirer.prompt(csr_questions)

    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, answers['country']),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, answers['state']),
        x509.NameAttribute(NameOID.LOCALITY_NAME, answers['locality']),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, answers['organization_name']),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, answers['organization_unit']),
        x509.NameAttribute(NameOID.COMMON_NAME, answers['common_name']),
    ])

def csr_sans():
    """Function asking for sans one per line"""
    question = [inquirer.Text(
        'sans', 'Subject Alternative Names (SANs)', validate=lambda _, x: len(str(x)))]
    sans = inquirer.prompt(question)['sans']
    if not sans:
        return []
    sans_list = [san.strip() for san in sans.split(",")]
    sans_obj = [x509.DNSName(san) for san in sans_list]
    return sans_obj

def in_dir(indir_attrs):
    """Function writing key and csr file in pem format"""
    timestamp = int(time.time() * 1000)
    with open(f"{timestamp}_csr.csr".format(timestamp=timestamp), "a", encoding="utf-8") as csr:
        csr.write(indir_attrs.get('csr',''))
        csr.close()
    with open(f"{timestamp}_key.pem".format(timestamp=timestamp), "a", encoding="utf-8") as key:
        key.write(indir_attrs.get('key',''))
        key.close()

def verify(verify_attrs):
    """Function verifying match between csr, certificate and private key"""
    with open(verify_attrs.get('key',''), "r", encoding="utf-8") as f:
        key = f.read()
    with open(verify_attrs.get('cert',''), "r", encoding="utf-8") as f:
        cert = f.read()
    with open(verify_attrs.get('csr',''), "r", encoding="utf-8") as f:
        csr = f.read()

    try:
        pub_key_obj = crypto.load_certificate(crypto.FILETYPE_PEM, cert).get_pubkey()
        pub_key_modulus = pub_key_obj.to_cryptography_key().public_numbers().n
        private_key_obj = crypto.load_privatekey(crypto.FILETYPE_PEM, key)
        p_key_modulus = private_key_obj.to_cryptography_key().private_numbers().public_numbers.n
        csr_obj = x509.load_pem_x509_csr(csr.encode("utf-8"))
        csr_modulus = csr_obj.public_key().public_numbers().n
        return p_key_modulus == pub_key_modulus == csr_modulus
    except ValueError as ve:
        print(f'Error parsing files: {ve}')
        return False

def main():
    """Main function"""
    quest_map = {'Generate new CSR':'generate', 'Verify yor credentials':'verify'}
    questions = [inquirer.List('opt',
                               message="Choose a command to run",
                               choices=quest_map.keys(),carousel=True)]
    command = quest_map[inquirer.prompt(questions)['opt']]
    if command == 'verify':
        fp_questions = [
            inquirer.Text("pkey_fp", message="Private key filepath",
                          validate=lambda _, x: len(x) > 0),
            inquirer.Text("csr_fp", message="CSR filepath", default='./cert_request.csr',
                          validate=lambda _, x: len(x) > 0),
            inquirer.Text("cer_fp", message="Certificate filepath", default='./cert.crt',
                          validate=lambda _, x: len(x) > 0)]
        fps =  inquirer.prompt(fp_questions)
        v = verify({'key':fps['pkey_fp'],'cert':fps['cer_fp'],'csr':fps['csr_fp']})
        print('------------------------- Match: ', v)
    elif command == 'generate':
        r = create_csr()
        in_dir(r)

if __name__ == "__main__":
    main()
