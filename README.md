# CSR Generator

This project is a Python script for generating Certificate Signing Requests (CSRs) and verifying the consistency between CSRs, certificates, and private keys.

## Requirements

Ensure you have Python 3.6 or higher installed. Install the required dependencies by running:

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows use `.venv\Scripts\activate`
pip install -r requirements.txt
```

## Features

### Generate a New CSR

The script allows you to generate a CSR and a private key. During the process, you can configure:

- CSR Names: Country, State, Locality, Organization Name, Organizational Unit, Common Name.
- Key Usage
- SANs (Subject Alternative Names)

The generated files are saved in the current directory with a timestamp in their names:

- `<timestamp>_csr.csr`
- `<timestamp>_key.pem`

### Verify Credentials

The script can verify if a CSR, a certificate, and a private key match. You need to provide the file paths for:

- Private key (.pem)
- CSR (.csr)
- Certificate (.crt)

The script compares the public key modulus of the files to determine if they match.

## Usage

Run the script with:

```bash
python csr_gen.py
```

### Main Menu

The script presents a menu with two options:

- **Generate new CSR**: to create a new CSR.
- **Verify your credentials**: to verify the consistency between a CSR, certificate, and private key.

## Project Structure

- csrgen.py: Main script for generating and verifying CSRs.
- requirements.txt: List of required dependencies.
