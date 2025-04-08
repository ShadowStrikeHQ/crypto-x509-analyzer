import argparse
import logging
import sys
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID
from cryptography.exceptions import InvalidSignature

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(description="X.509 Certificate Analyzer")
    parser.add_argument("certificate_path", help="Path to the X.509 certificate file.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging (DEBUG level).")
    return parser


def analyze_certificate(cert_path):
    """
    Analyzes an X.509 certificate file for potential vulnerabilities.

    Args:
        cert_path (str): The path to the certificate file.

    Returns:
        None. Prints analysis results to the console.
    """
    try:
        with open(cert_path, "rb") as f:
            cert_data = f.read()
    except FileNotFoundError:
        logging.error(f"Error: Certificate file not found at {cert_path}")
        return
    except Exception as e:
        logging.error(f"Error reading certificate file: {e}")
        return

    try:
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        # Alternative: cert = x509.load_der_x509_certificate(cert_data, default_backend())
    except ValueError as e:
        logging.error(f"Error loading certificate: {e}.  Ensure it is in PEM format or DER if specified.")
        return
    except Exception as e:
         logging.error(f"General error loading certificate: {e}")
         return

    logging.info(f"Analyzing certificate: {cert.subject}")

    # Check certificate validity period
    if cert.not_valid_before_utc > cert.not_valid_after_utc:
        logging.warning("Certificate validity start date is after the end date. This is invalid.")

    if cert.not_valid_before_utc.timestamp() > time.time():
        logging.warning("Certificate is not yet valid.")

    if cert.not_valid_after_utc.timestamp() < time.time():
        logging.warning("Certificate is expired.")

    # Check signature algorithm
    sig_algorithm = cert.signature_algorithm
    logging.info(f"Signature Algorithm: {sig_algorithm.name}")
    if sig_algorithm.name in ["md5WithRSAEncryption", "sha1WithRSAEncryption", "dsaWithSHA1"]:
        logging.warning(f"Weak signature algorithm detected: {sig_algorithm.name}")

    # Check key usage extensions
    try:
        key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        logging.info(f"Key Usage: {key_usage}")

    except x509.ExtensionNotFound:
        logging.warning("Key Usage extension is missing. This can be a security risk.")
    except Exception as e:
        logging.error(f"Error reading Key Usage extension: {e}")

    # Check Basic Constraints extension
    try:
        basic_constraints = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        logging.info(f"Basic Constraints: {basic_constraints}")
        if basic_constraints.ca:
            logging.info("Certificate is a CA certificate.")
        else:
            logging.info("Certificate is an end-entity certificate.")
    except x509.ExtensionNotFound:
        logging.info("Basic Constraints extension not found.") # It's not necessarily an error
    except Exception as e:
        logging.error(f"Error reading Basic Constraints extension: {e}")


    # Check Subject Alternative Name (SAN)
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        logging.info(f"Subject Alternative Name: {san}")
    except x509.ExtensionNotFound:
        logging.info("Subject Alternative Name extension not found.")  # Not necessarily an error.
    except Exception as e:
        logging.error(f"Error reading Subject Alternative Name extension: {e}")

    # Verify certificate signature
    try:
        public_key = cert.public_key()
        verifier = public_key.verifier(
            cert.signature,
            sig_algorithm,
            default_backend()
        )
        verifier.update(cert.tbs_certificate_bytes)
        verifier.verify()
        logging.info("Certificate signature is valid.")

    except InvalidSignature:
        logging.error("Certificate signature is invalid.")
    except Exception as e:
        logging.error(f"Error verifying certificate signature: {e}")

    # Check if CA flag is consistent with usage.
    try:
        key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        basic_constraints = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        if basic_constraints.ca and not key_usage.key_cert_sign:
            logging.warning("CA certificate missing keyCertSign in KeyUsage extension")

    except x509.ExtensionNotFound:
        pass  # Ignore, some certs don't have these.
    except Exception as e:
        logging.error(f"Error in CA flag consistency check: {e}")

    # Print issuer
    logging.info(f"Issuer: {cert.issuer}")

    #Print subject
    logging.info(f"Subject: {cert.subject}")



def main():
    """
    Main function to execute the certificate analysis tool.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose logging enabled.")

    analyze_certificate(args.certificate_path)


if __name__ == "__main__":
    import time  #Imported here to be sure is not used if the program is imported as a module
    main()