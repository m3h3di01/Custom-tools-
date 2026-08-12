#!/usr/bin/env python
# SecretFinder - Tool for discover apikeys/accesstokens and sensitive data in js file
# based on LinkFinder - github.com/GerbenJavado
# By m4ll0k (@m4ll0k2) github.com/m4ll0k


import os,sys
if not sys.version_info.major >= 3:
    print("[ + ] Run this tool with python version 3.+")
    sys.exit(0)
os.environ["BROWSER"] = "open"

import re
import glob
import argparse
import jsbeautifier
import webbrowser
import subprocess
import base64
import requests
import string
import random
from html import escape
import urllib3
import xml.etree.ElementTree

# disable warning

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# for read local file with file:// protocol
from requests_file import FileAdapter
from lxml import html
from urllib.parse import urlparse

# regex
_regex = {
    'google_api'     : r'AIza[0-9A-Za-z-_]{35}',
    'firebase'  : r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
    'aws_secret_key_finder1': r'(?i)(aws)?.{0,20}?[\'"]?[A-Za-z0-9/+]{40}[\'"]?',
    'aws_secret_key_finder2': r'(?i)(?:AWS(?:_)?SECRET(?:_)?ACCESS(?:_)?KEY|secret(?:_)?access(?:_)?key)\s*[:=]\s*[\'"]?([A-Za-z0-9/+]{40})[\'"]?',
    'aws_secret_key_finder3': r'(?i)([A-Za-z0-9_]+)\s*[:=]\s*[\'"]?([A-Za-z0-9/+]{40})[\'"]?',
    'google_captcha' : r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
    'google_oauth'   : r'ya29\.[0-9A-Za-z\-_]+',
    'aws_access_key_id': r'(?i)([A-Za-z0-9_]+)\s*[:=]\s*[\'"]?(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}[\'"]?',
    'aws_mws_key_with_variable': r'(?i)(?:mwsAuthToken|AWSAccessKeyId)?\s*[:=]\s*[\'"]?amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[\'"]?',
    'amazon_mws_auth_toke' : r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'amazon_aws_url' : r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com',
    'amazon_aws_url2' : r"(" \
           r"[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com" \
           r"|s3://[a-zA-Z0-9-\.\_]+" \
           r"|s3-[a-zA-Z0-9-\.\_\/]+" \
           r"|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+" \
           r"|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+)",
    'facebook_access_token' : r'EAACEdEose0cBA[0-9A-Za-z]+',
    'facebook_secret_key_assigned': r'(?i)(facebook|fb)(_app_secret|_secret|_api_key)?\s*[:=]\s*[\'"]?[0-9a-f]{32}[\'"]?',
    'facebook_client_id_assigned': r'(?i)(?:facebook|fb)(_client_id|_app_id)?\s*[:=]\s*[\'"]?[0-9]{13,17}[\'"]?',
    'twitter_secret_key': r'(?i)twitter\s*[:=]\s*[\'"]?[0-9a-z]{35,44}[\'"]?',
    'twitter_client_id': r'(?i)twitter(_client_id|_api_id)?\s*[:=]\s*[\'"]?[0-9a-z]{18,25}[\'"]?',
    'github_personal_access_token': r'(?i)[\'"]?ghp_[0-9a-zA-Z]{36}[\'"]?',
    'github_oauth_access_token': r'(?i)[\'"]?gho_[0-9a-zA-Z]{36}[\'"]?',
    'github_app_token': r'(?i)[\'"]?(ghu|ghs)_[0-9a-zA-Z]{36}[\'"]?',
    'github_refresh_token_assigned': r'(?i)(?:github(?:_)?refresh(?:_)?token|ghr_token|refresh_token)\s*[:=]\s*[\'"]?ghr_[0-9a-zA-Z]{76}[\'"]?',
    'github_machine_to_machine_token': r'(?i)gsm_[a-zA-Z0-9]{21}',
    'linkedin_client_id_assigned': r'(?i)(?:linkedin(?:_)?client(?:_)?id|linkedin(?:_)?app(?:_)?id)\s*[:=]\s*[\'"]?[0-9a-z]{12}[\'"]?',
    'linkedin_secret_key_assigned': r'(?i)(?:linkedin(?:_)?client(?:_)?secret|linkedin(?:_)?app(?:_)?secret|linkedin(?:_)?secret)\s*[:=]\s*[\'"]?[0-9a-z]{16}[\'"]?',
    'asymmetric_private_key': r'(?i)\b-----BEGIN\s+((EC|PGP|DSA|RSA|OPENSSH)\s+)?PRIVATE KEY( BLOCK)?-----\b',
    'google_api_key_assigned': r'(?i)\b(?:google(?:_)?api(?:_)?key|google(?:_)?key|api(?:_)?key)\s*[:=]\s*[\'"]?AIza[0-9A-Za-z_-]{35}[\'"]?\b',
    'phones': r'(?<![\d-])(?:\+?\d{1,3}[-.\s*]?)?(?:\(?\d{3}\)?[-.\s*]?)?\d{3}[-.\s*]?\d{4}(?![\d-])|(?<![\d-])(?:\(\+?\d{2}\)|\+?\d{2})\s*\d{2}\s*\d{3}\s*\d{4}(?![\d-])',
    'emails': r'\b[a-z0-9!#$%&\'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&\'*+/=?^_`{|}~-]+)*@[a-z0-9.-]+\.[a-z]{2,6}\b',
    'street_addresses': r'\b\d{1,4}\s+[A-Za-z\s]{1,20}(?:street|st|avenue|ave|road|rd|highway|hwy|square|sq|trail|trl|drive|dr|court|ct|park|parkway|pkwy|circle|cir|boulevard|blvd)\b',
    'po_boxes': r'\bP\.?O\.?\s+Box\s+\d+\b',
    'ukphones': r'\b(?:0|\+44)\s?\d{2,4}\s?\d{3,4}\s?\d{3,4}\b',
    'email_3': r'\b[\w.+-]+@\w+\.(?:[A-Za-z]{2,6})\b',
    'ssn_3': r'\b(?!000|666)[0-8]\d{2}-(?!00)\d{2}-(?!0000)\d{4}\b',
    'ssn_number': r'\b(?!000|666|333)0*(?:[0-6]\d{2}|[0-7][0-6]\d|[0-7]{2}[0-2])-(?!00)\d{2}-(?!0000)\d{4}\b',
    'visa_credit_card': r'\b4\d{15}\b',
    'american_express_credit_card': r'\b3[47]\d{13}\b',
    'otp': r'^\b\d{6}\b$',
    'credit_card_2': r'\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|2(?:22[1-9]|2[2-9]\d|2[3-6]\d{2}|27[01]\d|2720)\d{12}|3[47]\d{13}|3(?:0[0-5]|[68]\d)\d{11}|6(?:011|5\d{2})\d{12}|(?:2131|1800|35\d{3})\d{11})\b',
    'uk_phone_numbers': r'\b(?:0|\+44)\s?(?:\d{2}\s?\d{4}\s?\d{4}|\d{3}\s?\d{3}\s?\d{3,4}|\d{4}\s?\d{2}\s?\d{2}\s?\d{2})\b',
    'us_phone_numbers': r'\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b',
    'email_addresses': r'\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,6}\b',
    'credit_card_3': r'\b(?:4\d{3}|5[1-5]\d{2}|2\d{3}|3[47]\d{1,2})[\s-]?\d{4,6}[\s-]?\d{4,6}(?:[\s-]\d{3,4})?\b',
    'amex_card': r'\b3[47]\d{13}\b',
    'bcglobal': r'\b(?:6541|6556)\d{12}\b',
    'carte_blanche_card': r'\b389\d{11}\b',
    'insta_payment_card': r'\b63[7-9]\d{13}\b',
    'jcb_card': r'\b(?:2131|1800|35\d{3})\d{11}\b',
    'korean_local_card': r'\b9\d{15}\b',
    'laser_card': r'\b(?:6304|6706|6709|6771)\d{12,15}\b',
    'maestro_card': r'\b(?:5018|5020|5038|6304|6759|6761|6763)\d{8,15}\b',
    'mastercard': r'\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|6(?:011|5\d{2})\d{12}|3[47]\d{13}|3(?:0[0-5]|[68]\d)\d{11}|(?:2131|1800|35\d{3})\d{11})\b',
    'solo_card': r'\b(?:6334|6767)\d{12}(?:\d{2,3})?\b',
    'switch_card': r'\b(?:4903|4905|4911|4936|6333|6759)\d{12}(?:\d{2,3})?\b|564182\d{10}(?:\d{2,3})?\b',
    'argentina_dni': r'\b\d{2}\.\d{3}\.\d{3}\b',
    'canada_passport_id': r'\b[A-Za-z]{2}\d{6}\b',
    'croatia_vat_id': r'\bHR\d{11}\b',
    'czech_vat_id': r'\bCZ\d{8,10}\b',
    'denmark_personal_id': r'\b\d{10}|\d{6}[-\s]\d{4}\b',
    'france_cni': r'\b\d{12}\b',
    'france_insee': r'\b\d{13}(?:\s\d{2})?\b',
    'france_passport_id': r'\b\d{2}11\d{5}\b',
    'germany_id_card': r'\bl\d{8}\b',
    'germany_passport_id': r'\b[cfghjk]\d{3}[A-Za-z]{5}\d\b',
    'germany_drivers_license': r'\b[\dA-Za-z]\d{2}[\dA-Za-z]{6}\d[\dA-Za-z]\b',
    'ireland_pps': r'\b\d{7}[A-Za-z]{1,2}\b',
    'netherlands_bsn': r'\b\d{8}|\d{3}[-.\s]\d{3}[-.\s]\d{3}\b',
    'poland_pesel': r'\b\d{11}\b',
    'portugal_citizen_card': r'\b\d{9}[\dA-Za-z]{2}|\d{8}-\d[\dA-Za-z]{2}\d\b',
    'spain_ssn': r'\b\d{2}/?\d{8}/?\d{2}\b',
    'spain_ssn_2': r'\b\d{3}[-.]\d{2}[-.]\d{4}\b',
    'sweden_passport_id': r'\b\d{8}\b',
    'uk_passport_id': r'\b\d{9}\b',
    'uk_drivers_license_id': r'\b[\w9]{5}\d{6}[\w9]{2}\d{5}\b',
    'uk_nhs_number': r'\b\d{3}\s\d{3}\s\d{4}\b',
    'ipv4': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
    'prices': r'<span class="math-inline">\s*[+\-]?\d{1,3}(?:,\d{3})*(?:\.\d{1,2})?\b',
    'hex_colors': r'\B#(?:[0-9a-fA-F]{3,4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})\b',
    'credit_cards': r'\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{15,16}\b',
    'visa_cards': r'\b4\d{3}(?:[\s-]?\d{4}){3}\b',
    'master_cards': r'\b5[1-5]\d{2}(?:[\s-]?\d{4}){3}\b',
    'btc_addresses': r'\b[13][a-km-zA-HJ-NP-Z0-9]{26,33}\b',
    'ssn_number_3': r'\b\d{3}-\d{2}-\d{4}\b',
    'md5_hashes': r'\b[0-9a-fA-F]{32}\b',
    'sha1_hashes': r'\b[0-9a-fA-F]{40}\b',
    'sha256_hashes': r'\b[0-9a-fA-F]{64}\b',
    'isbn13': r'\b(?:\d-?){12}[\dxX]\b',
    'isbn10': r'\b(?:\d-?){9}[\dxX]\b',
    'mac_addresses': r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b',
    'iban_numbers': r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z\d]{0,16})?\b',
    'git_repos': r'\b(?:git|ssh|https?)://[\w\.@:/~\-]+\.git\b',
    'drivers_license_number_simplified': r'^[A-Z]{2}-\d{6}</span>',
    'passport_number_simplified_3': r'^[A-Z]\d{7}$',
    'social_security_number_3': r'^\d{3}-\d{2}-\d{4}$',
    'social_security_number_4': r'\b\d{3}-?\d{2}-?\d{4}\b',
    'date_of_birth': r'^(?:\d{2}/\d{2}/\d{4}|\d{4}-\d{2}-\d{2})$',
    'arista_config_via_ip': r'via\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3},\s+\d{2}:\d{2}:\d{2}',
    'cisco_router_config_keywords': r'(?i)service\s+timestamps\s+[a-z]{3,5}\s+datetime\s+msec|boot-[a-z]{3,5}-marker|interface\s+[A-Za-z0-9]{1,10}\s*Ethernet',
    'dsa_private_key': r'-----BEGIN DSA PRIVATE KEY-----(?:[a-zA-Z0-9+/=\'"\s]+?)-----END DSA PRIVATE KEY-----',
    'dropbox_links': r'https:\/\/www\.dropbox\.com\/[sl]\/\S+',
    'ec_private_key': r'-----BEGIN (?:EC|ECDSA) PRIVATE KEY-----(?:[a-zA-Z0-9+/=\'"\s]+?)-----END (?:EC|ECDSA) PRIVATE KEY-----',
    'encrypted_dsa_private_key': r'-----BEGIN DSA PRIVATE KEY-----\s*.*?ENCRYPTED(?:.|\s)+?-----END DSA PRIVATE KEY-----',
    'encrypted_ec_private_key': r'-----BEGIN (?:EC|ECDSA) PRIVATE KEY-----\s*.*?ENCRYPTED(?:.|\s)+?-----END (?:EC|ECDSA) PRIVATE KEY-----',
    'encrypted_private_key': r'-----BEGIN ENCRYPTED PRIVATE KEY-----(?:.|\s)+?-----END ENCRYPTED PRIVATE KEY-----',
    'putty_ssh_dsa_key': r'PuTTY-User-Key-File-2: ssh-dss(?:.|\s)+?Private-MAC: [0-9a-f]+',
    'mailchimp_api_key_assigned': r'(?i)(?:mailchimp(?:_)?api(?:_)?key|mc(?:_)?api(?:_)?key)\s*[:=]\s*[\'"]?[0-9a-f]{32}-us[0-9]{1,2}[\'"]?',
    'mailgun_api_key_assigned': r'(?i)(?:mailgun(?:_)?api(?:_)?key|mg(?:_)?api(?:_)?key)\s*[:=]\s*[\'"]?key-[0-9a-z]{32}[\'"]?',
    'paypal_braintree_access_token': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    'picatic_api_key': r'sk_live_[0-9a-z]{32}',
    'sendgrid_api_key_assigned': r'(?i)(?:sendgrid(?:_)?api(?:_)?key)\s*[:=]\s*[\'"]?SG\\.[\\w_]{16,32}\\.[\\w_]{16,64}[\'"]?',
    'slack_webhook': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}',
    'stripe_api_key_assigned': r'(?i)(?:stripe(?:_)?api(?:_)?key|stripe(?:_)secret(?:_)?key)\s*[:=]\s*[\'"]?[sr]k_live_[0-9a-zA-Z]{24}[\'"]?',
    'square_access_token': r'sq0atp-[0-9A-Za-z\\-_]{22}',
    'square_oauth_secret': r'sq0csp-[0-9A-Za-z\\-_]{43}',
    'twilio_api_key_assigned': r'(?i)(?:twilio(?:_)?api(?:_)?key|twilio(?:_)auth(?:_)token)\s*[:=]\s*[\'"]?SK[0-9a-f]{32}[\'"]?',
    'dynatrace_ttoken': r'dt0[a-zA-Z]{1}[0-9]{2}\.[A-Z0-9]{24}\.[A-Z0-9]{64}',
    'shopify_shared_secret_assigned': r'(?i)(?:shopify(?:_)?shared(?:_)?secret)\s*[:=]\s*[\'"]?shpss_[a-fA-F0-9]{32}[\'"]?',
    'shopify_access_token': r'shpat_[a-fA-F0-9]{32}',
    'shopify_custom_app_access_token': r'shpca_[a-fA-F0-9]{32}',
    'shopify_private_app_access_token': r'shppa_[a-fA-F0-9]{32}',
    'pypi_upload_token': r'pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{50,1000}',
    'aws_credential_file_info': r'(?i)(aws_access_key_id|aws_secret_access_key)\s*=\s*[0-9a-zA-Z\\/+]{20,40}',
    'aws_secret_key': r'(?i)aws(?:_)?secret(?:_)?access(?:_)?key\s*[:=]?\s*[\'"]?[0-9a-zA-Z\\/+]{40}[\'"]?',
    'aws_mws_key': r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'facebook_secret_key_assigned': r'(?i)(?:facebook(?:_)?app(?:_)?secret|fb(?:_)?secret)\s*[:=]\s*[\'"]?[0-9a-f]{32}[\'"]?',
    'facebook_client_id_assigned': r'(?i)(?:facebook(?:_)?app(?:_)?id|fb(?:_)?client(?:_)?id)\s*[:=]\s*[\'"]?[0-9]{13,17}[\'"]?',
    'twitter_secret_key_assigned': r'(?i)(?:twitter(?:_)?consumer(?:_)?secret|twitter(?:_)?access(?:_)?token(?:_)?secret)\s*[:=]\s*[\'"]?[0-9a-zA-Z]{35,44}[\'"]?',
    'twitter_client_id_assigned': r'(?i)(?:twitter(?:_)?consumer(?:_)?key|twitter(?:_)?client(?:_)?id)\s*[:=]\s*[\'"]?[0-9a-zA-Z]{18,25}[\'"]?',
    'github_generic_token': r'(?i)github(?:_)?token\s*[:=]?\s*[\'"]?[0-9a-zA-Z]{35,40}[\'"]?',
    'linkedin_client_id_assigned': r'(?i)(?:linkedin(?:_)?client(?:_)?id|linkedin(?:_)?app(?:_)?id)\s*[:=]\s*[\'"]?[0-9a-zA-Z]{12}[\'"]?',
    'linkedin_secret_key_assigned': r'(?i)(?:linkedin(?:_)?client(?:_)?secret|linkedin(?:_)?app(?:_)?secret|linkedin(?:_)?secret)\s*[:=]\s*[\'"]?[0-9a-zA-Z]{16}[\'"]?',
    'slack_bot_token': r'(?i)xoxb-[0-9A-Za-z-]+',
    'slack_user_token': r'(?i)xoxa-[0-9A-Za-z-]+',
    'ec_private_key_header': r'-----BEGIN EC PRIVATE KEY-----',
    'google_api_key': r'AIza[0-9A-Za-z_-]{35}',
    'heroku_api_key_assigned': r'(?i)(?:heroku(?:_)?api(?:_)?key)\s*[:=]\s*[\'"]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[\'"]?',
    'generic_api_env_var': r'(?i)(?:api(?:_)?key|apikey|secret(?:_)?key|key|auth(?:_)?token|token|password|pass(?:word)?|pw|host)\s*=\s*[0-9a-zA-Z-_.{}\'"=!@#$%^&*()+]{8,200}',
    'generic_credential_assigned': r'(?i)(?:db(?:_)?(?:user|name|host|password)|api(?:_)?key|apikey|secret(?:_)?key|key|auth(?:_)?token|token|user(?:name)?|guid|hostname|pw|password)\s*[:=]\s*[\'"]?[0-9a-zA-Z-_\\/+!{}/=]{8,200}[\'"]?',
    'wordpress_config_credential': r'define\s*\(\s*[\'"]?(?:DB_CHARSET|NONCE_SALT|LOGGED_IN_SALT|AUTH_SALT|NONCE_KEY|DB_HOST|DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|DB_NAME|DB_USER)\s*[\'"]?\s*,\s*[\'"].{10,200}[\'"]\s*\)',
    'authorization_basic' : r'basic [a-zA-Z0-9=:_\+\/-]{5,100}',
    'authorization_bearer' : r'bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}',
    'authorization_api' : r'api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}',
    'mailgun_api_key' : r'key-[0-9a-zA-Z]{32}',
    'twilio_api_key' : r'SK[0-9a-fA-F]{32}',
    'twilio_account_sid' : r'AC[a-zA-Z0-9_\-]{32}',
    'twilio_app_sid' : r'AP[a-zA-Z0-9_\-]{32}',
    'paypal_braintree_access_token' : r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    'square_oauth_secret' : r'sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}',
    'square_access_token' : r'sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}',
    'stripe_standard_api' : r'sk_live_[0-9a-zA-Z]{24}',
    'stripe_restricted_api' : r'rk_live_[0-9a-zA-Z]{24}',
    'github_access_token' : r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
    'rsa_private_key' : r'-----BEGIN RSA PRIVATE KEY-----',
    'ssh_dsa_private_key' : r'-----BEGIN DSA PRIVATE KEY-----',
    'ssh_dc_private_key' : r'-----BEGIN EC PRIVATE KEY-----',
    'pgp_private_block' : r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    'json_web_token' : r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',
    'slack_token' : r"\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"",
    'SSH_privKey' : r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)",
    'Heroku API KEY' : r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    'possible_Creds' : r"(?i)(" \
                    r"password\s*[`=:\"]+\s*[^\s]+|" \
                    r"password is\s*[`=:\"]*\s*[^\s]+|" \
                    r"pwd\s*[`=:\"]*\s*[^\s]+|" \
                    r"passwd\s*[`=:\"]+\s*[^\s]+)",
}

_template = '''
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <style>
       h1 {
          font-family: sans-serif;
       }
       a {
          color: #000;
       }
       .text {
          font-size: 16px;
          font-family: Helvetica, sans-serif;
          color: #323232;
          background-color: white;
       }
       .container {
          background-color: #e9e9e9;
          padding: 10px;
          margin: 10px 0;
          font-family: helvetica;
          font-size: 13px;
          border-width: 1px;
          border-style: solid;
          border-color: #8a8a8a;
          color: #323232;
          margin-bottom: 15px;
       }
       .button {
          padding: 17px 60px;
          margin: 10px 10px 10px 0;
          display: inline-block;
          background-color: #f4f4f4;
          border-radius: .25rem;
          text-decoration: none;
          -webkit-transition: .15s ease-in-out;
          transition: .15s ease-in-out;
          color: #333;
          position: relative;
       }
       .button:hover {
          background-color: #eee;
          text-decoration: none;
       }
       .github-icon {
          line-height: 0;
          position: absolute;
          top: 14px;
          left: 24px;
          opacity: 0.7;
       }
  </style>
  <title>LinkFinder Output</title>
</head>
<body contenteditable="true">
  $$content$$

  <a class='button' contenteditable='false' href='https://github.com/m4ll0k/SecretFinder/issues/new' rel='nofollow noopener noreferrer' target='_blank'><span class='github-icon'><svg height="24" viewbox="0 0 24 24" width="24" xmlns="http://www.w3.org/2000/svg">
  <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22" fill="none" stroke="#000" stroke-linecap="round" stroke-linejoin="round" stroke-width="2"></path></svg></span> Report an issue.</a>
</body>
</html>
'''

def parser_error(msg):
    print('Usage: python %s [OPTIONS] use -h for help'%sys.argv[0])
    print('Error: %s'%msg)
    sys.exit(0)

def getContext(matches,content,name,rex='.+?'):
    ''' get context '''
    items = []
    matches2 =  []
    for  i in [x[0] for x in matches]:
        if i not in matches2:
            matches2.append(i)
    for m in matches2:
        context = re.findall('%s%s%s'%(rex,m,rex),content,re.IGNORECASE)

        item = {
            'matched'          : m,
            'name'             : name,
            'context'          : context,
            'multi_context'    : True if len(context) > 1 else False
        }
        items.append(item)
    return items


def parser_file(content,mode=1,more_regex=None,no_dup=1):
    ''' parser file '''
    if mode == 1:
        if len(content) > 1000000:
            content = content.replace(";",";\r\n").replace(",",",\r\n")
        else:
            content = jsbeautifier.beautify(content)
    all_items = []
    for regex in _regex.items():
        r = re.compile(regex[1],re.VERBOSE|re.I)
        if mode == 1:
            all_matches = [(m.group(0),m.start(0),m.end(0)) for m in re.finditer(r,content)]
            items = getContext(all_matches,content,regex[0])
            if items != []:
                all_items.append(items)
        else:
            items = [{
                'matched' : m.group(0),
                'context' : [],
                'name'    : regex[0],
                'multi_context' : False
            } for m in re.finditer(r,content)]
        if items != []:
            all_items.append(items)
    if all_items != []:
        k = []
        for i in range(len(all_items)):
            for ii in all_items[i]:
                if ii not in k:
                    k.append(ii)
        if k != []:
            all_items = k

    if no_dup:
        all_matched = set()
        no_dup_items = []
        for item in all_items:
            if item != [] and type(item) is dict:
                if item['matched'] not in all_matched:
                    all_matched.add(item['matched'])
                    no_dup_items.append(item)
        all_items = no_dup_items

    filtered_items = []
    if all_items != []:
        for item in all_items:
            if more_regex:
                if re.search(more_regex,item['matched']):
                    filtered_items.append(item)
            else:
                filtered_items.append(item)
    return filtered_items


def parser_input(input):
    ''' Parser Input '''
    # method 1 - url
    schemes = ('http://','https://','ftp://','file://','ftps://')
    if input.startswith(schemes):
        return [input]
    # method 2 - url inpector firefox/chrome
    if input.startswith('view-source:'):
        return [input[12:]]
    # method 3 - Burp file
    if args.burp:
        jsfiles = []
        items = []

        try:
            items = xml.etree.ElementTree.fromstring(open(args.input,'r').read())
        except Exception as err:
            print(err)
            sys.exit()
        for item in items:
            jsfiles.append(
                {
                    'js': base64.b64decode(item.find('response').text).decode('utf-8','replace'),
                    'url': item.find('url').text
                }
            )
        return jsfiles
    # method 4 - folder with a wildcard
    if '*' in input:
        paths = glob.glob(os.path.abspath(input))
        for index, path in enumerate(paths):
            paths[index] = "file://%s" % path
        return (paths if len(paths)> 0 else parser_error('Input with wildcard does not match any files.'))

    # method 5 - local file
    path = "file://%s"% os.path.abspath(input)
    return [path if os.path.exists(input) else parser_error('file could not be found (maybe you forgot to add http/https).')]


def html_save(output):
    ''' html output '''
    hide = os.dup(1)
    os.close(1)
    os.open(os.devnull,os.O_RDWR)
    try:
        text_file = open(args.output,"wb")
        text_file.write(_template.replace('$$content$$',output).encode('utf-8'))
        text_file.close()

        print('URL to access output: file://%s'%os.path.abspath(args.output))
        file = 'file:///%s'%(os.path.abspath(args.output))
        if sys.platform == 'linux' or sys.platform == 'linux2':
            subprocess.call(['xdg-open',file])
        else:
            webbrowser.open(file)
    except Exception as err:
        print('Output can\'t be saved in %s due to exception: %s'%(args.output,err))
    finally:
        os.dup2(hide,1)

def cli_output(matched):
    ''' cli output '''
    for match in matched:
        print(match.get('name')+'\t->\t'+match.get('matched').encode('ascii','ignore').decode('utf-8'))

def urlParser(url):
    ''' urlParser '''
    parse = urlparse(url)
    urlParser.this_root = parse.scheme + '://' + parse.netloc
    urlParser.this_path = parse.scheme + '://' + parse.netloc  + '/' + parse.path

def extractjsurl(content,base_url):
    ''' JS url extract from html page '''
    soup = html.fromstring(content)
    all_src = []
    urlParser(base_url)
    for src in soup.xpath('//script'):
        src = src.xpath('@src')[0] if src.xpath('@src') != [] else []
        if src != []:
            if src.startswith(('http://','https://','ftp://','ftps://')):
                if src not in all_src:
                    all_src.append(src)
            elif src.startswith('//'):
                src = 'http://'+src[2:]
                if src not in all_src:
                    all_src.append(src)
            elif src.startswith('/'):
                src = urlParser.this_root + src
                if src not in all_src:
                    all_src.append(src)
            else:
                src = urlParser.this_path + src
                if src not in all_src:
                    all_src.append(src)
    if args.ignore and all_src != []:
        temp = all_src
        ignore = []
        for i in args.ignore.split(';'):
            for src in all_src:
                if i in src:
                    ignore.append(src)
        if ignore:
            for i in ignore:
                temp.pop(int(temp.index(i)))
        return temp
    if args.only:
        temp = all_src
        only = []
        for i in args.only.split(';'):
            for src in all_src:
                if i in src:
                    only.append(src)
        return only
    return all_src

def send_request(url):
    ''' Send Request '''
    # read local file
    # https://github.com/dashea/requests-file
    if 'file://' in url:
        s = requests.Session()
        s.mount('file://',FileAdapter())
        return s.get(url).content.decode('utf-8','replace')
    # set headers and cookies
    headers = {}
    default_headers = {
        'User-Agent'      : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
        'Accept'          : 'text/html, application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language' : 'en-US,en;q=0.8',
        'Accept-Encoding' : 'gzip'
    }
    if args.headers:
        for i in args.header.split('\\n'):
            # replace space and split
            name,value = i.replace(' ','').split(':')
            headers[name] = value
    # add cookies
    if args.cookie:
        headers['Cookie'] = args.cookie

    headers.update(default_headers)
    # proxy
    proxies = {}
    if args.proxy:
        proxies.update({
            'http'  : args.proxy,
            'https' : args.proxy,
            # ftp
        })
    try:
        resp = requests.get(
            url = url,
            verify = False,
            headers = headers,
            proxies = proxies
        )
        return resp.content.decode('utf-8','replace')
    except Exception as err:
        print(err)
        sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-e","--extract",help="Extract all javascript links located in a page and process it",action="store_true",default=False)
    parser.add_argument("-i","--input",help="Input a: URL, file or folder",required="True",action="store")
    parser.add_argument("-o","--output",help="Where to save the file, including file name. Default: output.html",action="store", default="output.html")
    parser.add_argument("-r","--regex",help="RegEx for filtering purposes against found endpoint (e.g: ^/api/)",action="store")
    parser.add_argument("-b","--burp",help="Support burp exported file",action="store_true")
    parser.add_argument("-c","--cookie",help="Add cookies for authenticated JS files",action="store",default="")
    parser.add_argument("-g","--ignore",help="Ignore js url, if it contain the provided string (string;string2..)",action="store",default="")
    parser.add_argument("-n","--only",help="Process js url, if it contain the provided string (string;string2..)",action="store",default="")
    parser.add_argument("-H","--headers",help="Set headers (\"Name:Value\\nName:Value\")",action="store",default="")
    parser.add_argument("-p","--proxy",help="Set proxy (host:port)",action="store",default="")
    args = parser.parse_args()

    if args.input[-1:] == "/":
        # /aa/ -> /aa
        args.input = args.input[:-1]

    mode = 1
    if args.output == "cli":
        mode = 0
    # add args
    if args.regex:
        # validate regular exp
        try:
            r = re.search(args.regex,''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(random.randint(10,50))))
        except Exception as e:
            print('your python regex isn\'t valid')
            sys.exit()

        _regex.update({
            'custom_regex' : args.regex
        })

    if args.extract:
        content = send_request(args.input)
        urls = extractjsurl(content,args.input)
    else:
        # convert input to URLs or JS files
        urls = parser_input(args.input)
    # conver URLs to js file
    output = ''
    for url in urls:
        print('[ + ] URL: '+url)
        if not args.burp:
            file = send_request(url)
        else:
            file = url.get('js')
            url = url.get('url')

        matched = parser_file(file,mode)
        if args.output == 'cli':
            cli_output(matched)
        else:
            output += '<h1>File: <a href="%s" target="_blank" rel="nofollow noopener noreferrer">%s</a></h1>'%(escape(url),escape(url))
            for match in matched:
                _matched = match.get('matched')
                _named = match.get('name')
                header = '<div class="text">%s'%(_named.replace('_',' '))
                body = ''
                # find same thing in multiple context
                if match.get('multi_context'):
                    # remove duplicate
                    no_dup = []
                    for context in match.get('context'):
                        if context not in no_dup:
                            body += '</a><div class="container">%s</div></div>'%(context)
                            body = body.replace(
                                context,'<span style="background-color:yellow">%s</span>'%context)
                            no_dup.append(context)
                        # --
                else:
                    body += '</a><div class="container">%s</div></div>'%(match.get('context')[0] if len(match.get('context'))>1 else match.get('context'))
                    body = body.replace(
                        match.get('context')[0] if len(match.get('context')) > 0 else ''.join(match.get('context')),
                        '<span style="background-color:yellow">%s</span>'%(match.get('context') if len(match.get('context'))>1 else match.get('context'))
                    )
                output += header + body
    if args.output != 'cli':
        html_save(output)
