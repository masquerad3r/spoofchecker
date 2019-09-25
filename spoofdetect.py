import subprocess
import sys
import re


domain = ''

#  ANSI escape color codes for colored terminal output
CEND    = '\33[0m'
CRED    = '\033[91m'
CGREEN  = '\033[92m'
CYELLOW = '\033[93m'

def possible_spoofing():
	global domain
	print(CRED + "[-] " + CEND + "Spoofing possible for: " + CYELLOW + f"{domain}" + CEND + " !!")


def impossible_spoofing():
	global domain
	print(CGREEN + "[+] " + CEND + "Spoofing not possible for: " + CYELLOW + f"{domain}")


def print_spf_record(spf_record):
	print(CGREEN + "[+] " + CEND + "SPF record found " + CYELLOW + "-->" + CEND + f" {spf_record}")


def print_dmarc_record(dmarc_record):
	print(CGREEN + "[+] " + CEND + "DMARC record found " + CYELLOW + "-->" + CEND + f" {dmarc_record}")


def fetch_spf(domain):
	spf_check_command = ["dig", "-t", "txt", f"{domain}", "+short"]
	grep_spf_command = ["grep", "-i", "v=spf1"]

	spf_record = ''

	try:
		spf_check = subprocess.Popen(spf_check_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		spf_record = subprocess.check_output(grep_spf_command, stdin=spf_check.stdout)
		spf_record = spf_record.decode('utf-8').strip()
		spf_record = spf_record[1:-1]
		print_spf_record(spf_record)

	except subprocess.CalledProcessError as e:
		print(CRED + "[-] " + CEND + "No SPF record found for: " + CYELLOW + f"{domain}" + CEND)

	if spf_record == "v=spf1 -all":
		impossible_spoofing()
		exit()

	return spf_record


def fetch_dmarc(domain):
	dmarc_check_command = ["dig", "-t", "txt", f"_dmarc.{domain}", "+short"]
	grep_dmarc_command = ["grep", "-i", "v=dmarc1"]
	dmarc_record = ''

	try:
		dmarc_check = subprocess.Popen(dmarc_check_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		dmarc_record = subprocess.check_output(grep_dmarc_command, stdin=dmarc_check.stdout)
		dmarc_record = dmarc_record.decode('utf-8').strip()
		dmarc_record = dmarc_record[1:-1]
		print_dmarc_record(dmarc_record)

	except subprocess.CalledProcessError as e:
		print(CRED + "[-] " + CEND + f"No DMARC record found for: " + CYELLOW + f"{domain}" + CEND)
		possible_spoofing()
		exit()

	return dmarc_record


def extract_dmarc_tags(dmarc_record):
	pattern = "(\w+)=(.*?)(?:; ?|$)"
	return re.findall(pattern, dmarc_record)



def check_spf_strength(spf_record):

	spf_strength = False
 	
	if re.search("'+all'|-all|~all|'?all'", spf_record.lower()):
		all_position = re.search("~all|-all|'+all'|'?all'", spf_record.lower()).start()

		if '-all' in spf_record:
			spf_strength = True
			print(CYELLOW + "[*] " + CEND + f"SPF record is set to hardfail: {spf_record[all_position : all_position + 4]}")

		elif '~all' in spf_record:
			spf_strength = True
			print(CYELLOW + "[*] " + CEND + f"SPF record is set to softfail: {spf_record[all_position : all_position + 4]}")

		else:
			print(CRED + "[*] " + CEND + f"SPF record All item is too weak: {spf_record[all_position : all_position + 4]}")

	else:
		print(CRED + "[-] " + CEND + "SPF does not contain All mechanism")

	return spf_strength


def check_dmarc_strength(dmarc_tags):
	dmarc_policy_strength = False

	if "p" in dmarc_tags.keys():

		if dmarc_tags['p'] == 'none':
			print(CYELLOW + "[*] " + CEND + f"DMARC policy is set to: {dmarc_tags['p']}")
	
		else:
			dmarc_policy_strength = True
			print(CGREEN + "[+] " + CEND + f"DMARC policy is set to: {dmarc_tags['p']}")	

	else:
		print(CRED + "[*] " + CEND + "DMARC record has no policy")

	return dmarc_policy_strength


def fetch_dmarc_add_info(dmarc_tags):

	if "pct" in dmarc_tags.keys():
		if dmarc_tags['pct'] != str(100):
			print(CYELLOW + "[*] " + CEND + f"DMARC pct is set to {dmarc_tags['pct']}")

	if "rua" in dmarc_tags.keys():
		print(CYELLOW + "[*] " + CEND + f"Analysis reports will be sent to: {dmarc_tags['rua']}")

	if "ruf" in dmarc_tags.keys():
		print(CYELLOW + "[*] " + CEND + f"Forensic reports will be sent to: {dmarc_tags['ruf']}")


if __name__ == "__main__":

	spoofable = False
	try:
		domain = sys.argv[1]

		#  Fetching SPF record for the domain
		spf_record = fetch_spf(domain)
		
		if spf_record != '':
			spf_strength = check_spf_strength(spf_record)


		#  Fetching DMARC record for the domain
		dmarc_record = fetch_dmarc(domain)
		dmarc_tags = dict(extract_dmarc_tags(dmarc_record))
		dmarc_strength = check_dmarc_strength(dmarc_tags)

		fetch_dmarc_add_info(dmarc_tags)

		if dmarc_strength:
			impossible_spoofing()

		else:
			possible_spoofing()

	except IndexError:
		print(f"Usage: {sys.argv[0]} [DOMAIN]")
