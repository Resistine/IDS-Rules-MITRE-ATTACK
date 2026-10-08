#!/usr/bin/env python3
# Copyright (c) 2024 Resistine

import sys
import traceback
import os.path
import os
import urllib.request
import tarfile
import zipfile
import re
import pandas as pd
import ast

# Ensure the project root and current script directory are on sys.path
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

CUR_DIR = os.path.abspath(os.path.dirname(__file__))
if CUR_DIR not in sys.path:
    sys.path.insert(0, CUR_DIR)

from snortparser import Parser, Dicts
#from SRParser import SnortParser
import mitreattack.attackToExcel.attackToExcel as attackToExcel

# Support extended protocols used in Suricata and Emerging Threats rules
_orig_proto = getattr(Parser, 'proto', None)
def _extended_proto(proto: str) -> str:
    return proto

Parser.proto = staticmethod(_extended_proto)


# Constants
INBOUND = 'inb'
LATERAL = 'lat'
OUTBOUND = 'out'

# Output file
CSVFILE = "rules_parsed.csv"
COLUMNS = ['sid', 'proto', 'source', 'src_port', 'arrow', 'destination', 'dst_port', 'classtype', 
           'direction',	'TActic', 'Technique', 'Tname', 'TA_inb', 'T_inb',  'TA_lat', 'T_lat', 'TA_out', 'T_out',
           'msg', 'reference']

# Snort rules file and URL
TARFILE = "snort3-community-rules.tar.gz"
LINK = "https://www.snort.org/downloads/community/"+ TARFILE
DIR = "snort3-community-rules"
FILE = "snort3-community.rules"
RULES = os.path.join(DIR, FILE)

# ProofPoint Emerging Threats Open Ruleset
ET_FILE = "emerging.rules"
ET_LINK = "https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.zip"
ET_DIR = "et-open-rules"
ET_RULES = os.path.join(ET_DIR, ET_FILE)



# MITRE ATT&CK files
MAPPINGS = "mappings.csv"
ATTACK_DIR = "enterprise-attack"
TACTICS = "enterprise-attack-tactics.xlsx"
ATTACK_TAs = os.path.join(ATTACK_DIR, TACTICS)
TECHNIQUES = "enterprise-attack-techniques.xlsx"
ATTACK_Tes = os.path.join(ATTACK_DIR, TECHNIQUES)

# download the MITRE ATT&CK and create the Excel files if they do not exist
if (not os.path.exists(ATTACK_DIR)):
    try:
        attackToExcel.export("enterprise-attack")
    except Exception as e:
        print("Exception while downloading MITRE ATT&CK: "+ str(e))
        exit(1)

# read the MITRE ATT&CK TActics and Techniques into DataFrames
TAs = pd.read_excel(ATTACK_TAs, dtype=str)
Tes = pd.read_excel(ATTACK_Tes, dtype=str)


# read the Resistine Snort to MITRE ATT&CK TActics mappings or exit if the file was deleted
if (not os.path.exists(MAPPINGS)):
    print("There is no "+ MAPPINGS +" file in the current directory.")
    print("Please, get the mappings file from Git or the shared Drive and try again.")
    exit(1)

df_mappings = pd.read_csv(MAPPINGS, dtype=str)
print(df_mappings) # DEBUG: print the NaNs in the DataFrame
#PRINTS OUT NANS IN DF, simply prints out the df as is

# Helper function to get the TActic for the classtype and direction from the mappings file.
def get_TActic(classtype, column):
    '''Get the TActic for the classtype and direction from the mappings file.'''
    if classtype not in df_mappings['classtype'].values: #checks if classstype exists in df_mapping
        print(f"Classtype '{classtype}' not found in mappings")
        return None
    
    # get the TActic for the classtype a the proper direction from the mappings file
    try:
        d = df_mappings.loc[df_mappings['classtype'] == classtype, column].iloc[0]
        # fix the NaN and \xa0 BSs in the DataFrame ... 
        if (pd.isna(d)):
            d = None
        if isinstance(d, str):
            d=d.replace('/xa0', '').strip()
            if d== "":
                d= None

    except IndexError:
        print("No record for the classtype: "+ classtype)
        return None  # or any default value
    
    # if d is already defined, then return it or get the default TActic from the mappings
    if (d): 
        return d
    else:
        try:
            d = df_mappings.loc[df_mappings['classtype'] == classtype, "TActic"].iloc[0]
            if pd.isna(d): 
                d = None
            if isinstance(d, str):
                d = d.replace('\xa0', '').strip()
                if d == "":
                    d = None
        except:
            return None
    
    return d

#TESTING
#if __name__ == "__main__":
#    print("=== TESTING get_TActic() ===")
    # Try a known classtype that exists in mappings.csv
#    test_class = "attempted-admin"   # <-- replace with a real classtype from your CSV
#    test_column = "TA_inb"           # <-- or TA_lat, TA_out, whatever your CSV has
#
#    result = get_TActic(test_class, test_column)
#    print("Result:", result)


# download the Snort rules if they do not exist
if (not os.path.exists(RULES)):
    try:
        if (not os.path.isdir(DIR)): os.makedirs(DIR)
        urllib.request.urlretrieve(LINK, os.path.join(DIR, TARFILE))
        
        tar = tarfile.open(os.path.join(DIR, TARFILE), "r:gz")
        tar.extractall()
        tar.close()

    except Exception as e:
        print("Exception while downloading Snort rules: "+ str(e))

# download the ProofPoint Emerging Threats rules if they do not exist
if (not os.path.exists(ET_RULES)):
    try:
        if (not os.path.isdir(ET_DIR)): os.makedirs(ET_DIR)
        et_zip = os.path.join(ET_DIR, "emerging.rules.zip")
        print("Downloading ProofPoint Emerging Threats rules...")
        urllib.request.urlretrieve(ET_LINK, et_zip)
        
        print("Extracting ProofPoint Emerging Threats rules...")
        with zipfile.ZipFile(et_zip, "r") as zf:
            zf.extractall(ET_DIR)
        
        # Consolidate all rule files into ET_RULES if under rules/ subdirectory
        rules_subdir = os.path.join(ET_DIR, "rules")
        if os.path.isdir(rules_subdir):
            rule_files = [os.path.join(rules_subdir, f) for f in os.listdir(rules_subdir) if f.endswith(".rules")]
            rule_files.sort()
            with open(ET_RULES, "w", encoding="utf-8", errors="ignore") as outfile:
                for r_file in rule_files:
                    with open(r_file, "r", encoding="utf-8", errors="ignore") as infile:
                        outfile.write(infile.read())
                        outfile.write("\n")
        print("ProofPoint Emerging Threats rules downloaded and prepared.")

    except Exception as e:
        print("Exception while downloading ProofPoint Emerging Threats rules: "+ str(e))



# Helper function to get the connection/attack direction (inbound/outbound) from the parsed rule and return it.
def get_direction(source, arrow, destination):
    '''Get the connection/attack direction from the parsed rule and return it.
       This is a best effort function as the direction depends on the newtwork topology and the actual flow,
       ie> any, $EXTERNAL_NET, $HOME_NET, ... IP/CIDR, [groups], '!...', etc.
       @see: https://docs.snort.org/rules/headers/directions and https://docs.snort.org/rules/headers/ips 
       @see: https://docs.suricata.io/en/latest/rules/intro.html
    '''
    # not sure about undefined as the snortparser does not allow it (see https://github.com/g-rd/snortparser/issues/5)
    if (not source or not arrow):
        return None
    if destination is None:
        return None

    # FIXME: add more cases for the source and destination
    # normalizing strings
    if isinstance(source, (list, tuple)):
        source = str(source)
    if isinstance(destination, (list, tuple)):
        destination = str(destination)
    source = str(source).replace(" ", "")
    destination = str(destination).replace(" ", "")
    #easier readability
    HOME = "$HOME_NET"
    EXTERNAL = "$EXTERNAL_NET"
    if (arrow == '->'):
        if(source.startswith(EXTERNAL) and destination.startswith(HOME)):
            return INBOUND
        if(source.startswith(HOME) and destination.startswith(EXTERNAL)):
            return OUTBOUND
        if (source.startswith(EXTERNAL)):
            return INBOUND
        if (destination):
            if (destination.startswith(EXTERNAL)):
                return OUTBOUND
            if(destination.startswith(HOME)):
                return INBOUND
            elif (not destination.startswith('any') and not source.startswith(HOME)):
                return INBOUND
        if(source.startswith(HOME)):
            return OUTBOUND
        if any(c.isdigit() for c in destination) and destination[0].isdigit():
            return INBOUND
    return None

#Testing
#if __name__ == "__main__":
#    print("=== Testing get_direction() ===")
#    test_cases = [
        #expect INBOUND
#        ("$EXTERNAL_NET", "->", "$HOME_NET"),
#        ("$EXTERNAL_NET", "->", "any"),
#        ("$EXTERNAL_NET ", "->", " $HOME_NET"),  
#       ("1.2.3.4", "->", "10.0.0.5"),            
        #expect OUTBOUND
#        ("$HOME_NET", "->", "$EXTERNAL_NET"),
#        (" $HOME_NET", "->", " $EXTERNAL_NET "), 
        # expect None
#        (None, "->", "$HOME_NET"),
#        ("$HOME_NET", None, "$EXTERNAL_NET"),
#        ("$HOME_NET", "->", "$HOME_NET"),
#        ("$HOME_NET", "->", None),
#    ]

#    for src, arrow, dst in test_cases:
#        result = get_direction(src, arrow, dst)
#        print(f"source={src!r:20} arrow={arrow!r:4} dest={dst!r:20}  ->  result={result}")




# Helper function to get the first option that starts with the string from the parsed rule and return it.
def get_option(parsed, string):
    '''Get the first option that starts with the string from the parsed rule and return it.'''
    for n in parsed.options:
        if parsed.options[n][0].startswith(string):
            return parsed.options[n]
    return None


def parse_rule_to_df(rule):
    '''Parse a single IDS rule into a pandas DataFrame row.'''
    rule_clean = re.sub(r'\[([0-9a-fA-F.:]+)\]', r'\1', rule)
    parsed = Parser(rule_clean)
    # get options for easier coding      
    sid = get_option(parsed, 'sid')[1][0] if get_option(parsed, 'sid') else pd.NA
    proto = parsed.header.get('proto', pd.NA)
    source = parsed.header['source'][1] if parsed.header.get('source') else pd.NA
    src_port = parsed.header['src_port'][1] if parsed.header.get('src_port') else pd.NA
    arrow = parsed.header.get('arrow', pd.NA)
    destination = parsed.header['destination'][1] if parsed.header.get('destination') else pd.NA
    dst_port = parsed.header['dst_port'][1] if parsed.header.get('dst_port') else pd.NA
    classtype = get_option(parsed, 'classtype')[1][0] if get_option(parsed, 'classtype') else pd.NA
    msg = get_option(parsed, 'msg')[1][0] if get_option(parsed, 'msg') else pd.NA
    reference = get_option(parsed, 'reference')[1] if get_option(parsed, 'reference') else pd.NA

    # initialize df
    df = pd.DataFrame([[sid, proto, source, src_port, arrow, destination, dst_port, classtype,
        pd.NA, pd.NA, pd.NA, pd.NA, pd.NA, pd.NA, pd.NA, pd.NA, pd.NA, pd.NA, msg, reference]], columns=COLUMNS, dtype=str)

    # add the inbound/outbound directions
    direction = get_direction(source, arrow, destination)
    df['direction'] = direction

    # switch TActics -- first the specific one, then the generic one
    if (direction == INBOUND):
        df['TActic'] = df['TA_inb'] = get_TActic(classtype, 'TA_inb')
    elif (direction == LATERAL):
        df['TActic'] = df['TA_lat'] = get_TActic(classtype, 'TA_lat')
    elif (direction == OUTBOUND):
        df['TActic'] = df['TA_out'] = get_TActic(classtype, 'TA_out')
    else: # if the direction is not defined, then try to get the default TActic from the mappings
        df['TActic'] = get_TActic(classtype, 'TActic')

    # parse techniques from references
    # `reference` may be a pandas NA, a string representation of a list, or already a list/sequence.
    if reference is not pd.NA:
        try:
            # normalize to a Python list of strings
            if isinstance(reference, str):
                ref_list = ast.literal_eval(reference)
                if not isinstance(ref_list, (list, tuple)):
                    ref_list = [ref_list]
            elif isinstance(reference, pd.Series):
                ref_list = reference.tolist()
            elif isinstance(reference, (list, tuple)):
                ref_list = list(reference)
            else:
                # fallback: wrap single value
                ref_list = [reference]

            s = pd.Series(ref_list)
            # filter only MITRE technique URLs
            s = s[s.str.startswith('attack.mitre.org/techniques/')]
            if not s.empty:
                # take the first technique for now
                technique_id = s.iloc[0].replace('attack.mitre.org/techniques/', '')
                df['Technique'] = technique_id
                df['Tname'] = Tes.loc[Tes['ID'] == technique_id, 'name'].iloc[0] if not Tes.loc[Tes['ID'] == technique_id, 'name'].empty else pd.NA
        except Exception as e:
            print(f"Warning: could not parse reference for rule {sid}: {e}")

    return df


if __name__ == "__main__":
    RULE_FILES = [RULES, ET_RULES]

    # open output file for writing, not appending and write the header ...
    with open(CSVFILE, 'w') as csv_rules:
        csv_rules.write(','.join(COLUMNS) + '\n')

        for rules_path in RULE_FILES:
            if not os.path.exists(rules_path):
                print(f"Warning: rules file not found: {rules_path}")
                continue

            print(f"Parsing rules from: {rules_path}")
            # open input file
            with open(rules_path, 'r', encoding='utf-8', errors='ignore') as snort_rules:
                # for each line (rule)
                for rule in snort_rules:
                    rule = rule.strip()
                    if not rule or rule.startswith('#'):
                        continue

                    # try to parse the rule
                    try:
                        df = parse_rule_to_df(rule)
                        # print the Pandas DataFrame to the output file
                        csv_rules.write(df.to_csv(index=False, header=False))

                    # NOTE: If the snortparser is unable to parse the rule, it will return a ValueError with the invalid rule item.
                    except Exception as e:
                        print("Exception: "+ str(e))
                        print(traceback.format_exc())
                        print(rule)

    # Hooraay! We are done
    print('There you are: '+ CSVFILE)
