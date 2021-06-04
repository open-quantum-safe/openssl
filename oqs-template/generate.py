#!/usr/bin/env python3

import copy
import glob
import jinja2
import jinja2.ext
import os
import shutil
import subprocess
import yaml
import sys

# For list.append in Jinja templates
Jinja2 = jinja2.Environment(loader=jinja2.FileSystemLoader(searchpath="."),extensions=['jinja2.ext.do'])

def file_get_contents(filename, encoding=None):
    with open(filename, mode='r', encoding=encoding) as fh:
        return fh.read()

def file_put_contents(filename, s, encoding=None):
    with open(filename, mode='w', encoding=encoding) as fh:
        fh.write(s)

def populate(filename, config, delimiter, overwrite=False):
    fragments = glob.glob(os.path.join('oqs-template', filename, '*.fragment'))
    if overwrite == True:
        source_file = os.path.join('oqs-template', filename, os.path.basename(filename)+ '.base')
        contents = file_get_contents(source_file)
    else:
        contents = file_get_contents(filename)

    for fragment in fragments:
        identifier = os.path.splitext(os.path.basename(fragment))[0]

        if filename == 'README.md':
            identifier_start = '{} OQS_TEMPLATE_FRAGMENT_{}_START -->'.format(delimiter, identifier.upper())
        else:
            identifier_start = '{} OQS_TEMPLATE_FRAGMENT_{}_START'.format(delimiter, identifier.upper())
        identifier_end = '{} OQS_TEMPLATE_FRAGMENT_{}_END'.format(delimiter, identifier.upper())

        preamble = contents[:contents.find(identifier_start)]
        postamble = contents[contents.find(identifier_end):]

        if overwrite == True:
            contents = preamble + Jinja2.get_template(fragment).render({'config': config}) + postamble.replace(identifier_end + '\n', '')
        else:
            contents = preamble + identifier_start + Jinja2.get_template(fragment).render({'config': config}) + postamble

    file_put_contents(filename, contents)

def load_config(include_disabled_sigs=False):
    config = file_get_contents(os.path.join('oqs-template', 'generate.yml'), encoding='utf-8')
    config = yaml.safe_load(config)
    if include_disabled_sigs:
        return config
    for sig in config['sigs']:
        sig['variants'] = [variant for variant in sig['variants'] if variant['enable']]
    return config

# As claimed_nist_level is only a runtime struct, need to compile code to get at it:
def get_nistlevel(alg, iskem):
    # create file to compile
    TMPOQS_SRC="oqsnisttest.c"
    TMPOQS_EXE="oqsnisttest"
    with open(TMPOQS_SRC, "w") as f:
      f.write("#include <stdio.h>\n")
      f.write("#include <oqs/oqs.h>\n")
      if (iskem):
         f.write("int main(int argc, char* argv[]) { OQS_KEM *kem = OQS_KEM_new("+alg+"); printf(\"%d\", kem->claimed_nist_level); }")
      else:
         f.write("int main(int argc, char* argv[]) { OQS_SIG *sig = OQS_SIG_new("+alg+"); printf(\"%d\", sig->claimed_nist_level); }")
    # now compile this so that it works with both shared and static liboqs:
    # gcc must exist as otherwise nothing else will build afterwards
    if os.system("gcc -Ioqs/include -Loqs/lib "+TMPOQS_SRC+" -loqs -lcrypto -o "+TMPOQS_EXE) != 0:
       print("Compilation failed. Cannot get NIST level. Exiting.")
       exit(1)
    # now execute it so it works for both shared and static liboqs
    env =os.environ
    env["LD_LIBRARY_PATH"] = "oqs/lib"
    p = subprocess.Popen(["./"+TMPOQS_EXE], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    output, err = p.communicate()
    # delete temp files:
    os.remove(TMPOQS_EXE)
    os.remove(TMPOQS_SRC)
    # evaluate result
    if (p.returncode == 0):
      return output.decode()
    else:
      print("Error determining NIST level for %s: %s. Exiting." % (alg, output.decode()))
      exit(1)

def nist_to_bits(nistlevel):
   if nistlevel=="1" or nistlevel=="2":
      return 128
   if nistlevel=="3" or nistlevel=="4":
      return 192
   if nistlevel=="5":
      return 256
   print("Unknown NIST level %s. Exiting." % (nistlevel))
   exit(1)

def validate_config(config):
   for kem in config['kems']:
      bits_level = nist_to_bits(get_nistlevel(kem['oqs_alg'], True))
      if bits_level != int(kem['bit_security']):
         print("Warning: Correcting NIST level mismatch for %s: %s vs %s." % (kem['name_group'], kem['bit_security'], bits_level))
         kem['bit_security'] = bits_level
   for famsig in config['sigs']:
      for sig in famsig['variants']:
         bits_level = nist_to_bits(get_nistlevel(sig['oqs_meth'], False))
         if bits_level != int(sig['security']):
            print("Warning: Correcting NIST level mismatch for %s: %s vs %s " % (sig['name'], sig['security'], bits_level))
            sig['security'] = bits_level
   return config

config = load_config()
# only do sanity check on linux:
if sys.platform=="linux":
   config = validate_config(config)

# sigs
populate('crypto/asn1/standard_methods.h', config, '/////')
populate('crypto/ec/oqs_meth.c', config, '/////')
populate('crypto/evp/pmeth_lib.c', config, '/////')
populate('include/crypto/asn1.h', config, '/////')
populate('include/crypto/evp.h', config, '/////')
# We remove the delimiter comments from obj_mac.num
populate('crypto/objects/obj_mac.num', config, '#####', True)
populate('crypto/objects/obj_xref.txt', config, '#####')
populate('crypto/objects/objects.txt', config, '#####')
populate('crypto/x509/x509type.c', config, '/////')
populate('include/openssl/evp.h', config, '/////')
populate('ssl/ssl_cert_table.h', config, '/////')

# both
populate('apps/s_cb.c', config, '/////')
populate('ssl/ssl_local.h', config, '/////')
populate('ssl/t1_lib.c', config, '/////')
populate('ssl/t1_trce.c', config, '/////')
populate('oqs-test/common.py', config, '#####')
populate('oqs-interop-test/common.py', config, '#####')

config = load_config(include_disabled_sigs=True)
populate('README.md', config, '<!---')
