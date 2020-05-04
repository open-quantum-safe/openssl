import os
import subprocess
from pathlib import Path

def run_subprocess(command, working_dir='.', expected_returncode=0, input=None):
    """
    Helper function to run a shell command and report success/failure
    depending on the exit status of the shell command.
    """

    # Note we need to capture stdout/stderr from the subprocess,
    # then print it, which pytest will then capture and
    # buffer appropriately
    print(working_dir + " > " + " ".join(command))
    result = subprocess.run(
        command,
        input=input,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=working_dir,
    )
    if result.returncode != expected_returncode:
        print(result.stdout.decode('utf-8'))
        assert False, "Got unexpected return code {}".format(result.returncode)
    return result.stdout.decode('utf-8')

def gen_keys(ossl, ossl_config, sig_alg, test_artifacts_dir):
    Path(test_artifacts_dir).mkdir(parents=True, exist_ok=True)
    run_subprocess([ossl, 'req', '-x509', '-new',
                                 '-newkey', sig_alg,
                                 '-keyout', os.path.join(test_artifacts_dir, '{}_CA.key'.format(sig_alg)),
                                 '-out', os.path.join(test_artifacts_dir, '{}_CA.crt'.format(sig_alg)),
                                 '-nodes',
                                     '-subj', '/CN=oqstest_CA',
                                     '-days', '365',
                                 '-config', ossl_config])
    run_subprocess([ossl, 'req', '-new',
                          '-newkey', sig_alg,
                          '-keyout', os.path.join(test_artifacts_dir, '{}_srv.key'.format(sig_alg)),
                          '-out', os.path.join(test_artifacts_dir, '{}_srv.csr'.format(sig_alg)),
                          '-nodes',
                              '-subj', '/CN=oqstest_server',
                          '-config', ossl_config])
    run_subprocess([ossl, 'x509', '-req',
                                  '-in', os.path.join(test_artifacts_dir, '{}_srv.csr'.format(sig_alg)),
                                  '-out', os.path.join(test_artifacts_dir, '{}_srv.crt'.format(sig_alg)),
                                  '-CA', os.path.join(test_artifacts_dir, '{}_CA.crt'.format(sig_alg)),
                                  '-CAkey', os.path.join(test_artifacts_dir, '{}_CA.key'.format(sig_alg)),
                                  '-CAcreateserial',
                                  '-days', '365'])
