"""CLI checks shared by disposable-VM and real-router tests.

The caller snapshots configuration before/after these read-only invocations.
"""
import json


def check_cli(run):
    for arguments in ([], ['help'], ['--help'], ['-h']):
        result=run(arguments)
        assert result.returncode==0, (arguments,result.stderr,result.stdout)
        assert 'Usage: knock-control COMMAND' in result.stdout
        assert 'help init' in result.stdout
    for arguments in (['help','init'], ['init','--help'], ['init','-h']):
        result=run(arguments)
        assert result.returncode==0, (arguments,result.stderr,result.stdout)
        assert '--public-host HOST' in result.stdout and '--interface DEVICE' in result.stdout
        assert 'router.example.com' in result.stdout
    invalid=[(['init'],'--public-host'),
             (['init','--public-host'],'requires a value'),
             (['init','--public-host','router.example.com','--unknown','value'],'--unknown'),
             (['issue'],'--name'),
             (['export','0123456789abcdef01234567'],'--out'),
             (['tls'],'--cert'),
             (['does-not-exist'],'help')]
    for arguments,expected in invalid:
        result=run(arguments)
        assert result.returncode!=0, arguments
        value=json.loads(result.stdout)
        assert value['ok'] is False and expected in value['error'], (arguments,value)
        assert 'help' in value['error'], (arguments,value)
    return 'help aliases and init usage errors work without changing configuration'
