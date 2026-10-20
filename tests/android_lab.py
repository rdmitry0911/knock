#!/usr/bin/python3
"""Start a dedicated AVD/ADB inside `sudo unshare --net`; never alter host firewall.

ANDROID_SDK_ROOT and ANDROID_AVD_HOME must refer to an installed SDK and test AVD.
Create the AVD with a Google APIs x86_64 image containing Chrome before running.
"""
import argparse
import os
from pathlib import Path
import signal
import subprocess

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--directory',type=Path,required=True)
parser.add_argument('--avd',required=True)
args=parser.parse_args()
assert os.geteuid()==0 and os.readlink('/proc/self/ns/net')!=os.readlink('/proc/1/ns/net'),'Run in a dedicated network namespace'
sdk=Path(os.environ['ANDROID_SDK_ROOT']);work=args.directory;work.mkdir(mode=0o700,parents=True,exist_ok=True)
assert (sdk/'emulator/emulator').is_file() and (sdk/'platform-tools/adb').is_file()
for command in [['ip','link','set','lo','up'],['ip','addr','add','203.0.113.1/32','dev','lo']]:subprocess.run(command,check=True)
(work/'pid').write_text(str(os.getpid()));env={**os.environ,'ANDROID_HOME':str(sdk),'ANDROID_USER_HOME':str(work/'user')};adb=str(sdk/'platform-tools/adb')
subprocess.run([adb,'start-server'],env=env,check=True)
with (work/'emulator.log').open('w') as log:
    process=subprocess.Popen([str(sdk/'emulator/emulator'),'-avd',args.avd,'-no-window','-no-audio','-no-snapshot','-no-boot-anim','-accel','on','-gpu','swiftshader','-memory','4096','-cores','4','-port','5554','-writable-system'],env=env,stdout=log,stderr=log)
    def stop(*_):process.terminate()
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    try:process.wait()
    finally:
        if process.poll() is None:process.terminate();process.wait(timeout=15)
        subprocess.run([adb,'kill-server'],env=env)
