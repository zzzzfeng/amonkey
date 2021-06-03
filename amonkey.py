#coding: utf-8

import subprocess, sys, os
import threading, time, datetime
import logging, argparse
import shutil
from inter.apkcookpy.lib.apk import APKCook
import xml.etree.ElementTree as ET

logging.basicConfig(level = logging.INFO, format='%(asctime)s - %(levelname)s [%(filename)s:%(lineno)d]: %(message)s')


def execShellDaemon(cmd):
    '''
    async
    '''
    return subprocess.Popen(cmd, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

def execShell(cmd, t=120):
    '''
    sync
    haskey('d') == success, only cmd success, should check output
    '''
    ret = {}
    try:
        p = subprocess.run(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=True, timeout=t)
        
        if p.returncode == 0:
            try:
                ret['d'] = p.stdout.decode('utf-8')
            except:
                ret['d'] = p.stdout.decode('gbk')
        else:
            try:
                ret['e'] = p.stderr.decode('utf-8')
            except:
                ret['e'] = p.stderr.decode('gbk')
            
    except subprocess.TimeoutExpired:
        ret['e'] = 'timeout'
    except Exception as e:
        logging.error('subprocess '+str(e))

    return ret

def getPkgList(pkg):
    if os.path.isfile(pkg):
        try:
            with open(pkg, 'r') as f:
                pkgs = f.read().split('\n')
        except Exception as e:
            #logging.info(str(e))
            return []
    elif pkg:
        pkgs = pkg.split(',')
    out = []
    for p in pkgs:
        if p:
            out.append(p.strip())
    return out

def getChildNode(node):
    out = []
    if node.get('clickable') == 'true' or node.get('long-clickable') == 'true' or node.get('scrollable') == 'true' or (node.get('class') and node.get('class').startswith('android.widget.EditText')):
        out.append(node.attrib)
    
    if list(node):
        for child in node:
            out += getChildNode(child)

    return out
        
def parseUIDump(dumpfile):
    tree = ET.parse(dumpfile)
    root = tree.getroot()
    
    return getChildNode(root)


class AMonkey(object):
    def __init__(self, did):
        self._adb = 'adb'
        self._frida = 'frida -U '
        self._did = did
        self._devicepkg = []
        self._curdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '')
        self._dirapps = os.path.join(self._curdir, 'apps', '')
        self._dirappstmp = os.path.join(self._dirapps, 'tmp', '')
        self._dirinter = os.path.join(self._curdir, 'inter', '')
        self._androidver = ''
        self._blacklist = [
            'com.android.settings',
            'com.topjohnwu.magisk',
            'com.speedsoftware.rootexplorer',
            'org.proxydroid',
            'android'
        ]

        self._init()
    
    def _init(self):
        if not self.checkOnline(self._did):
            sys.exit()
        if self._did:
            self._adb = 'adb -s '+self._did+' '
        self._devicepkg = self.getDevicePkgs()
        try:
            os.mkdir(self._dirapps)
        except:
            pass
        try:
            os.mkdir(self._dirappstmp)
        except:
            pass

        cmd = self._adb + ' shell  "mkdir /sdcard/monkeylogs"'
        ret = execShell(cmd)
        cmd = self._adb + ' shell  "mkdir /sdcard/monkeyxmls"'
        ret = execShell(cmd)

    def checkOnline(self, deviceid=''):
        devices = execShell('adb devices -l').get('d').split('\n')
        ret = [d for d in devices if d.find('device ') != -1]
        dids = [d.split()[0] for d in ret]
        if deviceid:
            if deviceid in dids:
                return True
            else:
                logging.error('Device id error')
                logging.error(execShell('adb devices -l').get('d'))
                return False
        else:
            if len(dids) == 0:
                logging.error('No device')
                return False
            elif len(dids) == 1:
                return True
            elif len(dids) > 1:
                logging.error('More than one device, please set -s deviceid')
                return False

    def timeoutKIll(self, pkg, t):
        for i in range(t):
            time.sleep(1)
        cmd = self._adb + ' shell "am force-stop '+pkg+' " '
        execShell(cmd)

    def getDevicePkgs(self):
        ret = execShell(self._adb + ' shell pm list packages')
        pkgs = []
        if 'e' not in ret.keys():
            dt = ret.get('d').split('\n')
            for p in dt:
                p = p.strip()
                if p:
                    pkgs.append(p.split(':')[1])
        else:
            logging.error(ret.get('e'))
        return pkgs
    
    def pullXml(self, p):
        logging.info('==pull xml')

        if not self.setupBusybox():
            logging.error('busybox error')
            return

        sp = self._dirapps+p
        cmd = self._adb + ' shell "pm path '+p+'"'
        ret = execShell(cmd)
        if 'd' in ret.keys() and ret.get('d'):
            # multiple returns?
            apkpath = ret.get('d').split('\n')[0].split(':')[1]
            cmd = self._adb + ' shell  "/data/local/tmp/busybox unzip -p '+apkpath+' AndroidManifest.xml > /sdcard/monkeyxmls/'+p+'"'
            ret = execShell(cmd)

            cmd = self._adb + ' shell ls  /sdcard/monkeyxmls/'+p
            ret = execShell(cmd)
            if 'No such file' in str(ret) :
                logging.error('xml unzip error')
                return
                
            cmd = self._adb + ' pull /sdcard/monkeyxmls/'+p+' '+sp
            ret = execShell(cmd)
            if 'd' in ret.keys():
                shutil.move(sp, sp+'.xml')
                return sp+'.xml'
            else:
                logging.error('pull error'+ret.get('e')+apkpath)
        else:
            logging.error('device has no '+p)
        
    def setupBusybox(self):
        cmd = self._adb + ' shell ls  /data/local/tmp/busybox'
        ret = execShell(cmd)
            
        if 'No such file' in str(ret) :
            busybox = self._dirinter+'busybox'
            if not os.path.isfile(busybox):
                logging.error('please put busybox in dir "inter")')
                return False
            cmd = self._adb + ' push '+busybox+' /data/local/tmp/busybox'
            ret = execShell(cmd)
            if 'd' in ret.keys():
                logging.info('push busybox success')
                cmd = cmd = self._adb + ' shell "chmod +x /data/local/tmp/busybox" '
                ret = execShell(cmd)
                return True
            else:
                return False
        return True

    def killMonkey(self):
        logging.info('Clean monkey')
        cmd = self._adb + ' shell "ps -A | grep com.android.commands.monkey" '
        ret = execShell(cmd)
        if 'd' in ret.keys():
            data = ret.get('d').split('\n')
            for d in data:
                tmp = d.split()
                if len(tmp) == 9 and tmp[8] == 'com.android.commands.monkey':
                    cmd = self._adb + ' shell "su -c \' kill -9 '+tmp[1]+'\' "'
                    ret = execShell(cmd)
                    if 'e' in ret.keys():
                        logging.info(ret.get('e'))

        logging.info('Clean monkey done')

    def getCurActivity(self):
        cmd = self._adb + ' shell  "dumpsys activity top | grep ACTIVITY "'
        ret = execShell(cmd)
        out = ret.get('d')
        if out:
            out = out.split('\n')
            out = out[-2]
            out = out.split()[1]
            ret = out
            if '/.' in out:
                ret = ret.replace('/', '')
            else:
                ret = ret.split('/')[1].strip()

            return ret

    def UIClick(self, p, a):
        if p not in self.getCurActivity():
            return
        cmd = self._adb + ' shell  "/system/bin/uiautomator dump /sdcard/window_dump.xml "'
        ret = execShell(cmd)
        curdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '')
        dumpfile = curdir+'/apps/tmp/uidump.xml'
        cmd = self._adb + ' pull /sdcard/window_dump.xml '+dumpfile
        ret = execShell(cmd)

        clicks = parseUIDump(dumpfile)
        
        for c in clicks:
            if p not in self.getCurActivity():
                break
            if c.get('class') and c.get('class').startswith('android.widget.EditText'):
                xy = c.get('bounds')
                xy = xy.split('][')[0]
                xy = xy.lstrip('[')
                x,y = xy.split(',')
                x = int(x) + 3
                y = int(y) + 3
                cmd = self._adb + ' shell "input tap {} {}"'.format(x, y)
                ret = execShell(cmd)
                cmd = self._adb + ' shell "input text tex{}{}"'.format(x, y)
                ret = execShell(cmd)
                logging.info('input '+c.get('resource-id'))
                
            elif c.get('clickable') == 'true':
                xy = c.get('bounds')
                xy = xy.split('][')[0]
                xy = xy.lstrip('[')
                x,y = xy.split(',')
                x = int(x) + 3
                y = int(y) + 3
                logging.info('click ({},{}) {}'.format(x, y, c.get('resource-id')))
                cmd = self._adb + ' shell "input tap {} {}"'.format(x, y)
                ret = execShell(cmd)
                time.sleep(1)
                if a not in self.getCurActivity():
                    cmd = self._adb + ' shell "input keyevent 4"'
                    ret = execShell(cmd)

        return clicks


    def monkey(self, pkg):
        pkgs = getPkgList(pkg)
        
        for p in pkgs:
            if p in self._blacklist:
                continue
            if p not in self._devicepkg:
                logging.error(p+' not installed')
                continue
            #检查设备在线
            if not self.checkOnline(self._did):
                logging.error('Device offline')
                return
            
            logging.info('=='+p)
                
            try:
                #准备apk文件
                sp = self._dirapps+p
                if os.path.isfile(sp+'.xml') and os.stat(sp+'.xml').st_size > 0:
                    apkcook = APKCook(sp+'.xml', True)
                else:
                    xmlpath = self.pullXml(p)
                    if xmlpath:
                        apkcook = APKCook(xmlpath, True)
                    else:
                        logging.error('xml error'+p)
                        return
                    
                activity = apkcook.show('ma').split(',')
                if len(activity) < 2:
                    logging.info('maybe encrypted')

                #timeout kill
                timeout = 220
                timeoutThread = threading.Thread(target=self.timeoutKIll, args=(p, timeout), daemon=True)
                timeoutThread.start()

                cmd = self._adb + ' shell  "rm /sdcard/monkeylogs/'+p+'.log"'
                ret = execShell(cmd)

                cmd = self._adb + ' shell  "logcat -c"'
                ret = execShell(cmd)
                
                cmd = self._adb + ' shell  "logcat > /sdcard/monkeylogs/'+p+'.log.log"'
                logcatdameon = execShellDaemon(cmd)

                UIcomponent = []

                for a in activity:
                    if not a:
                        continue
                    logging.info(a)
                    cmd = self._adb + ' shell "am start -n '+p+'/'+a+'"'
                    #timeout not working, because connected to pipe??
                    execShell(cmd)

                    #monkey click
                    # cmd = self._adb + ' shell "monkey -p '+p+' -vvv  --throttle 100 --pct-syskeys 0  --ignore-crashes 133 >> /sdcard/monkeylogs/'+p+'.log " '
                    # execShell(cmd, 40)

                    #uiautomator dump
                    time.sleep(1)
                    self.UIClick(p, a)

                    if not timeoutThread.is_alive():
                        timeoutThread = threading.Thread(target=self.timeoutKIll, args=(p, timeout), daemon=True)
                        timeoutThread.start()

                service = apkcook.show('ms').split(',')
                for s in service:
                    if not s:
                        continue
                    logging.info(s)
                    cmd = self._adb + ' shell "am start-service  '+p+'/'+s+' " '
                    execShell(cmd, 40)
                    time.sleep(1)

                receiver = apkcook.show('mr').split(',')
                for s in receiver:
                    if not s:
                        continue
                    logging.info(s)
                    cmd = self._adb + ' shell "am broadcast  '+p+'/'+s+' " '
                    execShell(cmd, 40)
                    time.sleep(1)

                if logcatdameon.poll():
                    logcatdameon.terminate()

                
            except KeyboardInterrupt:
                cmd = self._adb + ' shell "am force-stop '+p+' " '
                ret = execShell(cmd)
                raise KeyboardInterrupt

            except Exception as e:
                import traceback
                traceback.print_exc()
                logging.error(str(e))

            cmd = self._adb + ' shell "am force-stop '+p+' " '
            ret = execShell(cmd)
            
            time.sleep(0.2)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Android Monkey', formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog='''
    python3 amonkey.py -p com.xiaomi.music
    python3 amonkey.py -P plist.txt
    ''')
    parser.add_argument("-p", "--pkg", type=str, help="single app")
    parser.add_argument("-P", "--plist", type=str, help="multiple apps")
    parser.add_argument("-s", "--did", type=str, help="device ID")

    if sys.version_info < (3, 7):
        logging.error('Run with python3.7+')
        sys.exit()
    
    args = parser.parse_args()
    pkg = args.pkg
    plist = args.plist
    did = args.did

    # parseUIDump('dump_2147992889569360909.uix')
    # sys.exit()

    try:
        if pkg:
            amonkey = AMonkey(did)
            amonkey.monkey(pkg)
        
        elif plist:
            amonkey = AMonkey(did)
            amonkey.monkey(plist)

        else:
            parser.print_help()
    except KeyboardInterrupt:
        logging.info('Ctrl+C')
