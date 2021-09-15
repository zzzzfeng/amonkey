#coding:utf8
'''

1、从raw AndroidManifest.xml文件或APK文件中获取暴露组件
2、从raw AndroidManifest.xml文件或APK文件中获取明文AndroidManifest.xml

'''
# 加密zip ChilkatZip

#from .axmlprinter import AXMLPrinter
from .axml import AXMLPrinter

import zipfile,json
from io import StringIO, BytesIO
from struct import pack, unpack
from xml.dom import minidom


class APKCook:
    def __init__(self, filename, single=False, text=False):
        
        self.filename = filename
        self.xml = {}
        self.package = ""
        self.androidversion = {}
        self.raw_manifest = ""

        fd = open(filename, "rb")
        self.__raw = fd.read()
        fd.close()

        if single:
            self.raw_manifest = self.__raw
        else:
            self.zip = zipfile.ZipFile(BytesIO(self.__raw))
            for i in self.zip.namelist():
                if i == "AndroidManifest.xml":
                    self.raw_manifest = self.zip.read(i)

        if text:
            self.xml = minidom.parseString(self.raw_manifest)
        else:
            self.xml = minidom.parseString(AXMLPrinter(self.raw_manifest).get_xml())

        self.package = self.xml.documentElement.getAttribute("package")
        self.androidversion["Code"] = self.xml.documentElement.getAttribute("android:versionCode")
        self.androidversion["Name"] = self.xml.documentElement.getAttribute("android:versionName")

        self.permission = self.get_permission()

    def get_package(self):
        return self.package

    def get_androidversion_code(self):
        return self.androidversion["Code"]
    
    def get_androidversion_name(self):
        return self.androidversion["Name"]

    def get_permission(self):
        out = []
        for item in self.xml.getElementsByTagName("permission"):
            name = item.getAttribute("android:name")
            pl = item.getAttribute("android:protectionLevel")
            if pl == "0x00000000" or pl == "normal":
                name += "-normal"
            elif pl == "0x00000001" or pl == "dangerous":
                name += "-dangerous"
            elif pl == "0x00000002" or pl == "signature":
                name += "-signature"
            elif pl == "0x00000003" or pl == "signatureOrSystem":
                name += "-signatureOrSystem"

            out.append(name)

        return out

    def get_element(self, tag_name, attribute):
        for item in self.xml.getElementsByTagName(tag_name):
            value = item.getAttribute(attribute)

            if len(value) > 0:
                return value
        return ""

    def get_min_sdk_version(self):
        return self.get_element("uses-sdk", "android:minSdkVersion")
    
    def get_target_sdk_version(self):
        return self.get_element("uses-sdk", "android:targetSdkVersion")

    def get_intentfilter(self, item):
        f2 = {}
        for i in item.getElementsByTagName("intent-filter"):
            c = ''
            for ii in i.getElementsByTagName("category"):
                c += ii.getAttribute("android:name")+','
            c = c.rstrip(',')
            if c:
                f2["category"] = c

            c = ''
            for ii in i.getElementsByTagName("action"):
                c += ii.getAttribute("android:name")+','
            c = c.rstrip(',')
            if c:
                f2["action"] = c

            c = ''
            for ii in i.getElementsByTagName("data"):
                c += ii.getAttribute("android:scheme")+'://'+ii.getAttribute("android:host") +'/,'
            c = c.rstrip(',')
            if c:
                f2["data"] = c
        return f2

    def checkPermission(self, p):
        for i in self.permission:
            if i.startswith(p+'-'):
                return i
        return p

    def get_activities(self):
        out = []
        for item in self.xml.getElementsByTagName("activity"):
            exported = item.getAttribute("android:exported")
            name = ""
            if exported == "true":
                name = item.getAttribute("android:name")
            elif exported != "false":
                #未设置exported属性，则检查是否有intent-filter
                if len(item.getElementsByTagName("intent-filter")) > 0:
                    name = item.getAttribute("android:name")
            
            if name != "":
                name = ">"+name
                #未开启
                if item.getAttribute("android:enabled") == "false":
                    name = "!disabled!"+name

                #要求权限
                if item.getAttribute("android:permission") != "":
                    name += ",need-permission:"+self.checkPermission(item.getAttribute("android:permission"))
                
                f2 = self.get_intentfilter(item)
                if f2:
                    name += "\n\t"+json.dumps(f2)
                out.append(name)

        for item in self.xml.getElementsByTagName("activity-alias"):
            exported = item.getAttribute("android:exported")
            name = ""
            f2 = {}
            if exported == "true":
                name = item.getAttribute("android:name")
            elif exported != "false":
                #未设置exported属性，则检查是否有intent-filter
                if len(item.getElementsByTagName("intent-filter")) > 0:
                    name = item.getAttribute("android:name")
            
            if name != "":
                name = ">"+name
                name += ',target:'+item.getAttribute("android:targetActivity")
                #未开启，代码中可以开启
                if item.getAttribute("android:enabled") == "false":
                    name = "!disabled!"+name
                #要求权限
                if item.getAttribute("android:permission") != "":
                    name += ",need-permission:"+self.checkPermission(item.getAttribute("android:permission"))
                f2 = self.get_intentfilter(item)
                if f2:
                    name += "\n\t"+json.dumps(f2)
                out.append(name)

        return out
    
    def get_services(self):
        out = []
        for item in self.xml.getElementsByTagName("service"):
            exported = item.getAttribute("android:exported")
            name = ""
            if exported == "true":
                name = item.getAttribute("android:name")
            elif exported != "false":
                #未设置exported属性，则检查是否有intent-filter
                item1 = item.getElementsByTagName("intent-filter")
                if len(item1) > 0:
                    name = item.getAttribute("android:name")
                    
            if name != "":
                name = ">"+name
                #未开启
                if item.getAttribute("android:enabled") == "false":
                    name = "!disabled!"+name

                #要求权限
                if item.getAttribute("android:permission") != "":
                    name += ",need-permission:"+self.checkPermission(item.getAttribute("android:permission"))
                f2 = self.get_intentfilter(item)
                if f2:
                    name += "\n\t"+json.dumps(f2)
                out.append(name)

        return out
    
    def get_receivers(self):
        out = []
        for item in self.xml.getElementsByTagName("receiver"):
            exported = item.getAttribute("android:exported")
            name = ""
            if exported == "true":
                name = item.getAttribute("android:name")
            elif exported != "false":
                item1 = item.getElementsByTagName("intent-filter")
                if len(item1) > 0:
                    name = item.getAttribute("android:name")
                                
            if name != "":
                name = ">"+name
                #未开启
                if item.getAttribute("android:enabled") == "false":
                    name = "!disabled!"+name

                #要求权限
                if item.getAttribute("android:permission") != "":
                    name += ",need-permission:"+self.checkPermission(item.getAttribute("android:permission"))
                f2 = self.get_intentfilter(item)
                if f2:
                    name += "\n\t"+json.dumps(f2)
                out.append(name)

        return out
    
    def get_providers(self):
        out = []
        for item in self.xml.getElementsByTagName("provider"):
            exported = item.getAttribute("android:exported")
            name = ""
            if exported == "true":
                name = item.getAttribute("android:name")
            elif exported != "false":
                item1 = item.getElementsByTagName("intent-filter")
                if len(item1) > 0:
                    name = item.getAttribute("android:name")
            elif item.getAttribute("android:grantUriPermissions") == "true":
                name = item.getAttribute("android:name")+'-grant'

            if name != "":
                name = ">"+name
                #未开启
                if item.getAttribute("android:enabled") == "false":
                    name = "!disabled!"+name

                if item.getAttribute("android:authorities") != "":
                    name += ",authorities:"+item.getAttribute("android:authorities")
                #要求权限
                if item.getAttribute("android:permission") != "":
                    name += ",need-permission:"+self.checkPermission(item.getAttribute("android:permission"))
                if item.getAttribute("android:readPermission") != "":
                    name += ",read-permission:"+self.checkPermission(item.getAttribute("android:readPermission"))
                if item.getAttribute("android:writePermission") != "":
                    name += ",write-permission:"+self.checkPermission(item.getAttribute("android:writePermission"))
                
                f2 = self.get_intentfilter(item)
                c = ''
                for m in item.getElementsByTagName("meta-data"):
                  c += m.getAttribute("android:resource")+','
                c = c.rstrip(',')
                if c:
                    f2["filepath"] = c

                if f2:
                    name += "\n\t"+json.dumps(f2)
                out.append(name)
               
        return out

    def get_comp_exposed(self, cname):
        out = []
        for item in self.xml.getElementsByTagName(cname):
            exported = item.getAttribute("android:exported")
            name = ""
            if exported == "true":
                name = item.getAttribute("android:name")
            elif exported != "false":
                item1 = item.getElementsByTagName("intent-filter")
                if len(item1) > 0:
                    name = item.getAttribute("android:name")
            if name:
              out.append(name)
            
        return out

        
    
    def get_comp_all(self, name):
        out = []
        for item in self.xml.getElementsByTagName(name):
            name = item.getAttribute("android:name")
            out.append(name)
        return out
   
    def show(self, monkey=False):
        import re
        if monkey == 'a':
            return self.get_comp_all('activity')
        elif monkey == 's':
            return self.get_comp_all('service')
        elif monkey == 'r':
            return self.get_comp_all('receiver')
        
        #browsable
        elif monkey == 'b':
            out = []
            for a in self.get_activities():
                if ' BROWSABLE' in a:
                    a = a.replace(' BROWSABLE', '')
                    a = a.replace('!activity-alias!', '')
                    a = a.replace('!disabled!', '')
                    a = re.sub('@.*', '', a)
                    out.append(a)
            return out

        elif monkey == 'v':
            #print(self.get_androidversion_name())
            return self.get_androidversion_name()
        if monkey == 'ma':
            ret = ",".join(self.get_comp_exposed('activity'))
            return ret
        elif monkey == 'ms':
            ret = ",".join(self.get_comp_exposed('service'))
            return ret
            
        elif monkey == 'mr':
            ret = ",".join(self.get_comp_exposed('receiver'))
            return ret
        else:
            print ("===exposed component===(no dynamic registerReceiver)")
            print ("Package: "+self.get_package())
            print ("VersionName: "+self.androidversion["Name"]+" VersionCode: "+self.androidversion["Code"])
            print ("Min_sdk: "+self.get_min_sdk_version()+" Target_sdk: "+self.get_target_sdk_version())
            print ("==Activity:\n"+"\n".join(self.get_activities()))
            print ("==Service:\n"+"\n".join(self.get_services()))
            print ("==Receiver:\n"+"\n".join(self.get_receivers()))
            print ("==Provider:\n"+"\n".join(self.get_providers()))
            #print ("==Permission:\n"+"\n".join(self.get_permission()))

    def output(self):
        print(AXMLPrinter(self.raw_manifest).get_xml())


if __name__ == "__main__":
    apkcook = APKCook('../../oemapp/thememanager.apk')
    apkcook.show()

    # apkcook = APKCook('AndroidManifest.xml' ,True)
    # apkcook.show()