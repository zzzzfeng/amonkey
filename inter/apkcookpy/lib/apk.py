#coding:utf8
'''

1、从raw AndroidManifest.xml文件或APK文件中获取暴露组件
2、从raw AndroidManifest.xml文件或APK文件中获取明文AndroidManifest.xml

'''
# 加密zip ChilkatZip

#from .axmlprinter import AXMLPrinter
from .axml import AXMLPrinter

import zipfile
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

        return out;

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
            
            #未开启
            if item.getAttribute("android:enabled") == "false":
                if name != "":
                    name = "!disabled!"+name

            #要求权限
            if item.getAttribute("android:permission") != "":
                if name != "":
                    name += "@"+item.getAttribute("android:permission")
            
            #可否从浏览器启动
            browsable = False
            for item1 in item.getElementsByTagName("intent-filter"):
                for item2 in item1.getElementsByTagName("category"):
                    if item2.getAttribute("android:name") == "android.intent.category.BROWSABLE":
                        browsable = True
                        
            if name != "":
                if browsable:
                    name += ' BROWSABLE'
                out.append(name)

        for item in self.xml.getElementsByTagName("activity-alias"):
            exported = item.getAttribute("android:exported")
            name = "!activity-alias!"
            if exported == "true":
                name += item.getAttribute("android:name")
            elif exported != "false":
                #未设置exported属性，则检查是否有intent-filter
                if len(item.getElementsByTagName("intent-filter")) > 0:
                    name += item.getAttribute("android:name")
            
            #未开启
            if item.getAttribute("android:enabled") == "false":
                if name != "":
                    name = "!disabled!"+name

            #要求权限
            if item.getAttribute("android:permission") != "":
                if name != "":
                    name += "@"+item.getAttribute("android:permission")
            
            #可否从浏览器启动
            browsable = False
            for item1 in item.getElementsByTagName("intent-filter"):
                for item2 in item1.getElementsByTagName("category"):
                    if item2.getAttribute("android:name") == "android.intent.category.BROWSABLE":
                        browsable = True

            if name != "!activity-alias!":
                if browsable:
                    name += ' BROWSABLE'
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
                if len(item.getElementsByTagName("intent-filter")) > 0:
                    name = item.getAttribute("android:name")
            
            #未开启
            if item.getAttribute("android:enabled") == "false":
                if name != "":
                    name = "!disabled!"+name

            #要求权限
            if item.getAttribute("android:permission") != "":
                if name != "":
                    name += "@"+item.getAttribute("android:permission")
            
            if name != "":
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
                #未设置exported属性，则检查是否有intent-filter
                if len(item.getElementsByTagName("intent-filter")) > 0:
                    name = item.getAttribute("android:name")
            
            #未开启
            if item.getAttribute("android:enabled") == "false":
                if name != "":
                    name = "!disabled!"+name

            #要求权限
            if item.getAttribute("android:permission") != "":
                if name != "":
                    name += "@"+item.getAttribute("android:permission")
            
            if name != "":
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
                #未设置exported属性，则检查是否有intent-filter
                if len(item.getElementsByTagName("intent-filter")) > 0:
                    name = item.getAttribute("android:name")
            #####新增####临时访问权限
            elif item.getAttribute("android:grantUriPermissions") == "true":
                name = item.getAttribute("android:name")+'-grant'
            
            #未开启
            if item.getAttribute("android:enabled") == "false":
                if name != "":
                    name = "!disabled!"+name

            #要求权限
            if item.getAttribute("android:permission") != "":
                if name != "":
                    name += "@"+item.getAttribute("android:permission")
            if item.getAttribute("android:readPermission") != "":
                if name != "":
                    name += "@"+item.getAttribute("android:readPermission")
            if item.getAttribute("android:writePermission") != "":
                if name != "":
                    name += "@"+item.getAttribute("android:writePermission")
            
            if name != "":
                out.append(name)
                
        return out
    
    def get_activities_all(self):
        out = []
        for item in self.xml.getElementsByTagName("activity"):
            name = item.getAttribute("android:name")
            out.append(name)

        return out
    
    def get_services_all(self):
        out = []
        for item in self.xml.getElementsByTagName("service"):
            name = item.getAttribute("android:name")
            out.append(name)

        return out
    
    def get_receivers_all(self):
        out = []
        for item in self.xml.getElementsByTagName("receiver"):
            name = item.getAttribute("android:name")
            out.append(name)

        return out
    
    
    def show(self, monkey=False):
        import re
        if monkey == 'a':
            return self.get_activities_all()
        elif monkey == 's':
            return self.get_services_all()
        elif monkey == 'r':
            return self.get_receivers_all()
        
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
            ret = ",".join(self.get_activities())
            ret = ret.replace(' BROWSABLE', '')
            ret = ret.replace('!activity-alias!', '')
            ret = ret.replace('!disabled!', '')
            ret += ','
            ret = re.sub('@.*?,', ',', ret)
            #print(ret.strip(','))
            return ret.strip(',')
        elif monkey == 'ms':
            ret = ",".join(self.get_services())
            ret = ret.replace('!disabled!', '')
            ret += ','
            ret = re.sub('@.*?,', ',', ret)
            #print(ret.strip(','))
            return ret.strip(',')
        elif monkey == 'mr':
            ret = ",".join(self.get_receivers())
            ret = ret.replace('!disabled!', '')
            ret += ','
            ret = re.sub('@.*?,', ',', ret)
            #print(ret.strip(','))
            return ret.strip(',')
        else:
            print ("===暴露组件===(注意调用权限，动态registerReceiver未检测)")
            print ("Package: "+self.get_package())
            print ("VersionName: "+self.androidversion["Name"]+" VersionCode: "+self.androidversion["Code"])
            print ("Min_sdk: "+self.get_min_sdk_version()+" Target_sdk: "+self.get_target_sdk_version())
            print ("==Activity:\n"+"\n".join(self.get_activities()))
            print ("==Service:\n"+"\n".join(self.get_services()))
            print ("==Receive:\n"+"\n".join(self.get_receivers()))
            print ("==Provider:\n"+"\n".join(self.get_providers()))
            print ("==Permission:\n"+"\n".join(self.get_permission()))

    def output(self):
        print(AXMLPrinter(self.raw_manifest).get_xml())


if __name__ == "__main__":
    apkcook = APKCook('../../oemapp/thememanager.apk')
    apkcook.show()

    # apkcook = APKCook('AndroidManifest.xml' ,True)
    # apkcook.show()