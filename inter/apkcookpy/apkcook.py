#!/usr/bin/env python
#coding:utf8
'''

1、获取APK暴露组件
2、扫描反编译源码目录（动态recevier；）

'''

import argparse
from lib import apk

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Android apk tools")
    parser.add_argument("-f", dest="file", help="Path to raw AndroidManifest.xml")
    parser.add_argument("-p", dest="package", help="Path to APK")
    parser.add_argument("-t", dest="text", help="Path to plain AndroidManifest.xml")
    parser.add_argument("-a", dest="all", action='store_true', help="Print AndroidManifest.xml")

    parser.add_argument("-m", dest="monkey", type=str, help="for monkey")

    
    args = parser.parse_args()
    if args.package:
        apkcook = apk.APKCook(args.package)
        if args.all:
            apkcook.output()
        else:
            apkcook.show(args.monkey)
    elif args.file:
        apkcook = apk.APKCook(args.file, True)
        if args.all:
            apkcook.output()
        else:
            apkcook.show()
    elif args.text:
        apkcook = apk.APKCook(args.text, True, True)
        if args.all:
            apkcook.output()
        else:
            apkcook.show()
        
    else:
        parser.print_help()