# A Monkey
Android APP autotest tool based on uiautomator, need no root

# usage
- pip install -r requirements.txt
- python amonkey.py -p com.xiaomi.music

# how does it work?
- get all exposed component through axml from `androguard`, and start it one by one
- analyse UI: `adb shell "/system/bin/uiautomator dump /sdcard/window_dump.xml"`, use `adb shell input tap x y` to auto click