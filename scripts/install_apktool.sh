#!/bin/bash

wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.12.1.jar
mv apktool_2.12.1.jar /usr/local/bin/apktool.jar

wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool
mv apktool /usr/local/bin/apktool

chmod +x /usr/local/bin/apktool
chmod +x /usr/local/bin/apktool.jar

apktool --version