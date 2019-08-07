#!/usr/bin/python3
import json
import ssl
import sys
import signal

import time
from os import path
sys.path.append(path.abspath('./CMSeeK'))


from CMSeeK.VersionDetect import detect as version_detect  # Version detection
from CMSeeK.cmseekdb import basic as cmseek  # All the basic functions
from CMSeeK.cmseekdb import sc as source  # Contains function to detect cms from source code
from CMSeeK.cmseekdb import header as header  # Contains function to detect CMS from gathered http headers
from CMSeeK.cmseekdb import cmss as cmsdb  # Contains basic info about the CMSs
from CMSeeK.cmseekdb import robots as robots
from CMSeeK.cmseekdb import generator as generator
from CMSeeK.cmseekdb import result as result

from urllib.parse import urlparse

from http.server import BaseHTTPRequestHandler, HTTPServer

def main_proc(site, cua, write):
    init_source = cmseek.getsource(site, cua)
    if init_source[0] != '1':
        cmseek.error("Aborting CMSeek! Couldn't connect to site \n    Error: %s" % init_source[1])
        res = {'cms_version': 0, 'name': 'unknown', 'url': ''}
        write(bytes(json.dumps(res), "utf-8"))
        return
    else:
        scode = init_source[1]
        headers = init_source[2]
        if site != init_source[3] and site + '/' != init_source[3]:
            site = init_source[3]
            cmseek.info("Followed redirect, New target: " + cmseek.bold + cmseek.fgreen + init_source[3] + cmseek.cln)
            cmseek.statement("Reinitiating Headers and Page Source for Analysis")
            tmp_req = cmseek.getsource(site, cua)
            scode = tmp_req[1]
            headers = tmp_req[2]
    if scode == '':
        # silly little check thought it'd come handy
        cmseek.error('Aborting detection, source code empty')
        res = {'cms_version': 0, 'name': 'unknown', 'url': ''}
        write(bytes(json.dumps(res), "utf-8"))
        return

    cmseek.statement("Detection Started")

    ## init variables
    cms = ''  # the cms id if detected
    cms_detected = '0'  # self explanotory
    detection_method = ''  # ^
    ga = '0'  # is generator available
    ga_content = ''  # Generator content

    ## Parse generator meta tag
    parse_generator = generator.parse(scode)
    ga = parse_generator[0]
    ga_content = parse_generator[1]

    cmseek.statement("Using headers to detect CMS (Stage 1 of 4)")
    header_detection = header.check(headers)

    if header_detection[0] == '1':
        detection_method = 'header'
        cms = header_detection[1]
        cms_detected = '1'

    if cms_detected == '0':
        if ga == '1':
            # cms detection via generator
            cmseek.statement("Using Generator meta tag to detect CMS (Stage 2 of 4)")
            gen_detection = generator.scan(ga_content)
            if gen_detection[0] == '1':
                detection_method = 'generator'
                cms = gen_detection[1]
                cms_detected = '1'
        else:
            cmseek.statement('Skipping stage 2 of 4: No Generator meta tag found')

    if cms_detected == '0':
        # Check cms using source code
        cmseek.statement("Using source code to detect CMS (Stage 3 of 4)")
        source_check = source.check(scode, site)
        if source_check[0] == '1':
            detection_method = 'source'
            cms = source_check[1]
            cms_detected = '1'

    if cms_detected == '0':
        # Check cms using robots.txt
        cmseek.statement("Using robots.txt to detect CMS (Stage 4 of 4)")
        robots_check = robots.check(site, cua)
        if robots_check[0] == '1':
            detection_method = 'robots'
            cms = robots_check[1]
            cms_detected = '1'

    if cms_detected == '1':
        cmseek.success(
            'CMS Detected, CMS ID: ' + cmseek.bold + cmseek.fgreen + cms + cmseek.cln + ', Detection method: ' + cmseek.bold + cmseek.lblue + detection_method + cmseek.cln)
        cmseek.update_log('detection_param', detection_method)
        cmseek.update_log('cms_id', cms)  # update log
        cmseek.statement('Getting CMS info from database')  # freaking typo
        cms_info = getattr(cmsdb, cms)
        if cms_info['vd'] == '1':
            cmseek.success('Starting version detection')
            cms_version = '0'  # Failsafe measure
            cms_version = version_detect.start(cms, site, cua, ga, scode, ga_content, init_source[2])
            result.target(site)
            result.cms(cms_info['name'], cms_version, cms_info['url'])
            cmseek.update_log('cms_name', cms_info['name'])  # update log
            if cms_version != '0' and cms_version != None:
                cmseek.update_log('cms_version', cms_version)  # update log
            cmseek.update_log('cms_url', cms_info['url'])  # update log
            comptime = round(time.time() - cmseek.cstart, 2)
            log_dir = cmseek.log_dir
            if log_dir is not "":
                log_file = log_dir + "/cms.json"
            result.end(str(cmseek.total_requests), str(comptime), log_file)
            res = {'cms_version': cms_version, 'name': cms_info['name'], 'url': cms_info['url']}

            write(bytes(json.dumps(res), "utf-8"))

            return
        else:
            # nor version detect neither DeepScan available
            result.target(site)
            result.cms(cms_info['name'], '0', cms_info['url'])
            comptime = round(time.time() - cmseek.cstart, 2)
            log_dir = cmseek.log_dir
            if log_dir is not "":
                log_file = log_dir + "/cms.json"
            result.end(str(cmseek.total_requests), str(comptime), log_file)

            res = {'cms_version': 0, 'name': cms_info['name'], 'url': cms_info['url']}
            write(bytes(json.dumps(res), "utf-8"))

            # '''
            # cmseek.result('Target: ', site)
            # cmseek.result("Detected CMS: ", cms_info['name'])
            # cmseek.update_log('cms_name', cms_info['name']) # update log
            # cmseek.result("CMS URL: ", cms_info['url'])
            # cmseek.update_log('cms_url', cms_info['url']) # update log
            # '''
            return
    else:
        print('\n')
        cmseek.error(
            'CMS Detection failed, if you know the cms please help me improve CMSeeK by reporting the cms along with the target by creating an issue')
        print('''
{2}Create issue:{3} https://github.com/Tuhinshubhra/CMSeeK/issues/new

{4}Title:{5} [SUGGESTION] CMS detction failed!
{6}Content:{7}
    - CMSeeK Version: {0}
    - Target: {1}
    - Probable CMS: <name and/or cms url>

N.B: Create issue only if you are sure, please avoid spamming!
        '''.format(cmseek.cmseek_version, site, cmseek.bold, cmseek.cln, cmseek.bold, cmseek.cln, cmseek.bold,
                   cmseek.cln))
        res = {'cms_version': 0, 'name': 'unknown', 'url': ''}
        write(bytes(json.dumps(res), "utf-8"))

        return
    return


ssl._create_default_https_context = ssl._create_unverified_context
hostName = "0.0.0.0"
hostPort = 1337


class MyServer(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        query = urlparse(self.path).query
        if query:
            query_components = dict(qc.split("=") for qc in query.split("&"))
            s = query_components["url"]
            cmseek.redirect_conf = '1'

            cua = cmseek.randomua('random')

            target = cmseek.process_url(s)

            main_proc(target, cua, self.wfile.write)
        else:
            res = {'cms_version': 0, 'name': 'unknown', 'url': ''}
            self.wfile.write(bytes(json.dumps(res), "utf-8"))

myServer = HTTPServer((hostName, hostPort), MyServer)

def signal_handler(signal, frame):
    myServer.server_close()
    print(time.asctime(), "Server Stops - %s:%s" % (hostName, hostPort))
    quit()
signal.signal(signal.SIGINT, signal_handler)

print(time.asctime(), "Server Starts - %s:%s" % (hostName, hostPort))

myServer.serve_forever()
