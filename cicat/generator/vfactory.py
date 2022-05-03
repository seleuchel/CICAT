# -*- coding: utf-8 -*-
"""
::::::::::::::::::::::::  Critical Infrastructure Cyberspace Analysis Tool (CICAT)  :::::::::::::::::::::::::::::::::::::::

                                            NOTICE
                                            
The contents of this material reflect the views of the author and/or the Director of the Center for Advanced Aviation 
System Development (CAASD), and do not necessarily reflect the views of the Federal Aviation Administration (FAA) 
or the Department of Transportation (DOT). Neither the FAA nor the DOT makes any warranty or guarantee, or promise, 
expressed or implied, concerning the content or accuracy of the views expressed herein. 

This is the copyright work of The MITRE Corporation and was produced for the U.S. Government under Contract Number 
DTFAWA-10-C-00080 and is subject to Federal Aviation Administration Acquisition Management System Clause 3.5-13, 
Rights in Data-General, Alt. III and Alt. IV (Oct. 1996). No other use other than that granted to the U.S. Government, 
or to those acting on behalf of the U.S. Government, under that Clause is authorized without the express written permission 
of The MITRE Corporation. For further information, please contact The MITRE Corporation, Contract Office, 7515 Colshire Drive, 
McLean, VA 22102 (703) 983-6000. ©2020 The MITRE Corporation. 

The Government retains a nonexclusive, royalty-free right to publish or reproduce this document, or to allow others to do so, for 
“Government Purposes Only.”                                           
                                            
(c) 2020 The MITRE Corporation. All Rights Reserved.

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
vfactory.py - SAX parser for importing CVE XML file data
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
"""


import datetime
import xml.sax
import collections
import re
import json

from tmodel import VULNERABILITY, CPE

m_CVElist = collections.defaultdict(list)

'''
[xml] mitre CVEs
class CVEHandler (xml.sax.ContentHandler):
    def __init__(self):
        self.CurrentData = ""
        self.currCVE = ""
        self.skipflag = False
        
    def startElement(self, tag, attributes):
        self.CurrentData = tag
        if tag == "Vulnerability":
            self.currCVE = VULNERABILITY(attributes["c"])
        elif (( tag == "Note") and (attributes["Type"] == "Other")):
            self.skipflag = True
            
    def endElement(self, tag):
        if tag == "Vulnerability":
            m_CVElist[self.currCVE.getTitle()] = self.currCVE
        elif ((tag == "Note") and self.skipflag ):
            self.skipflag = False
            
    def characters(self, content):
      if self.currCVE == '':
          return
      elif self.CurrentData == "Title":
          if self.currCVE.getTitle() == '':
             self.currCVE.setTitle (content)
      elif ((self.CurrentData == "Note") and not(self.skipflag)):
          self.currCVE.setDescription(content )
      elif self.CurrentData == "URL":
          if (content.find('http') >= 0):
             self.currCVE.addReference (content )
'''
# 22.04.21 : CVE parser : need refactoring
def cves_parser(file):
    f = open(file, 'rb')
    cves_raw = json.loads(f.read())['CVE_Items']
    f.close()

    for cve_raw in cves_raw:
        # set vul
        vul = VULNERABILITY()
        title = cve_raw['cve']['CVE_data_meta']['ID']
        vul.setTitle(title) # cve-xxxx-xxxx
        vul.setDescription(cve_raw['cve']['description']['description_data'][0]['value'])
        for rf in cve_raw['cve']['references']['reference_data']:
            vul.addReference(rf)

        # check cvss v3
        try: # key error
            if cve_raw['impact'] : # impact is
                vul.setCvssv3(float(cve_raw['impact']['baseMetricV3']['cvssV3']['baseScore']))
                vul.setHascvss = True
        except KeyError:
                pass # print("no cvssv3")

        # check cpe
        try: # key error
            if cve_raw['configurations']['nodes'] : # impact is
                for cpeinfo in cve_raw['configurations']['nodes']:
                    cpe_match = cpeinfo['cpe_match']
                    cpe_children = cpeinfo['children']
                    print(title)
                    if cpe_match:
                        for cpe in cpe_match:
                            setCPEversions(cpe, vul) # set 4 versions
                            '''
                            cpeid = cpe['cpe23Uri']
                            cpestart_inversion = ""
                            cpestart_exversion = ""
                            cpeend_inversion = ""
                            cpeend_exversion = ""

                            if 'versionStartIncluding' in cpe.keys():
                                cpestart_inversion = cpe['versionStartIncluding']

                            if 'versionStartExcluding' in cpe.keys():
                                cpestart_exversion = cpe['versionStartExcluding']

                            if 'versionEndIncluding' in cpe.keys():
                                cpeend_inversion = cpe['versionEndIncluding']

                            if 'versionEndExcluding' in cpe.keys():
                                cpeend_exversion = cpe['versionEndExcluding']

                            print(cpeid, ",", cpestart_inversion, ",", cpestart_exversion, ",", cpeend_inversion, ",",
                                  cpeend_exversion)
                            vul.appendCpe(
                                CPE(cpeid, cpestart_inversion, cpestart_exversion, cpeend_inversion, cpeend_exversion))
                            '''
                    if cpe_children:
                        for c in cpe_children:
                            clist = c['cpe_match']
                            if clist:
                                for cpe in clist:
                                    setCPEversions(cpe, vul) # set 4 versions
                                    '''
                                    cpeid = cpe['cpe23Uri']

                                    # check 4 version
                                    cpestart_inversion = ""
                                    cpestart_exversion = ""
                                    cpeend_inversion = ""
                                    cpeend_exversion = ""

                                    if 'versionStartIncluding' in cpe.keys():
                                        cpestart_inversion = cpe['versionStartIncluding']

                                    if 'versionStartExcluding' in cpe.keys():
                                        print("it has startversion", cpe['versionStartExcluding']) # great
                                        cpestart_exversion = cpe['versionStartExcluding']

                                    if 'versionEndIncluding' in cpe.keys():
                                        print("it has endversion", cpe['versionEndIncluding']) # great
                                        cpeend_inversion = cpe['versionEndIncluding']

                                    if 'versionEndExcluding' in cpe.keys():
                                        print("it has endversion", cpe['versionEndExcluding']) # great
                                        cpeend_exversion = cpe['versionEndExcluding']

                                    print(cpeid, ",", cpestart_inversion, ",", cpestart_exversion,",", cpeend_inversion,  ",", cpeend_exversion)
                                    vul.appendCpe(CPE(cpeid, cpestart_inversion, cpestart_exversion,cpeend_inversion,  cpeend_exversion))
                                    '''
                    vul.setHascpe = True
        except KeyError:
                print("no cpe")

        vul.setPublishedDate(cve_raw['publishedDate'])
        vul.setLastModifiedDate(cve_raw['lastModifiedDate'])


        m_CVElist[title] = vul # m_CVElist["cve-1111-2222"] = cve-1111-2222 vul obj
# 22.04.15 : end edit here

# need for refactoring
def setCPEversions(cpe, vul):
    cpeid = cpe['cpe23Uri']

    cpestart_inversion = ""
    cpestart_exversion = ""
    cpeend_inversion = ""
    cpeend_exversion = ""

    if 'versionStartIncluding' in cpe.keys():
        cpestart_inversion = cpe['versionStartIncluding']

    if 'versionStartExcluding' in cpe.keys():
        cpestart_exversion = cpe['versionStartExcluding']

    if 'versionEndIncluding' in cpe.keys():
        cpeend_inversion = cpe['versionEndIncluding']

    if 'versionEndExcluding' in cpe.keys():
        cpeend_exversion = cpe['versionEndExcluding']

    # DBG
    print(cpeid, ",", cpestart_inversion, ",", cpestart_exversion, ",", cpeend_inversion, ",",
          cpeend_exversion)
    vul.appendCpe(
        CPE(cpeid, cpestart_inversion, cpestart_exversion, cpeend_inversion, cpeend_exversion))

# 22.04.15 : need refactoring
def findCVEs(pattern): # only cpe obj
    ret = []
    for k in m_CVElist: # all cve
        vcpes = m_CVElist.get(k).getCpes()
        # first check id
        vcpeids = [i.getCPE() for i in vcpes]
        if pattern.getCPE() in vcpeids:
            ret.append(k)
        # second : version high / low * * * * *

        for vcpe in vcpes:
            cp = pattern.getCPE().split(":")[:5]
            cp.append("*")
            cv = vcpe.getCPE().split(":")[:6]

            if cv == cp:
                print(cp)
                # check version
                # check = False
                vcpestartver = vcpe.getStartIncluding() or vcpe.getStartExcluding()
                vcpeendver = vcpe.getEndIncluding() or vcpe.getEndExcluding()
                print("gentler  : ", vcpestartver,"~", vcpeendver )
                patternver = pattern.getCPE().split(":")[5]
                print("Real pattern ver : ", patternver)

                if patternver == "*" : # or patternver == "-" # <- need to set
                    ret.append(k)# check = True
                    print("OK** ", pattern.getCPE(), "with ", vcpe.getCPE(), " version ", patternver, "start ",
                          vcpestartver, "end ", vcpeendver)
                    break

                if vcpestartver and vcpeendver:
                    p_= len(patternver.split(".")[0])
                    s_ = len(vcpestartver.split(".")[0])
                    e_ = len(vcpeendver.split(".")[0])
                    if s_ < p_ or s_ < e_:
                        vcpestartver = "0" + vcpestartver
                    if p_ < s_ or p_ < e_:
                        patternver = "0" + patternver
                    if e_ < s_ or e_ < p_:
                        vcpeendver = "0" + vcpeendver

                    if patternver >= vcpestartver and patternver <= vcpeendver:
                        # check = True
                        ret.append(k)
                        print("OK** ", pattern.getCPE(), "with ", vcpe.getCPE(), " version ", patternver, "start ",
                              vcpestartver, "end ", vcpeendver)
                        break

                if vcpestartver and not vcpeendver :
                    p_= len(patternver.split(".")[0])
                    s_ = len(vcpestartver.split(".")[0])
                    if p_ < s_:
                        patternver = "0" + patternver
                    if s_ < p_:
                        vcpestartver = "0" + vcpestartver

                    if patternver >= vcpestartver:
                        #check = True
                        ret.append(k)
                        print("OK** ", pattern.getCPE(), "with ", vcpe.getCPE(), " version ", patternver, "start ",
                              vcpestartver, "end ", vcpeendver)
                        break

                if not vcpestartver and vcpeendver:
                    p_= len(patternver.split(".")[0])
                    e_ = len(vcpeendver.split(".")[0])
                    if p_ < e_:
                        patternver = "0" + patternver
                    if e_ < p_:
                        vcpeendver = "0" + vcpeendver

                    if patternver <= vcpeendver:
                        #check = True
                        ret.append(k)
                        print("OK** ", pattern.getCPE(), "with ", vcpe.getCPE(), " version ", patternver, "start ",
                              vcpestartver, "end ", vcpeendver)
                        break

    '''
    p = re.compile(pattern, re.IGNORECASE)
    for j in m_CVElist:
        entry = m_CVElist.get(j)
        if p.search(entry.getDescription().casefold() ):
            ret.append(j)
    '''
    print("RET : ", ret)
    return list(set(ret))

# parseCVEs
def parseCVEs(file):
    f = open(file, 'rb')
    cves_raw = json.loads(f.read())['CVE_Items']
    f.close()

    for cve_raw in cves_raw:
        # set vul
        vul = VULNERABILITY()
        title = cve_raw['cve']['CVE_data_meta']['ID']
        vul.setTitle(title) # cve-xxxx-xxxx
        vul.setDescription(cve_raw['cve']['description']['description_data'][0]['value'])
        for rf in cve_raw['cve']['references']['reference_data']:
            vul.addReference(rf)

        # check cvss v3
        try: # key error
            if cve_raw['impact'] : # impact is
                vul.setCvssv3(float(cve_raw['impact']['baseMetricV3']['cvssV3']['baseScore']))
                vul.setHascvss = True
        except KeyError:
                print("no cvssv3")

        # check cpe
        try: # key error
            if cve_raw['configurations']['nodes'] : # impact is
                for cpeinfo in cve_raw['configurations']['nodes']:
                    cpe_match = cpeinfo['cpe_match']
                    cpe_children = cpeinfo['children']
                    if cpe_match:
                        for cpe in cpe_match:
                            vul.appendCpe(cpe['cpe23Uri'])
                    if cpe_children:
                        for c in cpe_children:
                            clist = c['cpe_match']
                            if clist:
                                for cpe in clist:
                                    vul.appendCpe(cpe['cpe23Uri'])
                    vul.setHascpe = True
        except KeyError:
                print("no cpe")

        vul.setPublishedDate(cve_raw['publishedDate'])
        vul.setLastModifiedDate(cve_raw['lastModifiedDate'])

        m_CVElist[title] = vul

# edit 22.04.18
def CVEsetbyCpes(cpes): # cpe objs
    ret = set()
    for cpe in cpes: # cpe objs
        cvelist = findCVEs(cpe)
        ret.update(cvelist)
    return ret

def CVEsetbyVendor(vendor):
    ret = set()
    vlst = findCVEs(vendor)
    for v in vlst:
        ret.add(v)  
    return ret

def CVEsetbyType (eqtype):
    ret = set()
    vlst = findCVEs(eqtype)
    for v in vlst:
        ret.add (v)
    return ret

def CVEsetbyModel (modelinfo):
    ret = set()
    vlst = findCVEs(modelinfo)
    for v in vlst:
        ret.add(v)
    return ret


def showCVE(name):
    m_CVElist[name].PP()

# Recent vul facory
class RECENT_VULNERABILITY_FACTORY():
    def __init__ (self,trace):
        self.recentcvefilelist = []
        self.recentcvelist = []
        self.startdate = "" # datetime.datetime
        self.enddate = "" # datetime.datetime
        self.trace = trace

    def load(self, recentcvefilelist):
        self.recentcvefilelist = recentcvefilelist

        if self.trace:
            print('Loading Recent CVE data..')

        # set start / end time
        _ = self.recentcvefilelist[0].split("_")
        st = _[3]
        et = _[4].split(".")[0]
        self.startdate = datetime.datetime(int(st[:4]),int(st[4:6]),int(st[6:]))
        self.enddate = datetime.datetime(int(et[:4]),int(et[4:6]),int(et[6:]))

        for file in self.recentcvefilelist:  # json
            if self.trace:
                print("Loading Recent file:", file)
            f = open(file, 'rt')
            self.recentcvelist = self.recentcvelist + f.read().split("\n")
            f.close()
        print("[DBG] count of recent cve")
        print(" real? : ", len(self.recentcvelist))
        self.recentcvelist = set(self.recentcvelist)
        print(" real set! : ", len(set(self.recentcvelist)))
        return self.recentcvelist,self.startdate, self.enddate

class VULNERABILIY_FACTORY(): 
    def __init__ (self, trace):
       self.filelist = []
       self.startdate = ""
       self.enddate = ""

       self.trace = trace
       if self.trace:
           print ('VULNERABILITY factory constructed..')

    # change VulDB to json of NVD
    def load(self, filelist, recentcvelist, ctypelist, startdate, enddate):
           # basic : H:\\0000_CICATEDIT\\CICAT\\cicat\\data\\CVE\\cve2000.xml
           # now : ~.json
           self.filelist = filelist
           self.startdate = startdate
           self.enddate = enddate

           print("[DBG] : filelist : ", filelist)
           '''
           parser = xml.sax.make_parser()
           parser.setFeature(xml.sax.handler.feature_namespaces, 0)
           Handler = CVEHandler()
           parser.setContentHandler(Handler)
           '''

           if self.trace:
               print('Loading CVE data..')

           for file in self.filelist:  # json
               if self.trace:
                   print("Loading file:", file)
               cves_parser(file)

           if self.trace:
               print("CVE data loaded:", len(m_CVElist), "entries")

           # TODO : REJECT, RESERVED DEL
           #
           # Once m_CVElist includes all of the CVEs read in, go through and filter out  entries that are reserved or rejected

           # reserved cve 제거. rejected cve 제거
           # edit again => 다시 수정 들어가야함
           # filist_1 = findCVEs('RESERVED')
           # for entry in filist_1:
           #     del m_CVElist [entry]
           #
           # if self.trace:
           #     print ("dropped RESERVED CVEs:", len(filist_1), "entries")
           #
           # filist_2 = findCVEs('REJECT')
           # for entry in filist_2:
           #     del m_CVElist [entry]
           #
           # if self.trace:
           #     print ("dropped REJECTED CVEs:", len(filist_2), "entries")

           ret = []
           # 최근 취약점 검사 루틴 ( 최근 사고 발생(cert) + NVD의 Pub date 기준 )
           # 1) load new cve
           newcvelist = []
           for c in m_CVElist.keys():
               _ = m_CVElist[c].getPublishedDate().split("T")[0].split("-")
               cvepubdate = datetime.datetime(int(_[0]), int(_[1]), int(_[2]))
               if self.startdate <= cvepubdate and cvepubdate <= self.enddate:
                   newcvelist.append(c)
                   print(self.startdate, " <= ", cvepubdate, "<= ", self.enddate)

           # 2) add 2 list
           recnewcvelist = list(set(newcvelist + list(recentcvelist)))

           # 3) check and set recent True
           for recentcve in recnewcvelist:
               print("recent cve id : ", recentcve)
               if recentcve in m_CVElist.keys():
                   m_CVElist[recentcve].setRecent(True)
               else:
                   print("Unable to find vuln ", recentcve)


           # 4) set CVE to each asset
           momo = 0
           for v in ctypelist:  # ctype
               # TODO: edit this vulset algorithm version & will be great
               print("[ This asset ] >>>> ", v.getID())  # edit 0418
               iset = CVEsetbyCpes(v.getCpes())  # edit
               print("Get cve is ", len(iset), )
               print("=" * 15)

               '''
               if self.trace:
                  print ("Search for", v.getVendor(), v.getDesc(), 'found', len(iset), 'CVEs' )
  
               if not(v.getType() == None ):
                  if not(bool(iset)):
                      eset = CVEsetbyType (str(v.getType()))
                      iset = vset & eset  # intersection set of vendor and type, e.g., Ford and Pickup
  
                      if self.trace:
                          print ("Alt. search for", v.getVendor(), v.getType(), 'found', len(iset), 'CVEs' )
               '''
               if bool(iset):
                   if self.trace:
                       pass
                   cvelist = list(iset)

                   momo = momo + len(cvelist)
                   for s in cvelist:
                       # show info test
                       m_CVElist[s].setTarget(v.getDesc())
                       m_CVElist[s].getEffects()
                       m_CVElist[s].getAccess()
                       ret.append(m_CVElist[s])
                       v.addVulnerability(m_CVElist[s])  # 자산에 cve 붙이기
                       # end

           print(">>>>>>>>> final before <<<<<<<<<")
           for i in ctypelist:
               print(i.getID(), " : ", len(i.getVulnerabilityList()))

           # add hw + sw asset
           onmachinelist = []
           for i in range(len(ctypelist)):
               for j in range(len(ctypelist)):
                   if ctypelist[i].getID() in ctypelist[j].getOnmachine():
                       for k in ctypelist[j].getVulnerabilityList():
                           ctypelist[i].addVulnerability(k)
                       onmachinelist.append(ctypelist[j].getID())

           print(">>> on machine list < ")
           print(onmachinelist)
           k = 0
           tmp_ctypelist = ctypelist[:]
           for i in range(len(tmp_ctypelist)):
               if tmp_ctypelist[i].getID() in onmachinelist:
                   del ctypelist[i - k]  # edit
                   k += 1

           print(">>>>>>>>> final <<<<<<<<<")
           for i in ctypelist:
               print(i.getID(), " : ", len(i.getVulnerabilityList()), " ")
               cnt = 0
               for k in i.getVulnerabilityList():
                   if k.getRecent():
                       cnt += 1
                       print(k, end=', ')
               print("Recent CVE : ", cnt)
               print("=" * 15)
           print("++++++++ the end +++++ get id ")

           print("LLEENN : ", momo)
           print(print(ctypelist))
           print(type(ctypelist[0]))

           return ret


    '''
    [before load]
    def load (self, filelist, ctypelist ):
       self.filelist = filelist
       
       [xml] mitre CVEs
       parser = xml.sax.make_parser()
       parser.setFeature(xml.sax.handler.feature_namespaces, 0)
       Handler = CVEHandler()
       parser.setContentHandler( Handler )
       
       if self.trace:
          print ('Loading CVE data..')

       for file in self.filelist:
          if self.trace:
             print ("Loading file:", file )
          parseCVEs(file)
       
       if self.trace:
          print ("CVE data loaded:", len(m_CVElist), "entries")     
          
# Once m_CVElist includes all of the CVEs read in, go through and filter out  entries that are reserved or rejected
             
       filist_1 = findCVEs('RESERVED')
       for entry in filist_1:
           del m_CVElist [entry]
           
       if self.trace:          
           print ("dropped RESERVED CVEs:", len(filist_1), "entries")
           
       filist_2 = findCVEs('REJECT')
       for entry in filist_2:
           del m_CVElist [entry]       
       
       if self.trace:
           print ("dropped REJECTED CVEs:", len(filist_2), "entries")
 
       # [DBG] bring all CVEs which is great
       if self.trace:
           print("+"*10, "Data_Load_Check", "+"*10)
           ll = m_CVElist.keys()
           for cveid in ll:
               print(m_CVElist[cveid])
           print("=" * 10, "The End", "="*10)

        # DBG CTYPELIST INFO
       print("ctypelist")
       for kk in ctypelist:
           print(kk)

       ret = []
       for v in ctypelist:
           
         vset = CVEsetbyVendor(str(v.getVendor()))   
         mset = CVEsetbyModel(str(v.getDesc()))         
         iset = vset & mset   # intersection set of vendor and model, e.g., Ford and F150
         
         if self.trace:
            print ("Search for", v.getVendor(), v.getDesc(), 'found', len(iset), 'CVEs' )
         
         if not(v.getType() == None ):
            if not(bool(iset)):
               eset = CVEsetbyType (str(v.getType()))
               iset = vset & eset  # intersection set of vendor and type, e.g., Ford and Pickup 
               if self.trace:
                  print ("Alt. search for", v.getVendor(), v.getType(), 'found', len(iset), 'CVEs' )        
     
         if bool(iset):
           if self.trace:
              print ('CVE list:', iset)
           cvelist = list(iset)           
  
           for s in cvelist:
               m_CVElist[s].setTarget (v.getDesc())
               m_CVElist[s].getEffects()
               m_CVElist[s].getAccess()
               ret.append (m_CVElist[s])
               v.addVulnerability (m_CVElist[s])                   
               
       return ret
       '''

