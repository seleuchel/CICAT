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


import xml.sax
import collections
import re
import json

from tmodel import VULNERABILITY

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
def findCVEs( pattern):
    ret = []
    p = re.compile(pattern, re.IGNORECASE)
    for j in m_CVElist:
        entry = m_CVElist.get(j)
        if p.search(entry.getDescription().casefold() ):
            ret.append(j)
    return ret

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
        

class VULNERABILIY_FACTORY(): 
    def __init__ (self, trace):
       self.filelist = []
       self.trace = trace
       if self.trace:
           print ('VULNERABILITY factory constructed..')

    # change to json of NVD
    def load (self, filelist, ctypelist ):
       self.filelist = filelist
       '''
       [xml] mitre CVEs
       parser = xml.sax.make_parser()
       parser.setFeature(xml.sax.handler.feature_namespaces, 0)
       Handler = CVEHandler()
       parser.setContentHandler( Handler )
       '''
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

