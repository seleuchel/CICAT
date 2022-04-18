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
tmodel.py - Object classes for vulnerability, indicator, target, scenario, entrypoint, COA
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
"""

import re

class VULNERABILITY:
    _idx = 0
    def __init__ (self, idx ):
        VULNERABILITY._idx += 1 # start from 1
        self.idx = VULNERABILITY._idx
        self.vendor = ''
        self.title = '' # CVE-XXXX-XXXX
        self.target = ''
        self.desc = '' # description
        self.ref = [] # ref list ["https:~",]
        self.effects = []
        self.access = []
        self.indicator = []
        self.reserved = False
        # add
        self.hascvss = False
        self.hascpe = False
        self.cvssv3 = 0.0 # check impact is null? [impact][baseMetricV3][cvssV3][baseScore] # no? then, cve
        self.cpe = []
        self.publisheddate = "" # datetime.datetime.strptime(date[:10], "%Y-%m-%d")
        self.lastmodifieddate = ""  # datetime.datetime.strptime(date[:10], "%Y-%m-%d")

    effectkeys = ['DoS','denial of service', 'denial-of-service', 'hang', 'crash', 'panic', 'outage', 'reload', 'reboot', 'restart', \
                  'degrade', 'flood', 'slow', 'delay', 'replay', 'exhaust', 'leak', 'deplete', 'consume', 'overwrite', 'corrupt', 'modify', 'alter', \
                  'read', 'exfiltrate', 'steal', 'capture', 'obtain sensitive information', 'spoof', 'disrupt', 'execute code', 'arbitrary code', \
                  'inject', 'unauthenticate', 'unauthorize', 'mascarade', 'bypass', 'privilege', 'escalat', 'elevate', 'root access', 'damage', 'destroy' ]                

    accesskeys = ['remote', 'web interface', 'tcp connection', 'session', 'ethernet', 'local', 'privilege', 'crafted packet']

    # for dbg
    def __str__(self):
        result = "============= after load cve =============\n"
        result += "idx : " + str(self.idx) + "\n"
        result += "vendor : " + str(self.vendor) + "\n"
        result += "title : " + str(self.title) + "\n"
        result += "target : " + str(self.target) + "\n"
        result += "desc : " + str(self.desc) + "\n"
        result += "ref : " + str(self.ref) + "\n"
        result += "effects : " + str(self.effects) + "\n"
        result += "access : " + str(self.access) + "\n"
        result += "indicator : " + str(self.indicator) + "\n"
        result += "reserved : " + str(self.reserved) + "\n"
        # here
        result += "hascvss : " + str(self.hascvss) + "\n"
        result += "hascpe : " + str(self.hascpe) + "\n"
        result += "cvssv3 : " + str(self.cvssv3) + "\n"
        result += "cpe : " + str(self.cpe) + "\n"
        result += "publisheddate : " + str(self.publisheddate) + "\n"
        result += "lastmodifieddate : " + str(self.lastmodifieddate) + "\n"
        return result

    def getCVE(self):
        return self.title

    def setTitle(self, title):
        if self.title == "":
            self.title = title
        else:
            self.title = self.title + title
            
    def getTitle(self):
        return self.title
            
    def setDescription(self, desc):
        if self.desc == "":
            self.desc = desc.replace('\n', ' ') 
        else:
            self.desc = self.desc + desc.replace('\n', ' ')
            
    def getDescription(self):
        return self.desc
            
    def addReference(self, ref ):
        self.ref.append(ref)
            
    def getReferences(self):
        return self.ref
    
    def setTarget(self, target):
        self.target = target
        
    def getTarget(self):
        return self.target

# add
    def setCvssv3(self, cvssv3):
        self.cvssv3 = cvssv3

    def getCvssv3(self):
        return self.cvssv3

    def appendCpe(self, cpe):
        self.cpe.append(cpe)

    def getCpe(self):
        return self.cpe

    def setPublishedDate(self, pubdate):
        self.publisheddate = pubdate

    def getPublishedDate(self):
        return self.publisheddate

    def setLastModifiedDate(self, moddate):
        self.lastmodifieddate = moddate

    def getLastModifiedDate(self):
        return self.lastmodifieddate

    def setHascvss(self, hascvss):
        self.hascvss = hascvss

    def getHascvss(self):
        return self.hascvss

    def setHascpe(self, hascpe):
        self.hascpecvss = hascpe

    def getHascpe(self):
        return self.hascpe
# end edit


    def searchbyKeys (self, keylist):
        ret = []
        for k in keylist:
           p = re.compile(k, re.IGNORECASE)
           if p.search(self.getDescription().casefold() ):
            ret.append(k)         
        return ret

    def getEffects(self):
        if (self.effects):
            return self.effects
        self.effects = self.searchbyKeys(self.effectkeys)
        if not(self.effects):
            self.effects = ['None found']
        return self.effects 

    def getAccess(self):
        if (self.access):
          return self.access
        self.access = self.searchbyKeys(self.accesskeys)  
        if not(self.access):
            self.access = ['None found']
        return self.access     
    
    def isUniqueIndy (self, entry):
        if (entry in self.indicator):
            return False
        return True

    def link_11 (self, indyArray, trace=False):
        for indy in indyArray:
            if (indy.getCVE() == self.getCVE()):
                if (self.isUniqueIndy(indy)):
                   self.indicator.append (indy ) 
                   if (trace):
                      print ('link_11: INDICATOR', indy.getCVE(), 'added to VULNERABILITY', self.getCVE() )
             
    def PP(self, verbose=False):
        if self.ref:
            print (self.title, 'URL:', self.ref[0])
        else:
            print (self.title, 'URL: none')

        if verbose:
           print ('Effects:', self.effects, 'Access:', self.access )
           cnt = 0
           maxwc = 30
           shortdesc = ''
           wlist = self.desc.split(' ')
           if wlist:            
            for j in wlist:
                shortdesc = shortdesc + ' ' + j
                cnt = cnt + 1
                if cnt > maxwc:
                    shortdesc = shortdesc + '...'
                    break                
           print (shortdesc)

"""   
class INDICATOR:
    def __init__ (self, cveID, desc):
        self.cveID = cveID
        self.desc = desc
        
    def getCVE(self):
        return self.cveID
    
    def getDescription(self):
        return self.desc   
    
    def PP(self, verbose=False ):
        print ('INDICATOR:', self.desc)
"""    

class TARGET:
    def __init__ (self, cid, cname):
        self.cid = cid
        self.cname = cname
        self.component = None

    def initTarget(self, clist ):
        if self.component:
            return self.component         

        for x in clist:
            if x.getID() == self.cid:
              self.component = x  
              return self.component
        
    def getCID(self):
        return self.cid
    
    def getName(self):
        return self.cname   
    
    def getComponent (self):
        return self.component
    
    def getIPAddr(self):
        if self.component:
            return self.component.getIPAddress()
        
    def getZone(self):
        if self.component:
            return self.component.getZone()
        
    def getCriticality(self ):
        if self.component:
           return self.component.getCriticality()
    
    def PP(self, verbose =True ):
        print ('TARGET:', self.cid, ' :', self.cname)
        self.component.PP(verbose )
       
class SCENARIO:
    def __init__(self, dbID, shortname, name, desc, detail, actorID, intendedEffect, targetID ):
        self.dbID = dbID
        self.shortname = shortname
        self.name = name
        self.desc = desc
        self.detail = detail
        self.actorID = actorID
        self.intendedEffect = intendedEffect
        self.targetID = targetID
        self.targetIP = None
        self.actor = []
        self.target = []
        
    def getID(self):
        return self.dbID
    
    def getShortName(self):
       return self.shortname
   
    def getName(self):
        return self.name
   
    def getDesc(self):
        return self.desc
    
    def setDetail(self, trace):
        self.detail = trace
        
    def getDetail(self):
        return self.detail
    
    def setActor(self, actor):
        self.actor.append(actor)
    
    def getActor(self):
        return self.actor
    
    def getTargetID(self):
        return self.targetID
    
    def getActorID(self):
        return self.actorID
       
    def getIntendedEffect(self):
        return self.intendedEffect
    
    def getStartHint(self):
        return self.startHint
    
    def setTarget(self, target):
        self.target.append(target)
        
    def getTarget(self):
        return self.target   

    def PP(self):
        print ('\nSCENARIOX ' + self.name + ":")
        print (self.desc)


class ENTRYPOINT:
    def __init__(self, cid, cname ):
        self.cid = cid
        self.cname = cname
        self.component = None
        
    def initEntrypoint(self, clist ):
        if self.component:
            return self.component 
        
        for x in clist:
            if x.getID() == self.cid:
              self.component = x  
              return self.component        

    def getCID(self):
        return self.cid
    
    def getName(self):
        return self.cname    
       
    def getComponent (self):
        return self.component

    def getIPAddr (self):
        if self.component:
            return self.component.getIPAddress()
        
    def getSysName(self):
        if self.component:
            return self.component.getSysName()
        
    def getZone(self):
        if self.component:
            return self.component.getZone()
"""          
class COA:
   def __init__ (self, family, name, title, priority, impact, desc, supp, related ):
       self.family = family
       self.name = name
       self.title = title
       self.priority = priority
       self.impact = impact
       self.desc = desc
       self.supplmental = supp
       self.related = related
       self.parameters = []
       self.myKeys = []      
       self.coakeys = ['prevent', 'policy', 'detect', 'audit', 'assess', 'alert', 'warn', 'analy', 
                       'scan','inspect', 'aware', 'verify', 'train', 'respond', 'monitor', 'recover', 
                       'certify']
       
   def appendDesc(self, name, desc):
       self.desc = self.desc+'\n'+name+': '+desc
   
   def getParameterList(self):
       if self.parameters:
           return self.parameters    
       wlist = self.desc.split(':')
       for w in wlist:
           if w.find(']') > 0:
              endst = w.index(']')
              self.parameters.append(w[1:endst])              
       return self.parameters
  
   def getName(self):
       return self.name
   
   def searchbyKeys (self, keylist):
       ret = []
       for k in keylist:
           p = re.compile(k, re.IGNORECASE)
           if p.search(self.desc.casefold() ):
               ret.append(k)   
           elif p.search(self.supplmental.casefold() ):
               ret.append(k)
       return ret

   def getCOAkeys(self):
       if self.myKeys:
            return self.myKeys
       self.myKeys = self.searchbyKeys(self.coakeys)
       return self.myKeys     
"""       
       
