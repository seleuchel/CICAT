# -*- coding: utf-8 -*-
"""
:::::::::::::::::::::::::::::::::::::  MITRE CRP PROJECT  :::::::::::::::::::::::::::::::::::::::
      
                                            NOTICE

This software (or technical data) was produced for the U. S. Government under contract 355358
with Brookhaven National Laboratory, and is subject to the Rights in Data-General Clause 52.227-14 (MAY 2014) or (DEC 2007).

The following copyright notice may be affixed after receipt of written approval from the Contracting Officer.
Please contact the Contracts Management Office for assistance with obtaining approval or identifying the correct clause.
If the contract has Clause 52.227-14, Alt. IV, written approval is not required and the below copyright notice may be affixed.

(c) 2020 The MITRE Corporation. All Rights Reserved.

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
"""

import sys
from random import sample
from collections import defaultdict
from ffactory import FILTER_FACTORY, INIT_FILTERS #, getTTPs, showTTPs
from loaddata import LOAD_DATA, LOAD_TTP_SUPPLEMENT #, LOAD_ATK4ICS, LOAD_ACTOR_PROFILES 
 
from topology import INIT_TOPOLOGY #, m_topology, m_zoneCIs, m_zoneMMap
from loaddata import m_file_INFRASTRUCTURE, m_file_SCENARIOS, m_file_ODNI #m_file_EXTENSIONS, 
from TTPFilter import TTP_FILTER

#from stats import TAGS_INDEX, x_TACTICS 

#from mitGEN import ACTOR_REPORT
import ODNI


# ATT&CK tactics list
m_TACTIC_LIST = ['initial-access', 'execution', 'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access', 
               'discovery', 'lateral-movement', 'collection', 'command-and-control', 'exfiltration', 'deny',
               'impact', 'inhibit-response-function', 'impair-process-control' ]

# Note: ICS patterns do support privilege escalation[3], credential-access[5], and exfiltration[10] tactics
# Note: Non-ICS patterns do not support inhibit-response-function[13] and impair-process-control[14] tactics
# Note: Current ATT&CK dataset provides no attribution for impact tactic or ICS-SCADA (scenearios must use threat actor profiles to use)


# objseqs reference ATT&CK tactics using m_tactList indexes
m_objseqs = [['foothold',           'first',     [0, 7] ], 
             ['justgo',             'any',       [7] ],
             ['recceandgo',         'any',       [6, 7] ],
             ['collectandgo',       'any',       [6, 8, 7] ],
             ['coverandgo',         'any',       [4, 7] ],
             ['credsandgo',         'any',       [3, 5, 7 ]],
             ['phonehomeandgo',     'any',       [9, 7] ],
             ['backdoor',           'last',      [6, 3, 2] ],
             ['hammer_1',           'last',      [6, 3, 12] ],   #12 - impact
             ['hammer_2',           'last',      [6, 12] ],
             ['hammer_3',           'last',      [6, 13] ],  #13 - inhibit-response-function
             ['hammer_4',           'last',      [6, 14] ],  #14 - impair-process-contro
             ['exfil',              'last',      [8, 10] ]  ]

# dictionary of tactic sequences
m_objdict = defaultdict (list)
m_tactDict = defaultdict (list)
m_patternMenu = defaultdict (list)

# initialize data structure and pattern menu

def initDS():
    for p in m_objseqs:
        m_objdict[p[0]].append([p[1], p[2]] )


def initPatternMenu ():
    if m_patternMenu.keys():
        return m_patternMenu
    
    initDS()

    m_patternMenu ['Saguaro'] = ['foothold', 'justgo', 'hammer_1'] 
    m_patternMenu ['Barrel'] = ['foothold', 'recceandgo', 'hammer_1' ]
    m_patternMenu ['Star'] = ['foothold', 'credsandgo', 'exfil'] 
    m_patternMenu ['Feather'] = ['foothold', 'collectandgo', 'exfil'] 
    m_patternMenu ['Old Lady'] = ['recceandgo', 'recceandgo', 'coverandgo', 'backdoor']
    m_patternMenu ['Bunny Ear'] = ['justgo', 'recceandgo', 'coverandgo', 'hammer_1'] 
    m_patternMenu ['Blue Columnar'] = ['justgo', 'justgo', 'hammer_1'] 
    m_patternMenu ['Moon'] = ['collectandgo', 'collectandgo', 'exfil']
    m_patternMenu ['Easter'] = ['justgo', 'justgo', 'backdoor']
    m_patternMenu ['Ladyfinger'] = ['justgo', 'justgo', 'hammer_1']
    m_patternMenu ['Parodia'] = ['justgo', 'justgo', 'hammer_2']
    m_patternMenu ['Bishops Cap'] = ['justgo', 'justgo', 'hammer_3']
    m_patternMenu ['Fairy Castle'] = ['foothold', 'justgo', 'hammer_4']
    
    return m_patternMenu


# assundry utility functions

def gettactics (entry):
    ret = []
    for t in entry:
        ret.append(m_TACTIC_LIST[t])       
    return ret
        
def gettactlist (obj):
    entry = m_objdict[obj]
    if not (entry):
        print ('Warning! gettactlist has no entry for', obj)
        return
    return gettactics ((entry [0])[1] )

def isFirst (entry, listx):
    if listx[0] == entry:
        return True
    return False

def isLast (entry, listx):
    if listx[len(listx)-1] == entry:
        return True
    return False

def inMiddle (entry, listx):
    if not(isFirst (entry, listx)) and not (isLast(entry, listx)):
        return True
    return False

def randomMiddle(listx):
    ret = sample (listx[1:len(listx)-1], 1)
    return ret[0]

# returns sequence of attack patterns assigned each host from objective sequence
def genObjectiveSequence ( pathlist, attackpat ):
    
    ret = []
    for host in pathlist:
        if isFirst(host, pathlist):
            ret.append (attackpat[0] )
        elif isLast(host, pathlist):
            ret.append (attackpat[len(attackpat) - 1])
        else:
            ret.append (randomMiddle(attackpat))

    return ret
        

# returns tactic sequence for hosts in attack path applying specified pattern   
def GenTacticPattern (path, pattern, trace ):

   tactSeq = []
   
   objseq = genObjectiveSequence (path, pattern)
   for o in objseq:
       tactSeq.append (gettactlist(o))
           
   mixlist = []
       
   indx = 0
   for t in tactSeq:
       mixlist.append ([path[indx], t])
       indx = indx + 1
       
   if trace:
      print (mixlist)
          
   return mixlist

def getComponentbyName(dataset, cname):
   for c in dataset['COMPONENT']:
      if c.getName() == cname:
          return c     
   return None
    
def getActorbyName(dataset, aname):
   for c in dataset['ATKGROUPS']:
      if c.getGroupID() == aname:
          return c     
   return None

def GenTTPSequence (dataset, factory, patSeq, aName, actFlag, trace):

    ret = []
    
    actor = getActorbyName (dataset, aName)
    for p in patSeq:
        
        foo = []
        
        cmpName = p[0]
        tacpat  = p[1]
        
        component = getComponentbyName (dataset, cmpName)
        if not (component):
            if trace:
                print ('WARNING! GenTTPSequence cannot find host', cmpName )
            return
        
        foo.append(cmpName)
        
        platflag = True
        if component.getSurfaceList():
           if trace:
               print ('INFO.. GenTTPSequence component has surface list.')
           platflag = False
           
        for t in tacpat:                    
           foo.append (TTP_FILTER (dataset, factory, cmpName, t, platflag, actor, actFlag, trace) )
           
        ret.append (foo)
        
    return ret
   
# returns the objective sequence for the name pattern      
def GetPatternbyName(name):    
    patternDict = initPatternMenu()    
    return patternDict[name]


# Helper function for reading options from command line     
def optionReader(params, flag):
    idx = params.index(flag)
    if len(params) > idx + 1 and '-' not in params[idx + 1]:
        return params[idx + 1]
    else:
        print(flag + ' flag must include an option!')
        exit()    

# main entry point
if ( __name__ == "__main__"):   
        
    Ispread = m_file_INFRASTRUCTURE
    Tspread = m_file_SCENARIOS
 
    params = sys.argv
    if len(params) > 1:
        if 'help' in params[1].lower():
            print ('\nUSAGE: python', params[0], '[-i <Path to Infrastructure spreadsheet>] [-s <Path to Scenarios spreadsheet>]')
            exit()
        
        if '-i' in params:
            Ispread = optionReader(params, '-i')

        if '-s' in params:
            Tspread = optionReader(params, '-s')   
     
      
    myDATASET = LOAD_DATA (Ispread, Tspread, False, False )
    zonemap = INIT_TOPOLOGY(myDATASET, True ) 
    ODNI.loadODNI(m_file_ODNI )
    m_STAGES = ODNI.mapTTPs(myDATASET['ATT&CK']) 
   
    LOAD_TTP_SUPPLEMENT (myDATASET) 
   
    ffactory = FILTER_FACTORY(False )
    INIT_FILTERS (ffactory, myDATASET)
        
    initPatternMenu()    
    
    ITpath = ['DCAE1TSC001', 'DCAE1SWC001', 'DCAE0SWC001' ] 
      
    ICSpath = ['SiemensPLC_#1', 'SiemensPLC_#2']
    
    print ('\n')
    print ('>> Objective to Tactic mappings test <<')

    
    for k in m_patternMenu.keys():
        print ('\n')
        print ('Testing pattern:', k)
        
        actor = None
        if 'ICS' in k:
            testpath = ICSpath
            actor = 'ICSCUB_1'
        else:
            testpath = ITpath
            actor = 'APT28'
        
        print ('Using attack path:', testpath )
        
        
        patseq = GenTacticPattern(testpath, GetPatternbyName (k), False)
        print (patseq)       
        print ('\n')
        print ('TTP Sequence(', actor,'):', GenTTPSequence (myDATASET, ffactory, patseq, actor, True, True) )
        
    
    print ('End of run.')

