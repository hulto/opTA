import json
import uuid

#def newteam(name,uid):
#    retval = '{ \n\
#        "Name": "%s", \n\
#        "Type": 2, \n\
#        "Uid": "%s" \n\
#    }' % (name, uid)
#    return retval

def newhost(ip, puid, uid):
    retval = {}
    retval['HostAddress'] = ip
    retval['Name'] = "client"
    retval['ParentUid'] = puid
    retval['Type'] = 3
    retval['Uid'] = uid
    return retval

def newuid(addr, store):
    uid = uuid.uuid3(uuid.NAMESPACE_DNS, addr)
    return str(uid)

def getTeamUid(name, store):
    for i,o in enumerate(store):
        if(o['Type'] == 2 and o['Name'] == name):
            retval = "%s" % (o['Uid'])
            return retval
        
def main():
    #Load the inventory
    ips = []
    with open("inventory.ini", "r") as f:
        for line in f:
            if '[all]' in line:                
                for line in f:
                    ips.append(line)
    #print(ips)
    #Load the file
    with open('/root/Downloads/test.json') as json_file:
        team_uids = []
        data = json.load(json_file)
        storearr = data['BuiltinDirectory']['NetworkObjects']['JsonStoreArray']
        for i in ips:
            name = 'Team%s' % (i.split('.')[2])
            uid = newuid(i, storearr)
            host = newhost(i.strip(),getTeamUid(name,storearr),uid)
            data['BuiltinDirectory']['NetworkObjects']['JsonStoreArray'].append(host)
            print(json.dump(data, open("config2.json", "w"), indent=4))

                        
    #Add hosts





if __name__ == "__main__":
    main()
