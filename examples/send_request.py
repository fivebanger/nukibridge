

import requests


url = 'http://localhost:8080/bridgeInfo'
headers = {'user-agent': 'MyFancyAgent'}
r = requests.get(url, headers=headers)
stat = r.status_code
if( 200 == stat ):
    result = r.json()
    print result
    
    print result['bridgeId']
    print result['bridgeName']
else:
    print 'HTTP error: ' + str(stat)
    
    
url = 'http://localhost:8080/list'
headers = {'user-agent': 'MyFancyAgent'}
r = requests.get(url, headers=headers)
stat = r.status_code
if( 200 == stat ):
    result = r.json()
    print result
    
    for item in result:
        print item['nukiId']
        print item['name']
else:
    print 'HTTP error: ' + str(stat)
    
    

url = 'http://localhost:8080/lockState'
headers = {'user-agent': 'MyFancyAgent'}
nukiId = 1
payload = {'nukiId': nukiId}
r = requests.get(url, headers=headers, params=payload)
stat = r.status_code
if( 200 == stat ):
    result = r.json()
    print result['success']  
    print result['state']
    print result['stateName']  
    print result['batteryCritical']  
else:
    print 'HTTP error: ' + str(stat)
    
    

url = 'http://localhost:8080/lockAction'
headers = {'user-agent': 'MyFancyAgent'}
nukiId = 1
action = 3
payload = {'nukiId': nukiId, 'action': action}
r = requests.get(url, headers=headers, params=payload)
stat = r.status_code
if( 200 == stat ):
    result = r.json()
    print result
    
    print result['success']  
    print result['batteryCritical']
else:
    print 'HTTP error: ' + str(stat)
    
    

url = 'http://localhost:8080/updateTime'
headers = {'user-agent': 'MyFancyAgent'}
nukiId = 1
nukiPin = 3345
payload = {'nukiId': nukiId, 'nukiPin': nukiPin}
r = requests.get(url, headers=headers, params=payload)
stat = r.status_code
if( 200 == stat ):
    result = r.json()
    print result
    
    print result['success']  
    print result['batteryCritical']
else:
    print 'HTTP error: ' + str(stat)



"""
open issues: http://.../lockState/ : u'success': u'false' or u'success': false
[{"nukiId": 1, "name": "Test_1"}, {"nukiId": 2, "name": "Test_2"}] -> if remove 1, [{"nukiId": 1, "name": "Test_2"}] or [{"nukiId": 2, "name": "Test_2"}]
"""
