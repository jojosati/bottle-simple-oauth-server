import oauth2

def request_client (url,key,secret,method='GET',header=False) :
    """
    POST - support oauth via either postdata or header
    GET - support oauth via query string only
    """
    consumer = oauth2.Consumer(key=key,secret=secret)
    client = oauth2.Client(consumer)
    resp,content = client.request(url,method=method, \
        headers=None if header or method=='GET' else {'Content-Type':''})
    status = resp.get('status')
    if status!='200' :
        return 'status %s' % (status)
    return content

def request_urllib2 (url,key,secret, method='GET',header=False):
    import urllib2

    consumer = oauth2.Consumer(key=key,secret=secret)
    params = {
        'oauth_version': "1.0",
        'oauth_nonce': oauth2.generate_nonce(),
        'oauth_timestamp': oauth2.generate_timestamp(),
        'oauth_consumer_key': key,
    }

    req = oauth2.Request(method=method, url=url, parameters=params)
    signature_method = oauth2.SignatureMethod_HMAC_SHA1()
    req.sign_request(signature_method, consumer, None)
    if header:
        data = None if method=='GET' else ''
        u = urllib2.urlopen(urllib2.Request(url,headers=req.to_header()),data=data)
    else:
        if method=='GET':
            u = urllib2.urlopen(req.to_url())
        else:
            u = urllib2.urlopen(url,data=req.to_postdata())
    return u.readlines()

for m in ('GET','POST') :
    print '=== urllib2 %s ===' % m
    for k,v in (('test','test'),('invalid','test')):
        print '-----> key:%s secret:%s' % (k,v)
        try :
            print request_urllib2('http://localhost:8080/ajax',k,v,m)
        except Exception as e :
            print '%s' % e

    print '=== urllib2 %s via headers ===' % m
    for k,v in (('test','test'),('invalid','test')):
        print '-----> key:%s secret:%s' % (k,v)
        try :
            print request_urllib2('http://localhost:8080/ajax',k,v,m,True)
        except Exception as e :
            print '%s' % e

    print '=== oauth2.Client %s ===' % m
    for k,v in (('test','test'),('invalid','test')):
        print '-----> key:%s secret:%s' % (k,v)
        try :
            print request_client('http://localhost:8080/ajax',k,v,m)
        except Exception as e :
            print '%s' % e
    if m=='POST' :
        print '=== oauth2.Client %s via header ===' % m
        for k,v in (('test','test'),('invalid','test')):
            print '-----> key:%s secret:%s' % (k,v)
            try :
                print request_client('http://localhost:8080/ajax',k,v,m)
            except Exception as e :
                print '%s' % e
