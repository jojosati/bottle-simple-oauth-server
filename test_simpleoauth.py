import oauth2

def request_client (url,key,secret,method='GET') :
    consumer = oauth2.Consumer(key=key,secret=secret)
    client = oauth2.Client(consumer)
    resp,content = client.request(url,method=method)
    status = resp.get('status')
    if status!='200' :
        return 'status %s' % status
    return content

def request_urllib2 (url,key,secret, method='GET'):
    import urllib2

    consumer = oauth2.Consumer(key=key,secret=secret)
    params = {
        'oauth_version': "1.0",
        'oauth_nonce': oauth2.generate_nonce(),
        'oauth_timestamp': oauth2.generate_timestamp(),
    }
    params['oauth_consumer_key'] = consumer.key

    req = oauth2.Request(method=method, url=url, parameters=params)
    signature_method = oauth2.SignatureMethod_HMAC_SHA1()
    req.sign_request(signature_method, consumer, None)
    if method=='GET' :
        u = urllib2.urlopen(req.to_url())
    else :
        u = urllib2.urlopen(req.normalized_url,req.to_postdata())
    return u.readlines()

for m in ('GET','POST') :
    print '=== urllib2 %s ===' % m
    for k,v in (('test','test'),('invalid','test')):
        print '-----> key:%s secret:%s' % (k,v)
        try :
            print request_urllib2('http://localhost:8080/ajax',k,v,m)
        except Exception as e :
            print '%s' % e

    print '=== oauth2.Client %s ===' % m
    for k,v in (('test','test'),('invalid','test')):
        try :
            print request_client('http://localhost:8080/ajax',k,v,m)
        except Exception as e :
            print '%s' % e
