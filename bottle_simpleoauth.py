#-*- coding: utf-8 -*-
import bottle
import oauth2

__author__ = 'Sathit Jittanupat'
__version__ = '0.1'
__license__ = 'MIT'

def simple_oauth(consumer_secret=None):
    """
    Verify 2-legged oauth (per request).
    base on http://philipsoutham.com/post/2172924723/two-legged-oauth-in-python
    Parameters accepted as values in "Authorization" header, or as a GET request
    or in a POST body.
    options consumer_secret : may be callable, dict, a string, or simple default secret == consumer_key
    """

    if not hasattr(bottle,'oauth_server') :
        bottle.oauth_server = oauth2.Server(
                    signature_methods={
                    # Supported signature methods
                    'HMAC-SHA1': oauth2.SignatureMethod_HMAC_SHA1()
                    })

    def decorator(func):
        def wrapper(*a, **ka):
            req = oauth2.Request.from_request(
                bottle.request.method,
                bottle.request.url,
                headers=dict([(k,v) for k,v in bottle.request.headers.iteritems()]),
                # the immutable type of "request.params" prevents us from sending
                # that directly, so instead we have to turn it into a python
                # dict
                parameters=dict([(k,v) for k,v in bottle.request.params.iteritems()]),
                #query_string=bottle.request.query_string
                )
            # fixed duplicated query bug in oauth2.get_normalized_parameters()
            if bottle.request.method=='GET' :
                req.url = req.normalized_url

            oauth_key = req.get('oauth_consumer_key') #bottle.request.params.get('oauth_consumer_key')
            if oauth_key :
                secret = None
                if callable(consumer_secret) :
                    secret = consumer_secret(oauth_key)
                if isinstance(consumer_secret,dict) :
                    secret = consumer_secret.get(mock.key)
                if isinstance(consumer_secret,basestring) :
                    secret = consumer_secret
                if consumer_secret is None : # default
                    secret = oauth_key
                if not secret :
                    raise bottle.HTTPError(401,'Invalid consumer key.')
                if hasattr(secret,'key') and hasattr(secret,'secret') :
                    consumer = secret
                else :
                    consumer = oauth2.Consumer(oauth_key,secret)
                try:
                    bottle.oauth_server.verify_request(req,consumer,None)
                except oauth2.Error, e:
                    raise bottle.HTTPError(401,e)
                except KeyError, e:
                    raise bottle.HTTPError(401,"You failed to supply the "\
                                       "necessary parameters (%s) to "\
                                       "properly authenticate "%e)
                bottle.request.environ['oauth_consumer_key'] = oauth_key
            return func(*a, **ka)
        return wrapper
    return decorator


@bottle.route('/ajax',method=('GET','POST'))
@simple_oauth()
def ajax() :
    if not bottle.request.environ.get('oauth_consumer_key') :
        bottle.abort(401,'not allow')
    return {'json':['ajax','web service',bottle.request.environ.get('oauth_consumer_key')]}

@bottle.route('/test/:key/:secret')
def test(key,secret) :
    method = bottle.request.method
    url = bottle.urljoin(bottle.request.url,'/ajax')

    params = {
        'oauth_version': "1.0",
        'oauth_nonce': oauth2.generate_nonce(),
        'oauth_timestamp': oauth2.generate_timestamp(),
        'oauth_consumer_key':key
    }
    consumer = oauth2.Consumer(key=key,secret=secret)

    req = oauth2.Request(method=method, url=url, parameters=params)
    signature_method = oauth2.SignatureMethod_HMAC_SHA1()
    req.sign_request(signature_method, consumer, None)
    bottle.redirect(req.to_url())

@bottle.route('/')
def index() :
    return """
<a href="/test/demo/demo">test key=demo, secret=demo</a><br>
<a href="/test/incorrect/demo">test key=incorrect, secret=demo</a><br>
"""

if __name__ == "__main__":
    bottle.debug()
    bottle.run()

