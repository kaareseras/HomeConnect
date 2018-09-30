from requests_oauthlib import OAuth2Session
from flask import Flask, request, redirect, session, url_for
from flask.json import jsonify
import sseclient
import os
import mpu.io

app = Flask(__name__)


# https://github.com/requests/requests-oauthlib/blob/master/docs/examples/real_world_example_with_refresh.rst

simulated = True

stateStore = ""
client_id = "7D53E0326CD786675180B9E1EA334A06CE8CE24722D1EFF3A42B06775132BD95"
client_secret = "81CF0EE81B529170E0E184742148F19ACD2E2FD8A24854E5EC0AFB9F6C3B702A"


if (simulated == True):
    authorization_base_url = 'https://simulator.home-connect.com/security/oauth/authorize'
    token_url = 'https://simulator.home-connect.com/security/oauth/token'
else:
    authorization_base_url = 'https://api.home-connect.com/security/oauth/authorize'
    token_url = 'https://api.home-connect.com/security/oauth/token'

scope = [
    "IdentifyAppliance",
    "Monitor",
    "Control",
    "Images",
    "Settings",
]

def with_requests(url):
    """Get a streaming response for the given event feed using requests."""
    
    token = session['oauth_token']
    github = OAuth2Session(client_id, token=token) 
    return github.get(url, stream=True)

@app.route("/")
def demo():
    """Step 1: User Authorization.

    Redirect the user/resource owner to the OAuth provider (i.e. Github)
    using an URL with a few key OAuth parameters.
    """

    #Test if token exists
    try:
        token = mpu.io.read('example.json')
        return redirect(url_for('.events'))
    except:
        
        data = mpu.io.read('example.json')

        github = OAuth2Session(client_id, scope=scope)
        authorization_url, state = github.authorization_url(authorization_base_url)

        # State is used to prevent CSRF, keep this for later.
        stateStore = state
        
        return redirect(authorization_url)


# Step 2: User authorization, this happens on the provider.

@app.route("/callback", methods=["GET"])
def callback():
    """ Step 3: Retrieving an access token.

    The user has been redirected back from the provider to your registered
    callback URL. With this redirection comes an authorization code included
    in the redirect URL. We will use that to obtain an access token.
    """


    HomeConnect = OAuth2Session(client_id, state=stateStore)

    token = HomeConnect.fetch_token(token_url, client_secret=client_secret,
                               authorization_response=request.url)

    # At this point you can fetch protected resources but lets save
    # the token and show how this is done from a persisted token
    # in /profile.

    session['oauth_token'] = token

    

    mpu.io.write('example.json', token)

    return redirect(url_for('.events'))


@app.route("/home", methods=["GET"])
def home():
    """Fetching a protected resource using an OAuth 2 token.
    """
    token = session['oauth_token']
    
    if (simulated == True):
        github = OAuth2Session(client_id, token=token)
        return jsonify(github.get('https://simulator.home-connect.com/api/homeappliances').json())
    
    
    else:
        github = OAuth2Session(client_id, token=token)   
        return jsonify(github.get('https://api.home-connect.com/api/homeappliances').json())

@app.route("/events", methods=["GET"])
def events():
    import requests
    import sseclient
    
    url = 'https://simulator.home-connect.com/api/homeappliances/SIEMENS-HCS02DWH1-49C805BCCF4120/events'
       

    #token = session['oauth_token']
    token = mpu.io.read('example.json')


    #myToken = access_token
    myUrl = url
    head = {'Authorization': 'Bearer 225852941EB8953E17EED768FDAADB1116C5EA8D095E78FD086E1E80AB130DC7', 'Accept':'text/event-stream'}
    response = requests.get(myUrl, headers=head, stream=True)

    client = sseclient.SSEClient(response)
    for event in client.events():
        try:
            print(event.data)
        except:
            pass

    return jsonify(token)

if __name__ == "__main__":
    # This allows us to use a plain HTTP callback
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = "1"

    app.secret_key = os.urandom(24)
    app.run(debug=True)