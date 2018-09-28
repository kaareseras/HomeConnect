from requests_oauthlib import OAuth2Session
from flask import Flask, request, redirect, session, url_for
from flask.json import jsonify
import os

app = Flask(__name__)


# This information is obtained upon registration of a new GitHub OAuth
# application here: https://github.com/settings/applications/new
# https://github.com/requests/requests-oauthlib/blob/master/docs/examples/real_world_example_with_refresh.rst
simulated = True

if (simulated == True):
    client_id = "445E34FA4043FC0A844A08388EFC81A85163D8D1C200E1CD63134DAD9D187999"
    client_secret = "81CF0EE81B529170E0E184742148F19ACD2E2FD8A24854E5EC0AFB9F6C3B702A"
    authorization_base_url = 'https://simulator.home-connect.com/security/oauth/authorize'
    token_url = 'https://simulator.home-connect.com/security/oauth/token'
else:
    client_id = "7D53E0326CD786675180B9E1EA334A06CE8CE24722D1EFF3A42B06775132BD95"
    client_secret = "81CF0EE81B529170E0E184742148F19ACD2E2FD8A24854E5EC0AFB9F6C3B702A"
    authorization_base_url = 'https://api.home-connect.com/security/oauth/authorize'
    token_url = 'https://api.home-connect.com/security/oauth/token'


@app.route("/")
def demo():
    """Step 1: User Authorization.

    Redirect the user/resource owner to the OAuth provider (i.e. Github)
    using an URL with a few key OAuth parameters.
    """

    github = OAuth2Session(client_id, scope='IdentifyAppliance')
    authorization_url, state = github.authorization_url(authorization_base_url)

    # State is used to prevent CSRF, keep this for later.
    session['oauth_state'] = state

    if(simulated == True):
        return redirect(url_for('.callback'))
    else:
        return redirect(authorization_url)


# Step 2: User authorization, this happens on the provider.

@app.route("/callback", methods=["GET"])
def callback():
    """ Step 3: Retrieving an access token.

    The user has been redirected back from the provider to your registered
    callback URL. With this redirection comes an authorization code included
    in the redirect URL. We will use that to obtain an access token.
    """

    github = OAuth2Session(client_id, state=session['oauth_state'])
    #token = github.fetch_token(token_url, client_secret=client_secret,
    #                           authorization_response=request.url)

    token = github.fetch_token(token_url)

    # At this point you can fetch protected resources but lets save
    # the token and show how this is done from a persisted token
    # in /profile.

    session['oauth_token'] = token

    return redirect(url_for('.profile'))


@app.route("/profile", methods=["GET"])
def profile():
    """Fetching a protected resource using an OAuth 2 token.
    """
    
    if (simulated == True):
        github = OAuth2Session(client_id, token=session['oauth_token'])
        return jsonify(github.get('https://simulator.home-connect.com/api/homeappliances').json())
    else:
        github = OAuth2Session(client_id, token=session['oauth_token'])   
        return jsonify(github.get('https://api.home-connect.com/api/homeappliances').json())


if __name__ == "__main__":
    # This allows us to use a plain HTTP callback
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = "1"

    app.secret_key = os.urandom(24)
    
    app.run(debug=True)