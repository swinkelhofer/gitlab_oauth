# gitlab_oauth

Help on module oauth_flask:

NAME
    oauth_flask

FILE
    /oauth/oauth_flask.py

CLASSES
    OAuth
    User
    
    class OAuth
     |  Methods defined here:
     |  
     |  __init__(self, oauth_provider_uri=None, oauth_authorize_path=None, oauth_token_path=None, oauth_user_path=None, oauth_revoke_path=None, oauth_client_id=None, oauth_client_secret=None, client_signin_uri=None, client_signout_uri=None, client_callback_uri=None, client_uri=None, usermeta_variable_mapping=None)
     |  
     |  authorize(self)
     |  
     |  default_routes(self, sign_in='/sign_in', sign_out='/sign_out', get_token='/get_token', app=None)
     |  
     |  is_oauth_session(self)
     |  
     |  load_defaults(self, provider='gitlab', provider_uri='https://gitlab.com')
     |  
     |  protect(self)
     |  
     |  retrieve_token(self)
     |  
     |  revoke_token(self)
     |  
     |  validate_token(self, access_token)
     |  
     |  ----------------------------------------------------------------------
     |  Data and other attributes defined here:
     |  
     |  client_callback_uri = None
     |  
     |  client_signin_uri = None
     |  
     |  client_signout_uri = None
     |  
     |  client_uri = None
     |  
     |  oauth_authorize_path = None
     |  
     |  oauth_client_id = None
     |  
     |  oauth_client_secret = None
     |  
     |  oauth_provider_uri = None
     |  
     |  oauth_revoke_path = None
     |  
     |  oauth_token_path = None
     |  
     |  oauth_user_path = None
     |  
     |  usermeta_variable_mapping = {'email': 'email', 'fullname': 'name', 'is...
    
    class User
     |  Data and other attributes defined here:
     |  
     |  cookie = None
     |  
     |  email = None
     |  
     |  fullname = None
     |  
     |  is_admin = False
     |  
     |  username = None

FUNCTIONS
    multi_oauth(oauth_handlers)

DATA
    logger = <logging.Logger object>
    request = <LocalProxy unbound>
    session = <LocalProxy unbound>


