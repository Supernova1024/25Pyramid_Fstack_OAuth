import os 
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
## github
git_client_id = "97850277ee578cea0b8e"
git_client_secret = "b38555d506b3260e05de4a3e3474a42ece38cdca"
git_authorization_base_url = 'https://github.com/login/oauth/authorize'
git_token_url = 'https://github.com/login/oauth/access_token'
git_profile_url = 'https://api.github.com/user'

## google
ggl_client_id = "222099138393-37bhebuhu81lcgs6vvt568bgbihis3hj.apps.googleusercontent.com"
ggl_client_secret = "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"
ggl_authorization_base_url = 'https://accounts.google.com/o/oauth2/auth'
ggl_token_url = 'https://accounts.google.com/o/oauth2/token'
ggl_profile_url = 'https://www.googleapis.com/oauth2/v1/userinfo'
ggl_scope = ['https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile']
# ggl_redirect_url = 'http://e29b-80-237-47-16.ngrok.io/ggl_login_success'

# ## Rambo
# rmb_client_id = "z3UTnqs2nOFkB4gbrKwQdFpp"
# rmb_client_secret = "BCFwzCKEkS6vSMoPTMpK6hC1wGKY4asp2IeSw1h9hMPlC00a"
# rmb_authorization_base_url = 'https://flask-provider111.herokuapp.com/oauth/authorize' ## Provider
# rmb_token_url = 'https://flask-provider111.herokuapp.com/oauth/token'  ## Provider
# rmb_profile_url = 'https://flask-provider111.herokuapp.com/api/me'   ## Provider
# rmb_scope = 'profile'
# rmb_redirect_url = 'https://1717-80-237-47-16.ngrok.io/rmb_login_success' ## Client 

# authorization_code
# password

## ubuntu
rmb_client_id = "UjPgcldTZFf6dPuh1LJXM9AS"
rmb_client_secret = "aUokWB2y8UfLdqWHtlA0qmCK1hPxB0QyjoI3dqg95xnaPB0N"
rmb_authorization_base_url = 'https://851d-80-237-47-16.ngrok.io/oauth/authorize' ## Provider
rmb_token_url =              'https://851d-80-237-47-16.ngrok.io/oauth/token'  ## Provider
rmb_profile_url =            'https://851d-80-237-47-16.ngrok.io/api/me'   ## Provider
rmb_scope = 'profile'
rmb_redirect_url =           'https://ae89-80-237-47-16.ngrok.io/rmb_login_success' ## Client 

# ## windows
# rmb_client_id = "K85OCLus2rjdjnVmaLddQi56"
# rmb_client_secret = "jjdPRi5PADM9F9Ea5oQhBlS6N6jAtd1tzSsMINnI4ULz6oWm"
# rmb_authorization_base_url = 'https://fcdd-80-237-47-16.ngrok.io/oauth/authorize' ## Provider
# rmb_token_url =              'https://fcdd-80-237-47-16.ngrok.io/oauth/token'  ## Provider
# rmb_profile_url =            'https://fcdd-80-237-47-16.ngrok.io/api/me'   ## Provider
# rmb_scope = 'profile'
# rmb_redirect_url =           'https://dba2-80-237-47-16.ngrok.io/rmb_login_success' ## Client 
