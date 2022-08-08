import datetime
import logging
import re
import traceback
import uuid
from ast import literal_eval

import validators
from formencode.variabledecode import variable_decode
from pyramid.httpexceptions import HTTPFound
from pyramid.httpexceptions import HTTPNotFound
from pyramid.response import Response
from pyramid.security import remember
from pyramid.session import check_csrf_token

import client1.plugins as p
from client1.config.encdecdata import encode_data
from client1.processes.avatar import Avatar
from .classes import PublicView
from ..config.auth import get_user_data
from ..processes.db import (
    register_user,
    update_last_login,
)
#*****************************************vvvvv***************************************
from requests_oauthlib import OAuth2Session
from client1.config import conf
from webob import Response
import json
import string
import random

def pass_generator(size=200, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))
#*****************************************^^^^^****************************************
log = logging.getLogger("client1")


class HomeView(PublicView):
    def process_view(self):
        return {"activeUser": None}


class NotFoundView(PublicView):
    def process_view(self):
        self.request.response.status = 404
        return {}


class Gravatar(PublicView):
    def process_view(self):
        self.returnRawViewResult = True
        try:
            size = int(self.request.params.get("size", 45))
        except ValueError:
            size = 45
        name = self.request.params.get("name", "#")
        avatar = Avatar.generate(size, name, "PNG")
        headers = [("Content-Type", "image/png")]
        return Response(avatar, 200, headers)


class ErrorView(PublicView):
    def process_view(self):
        user = None
        i_user_authorization = p.PluginImplementations(p.IUserAuthorization)
        continue_authorization = True
        for plugin in i_user_authorization:
            continue_authorization = plugin.before_check_authorization(self.request)
            break  # Only only plugin will be called for before_check_authorization
        if continue_authorization:
            policy = get_policy(self.request, "main")
            login_data = policy.authenticated_userid(self.request)
            if login_data is not None:
                login_data = literal_eval(login_data)
                if login_data["group"] == "mainApp":
                    user = login_data["login"]
        else:
            authorized = False
            user_authorized = None
            for plugin in i_user_authorization:
                authorized, user_authorized = plugin.custom_authorization(self.request)
                break  # Only only plugin will be called for custom_authorization
            if authorized:
                user = user_authorized

        if user is None:
            policy = get_policy(self.request, "assistant")
            login_data = policy.authenticated_userid(self.request)
            if login_data is not None:
                login_data = literal_eval(login_data)
                if login_data["group"] == "collaborator":
                    user = login_data["login"]

        if user is None:
            user = "Unknown"
        log.error(
            "Server Error in URL {}.\nAccount: {}\nError: \n{}".format(
                self.request.url, user, traceback.format_exc()
            )
        )
        self.request.response.status = 500
        return {}


class LoginView(PublicView):
    def process_view(self):
        # If we logged in then go to private
        next_page = self.request.params.get("next")
        if self.request.method == "GET":
            policy = get_policy(self.request, "main")
            login_data = policy.authenticated_userid(self.request)
            if login_data is not None:
                login_data = literal_eval(login_data)
                if login_data["group"] == "mainApp":
                    current_user = get_user_data(login_data["login"], self.request)
                    if current_user is not None:
                        self.returnRawViewResult = True
                        return HTTPFound(
                            location=self.request.route_url(
                                "private", userid=current_user.login
                            ),
                            headers={"FS_error": "true"},
                        )
        else:
            if (
                self.request.registry.settings.get("perform_post_checks", "true")
                == "true"
            ):
                safe = check_csrf_token(self.request, raises=False)
                if not safe:
                    raise HTTPNotFound()
            data = variable_decode(self.request.POST)

            login = data["email"]
            passwd = data["passwd"]
            user = get_user_data(login, self.request)
            login_data = {"login": login, "group": "mainApp"}
            if user is not None:
                if user.check_password(passwd, self.request):
                    continue_login = True
                    # Load connected plugins and check if they modify the login authorization
                    for plugin in p.PluginImplementations(p.IUserAuthentication):
                        continue_with_login, error_message = plugin.after_login(
                            self.request, user
                        )
                        if not continue_with_login:
                            self.append_to_errors(error_message)
                            continue_login = False
                        break  # Only one plugging will be called to extend after_login
                    if continue_login:
                        update_last_login(self.request, user.login)
                        headers = remember(
                            self.request, str(login_data), policies=["main"]
                        )
                        next_page = self.request.params.get(
                            "next"
                        ) or self.request.route_url("private", userid=user.login)
                        self.returnRawViewResult = True
                        print("-----------", headers)
                        return HTTPFound(location=next_page, headers=headers)
                else:
                    log.error(
                        "Logging into account {} provided an invalid password".format(
                            login
                        )
                    )
                    self.append_to_errors(
                        self._(
                            "The user account does not exists or the password is invalid"
                        )
                    )
            else:
                log.error("User account {} does not exist".format(login))
                self.append_to_errors(
                    self._(
                        "The user account does not exists or the password is invalid"
                    )
                )
        return {"next": next_page}


class RefreshSessionView(PublicView):
    def process_view(self):
        return {}


def get_policy(request, policy_name):
    policies = request.policies()
    for policy in policies:
        if policy["name"] == policy_name:
            return policy["policy"]
    return None


def log_out_view(request):
    policy = get_policy(request, "main")
    headers = policy.forget(request)
    loc = request.route_url("home")
    raise HTTPFound(location=loc, headers=headers)
#*********************************vvvvv****************************
class Git_loginView(PublicView):
    def process_view(self):
        session = self.request.session
        github = OAuth2Session(conf.git_client_id)
        authorization_url, state = github.authorization_url(conf.git_authorization_base_url)
        # State is used to prevent CSRF, keep this for later.
        session['git_oauth_state'] = state
        self.returnRawViewResult = True
        return HTTPFound(location=authorization_url)

class Git_loginSuccess(PublicView):
    def process_view(self):
        session = self.request.session
        github = OAuth2Session(conf.git_client_id, state=session['git_oauth_state'])
        self.returnRawViewResult = True
        token = github.fetch_token(conf.git_token_url, client_secret=conf.git_client_secret,
                               authorization_response=self.request.url)
        session['git_oauth_token'] = token
        profile_info = github.get(conf.git_profile_url).json()
        email = profile_info['email']
        login = email
        user = get_user_data(login, self.request)
        login_data = {"login": login, "group": "mainApp"}

        if user is not None: ## login
            update_last_login(self.request, user.login)
            headers = remember(
                self.request, str(login_data), policies=["main"]
            )
            next_page = self.request.params.get(
                "next"
            ) or self.request.route_url("private", userid=user.login)
            self.returnRawViewResult = True
            return HTTPFound(location=next_page, headers=headers)

        else:  ## register 
            data = {}
            data["csrf_token"] = token
            data["user_name"] = profile_info['name']
            data["user_email"] = email
            data["user_id"] = profile_info['login']
            data["user_apikey"] = str(uuid.uuid4())
            data["user_password"] = pass_generator() + data["user_apikey"]
            data["user_password2"] = pass_generator()
            data["user_cdate"] = datetime.datetime.now()
            data["user_active"] = 1
            added, error_message = register_user(
                self.request, data
            )
            if not added:
                self.append_to_errors(error_message)
            else:
                # Load connected plugins so they perform actions after the registration
                # is performed
                next_page = self.request.route_url(
                    "private", userid=data["user_id"]
                )
                plugin_next_page = ""
                for plugin in p.PluginImplementations(
                    p.IRegistration
                ):
                    plugin_next_page = plugin.after_register(
                        self.request, data
                    )
                    break  # Only one plugging will be called to extend after_register
                if plugin_next_page is not None:
                    if plugin_next_page != "":
                        if plugin_next_page != next_page:
                            next_page = plugin_next_page
                if next_page == self.request.route_url(
                    "private", userid=data["user_id"]
                ):
                    login_data = {
                        "login": data["user_id"],
                        "group": "mainApp",
                    }
                    headers = remember(
                        self.request,
                        str(login_data),
                        policies=["main"],
                    )
                    self.returnRawViewResult = True
                    return HTTPFound(
                        location=self.request.route_url(
                            "private", userid=data["user_id"]
                        ),
                        headers=headers,
                    )
                else:
                    self.returnRawViewResult = True
                    return HTTPFound(next_page)

class Ggl_loginView(PublicView):
    def process_view(self):
        session = self.request.session
        google = OAuth2Session(conf.ggl_client_id, redirect_uri=conf.ggl_redirect_url, scope=conf.ggl_scope)
        authorization_url, state = google.authorization_url(conf.ggl_authorization_base_url)
        
        # State is used to prevent CSRF, keep this for later.
        session['ggl_oauth_state'] = state
        self.returnRawViewResult = True
        return HTTPFound(location=authorization_url)

class Ggl_loginSuccess(PublicView):
    def process_view(self):
        session = self.request.session
        google = OAuth2Session(conf.ggl_client_id, state=session['ggl_oauth_state'], redirect_uri=conf.ggl_redirect_url)
        self.returnRawViewResult = True
        token = google.fetch_token(conf.ggl_token_url, client_secret=conf.ggl_client_secret,
                               authorization_response=self.request.url)
        session['ggl_oauth_token'] = token
        profile_info = google.get(conf.ggl_profile_url).json()
        email = profile_info['email']
        login = email
        user = get_user_data(login, self.request)
        login_data = {"login": login, "group": "mainApp"}

        if user is not None: ## login
            update_last_login(self.request, user.login)
            headers = remember(
                self.request, str(login_data), policies=["main"]
            )
            next_page = self.request.params.get(
                "next"
            ) or self.request.route_url("private", userid=user.login)
            self.returnRawViewResult = True
            return HTTPFound(location=next_page, headers=headers)

        else:  ## register 
            data = {}
            data["csrf_token"] = token
            data["user_name"] = profile_info['name']
            data["user_email"] = email
            data["user_id"] = profile_info['given_name']
            data["user_apikey"] = str(uuid.uuid4())
            data["user_password"] = pass_generator() + data["user_apikey"]
            data["user_password2"] = pass_generator()
            data["user_cdate"] = datetime.datetime.now()
            data["user_active"] = 1
            added, error_message = register_user(
                self.request, data
            )
            if not added:
                self.append_to_errors(error_message)
            else:
                # Load connected plugins so they perform actions after the registration
                # is performed
                next_page = self.request.route_url(
                    "private", userid=data["user_id"]
                )
                plugin_next_page = ""
                for plugin in p.PluginImplementations(
                    p.IRegistration
                ):
                    plugin_next_page = plugin.after_register(
                        self.request, data
                    )
                    break  # Only one plugging will be called to extend after_register
                if plugin_next_page is not None:
                    if plugin_next_page != "":
                        if plugin_next_page != next_page:
                            next_page = plugin_next_page
                if next_page == self.request.route_url(
                    "private", userid=data["user_id"]
                ):
                    login_data = {
                        "login": data["user_id"],
                        "group": "mainApp",
                    }
                    headers = remember(
                        self.request,
                        str(login_data),
                        policies=["main"],
                    )
                    self.returnRawViewResult = True
                    return HTTPFound(
                        location=self.request.route_url(
                            "private", userid=data["user_id"]
                        ),
                        headers=headers,
                    )
                else:
                    self.returnRawViewResult = True
                    return HTTPFound(next_page)

class Rmb_loginView(PublicView):
    def process_view(self):
        session = self.request.session
        rambo = OAuth2Session(conf.rmb_client_id, scope=conf.rmb_scope)
        authorization_url, state = rambo.authorization_url(conf.rmb_authorization_base_url)
        
        # State is used to prevent CSRF, keep this for later.
        session['rmb_oauth_state'] = state
        self.returnRawViewResult = True
        return HTTPFound(location=authorization_url)

class Rmb_loginSuccess(PublicView):
    def process_view(self):

        session = self.request.session
        rambo = OAuth2Session(conf.rmb_client_id, state=session['rmb_oauth_state'], redirect_uri=conf.rmb_redirect_url)
        self.returnRawViewResult = True
        token = rambo.fetch_token(conf.rmb_token_url, client_secret=conf.rmb_client_secret,
                               authorization_response=self.request.url)
        session['rmb_oauth_token'] = token
        profile_info = rambo.get(conf.rmb_profile_url).json()
        email = profile_info['email']
        login = email
        user = get_user_data(login, self.request)
        login_data = {"login": login, "group": "mainApp"}

        if user is not None: ## login
            update_last_login(self.request, user.login)
            headers = remember(
                self.request, str(login_data), policies=["main"]
            )
            next_page = self.request.params.get(
                "next"
            ) or self.request.route_url("private", userid=user.login)
            self.returnRawViewResult = True
            return HTTPFound(location=next_page, headers=headers)

        else:  ## register 
            data = {}
            data["csrf_token"] = token
            data["user_name"] = profile_info['name']
            data["user_email"] = email
            data["user_id"] = profile_info['given_name']
            data["user_apikey"] = str(uuid.uuid4())
            data["user_password"] = pass_generator() + data["user_apikey"]
            data["user_password2"] = pass_generator()
            data["user_cdate"] = datetime.datetime.now()
            data["user_active"] = 1
            added, error_message = register_user(
                self.request, data
            )
            if not added:
                self.append_to_errors(error_message)
            else:
                # Load connected plugins so they perform actions after the registration
                # is performed
                next_page = self.request.route_url(
                    "private", userid=data["user_id"]
                )
                plugin_next_page = ""
                for plugin in p.PluginImplementations(
                    p.IRegistration
                ):
                    plugin_next_page = plugin.after_register(
                        self.request, data
                    )
                    break  # Only one plugging will be called to extend after_register
                if plugin_next_page is not None:
                    if plugin_next_page != "":
                        if plugin_next_page != next_page:
                            next_page = plugin_next_page
                if next_page == self.request.route_url(
                    "private", userid=data["user_id"]
                ):
                    login_data = {
                        "login": data["user_id"],
                        "group": "mainApp",
                    }
                    headers = remember(
                        self.request,
                        str(login_data),
                        policies=["main"],
                    )
                    self.returnRawViewResult = True
                    return HTTPFound(
                        location=self.request.route_url(
                            "private", userid=data["user_id"]
                        ),
                        headers=headers,
                    )
                else:
                    self.returnRawViewResult = True
                    return HTTPFound(next_page)

#*****************************^^^^^*******************************

class RegisterView(PublicView):
    def process_view(self):
        # If we logged in then go to private
        if self.request.method == "GET":
            data = {}
        else:
            if (
                self.request.registry.settings.get("perform_post_checks", "true")
                == "true"
            ):
                safe = check_csrf_token(self.request, raises=False)
                if not safe:
                    raise HTTPNotFound()
            data = variable_decode(self.request.POST)

            if validators.email(data["user_email"]):
                if data["user_password"] != "":
                    if re.match(r"^[A-Za-z0-9._]+$", data["user_id"]):
                        if data["user_password"] == data["user_password2"]:
                            if len(data["user_password"]) <= 50:
                                data["user_cdate"] = datetime.datetime.now()
                                if "user_apikey" not in data.keys():
                                    data["user_apikey"] = str(uuid.uuid4())
                                data["user_password"] = encode_data(
                                    self.request, data["user_password"]
                                )
                                data["user_active"] = 1
                                # Load connected plugins and check if they modify the registration of an user
                                continue_registration = True
                                for plugin in p.PluginImplementations(p.IRegistration):
                                    (
                                        data,
                                        continue_with_registration,
                                        error_message,
                                    ) = plugin.before_register(self.request, data)
                                    if not continue_with_registration:
                                        self.append_to_errors(error_message)
                                        continue_registration = False
                                    break  # Only one plugging will be called to extend before_register
                                if continue_registration:
                                    print("-------data-----", data)
                                    added, error_message = register_user(
                                        self.request, data
                                    )
                                    if not added:
                                        self.append_to_errors(error_message)
                                    else:
                                        # Load connected plugins so they perform actions after the registration
                                        # is performed
                                        next_page = self.request.route_url(
                                            "private", userid=data["user_id"]
                                        )
                                        plugin_next_page = ""
                                        for plugin in p.PluginImplementations(
                                            p.IRegistration
                                        ):
                                            plugin_next_page = plugin.after_register(
                                                self.request, data
                                            )
                                            break  # Only one plugging will be called to extend after_register
                                        if plugin_next_page is not None:
                                            if plugin_next_page != "":
                                                if plugin_next_page != next_page:
                                                    next_page = plugin_next_page
                                        if next_page == self.request.route_url(
                                            "private", userid=data["user_id"]
                                        ):
                                            login_data = {
                                                "login": data["user_id"],
                                                "group": "mainApp",
                                            }
                                            headers = remember(
                                                self.request,
                                                str(login_data),
                                                policies=["main"],
                                            )
                                            self.returnRawViewResult = True
                                            return HTTPFound(
                                                location=self.request.route_url(
                                                    "private", userid=data["user_id"]
                                                ),
                                                headers=headers,
                                            )
                                        else:
                                            self.returnRawViewResult = True
                                            return HTTPFound(next_page)
                            else:
                                self.append_to_errors(
                                    self._(
                                        "The password must be less than 50 characters"
                                    )
                                )
                        else:
                            log.error(
                                "Password {} and confirmation {} are not the same".format(
                                    data["user_password"], data["user_password2"]
                                )
                            )
                            self.append_to_errors(
                                self._(
                                    "The password and its confirmation are not the same"
                                )
                            )
                    else:
                        log.error(
                            "Registering user {} has invalid characters".format(
                                data["user_id"]
                            )
                        )
                        self.append_to_errors(
                            self._(
                                "The user id has invalid characters. Only underscore "
                                "and dot are allowed"
                            )
                        )
                else:
                    log.error(
                        "Registering user {} has empty password".format(data["user_id"])
                    )
                    self.append_to_errors(self._("The password cannot be empty"))
            else:
                log.error("Invalid email {}".format(data["user_email"]))
                self.append_to_errors(self._("Invalid email"))
        return {"next": next, "userdata": data}
