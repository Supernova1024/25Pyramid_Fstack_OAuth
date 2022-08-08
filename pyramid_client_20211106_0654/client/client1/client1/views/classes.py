# -*- coding: utf-8 -*-
"""
    client1.resources.resources
    ~~~~~~~~~~~~~~~~~~

    Provides the basic view classes for client1 and
    the Digest Authorization for ODK

    :copyright: (c) 2017 by QLands Technology Consultants.
    :license: AGPL, see LICENSE for more details.
"""

import json
import logging
from ast import literal_eval

from babel import Locale
from formencode.variabledecode import variable_decode
from pyramid.httpexceptions import HTTPFound
from pyramid.httpexceptions import HTTPNotFound, exception_response
from pyramid.response import Response
from pyramid.session import check_csrf_token

from client1.processes.db import (
    user_exists,
    get_user_details,
    get_user_by_api_key,
)
from .. import plugins as p
from ..config.auth import get_user_data

log = logging.getLogger("client1")


class PublicView(object):
    """
    This is the most basic public view. Used for 404 and 500. But then used for others more advanced classes
    """

    def __init__(self, request):
        self.request = request
        self._ = self.request.translate
        self.resultDict = {"errors": []}
        self.errors = []
        self.returnRawViewResult = False
        locale = Locale(request.locale_name)
        if locale.character_order == "left-to-right":
            self.resultDict["rtl"] = False
        else:
            self.resultDict["rtl"] = True

    def __call__(self):
        self.resultDict["errors"] = self.errors

        i_public_view_implementations = p.PluginImplementations(p.IPublicView)
        for plugin in i_public_view_implementations:
            plugin.before_processing(self.request)

        process_dict = self.process_view()

        for plugin in i_public_view_implementations:
            process_dict = plugin.after_processing(self.request, process_dict)

        if not self.returnRawViewResult:
            self.resultDict.update(process_dict)
            return self.resultDict
        else:
            return process_dict

    def process_view(self):
        raise NotImplementedError("process_view must be implemented in subclasses")

    def get_post_dict(self):
        dct = variable_decode(self.request.POST)
        return dct

    def append_to_errors(self, error):
        self.request.response.headers["client1_error"] = "true"
        self.errors.append(error)


class PrivateView(object):
    def __init__(self, request):
        self.request = request
        self.user = None
        self._ = self.request.translate
        self.errors = []
        self.userID = ""
        self.classResult = {}
        self.viewResult = {}
        self.returnRawViewResult = False
        self.viewingSelfAccount = True
        self.showWelcome = False
        self.checkCrossPost = True
        locale = Locale(request.locale_name)
        if locale.character_order == "left-to-right":
            self.classResult["rtl"] = False
        else:
            self.classResult["rtl"] = True
        self.classResult["activeMenu"] = ""

    def append_to_errors(self, error):
        self.request.response.headers["client1_error"] = "true"
        self.errors.append(error)

    def get_policy(self, policy_name):
        policies = self.request.policies()
        for policy in policies:
            if policy["name"] == policy_name:
                return policy["policy"]
        return None

    def check_post_put_delete(self):
        if (
            self.request.method == "POST"
            or self.request.method == "PUT"
            or self.request.method == "DELETE"
        ):
            if (
                self.request.registry.settings.get("perform_post_checks", "true")
                == "true"
            ):
                safe = check_csrf_token(self.request, raises=False)
                if not safe:
                    self.request.session.pop_flash()
                    log.error("SECURITY-CSRF error at {} ".format(self.request.url))
                    raise HTTPFound(self.request.route_url("refresh"))
                else:
                    if self.checkCrossPost:
                        if self.request.referer != self.request.url:
                            self.request.session.pop_flash()
                            log.error(
                                "SECURITY-CrossPost error. Posting at {} from {} ".format(
                                    self.request.url, self.request.referer
                                )
                            )
                            raise HTTPNotFound()

    def check_authorization(self):
        policy = self.get_policy("main")
        login_data = policy.authenticated_userid(self.request)
        if login_data is not None:
            login_data = literal_eval(login_data)
            if login_data["group"] == "mainApp":
                self.user = get_user_data(login_data["login"], self.request)
                self.classResult["activeUser"] = self.user
                if self.user is None:
                    raise HTTPFound(
                        location=self.request.route_url(
                            "login", _query={"next": self.request.url}
                        )
                    )
                self.check_post_put_delete()
            else:
                raise HTTPFound(
                    location=self.request.route_url(
                        "login", _query={"next": self.request.url}
                    )
                )
        else:
            raise HTTPFound(
                location=self.request.route_url(
                    "login", _query={"next": self.request.url}
                )
            )

    def __call__(self):
        error = self.request.session.pop_flash(queue="error")
        if len(error) > 0:
            self.append_to_errors(error[0].replace("|error", ""))

        self.userID = self.request.matchdict["userid"]
        if not user_exists(self.request, self.userID):
            raise HTTPNotFound()
        self.classResult["userDetails"] = get_user_details(self.request, self.userID)

        i_user_authorization = p.PluginImplementations(p.IUserAuthorization)
        continue_authorization = True
        for plugin in i_user_authorization:
            continue_authorization = plugin.before_check_authorization(self.request)
            break  # Only only plugin will be called for before_check_authorization
        if continue_authorization:
            self.check_authorization()
        else:
            authorized = False
            user_authorized = ""
            for plugin in i_user_authorization:
                authorized, user_authorized = plugin.custom_authorization(self.request)
                break  # Only only plugin will be called for custom_authorization
            if authorized:
                self.user = get_user_data(user_authorized, self.request)
                self.classResult["activeUser"] = self.user
                if self.user is None:
                    raise HTTPFound(
                        location=self.request.route_url(
                            "login", _query={"next": self.request.url}
                        )
                    )
                self.check_post_put_delete()
            else:
                raise HTTPFound(
                    location=self.request.route_url(
                        "login", _query={"next": self.request.url}
                    )
                )

        self.classResult["viewingSelfAccount"] = self.viewingSelfAccount
        self.classResult["errors"] = self.errors
        self.classResult["showWelcome"] = self.showWelcome

        i_private_view_implementations = p.PluginImplementations(p.IPrivateView)
        for plugin in i_private_view_implementations:
            plugin.before_processing(
                self.request,
                {
                    "returnRawViewResult": self.returnRawViewResult,
                    "viewingSelfAccount": self.viewingSelfAccount,
                    "showWelcome": self.showWelcome,
                    "checkCrossPost": self.checkCrossPost,
                    "user": self.user,
                },
            )

        self.viewResult = self.process_view()

        if not self.returnRawViewResult:
            self.classResult.update(self.viewResult)
            return self.classResult
        else:
            return self.viewResult

    def process_view(self):
        return {"activeUser": self.user}

    def set_active_menu(self, menu_name):
        self.classResult["activeMenu"] = menu_name

    def get_post_dict(self):
        dct = variable_decode(self.request.POST)
        return dct

    def reload_user_details(self):
        self.classResult["userDetails"] = get_user_details(self.request, self.userID)

    def add_error(self, message):
        self.request.session.flash("{}|error".format(message), queue="error")


class APIView(object):
    def __init__(self, request):
        self.request = request
        self.user = None
        self.api_key = ""
        self._ = self.request.translate
        self.error = False

    def __call__(self):
        if self.request.method == "GET":
            self.api_key = self.request.params.get("apikey", None)
        else:
            self.api_key = self.request.POST.get("apikey", None)
        if self.api_key is not None:
            self.user = get_user_by_api_key(self.request, self.api_key)
            if self.user is None:
                response = Response(
                    content_type="application/json",
                    status=401,
                    body=json.dumps(
                        {
                            "error": self._(
                                "This API key does not exist or is inactive"
                            ),
                            "error_type": "authentication",
                        }
                    ).encode(),
                )
                return response
        else:
            response = Response(
                content_type="application/json",
                status=401,
                body=json.dumps(
                    {
                        "error": self._("You need to specify an API key"),
                        "error_type": "api_key_missing",
                    }
                ).encode(),
            )
            return response

        res = self.process_view()
        if not self.error:
            return res
        else:
            response = Response(
                content_type="application/json",
                status=400,
                body=json.dumps(res).encode(),
            )
            return response

    def process_view(self):
        return {"key": self.api_key}

    def check_keys(self, key_list):
        not_found_keys = []
        for a_key in key_list:
            if a_key not in self.request.POST.keys():
                not_found_keys.append(a_key)
        if not_found_keys:
            json_result = {
                "error": self._(
                    "The following keys were not present in the submitted JSON"
                ),
                "keys": [],
                "error_type": "missing_key",
            }
            for a_key in not_found_keys:
                json_result["keys"].append(a_key)

            response = exception_response(
                400,
                content_type="application/json",
                body=json.dumps(json_result).encode(),
            )
            raise response

    def return_error(self, error_type, error_message):
        response = exception_response(
            400,
            content_type="application/json",
            body=json.dumps(
                {"error": error_message, "error_type": error_type}
            ).encode(),
        )
        raise response
