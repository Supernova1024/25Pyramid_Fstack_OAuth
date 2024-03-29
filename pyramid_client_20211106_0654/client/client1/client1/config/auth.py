import validators
from sqlalchemy import func

from client1.models import User as userModel
from client1.plugins.core import PluginImplementations
from client1.plugins.interfaces import IUserAuthentication
from .encdecdata import decode_data
from ..models import map_from_schema


class User(object):
    """
    This class represents a user in the system
    """

    def __init__(self, user_data):
        self.id = user_data["user_id"]
        self.email = user_data["user_email"]
        self.userData = user_data
        self.login = user_data["user_id"]
        self.name = user_data["user_name"]
        self.super = user_data["user_super"]
        self.gravatarURL = "#"
        if user_data["user_about"] is None:
            self.about = ""
        else:
            self.about = user_data["user_about"]
        self.apikey = user_data["user_apikey"]

    def check_password(self, password, request):
        self.set_gravatar_url(request, self.name, 45)
        # Load connected plugins and check if they modify the password authentication
        plugin_result = None
        for plugin in PluginImplementations(IUserAuthentication):
            plugin_result = plugin.on_authenticate_password(
                request, self.login, password
            )
            break  # Only one plugging will be called to extend authenticate_user
        if plugin_result is None:
            return check_login(self.login, password, request)
        else:
            return plugin_result

    def set_gravatar_url(self, request, name, size):
        self.gravatarURL = request.route_url(
            "gravatar", _query={"name": name, "size": size}
        )


def get_client1_user_data(request, user, is_email):
    if is_email:
        return map_from_schema(
            request.dbsession.query(userModel)
            .filter(func.lower(userModel.user_email) == func.lower(user))
            .filter(userModel.user_active == 1)
            .first()
        )
    else:
        return map_from_schema(
            request.dbsession.query(userModel)
            .filter(userModel.user_id == user)
            .filter(userModel.user_active == 1)
            .first()
        )


def get_user_data(user, request):
    email_valid = validators.email(user)
    # Load connected plugins and check if they modify the user authentication
    plugin_result = None
    plugin_result_dict = {}
    for plugin in PluginImplementations(IUserAuthentication):
        plugin_result, plugin_result_dict = plugin.on_authenticate_user(
            request, user, email_valid
        )
        break  # Only one plugging will be called to extend authenticate_user
    if plugin_result is not None:
        if plugin_result:
            # The plugin authenticated the user. Check now that such user exists in client1.
            internal_user = get_client1_user_data(request, user, email_valid)
            if internal_user:
                return User(plugin_result_dict)
            else:
                return None
        else:
            return None
    else:
        result = get_client1_user_data(request, user, email_valid)
        if result:
            result["user_password"] = ""  # Remove the password form the result
            return User(result)
        return None


def check_login(user, password, request):
    result = (
        request.dbsession.query(userModel)
        .filter(userModel.user_id == user)
        .filter(userModel.user_active == 1)
        .first()
    )
    if result is None:
        return False
    else:
        cpass = decode_data(request, result.user_password.encode())
        if cpass == bytearray(password.encode()):
            return True
        else:
            return False
