import logging

import client1.plugins as p
from ..plugins.utilities import add_route

from ..views.public_views import (
    NotFoundView,
    HomeView,
    log_out_view,
    LoginView,
    RegisterView,
    RefreshSessionView,
    ErrorView,
    Gravatar,
    ## *****************************vvvvv********************************
    Git_loginView,
    Ggl_loginView,
    Git_loginSuccess,
    Ggl_loginSuccess,
    Rmb_loginView,
    Rmb_loginSuccess,

    ## *****************************^^^^^********************************

)
from ..views.private_views import UserPrivatePageView

log = logging.getLogger("client1")

route_list = []


def append_to_routes(route_array):
    """
    #This function append or overrides the routes to the main list
    :param route_array: Array of routes
    """
    for new_route in route_array:
        found = False
        pos = 0
        for curr_route in route_list:
            if curr_route["path"] == new_route["path"]:
                found = True
                break
            pos = pos + 1
        if not found:
            route_list.append(new_route)
        else:
            route_list[pos]["name"] = new_route["name"]
            route_list[pos]["view"] = new_route["view"]
            route_list[pos]["renderer"] = new_route["renderer"]


def load_routes(config):
    """
    Call connected to plugins to add any routes before client1
    :param config: Pyramid config
    """
    routes = []
    for plugin in p.PluginImplementations(p.IRoutes):
        routes = plugin.before_mapping(config)
        append_to_routes(routes)

    # client1 public routes
    routes.append(add_route("home", "/", HomeView, "public/index.jinja2"))
    routes.append(
        add_route("refresh", "/refresh", RefreshSessionView, "generic/refresh.jinja2")
    )
    routes.append(add_route("login", "/login", LoginView, "user/login.jinja2"))
    routes.append(add_route("register", "/join", RegisterView, "user/register.jinja2"))
    routes.append(add_route("logout", "/logout", log_out_view, None))
    routes.append(add_route("gravatar", "/gravatar", Gravatar, None))
    ##**************************************vvvvv****************************************
    routes.append(add_route("git_login", "/git_login", Git_loginView, None))
    routes.append(add_route("git_login_success", "/git_login_success", Git_loginSuccess, None))
    routes.append(add_route("ggl_login", "/ggl_login", Ggl_loginView, None))
    routes.append(add_route("ggl_login_success", "/ggl_login_success", Ggl_loginSuccess, None))
    routes.append(add_route("rmb_login", "/rmb_login", Rmb_loginView, None))
    routes.append(add_route("rmb_login_success", "/rmb_login_success", Rmb_loginSuccess, None))
    ##*************************************^^^^^*****************************************

    # client1 private routes
    routes.append(
        add_route(
            "private", "/user/{userid}", UserPrivatePageView, "private/index.jinja2"
        )
    )

    append_to_routes(routes)

    # Add the not found route
    config.add_notfound_view(NotFoundView, renderer="generic/404.jinja2")

    if log.level == logging.WARN:
        config.add_view(ErrorView, context=Exception, renderer="generic/500.jinja2")

    # Call connected plugins to add any routes after client1
    for plugin in p.PluginImplementations(p.IRoutes):
        routes = plugin.after_mapping(config)
        append_to_routes(routes)

    # Now add the routes and views to the Pyramid config
    for curr_route in route_list:
        config.add_route(curr_route["name"], curr_route["path"])
        config.add_view(
            curr_route["view"],
            route_name=curr_route["name"],
            renderer=curr_route["renderer"],
        )
