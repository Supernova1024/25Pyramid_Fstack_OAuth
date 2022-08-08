import os

import client1.resources as r


def create_resources(apppath, config):
    r.add_library("main_library", os.path.join(apppath, "jsandcss"), config)

    # ----------------------------Basic CSS-----------------------
    r.add_css_resource(
        "main_library", "font-awesome", "plugins/fontawesome-free/css/all.min.css"
    )
    r.add_css_resource("main_library", "adminlte", "css/adminlte.min.css")

    # ----------------------------Basic JS----------------------------------------------------
    r.add_js_resource("main_library", "jquery", "plugins/jquery/jquery.min.js")
    r.add_js_resource(
        "main_library", "bootstrap", "plugins/bootstrap/js/bootstrap.bundle.min.js"
    )
    r.add_js_resource("main_library", "adminlte", "js/adminlte.min.js")
