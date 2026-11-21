import os

app = defines["app"]
app_name = os.path.basename(app)

format = "UDZO"
files = [app]
symlinks = {"Applications": "/Applications"}

window_rect = ((200, 120), (600, 400))
icon_size = 100
icon_locations = {
    app_name: (150, 190),
    "Applications": (450, 190),
}
show_status_bar = False
show_tab_view = False
show_toolbar = False
show_pathbar = False
show_sidebar = False
