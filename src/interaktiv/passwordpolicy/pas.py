from collections.abc import Callable
from Products.PluggableAuthService.PluggableAuthService import PluggableAuthService
from typing import Any
from zope.interface.interface import InterfaceClass


def add_plugin(
    pas: PluggableAuthService,
    plugin_id: str,
    manage_add: Callable[..., Any],
    plugin_title: str = "",
) -> None:
    if plugin_id in pas.objectIds():
        return

    manage_add(pas, plugin_id, plugin_title)
    plugin = pas[plugin_id]

    for info in pas.plugins.listPluginTypeInfo():
        interface = info["interface"]

        if not interface.providedBy(plugin):
            continue

        pas.plugins.activatePlugin(interface, plugin.getId())
        # move it to the top
        pas.plugins.movePluginsDown(
            interface, [x[0] for x in pas.plugins.listPlugins(interface)[:-1]]
        )


def remove_plugin(pas: PluggableAuthService, plugin_id: str) -> None:
    if plugin_id in pas.objectIds():
        pas.manage_delObjects([plugin_id])


def activate_plugin_interface(
    pas: PluggableAuthService, plugin_id: str, plugin_interface: InterfaceClass
) -> None:
    if plugin_id not in pas.objectIds():
        return

    active_plugins = [p[0] for p in pas.plugins.listPlugins(plugin_interface)]

    if plugin_id not in active_plugins:
        pas.plugins.activatePlugin(plugin_interface, plugin_id)


def deactivate_plugin_interface(
    pas: PluggableAuthService, plugin_id: str, plugin_interface: InterfaceClass
) -> None:
    active_plugins = [p[0] for p in pas.plugins.listPlugins(plugin_interface)]

    if plugin_id in active_plugins:
        pas.plugins.deactivatePlugin(plugin_interface, plugin_id)
