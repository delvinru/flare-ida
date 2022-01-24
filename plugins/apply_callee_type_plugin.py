#!/usr/bin/env python
# Jay Smith
# jay.smith@mandiant.com
#
########################################################################
# Copyright 2014 Mandiant/FireEye
# Copyright 2019 FireEye
#
# Mandiant/Fireye licenses this file to you under the Apache License, Version
# 2.0 (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at:
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.
########################################################################
#
# Mostly a glorified wrapper around the apply_callee_tinfo() idasdk function.
# Useful for when IDA doesn't apply stack analysis to an indirect call,
# and you can identify the function prototype during reverse engineering.
#
########################################################################

# Also based on code: github.com/oaLabs/hexcopy-ida/

import sys

import idc
import idautils
import idaapi

idaapi.require("flare")
idaapi.require("flare.apply_callee_type")
idaapi.require("flare.jayutils")

PLUGIN_NAME = "ApplyCalleeType"
PLUGIN_HOTKEY = "Shift+C"

# get the IDA version number
ida_major, ida_minor = map(int, idaapi.get_kernel_version().split("."))
using_ida7api = ida_major > 6

ex_addmenu_item_ctx = None


def PLUGIN_ENTRY():
    try:
        return apply_callee_type_plugin_t()
    except Exception as err:
        import traceback

        idaapi.msg("Error: %s\n%s" % (str(err), traceback.format_exc()))
        raise


# =======================================
# some handler
# =======================================
class ApplyCalleeHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        self._apply_callee()
        return True

    def update(self, ctx):
        return (
            idaapi.AST_ENABLE_FOR_WIDGET
            if ctx.widget_type == idaapi.BWN_DISASM
            or ctx.widget_type == idaapi.BWN_PSEUDOCODE
            else idaapi.AST_DISABLE_FOR_WIDGET
        )

    def _apply_callee(self, *args):
        flare.apply_callee_type.main()


# =======================================
# Entry point
# =======================================
class apply_callee_type_plugin_t(idaapi.plugin_t):
    """
    Apply Callee type plugin
    """

    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "Aplly callee type to indirect call location"
    help = "This is help ¯\_(ツ)_/¯"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        """
        Default handler for IDA
        """
        # Setup menu
        self._init_menu()

        # Setup hooks
        self._init_hooks()

        idaapi.msg("[%s] init\n" % self.wanted_name)
        return idaapi.PLUGIN_KEEP

    def run(self, args):
        flare.apply_callee_type.main()

    def term(self):
        self._hooks.unhook()
        self._del_action_callee()

    def _init_hooks(self):
        self._hooks = Hooks()
        self._hooks.ready_to_run = self._init_hexrays_hooks
        self._hooks.hook()

    def _init_hexrays_hooks(self):
        if idaapi.init_hexrays_plugin():
            idaapi.install_hexrays_callback(self._hooks.hxe_callback)

    # IDA Actions
    ACTION_NAME = "flare:apply_callee_type"

    def _init_menu(self):
        if hasattr(sys.modules["idaapi"], "_apply_callee_type_plugin_installFlag"):
            return

        action_desc = idaapi.action_desc_t(
            self.ACTION_NAME,  # Name. Acts as an ID. Must be unique.
            self.wanted_name,  # Label. That's what users see.
            ApplyCalleeHandler(),  # Handler. Called when activated, and for updating
            PLUGIN_HOTKEY,  # Shortcut (optional)
            self.comment,  # Tooltip (optional)
        )

        # Register action in IDA
        assert idaapi.register_action(action_desc), "Action registration failed"

        setattr(sys.modules["idaapi"], "_apply_callee_type_plugin_installFlag", True)

    def _del_action_callee(self):
        idaapi.unregister_action(self.ACTION_NAME)


# =======================================
# Hooks
# =======================================
class Hooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        """
        A right click menu is about to be shown. (IDA 7)
        """
        inject_callee_actions(widget, popup, idaapi.get_widget_type(widget))
        return 0

    def hxe_callback(self, event, *args):
        if event == idaapi.hxe_populating_popup:
            form, popup, vu = args

            idaapi.attach_action_to_popup(
                form,
                popup,
                apply_callee_type_plugin_t.ACTION_NAME,
                "Apply callee type plugin",
                idaapi.SETMENU_APP,
            )
        return 0


# =======================================
# Prefix
# =======================================
def inject_callee_actions(form, popup, form_type):
    # for work only in disasm or pseucode view
    if form_type == idaapi.BWN_DISASMS or form_type == idaapi.BWN_PSEUDOCODE:
        idaapi.attach_action_to_popup(
            form,
            popup,
            apply_callee_type_plugin_t.ACTION_NAME,
            "Apply callee type plugin",
            idaapi.SETMENU_APP,
        )
    return 0
