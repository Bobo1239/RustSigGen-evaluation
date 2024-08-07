import json
import sys

import ida_auto
import ida_funcs
import ida_idp
import ida_kernwin
import ida_loader
import ida_segment
import idautils
import idc

# ida64 -c -A -S"$(pwd)/ida_evaluation.py $(pwd)/out.txt match" /path/to/bin

# NOTE: Can't use `idat64` since our plugin depends on the Qt event loop
# NOTE: Disable Lumina in IDA's settings so we don't depend on external (non-deterministic) data

if len(idc.ARGV) > 1:
    # Batch mode
    f = open(idc.ARGV[1], "w")
    do_matching = idc.ARGV[2] == "match"
else:
    # Interactive mode
    f = sys.stdout
    do_matching = True


def log(msg):
    return f.write(msg + "\n")


# Exit IDA Pro if running in batch mode. Otherwise assume running interactively and don't quit.
def exit_if_batchmode():
    if f != sys.stdout:
        # Don't save `.i64` database file after quitting
        ida_loader.set_database_flag(ida_loader.DBFL_TEMP)
        f.close()
        idc.qexit(0)


def get_all_functions():
    ret = {}
    for ea in idautils.Functions():
        # Assert that Lumina hasn't affected our results
        assert ida_funcs.get_func(ea).flags & ida_funcs.FUNC_LUMINA == 0

        # Ignore imports (Linux)
        if ida_segment.get_segm_name(ida_segment.getseg(ea)) == "extern":
            continue
        # For MSVC binaries this doesn't work since they thunk functions are just in the default
        # .text segment. IDA does know that they're external symbols (since they're colored) but
        # I don't know how to access that flag... Their addresses are stable though so they don't
        # mess up our evaluation too much.

        ret[ea] = ida_funcs.get_func_name(ea)
    return ret


class IdpHook(ida_idp.IDP_Hooks):
    def __init__(self):
        super().__init__()

    def ev_auto_queue_empty(self, typee):
        if typee == ida_auto.AU_CHLB:  # load signature file
            after = get_all_functions()
            log(json.dumps(after))
            exit_if_batchmode()
            self.unhook()
        return 0


# log(ida_nalt.get_input_file_path())

# Wait for initial auto-analysis to complete
ida_auto.auto_wait()

if do_matching:
    idp_hook = IdpHook()
    idp_hook.hook()

    ida_kernwin.process_ui_action("rust:generate_signatures")
else:
    log(json.dumps(get_all_functions()))
    exit_if_batchmode()

# Our IDP hook waits until an "auto-analysis finished" event is triggered. We have to do it this way
# since our plugin action runs asynchronously and doesn't trigger an auto-analysis immediately. The
# hook will then take care of shutting down IDA Pro afterwards.

# # Unused code which doesn't work...
# class IdbHook(ida_idp.IDB_Hooks):
#     def __init__(self):
#         super().__init__()

#     def idasgn_loaded(self, short_sig_name):
#         # Triggered when FLIRT signature is planned; not when it gets used/applied!
#         # Unfortunately it seems like this script itself is in the same execution queue as the FLIRT
#         # application step so we can't block here until the signature is actually applied...
#         log("event: idasgn_loaded")

#     def auto_empty(self):
#         # Only emitted for the initial auto-analysis
#         log("event: auto_empty")

#     def auto_empty_finally(self):
#         # Never emitted???
#         log("event: auto_empty_finally")
