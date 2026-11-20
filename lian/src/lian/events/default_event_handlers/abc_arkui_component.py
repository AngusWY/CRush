


from lian.events.handler_template import EventData
import lian.events.event_return as er
from lian.common_structs import State
from lian.externs.modeling.abc_arkui import ARKUI_PARENT_BY_STATE_ID


ARKUI_PARENT_FIELD = "__arkui_parent"
ARKUI_CHILD_FIELD = "__arkui_child"


def _arg_state_indexes(in_data, position):

    args = getattr(in_data, "args", None)
    positional_args = getattr(args, "positional_args", None) or []
    if position >= len(positional_args):
        return set()
    return {
        arg.index_in_space
        for arg in positional_args[position]
        if getattr(arg, "index_in_space", -1) >= 0
    }


def model_arkui_component_parent(data: EventData):

    in_data = data.in_data
    frame = in_data.frame
    defined_symbol = getattr(in_data, "defined_symbol", None)
    app_return = er.config_event_unprocessed()
    if defined_symbol is None:
        return er.config_continue_event_processing(app_return)


    parent_states = {
        index
        for index in _arg_state_indexes(in_data, 0)
        if isinstance(frame.symbol_state_space[index], State)
    }
    if not parent_states:
        return er.config_continue_event_processing(app_return)


    child_states = set((getattr(in_data, "type_state_to_new_index", None) or {}).values())
    if not child_states:
        child_states = set(getattr(defined_symbol, "states", set()) or set())

    for child_index in child_states:
        child_state = frame.symbol_state_space[child_index]
        if not isinstance(child_state, State):
            continue
        child_state.fields.setdefault(ARKUI_PARENT_FIELD, set()).update(parent_states)
        child_state_id = getattr(child_state, "state_id", None)
        if child_state_id is not None:


            space_id = id(frame.symbol_state_space)
            ARKUI_PARENT_BY_STATE_ID.setdefault(child_state_id, set()).update(
                (space_id, index) for index in parent_states
            )
        for parent_index in parent_states:
            parent_state = frame.symbol_state_space[parent_index]
            if isinstance(parent_state, State):
                parent_state.fields.setdefault(ARKUI_CHILD_FIELD, set()).add(child_index)

    return er.config_continue_event_processing(app_return)
