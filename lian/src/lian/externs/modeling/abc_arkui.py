


from lian.common_structs import Argument, MethodCallArguments, State
from lian.util import util
from lian.config.constants import LIAN_INTERNAL



ARKUI_WRAPPER_MARKERS = (
    "ObservedProperty",
    "SynchedProperty",
    "AppStorage",
    "LocalStorage",
    "SubscriberManager",
    "ViewPU",
)


WRAPPER_VALUE_KEY = "value"





_NAVIGATION_PAYLOADS_BY_SPACE = {}




_COMPONENT_NAME_BY_CALLBACK_METHOD = {}



_LAZY_ITEMS_BY_LIFECYCLE = {}


def _access_path_key(point):
    key = getattr(point, "key", None)
    return key if isinstance(key, str) else ""


def _receiver_state_id(in_data):

    frame = in_data.frame
    for callee_state_index in in_data.unsolved_callee_states:
        callee_state = frame.symbol_state_space[callee_state_index]
        if not isinstance(callee_state, State):
            continue
        access_path = callee_state.access_path
        if len(access_path) >= 2:
            state_id = getattr(access_path[-2], "state_id", -1)
            if isinstance(state_id, int) and state_id >= 0:
                return state_id
    return -1


def _receiver_access_path_key(in_data):

    frame = in_data.frame
    for callee_state_index in in_data.unsolved_callee_states:
        callee_state = frame.symbol_state_space[callee_state_index]
        if not isinstance(callee_state, State):
            continue
        access_path = callee_state.access_path
        if len(access_path) >= 2:
            return _access_path_key(access_path[-2])
    return ""


def _receiver_states(in_data):

    frame = in_data.frame
    resolver = in_data.resolver
    status = in_data.status

    state_id = _receiver_state_id(in_data)
    if state_id >= 0:
        states = {
            index
            for index in resolver.collect_newest_states_by_state_ids(frame, status, {state_id})
            if index >= 0
        }
        if states:
            return states

    if status.used_symbols:
        return set(in_data.state_analysis.read_used_states(status.used_symbols[0], in_data.in_states))
    return set()


def _is_arkui_wrapper_receiver(in_data, receiver_states):

    if _receiver_access_path_key(in_data).startswith("__"):
        return True

    frame = in_data.frame
    for state_index in receiver_states:
        state = frame.symbol_state_space[state_index]
        data_type = str(getattr(state, "data_type", "") or "")
        if any(marker in data_type for marker in ARKUI_WRAPPER_MARKERS):
            return True
    return False


def _read_arg_states(in_data, position):

    status = in_data.status
    if len(status.used_symbols) <= position:
        return set()
    return set(
        in_data.state_analysis.read_used_states(
            status.used_symbols[position], in_data.in_states
        )
    )


def _read_arg_slot_states(in_data, slot):

    return _read_arg_states(in_data, slot + 1)


def _read_string_value(frame, state_indexes):

    for state_index in state_indexes:
        state = frame.symbol_state_space[state_index]
        if not isinstance(state, State):
            continue
        value = state.value
        if isinstance(value, str) and len(value) > 0:
            return value.strip('"')
    return ""


def _publish_result(in_data, result_states):

    if not result_states:
        return
    defined_symbol = in_data.defined_symbol
    if defined_symbol is not None and hasattr(defined_symbol, "states"):
        defined_symbol.states = set(result_states)
    in_data.status.defined_states.update(result_states)


def _callee_access_path_keys(in_data):

    frame = in_data.frame
    for state_index in in_data.unsolved_callee_states:
        state = frame.symbol_state_space[state_index]
        if not isinstance(state, State):
            continue
        keys = [
            getattr(point, "key", None)
            for point in (getattr(state, "access_path", None) or [])
        ]
        if keys:
            yield keys


def _is_access_path_method(in_data, owner, method):

    return any(keys[-1] == method and owner in keys for keys in _callee_access_path_keys(in_data))


def _build_arguments_from_states(in_data, state_indexes, position=0):

    frame = in_data.frame
    result = set()
    for state_index in state_indexes:
        state = frame.symbol_state_space[state_index]
        if not isinstance(state, State):
            continue
        result.add(
            Argument(
                state_id=state.state_id,
                call_stmt_id=in_data.stmt_id,
                position=position,
                source_symbol_id=state.source_symbol_id,
                access_path=state.access_path,
                index_in_space=state_index,
            )
        )
    return result


def _find_methods_after_constructor(loader, component_name, method_names):

    result = set()
    in_component = False
    for method_id in sorted(loader.get_all_method_ids() or set()):
        method_name = loader.convert_method_id_to_method_name(method_id) or ""
        if method_name == component_name:
            in_component = True
            continue
        if not in_component:
            continue
        if method_name in method_names:
            result.add(method_id)
            continue
        if method_name == "paramsLambda" or (
            method_name and not method_name.startswith("%") and method_name[0].isupper()
        ):
            break
    return result


def _find_about_to_appear_before_initial_render(loader, initial_render_id):

    unit_id = loader.convert_method_id_to_unit_id(initial_render_id)
    for method_id in sorted(loader.get_all_method_ids() or set(), reverse=True):
        if method_id >= initial_render_id:
            continue
        if loader.convert_method_id_to_unit_id(method_id) != unit_id:
            continue
        method_name = loader.convert_method_id_to_method_name(method_id)
        if method_name == "initialRender":
            break
        if method_name == "aboutToAppear":
            return {method_id}
    return set()


def _find_constructor_before_initial_render(loader, initial_render_id):

    unit_id = loader.convert_method_id_to_unit_id(initial_render_id)
    for method_id in sorted(loader.get_all_method_ids() or set(), reverse=True):
        if method_id >= initial_render_id:
            continue
        if loader.convert_method_id_to_unit_id(method_id) != unit_id:
            continue
        name = loader.convert_method_id_to_method_name(method_id) or ""
        if name and name[0].isupper() and not name.startswith("%"):
            return {method_id}
    return set()


def _find_page_map_methods(in_data):
    loader = in_data.frame.loader
    current_class = loader.convert_method_id_to_class_id(in_data.frame.method_id)
    result = set()
    if current_class:
        for method_id in loader.convert_class_id_to_method_ids(current_class) or set():
            if loader.convert_method_id_to_method_name(method_id) == "pageMap":
                result.add(method_id)
    if not result:
        result.update(loader.convert_method_name_to_method_ids("pageMap") or set())
    return result


def _read_object_field_string(in_data, slot, field_name):
    frame = in_data.frame
    for state_index in _read_arg_slot_states(in_data, slot):
        state = frame.symbol_state_space[state_index]
        if not isinstance(state, State):
            continue
        for field_index in state.fields.get(field_name, set()):
            field_state = frame.symbol_state_space[field_index]
            if isinstance(field_state, State) and util.is_available(field_state.value):
                return str(field_state.value).strip('"').strip("'")
    return ""


def model_set(data):

    in_data = data.in_data
    frame = in_data.frame

    receiver_states = _receiver_states(in_data)
    if not receiver_states or not _is_arkui_wrapper_receiver(in_data, receiver_states):
        return



    value_key = WRAPPER_VALUE_KEY
    if len(in_data.status.used_symbols) >= 3:
        key = _read_string_value(frame, _read_arg_states(in_data, 1))
        if util.is_available(key):
            value_key = key
        value_states = _read_arg_states(in_data, 2)
    else:
        value_states = _read_arg_states(in_data, 1)

    if not value_states:
        return

    for state_index in receiver_states:
        state = frame.symbol_state_space[state_index]
        if not isinstance(state, State):
            continue
        bucket = state.fields.get(value_key)
        if bucket is None:
            bucket = set()
            state.fields[value_key] = bucket
        bucket.update(value_states)


    _publish_result(in_data, receiver_states)


def model_get(data):

    in_data = data.in_data
    frame = in_data.frame

    receiver_states = _receiver_states(in_data)
    if not receiver_states or not _is_arkui_wrapper_receiver(in_data, receiver_states):
        return

    want_key = ""
    if len(in_data.status.used_symbols) >= 2:
        want_key = _read_string_value(frame, _read_arg_states(in_data, 1))

    result_states = set()
    for state_index in receiver_states:
        state = frame.symbol_state_space[state_index]
        if not isinstance(state, State):
            continue
        if util.is_available(want_key):
            bucket = state.fields.get(want_key)
            if bucket:
                result_states.update(bucket)
        else:

            for bucket in state.fields.values():
                if bucket:
                    result_states.update(bucket)
            result_states.update(state.tangping_elements)

    _publish_result(in_data, result_states)


def model_add(data):

    in_data = data.in_data
    frame = in_data.frame

    receiver_states = _receiver_states(in_data)
    if not receiver_states or not _is_arkui_wrapper_receiver(in_data, receiver_states):
        return

    value_states = _read_arg_states(in_data, 1)
    if not value_states:
        return

    for state_index in receiver_states:
        state = frame.symbol_state_space[state_index]
        if isinstance(state, State):
            state.tangping_flag = True
            state.tangping_elements.update(value_states)

    _publish_result(in_data, receiver_states)


def model_data_source_add_item(data):

    in_data = data.in_data
    frame = in_data.frame
    receiver_ids = {
        state.access_path[-2].state_id
        for index in in_data.unsolved_callee_states
        for state in [frame.symbol_state_space[index]]
        if isinstance(state, State) and len(state.access_path) >= 2
        and state.access_path[-2].state_id > 0
    }
    receiver_states = {
        index for index, state in enumerate(frame.symbol_state_space)
        if isinstance(state, State) and state.state_id in receiver_ids
    }
    if not receiver_states or not (
        _receiver_access_path_key(in_data) == "dataSource"
        or any(
            "DataSource" in str(getattr(frame.symbol_state_space[index], "data_type", ""))
            for index in receiver_states
        )
    ):
        return
    item_states = _read_arg_slot_states(in_data, 0)
    if not item_states:
        return
    if frame.method_name == "aboutToAppear":
        key = (id(frame.symbol_state_space), frame.method_id)

        space, saved_items = _LAZY_ITEMS_BY_LIFECYCLE.setdefault(
            key, (frame.symbol_state_space, set())
        )
        if space is frame.symbol_state_space:
            saved_items.update(item_states)
    for state_index in receiver_states:
        state = in_data.frame.symbol_state_space[state_index]
        if not isinstance(state, State):
            continue
        state.tangping_elements.update(item_states)
        for items_index in state.fields.get("items", set()):
            items_state = in_data.frame.symbol_state_space[items_index]
            if isinstance(items_state, State):
                items_state.tangping_elements.update(item_states)
                items_state.array.append(set(item_states))
    _publish_result(in_data, receiver_states)


def _collect_callback_method_ids(in_data, state_index):

    frame = in_data.frame
    state_analysis = in_data.state_analysis

    candidate_indexes = [state_index]
    try:
        candidate_indexes.extend(
            in_data.resolver.obtain_parent_states(
                in_data.stmt_id, frame, in_data.status, state_index
            ) or set()
        )
    except Exception:
        pass

    method_ids = set()
    for candidate_index in candidate_indexes:
        state = frame.symbol_state_space[candidate_index]
        if not isinstance(state, State):
            continue
        if getattr(state, "data_type", None) != LIAN_INTERNAL.METHOD_DECL:
            try:
                if not state_analysis.is_state_a_method_decl(state):
                    continue
            except Exception:
                continue
        value = getattr(state, "value", None)

        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)) and value > 0:
            method_ids.add(int(value))
    return method_ids


def _method_ids_from_component_fields(in_data, component_states, field_name):

    method_ids = set()
    frame = in_data.frame
    for state_index in component_states:
        state = frame.symbol_state_space[state_index]
        if not isinstance(state, State):
            continue
        for field_index in state.fields.get(field_name, set()):
            method_ids.update(_collect_callback_method_ids(in_data, field_index))
    return method_ids


def model_callback(data):

    in_data = data.in_data
    state_analysis = in_data.state_analysis
    status = in_data.status
    defined_symbol = in_data.defined_symbol
    args = in_data.args

    callback_method_ids = set()
    for arg_set in (getattr(args, "positional_args", None) or []):
        for arg in arg_set:
            callback_method_ids.update(_collect_callback_method_ids(in_data, arg.index_in_space))

    if not callback_method_ids:
        return



    if any(
        keys[-1] == "observeComponentCreation2"
        for keys in _callee_access_path_keys(in_data)
    ):
        component_name = _read_object_field_string(in_data, 1, "name")
        if util.is_available(component_name):
            for method_id in callback_method_ids:
                _COMPONENT_NAME_BY_CALLBACK_METHOD[method_id] = component_name

    this_states = set()
    receiver_state_id = _receiver_state_id(in_data)
    if receiver_state_id >= 0:
        this_states = _receiver_states(in_data)



    frame = in_data.frame
    if (
        any(keys[-1] == "observeComponentCreation2" for keys in _callee_access_path_keys(in_data))
        and frame.loader.convert_method_id_to_method_name(frame.method_id) == "initialRender"
        and frame.caller_id < 0
        and this_states
    ):
        for marker, lifecycle_ids in (
            ("_arkui_constructor_called", _find_constructor_before_initial_render(frame.loader, frame.method_id)),
            ("_arkui_about_to_appear_called", _find_about_to_appear_before_initial_render(frame.loader, frame.method_id)),
        ):
            if getattr(frame, marker, False):
                continue
            if lifecycle_ids:
                data.out_data = state_analysis.compute_target_method_states(
                    in_data.stmt_id, in_data.stmt, status, in_data.in_states,
                    lifecycle_ids, defined_symbol, MethodCallArguments(), this_states,
                )
                if data.out_data and data.out_data.interruption_flag:
                    return
            setattr(frame, marker, True)

    data.out_data = state_analysis.compute_target_method_states(
        in_data.stmt_id, in_data.stmt, status, in_data.in_states,
        callback_method_ids, defined_symbol, args, this_states
    )


def model_navigation_push_path_by_name(data):

    in_data = data.in_data
    frame = in_data.frame

    target_name = _read_string_value(frame, _read_arg_slot_states(in_data, 0))
    payload_states = {
        index
        for index in _read_arg_slot_states(in_data, 1)
        if isinstance(frame.symbol_state_space[index], State)
    }
    if not util.is_available(target_name) or not payload_states:
        return

    _NAVIGATION_PAYLOADS_BY_SPACE[id(frame.symbol_state_space)] = set(payload_states)

    page_map_methods = _find_page_map_methods(in_data)
    if not page_map_methods:
        return

    real_args = MethodCallArguments(
        positional_args=[
            _build_arguments_from_states(in_data, _read_arg_slot_states(in_data, 0), 0),
            _build_arguments_from_states(in_data, payload_states, 1),
        ],
        named_args=[],
    )
    data.out_data = in_data.state_analysis.compute_target_method_states(
        in_data.stmt_id,
        in_data.stmt,
        in_data.status,
        in_data.in_states,
        page_map_methods,
        in_data.defined_symbol,
        real_args,
        _receiver_states(in_data),
    )


def model_view_create(data):

    in_data = data.in_data
    if _is_access_path_method(in_data, "LazyForEach", "create"):
        model_lazy_foreach_create(data)
        return
    if not (
        _is_access_path_method(in_data, "ViewPU", "create")
        or _is_access_path_method(in_data, "ViewV2", "create")
    ):
        return

    component_states = {
        index
        for index in _read_arg_slot_states(in_data, 0)
        if isinstance(in_data.frame.symbol_state_space[index], State)
    }
    component_name = _COMPONENT_NAME_BY_CALLBACK_METHOD.get(in_data.frame.method_id, "")
    if not component_states or not util.is_available(component_name):
        return

    loader = in_data.frame.loader
    about_to_appear_methods = _method_ids_from_component_fields(
        in_data, component_states, "aboutToAppear"
    )
    initial_render_methods = _method_ids_from_component_fields(
        in_data, component_states, "initialRender"
    )
    if not initial_render_methods:
        initial_render_methods = _find_methods_after_constructor(
            loader, component_name, {"initialRender"}
        )
    if not about_to_appear_methods:
        about_to_appear_methods = _find_methods_after_constructor(
            loader, component_name, {"aboutToAppear"}
        )
    for method_ids in (about_to_appear_methods, initial_render_methods):
        if not method_ids:
            continue
        data.out_data = in_data.state_analysis.compute_target_method_states(
            in_data.stmt_id,
            in_data.stmt,
            in_data.status,
            in_data.in_states,
            method_ids,
            in_data.defined_symbol,
            MethodCallArguments(),
            component_states,
        )
        if data.out_data and data.out_data.interruption_flag:
            return


def model_lazy_foreach_create(data):

    in_data = data.in_data
    frame = in_data.frame
    data_source_states = _read_arg_slot_states(in_data, 2)
    item_states = set()
    for state_index in data_source_states:
        state = frame.symbol_state_space[state_index]
        if not isinstance(state, State):
            continue
        item_states.update(state.tangping_elements)
        for items_index in state.fields.get("items", set()):
            items_state = frame.symbol_state_space[items_index]
            if not isinstance(items_state, State):
                continue
            item_states.update(items_state.tangping_elements)
            for slot in items_state.array:
                item_states.update(slot)
    for lifecycle_id in _find_about_to_appear_before_initial_render(frame.loader, frame.method_id):
        saved = _LAZY_ITEMS_BY_LIFECYCLE.get((id(frame.symbol_state_space), lifecycle_id))
        if saved and saved[0] is frame.symbol_state_space:
            item_states.update(saved[1])

    callback_method_ids = set()
    for slot in (3, 4):
        for state_index in _read_arg_slot_states(in_data, slot):
            callback_method_ids.update(_collect_callback_method_ids(in_data, state_index))
    callback_method_ids = {
        method_id for method_id in callback_method_ids
        if (frame.loader.convert_method_id_to_method_name(method_id) or "").startswith(
            "__lazyForEachItem"
        )
    }
    if not callback_method_ids or not item_states:
        return

    real_args = MethodCallArguments(
        positional_args=[_build_arguments_from_states(in_data, item_states, 0)],
        named_args=[],
    )
    data.out_data = in_data.state_analysis.compute_target_method_states(
        in_data.stmt_id, in_data.stmt, in_data.status, in_data.in_states,
        callback_method_ids, in_data.defined_symbol, real_args, set(),
    )


def model_nav_destination_on_ready(data):

    in_data = data.in_data
    if not _is_access_path_method(in_data, "NavDestination", "onReady"):
        return

    callback_method_ids = set()
    for state_index in _read_arg_slot_states(in_data, 0):
        callback_method_ids.update(_collect_callback_method_ids(in_data, state_index))

    payload_states = set(
        _NAVIGATION_PAYLOADS_BY_SPACE.get(id(in_data.frame.symbol_state_space), set())
    )
    if not callback_method_ids or not payload_states:
        return

    state_analysis = in_data.state_analysis
    status = in_data.status
    path_info_index = state_analysis.create_state_and_add_space(
        status,
        in_data.stmt_id,
        value="NavDestination.pathInfo",
        data_type="object",
    )
    context_index = state_analysis.create_state_and_add_space(
        status,
        in_data.stmt_id,
        value="NavDestination.context",
        data_type="object",
    )
    path_info_state = in_data.frame.symbol_state_space[path_info_index]
    context_state = in_data.frame.symbol_state_space[context_index]
    path_info_state.fields["param"] = set(payload_states)
    context_state.fields["pathInfo"] = {path_info_index}
    status.defined_states.update({path_info_index, context_index})

    for payload_index in payload_states:
        state_analysis.sfg.add_edge(
            state_analysis.make_state_sfg_node(payload_index),
            state_analysis.make_state_sfg_node(path_info_index),
            state_analysis.make_stmt_sfg_edge(
                in_data.stmt_id,
                name="NavDestination.onReady.param",
            ),
        )

    real_args = MethodCallArguments(
        positional_args=[_build_arguments_from_states(in_data, {context_index}, 0)],
        named_args=[],
    )
    data.out_data = state_analysis.compute_target_method_states(
        in_data.stmt_id,
        in_data.stmt,
        status,
        in_data.in_states,
        callback_method_ids,
        in_data.defined_symbol,
        real_args,
        set(),
    )


def model_ability_on_create_return(data):

    in_data = data.in_data
    frame = in_data.frame
    if frame.method_name != "onCreate":
        return

    loader = frame.loader
    class_id = loader.convert_method_id_to_class_id(frame.method_id)
    class_name = loader.convert_class_id_to_class_name(class_id) if class_id else ""
    if not class_name.endswith(".EntryAbility"):
        return
    on_foreground_ids = {
        method_id
        for method_id in loader.convert_class_id_to_method_ids(class_id) or set()
        if loader.convert_method_id_to_method_name(method_id) == "onForeground"
    }
    this_symbol_id = frame.method_def_use_summary.this_symbol_id
    initial_this_states = {
        state_index
        for symbol in frame.symbol_state_space
        if getattr(symbol, "name", None) == "%this"
        and getattr(symbol, "symbol_id", None) == this_symbol_id
        for state_index in getattr(symbol, "states", set())
    }
    this_state_ids = {
        frame.symbol_state_space[index].state_id
        for index in initial_this_states
        if isinstance(frame.symbol_state_space[index], State)
    }
    this_states = set(in_data.state_analysis.resolver.collect_newest_states_by_state_ids(
        frame, in_data.status, this_state_ids
    )) if this_state_ids else set()
    if not on_foreground_ids or not this_states:
        return

    data.out_data = in_data.state_analysis.compute_target_method_states(
        in_data.stmt_id,
        in_data.stmt,
        in_data.status,
        in_data.in_states,
        on_foreground_ids,
        None,
        MethodCallArguments(),
        this_states,
    )



UI_CALLBACK_METHODS = (
    "onClick",
    "onChange",
    "onSubmit",
    "onAppear",
    "onDisAppear",
    "onDetach",
    "onAreaChange",
    "onScroll",
    "onTouch",
    "onHover",
    "observeComponentCreation2",
    "ifElseBranchUpdateFunction",
    "loadContent",


    "declareWatch",
)



_EMITTER_CALLBACKS = {}


def model_emitter_register(data):

    in_data = data.in_data
    frame = in_data.frame
    args = in_data.args

    event_name = _read_string_value(frame, _read_arg_states(in_data, 1))
    if not util.is_available(event_name):
        return

    callbacks = set()
    for arg_set in (getattr(args, "positional_args", None) or []):
        for arg in arg_set:
            callbacks.update(_collect_callback_method_ids(in_data, arg.index_in_space))
    if callbacks:
        _EMITTER_CALLBACKS.setdefault(event_name, set()).update(callbacks)
        if event_name == "stateChange" and any(
            keys[-1] == "on" and "bluetooth.access" in keys
            for keys in _callee_access_path_keys(in_data)
        ):
            data.out_data = in_data.state_analysis.compute_target_method_states(
                in_data.stmt_id, in_data.stmt, in_data.status, in_data.in_states,
                callbacks, in_data.defined_symbol, MethodCallArguments(), set(),
            )


def model_emitter_emit(data):

    in_data = data.in_data
    frame = in_data.frame
    state_analysis = in_data.state_analysis
    status = in_data.status

    event_name = _read_string_value(frame, _read_arg_states(in_data, 1))
    callback_method_ids = set(_EMITTER_CALLBACKS.get(event_name, set()))
    if not callback_method_ids:
        return

    payload_args = set()
    for state_index in _read_arg_states(in_data, 2):
        state = frame.symbol_state_space[state_index]
        if not isinstance(state, State):
            continue
        payload_args.add(
            Argument(
                state_id = state.state_id,
                call_stmt_id = in_data.stmt_id,
                position = state,
                source_symbol_id = state.source_symbol_id,
                access_path = state.access_path,
                index_in_space = state_index,
            )
        )
    real_args = MethodCallArguments([payload_args], []) if payload_args else in_data.args

    data.out_data = state_analysis.compute_target_method_states(
        in_data.stmt_id, in_data.stmt, status, in_data.in_states,
        callback_method_ids, in_data.defined_symbol, real_args, set()
    )





ARKUI_PROVIDED_PREFIX = "ArkUI.provided:"
ARKUI_PARENT_FIELD = "__arkui_parent"





ARKUI_PROVIDED_BY_STATE_ID = {}

ARKUI_PARENT_BY_STATE_ID = {}

ARKUI_PROVIDED_IN_SPACE = {}


def model_add_provided_var(data):

    in_data = data.in_data
    frame = in_data.frame
    receiver_states = _receiver_states(in_data)
    if not receiver_states:
        return

    key = _read_string_value(frame, _read_arg_states(in_data, 1))
    if not util.is_available(key):
        return
    wrapper_states = _read_arg_states(in_data, 2)
    if not wrapper_states:
        return

    for state_index in receiver_states:
        state = frame.symbol_state_space[state_index]
        if not isinstance(state, State):
            continue
        state.fields.setdefault(ARKUI_PROVIDED_PREFIX + key, set()).update(wrapper_states)
        state_id = getattr(state, "state_id", None)
        if state_id is not None:

            space_id = id(frame.symbol_state_space)
            ARKUI_PROVIDED_BY_STATE_ID.setdefault(state_id, {}).setdefault(key, set()).update(
                (space_id, index) for index in wrapper_states
            )



            ARKUI_PROVIDED_IN_SPACE.setdefault(space_id, {}).setdefault(key, set()).update(
                wrapper_states
            )


def _find_provided_states(frame, start_states, key):

    queue = list(start_states)
    visited_state_ids = set()
    while queue:
        state_index = queue.pop(0)
        state = frame.symbol_state_space[state_index]
        if not isinstance(state, State):
            continue

        state_id = getattr(state, "state_id", None)
        if state_id is not None:
            if state_id in visited_state_ids:
                continue
            visited_state_ids.add(state_id)

        space_id = id(frame.symbol_state_space)
        provided = set(state.fields.get(ARKUI_PROVIDED_PREFIX + key) or set())
        if not provided and state_id is not None:
            for entry_space_id, index in (ARKUI_PROVIDED_BY_STATE_ID.get(state_id) or {}).get(key, set()):
                if entry_space_id == space_id:
                    provided.add(index)
        if provided:
            return provided

        queue.extend(state.fields.get(ARKUI_PARENT_FIELD) or set())
        if state_id is not None:
            for entry_space_id, index in ARKUI_PARENT_BY_STATE_ID.get(state_id, set()):
                if entry_space_id == space_id:
                    queue.append(index)
    return set()


def model_initialize_consume(data):

    in_data = data.in_data
    frame = in_data.frame
    receiver_states = _receiver_states(in_data)
    if not receiver_states:
        return

    key = _read_string_value(frame, _read_arg_states(in_data, 1))
    if not util.is_available(key):
        return

    provided_states = _find_provided_states(frame, receiver_states, key)
    if not provided_states:
        return

    value_states = set()
    for state_index in provided_states:
        state = frame.symbol_state_space[state_index]
        if not isinstance(state, State):
            continue
        value_states.update(state.fields.get(WRAPPER_VALUE_KEY, set()))
    if not value_states:

        value_states = set(provided_states)

    _publish_result(in_data, value_states)


METHOD_NAME_TO_MODEL = {
    "set": model_set,
    "get": model_get,
    "add": model_add,
    "addItem": model_data_source_add_item,

    "then": model_callback,

    "on": model_emitter_register,
    "once": model_emitter_register,
    "emit": model_emitter_emit,

    "addProvidedVar": model_add_provided_var,
    "initializeConsume": model_initialize_consume,


    "pushPathByName": model_navigation_push_path_by_name,
    "create": model_view_create,
    "onReady": model_nav_destination_on_ready,
}
METHOD_NAME_TO_MODEL.update({name: model_callback for name in UI_CALLBACK_METHODS})
