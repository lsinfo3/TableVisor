%%%-------------------------------------------------------------------
%%% @author Stefan Herrnleben
%%% @copyright (C) 2015, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 02. Mai 2015 14:20
%%%-------------------------------------------------------------------
-module(tablevisor_ctrl4).

-include_lib("stdlib/include/ms_transform.hrl").
-include_lib("of_protocol/include/of_protocol.hrl").
-include_lib("of_protocol/include/ofp_v4.hrl").
-include_lib("pkt/include/pkt.hrl").

-compile([{parse_transform, lager_transform}]).

%% API
-export([
  start/1,
  send/2,
  send/3,
  message/1,
  tablevisor_switches/0,
  tablevisor_tables/0,
  tablevisor_switch_get/2,
  tablevisor_switch_get_outport/2,
  tablevisor_switch_get_gototable/2
]).


%% @doc Start the server.
start(Port) ->
  lager:start(),
  %ets:new(ttpsim_dpid2tableid, [public, named_table, {read_concurrency, true}]),
  %ets:insert(ttpsim_dpid2tableid, {2, 0}),
  spawn_link(fun() ->
    Opts = [binary, {packet, raw}, {active, once}, {reuseaddr, true}],
    {ok, LSocket} = gen_tcp:listen(Port, Opts),
    accept(LSocket)
  end).

accept(LSocket) ->
  {ok, Socket} = gen_tcp:accept(LSocket),
  Pid = spawn_link(fun() ->
    inet:setopts(Socket, [{active, once}]),
    handle_socket(Socket, [], <<>>)
  end),
  Pid ! {new},
  ok = gen_tcp:controlling_process(Socket, Pid),
  accept(LSocket).

%% The echo client process.
handle_socket(Socket, Waiters, Data1) ->
  ok = inet:setopts(Socket, [{active, once}]),
  receive
    {tcp, Socket, Data} ->
      Data2 = <<Data1/binary, Data/binary>>,
      <<_Version:8, _TypeInt:8, Length:16, _XID:32, _Binary2/bytes>> = Data2,
      % lager:info("Version ~p, TypeInt ~p, Length ~p, Xid ~p, calculated Length ~p",[Version, TypeInt, Length, XID, byte_size(Data)]),
      case Length of
        N when N > byte_size(Data2) ->
          handle_socket(Socket, Waiters, Data2);
        N when N < byte_size(Data2) ->
          lager:error("multiple OpenFlow messages in one TCP bytestream");
        _ ->
          true
      end,
      {ok, Parser} = ofp_parser:new(4),
      lager:debug("InputData from ~p: ~p",[Socket, Data]),
      Parsed = ofp_parser:parse(Parser, Data2),
      case Parsed of
        {ok, _, _} ->
          true;
        {error, Exception} ->
          lager:error("Error while parsing ~p because ~p", [Data, Exception]),
          handle_socket(Socket, Waiters, <<>>)
      end,
      {ok, _NewParser, Messages} = Parsed,
      lager:debug("Received messages ~p", [Messages]),
      FilteredWaiters = filter_waiters(Waiters),
      lists:foreach(fun(Message) ->
        Xid = Message#ofp_message.xid,
        spawn_link(fun() ->
          send_to_waiters(Socket, Message, Xid, FilteredWaiters),
          handle_input(Socket, Message)
        end)
      end, Messages),
      handle_socket(Socket, FilteredWaiters, <<>>);
  % close tcp socket by client (rb)
    {tcp_closed, Socket} ->
      tablevisor_switch_remove(Socket),
      lager:error("Client ~p disconnected.", [Socket]);
  % say hello, negotiate ofp version and get datapath id after connect
    {new} ->
      do_send(Socket, hello()),
      ListenerPid = self(),
      spawn_link(fun() ->
        send_features_request(Socket, ListenerPid)
      end),
      handle_socket(Socket, Waiters, <<>>);
    {add_waiter, Waiter} ->
      NewWaiters = [Waiter | Waiters],
      handle_socket(Socket, NewWaiters, <<>>);
    Other ->
      lager:error("Received unknown signal ~p", [Other]),
      handle_socket(Socket, Waiters, <<>>)
  end.

filter_waiters(Waiters) ->
  [Waiter || Waiter <- Waiters, is_process_alive(Waiter)].

send_features_request(Socket, Pid) ->
  timer:sleep(5000),
  Message = features_request(),
  Xid = Message#ofp_message.xid,
  lager:info("Send features request to ~p, xid ~p, message ~p", [Socket, Xid, Message]),
  Pid ! {add_waiter, self()},
  do_send(Socket, Message),
  receive
    {msg, Reply, Xid} ->
      lager:info("Received features reply from ~p, message ~p", [Socket, Reply]),
      Body = Reply#ofp_message.body,
      DataPathMac = Body#ofp_features_reply.datapath_mac,
      DataPathId = binary_to_int(DataPathMac),
      %lager:info("DataPathId ~p", [DataPathId]),
      {ok, TableId} = tablevisor_switch_connect(DataPathId, Socket, Pid),
      lager:info("Registered new Switch DataPath-ID ~p, Socket ~p, Pid ~p, Table-Id ~p", [DataPathId, Socket, Pid, TableId]),
      % set flow mod to enable process table different 0
      tablevisor_us4:tablevisor_init_connection(TableId),
      true
  after 2000 ->
    lager:error("Error while waiting for features reply from ~p, xid ~p", [Socket, Xid]),
    false
  end.

handle_input(Socket, Message) ->
  Xid = Message#ofp_message.xid,
  case Message of
    #ofp_message{body = #ofp_error_msg{type = hello_failed, code = incompatible}} ->
      lager:error("Received hello failed from ~p: ~p", [Socket, Message]),
      gen_tcp:close(Socket);
    #ofp_message{body = #ofp_error_msg{}} ->
      lager:info("Received error message from ~p: ~p", [Socket, Message]),
      tablevisor_us4:ofp_error_msg(Message);
    #ofp_message{body = #ofp_echo_request{}} ->
      lager:debug("Received echo request from ~p: ~p", [Socket, Message]),
      do_send(Socket, message(echo_reply(), Xid));
    #ofp_message{body = #ofp_hello{}} ->
      lager:info("Received hello message from ~p: ~p", [Socket, Message]);
    #ofp_message{body = #ofp_features_reply{datapath_mac = _DataPathMac}} ->
      lager:debug("Received features reply message from ~p: ~p", [Socket, Message]);
    #ofp_message{body = #ofp_packet_in{}} ->
      lager:info("Received packet in from ~p: ~p", [Socket, Message]),
      case tablevisor_switch_get(Socket, tableid) of
        false ->
          false;
        TableId ->
          tablevisor_us4:ofp_packet_in(TableId, Message)
      end;
    #ofp_message{} ->
      lager:info("Received message from ~p: ~p", [Socket, Message])
  %_ ->
  %  lager:error("Unknown message: ~p", [Message])
  end.

send_to_waiters(_Socket, _Message, _Xid, []) ->
  true;
send_to_waiters(Socket, Message, Xid, [Waiter | Waiters]) ->
  %lager:info("Send to waiter ~p, xid ~p, message ~p", [Waiter, Xid, Message]),
  Waiter ! {msg, Message, Xid},
  send_to_waiters(Socket, Xid, Message, Waiters).


%%%-----------------------------------------------------------------------------
%%% Helpers
%%%-----------------------------------------------------------------------------

message(Body) ->
  Xid = get_xid(),
  message(Body, Xid).

message(Body, Xid) ->
  #ofp_message{version = 4,
    xid = Xid,
    body = Body}.

get_xid() ->
  random:uniform(1 bsl 32 - 1).

binary_to_int(Bin) ->
  Size = size(Bin),
  <<Int:Size/integer-unit:8>> = Bin,
  Int.

%binary_to_hex(Bin) ->
%  binary_to_hex(Bin, "").

%binary_to_hex(<<>>, Result) ->
%  Result;
%binary_to_hex(<<B:8, Rest/bits>>, Result) ->
%  Hex = erlang:integer_to_list(B, 16),
%  NewResult = Result ++ ":" ++ Hex,
%  binary_to_hex(Rest, NewResult).

%%%-----------------------------------------------------------------------------
%%% ETS Helper
%%%-----------------------------------------------------------------------------

tablevisor_switch_remove(_Socket) ->
  true.
%{TableId, _, _} = ttpsim_switch_get(Socket),
%ets:delete(ttpsim_socket, Socket),
%ets:delete(ttpsim_switch, TableId).

tablevisor_switch_connect(DataPathId, Socket, Pid) ->
  SwitchList = tablevisor_switches(),
  SearchByDpId = fun(TableId, Config) ->
    {dpid, DpId} = lists:keyfind(dpid, 1, Config),
    case DpId of
      DataPathId ->
        tablevisor_switch_set(TableId, socket, Socket),
        tablevisor_switch_set(TableId, pid, Pid),
        ets:insert(tablevisor_socket, {Socket, TableId});
      _ ->
        false
    end
  end,
  [SearchByDpId(TableId, Config) || {TableId, Config} <- SwitchList],
  TableId2 = tablevisor_switch_get(Socket, tableid),
  {ok, TableId2}.

%ttpsim_switch_get(TableId) when is_integer(TableId) ->
%  try
%    ets:lookup_element(ttpsim_switch, TableId, 2)
%  catch
%    error:badarg ->
%      lager:error("No Switch with TableId ~p registered", [TableId]),
%      false
%  end;
%ttpsim_switch_get(Socket) ->
%  try
%    TableId = ets:lookup_element(ttpsim_socket, Socket, 2),
%    ttpsim_switch_get(TableId)
%  catch
%    error:badarg ->
%      lager:error("No Switch with Socket ~p registered", [Socket]),
%      false
%  end.


tablevisor_switch_get(TableId, Key) when is_integer(TableId) ->
  try
    Config = ets:lookup_element(tablevisor_switch, TableId, 2),
    % lager:error("Key ~p, Config ~p",[Key, Config]),
    {Key, Value} = lists:keyfind(Key, 1, Config),
    Value
  catch
    error:badarg ->
      lager:error("No Switch with TableId ~p registered", [TableId]),
      false
  end;
tablevisor_switch_get(Socket, Key) ->
  try
    TableId = ets:lookup_element(tablevisor_socket, Socket, 2),
    tablevisor_switch_get(TableId, Key)
  catch
    error:badarg ->
      lager:error("No Switch with Socket ~p registered", [Socket]),
      false
  end.

tablevisor_switch_set(TableId, Key, NewValue) ->
  try
    ReplaceConfig = fun(OldKey, OldValue) ->
      case OldKey of
        Key ->
          {OldKey, NewValue};
        _ ->
          {OldKey, OldValue}
      end
    end,
    Config = ets:lookup_element(tablevisor_switch, TableId, 2),
    NewConfig = [ReplaceConfig(Key2, Value2) || {Key2, Value2} <- Config],
    ets:insert(tablevisor_switch, {TableId, NewConfig})
  catch
    error:badarg ->
      lager:error("Error in ttpsim_switch_set", [TableId]),
      false
  end.

-spec tablevisor_switches() -> true.
tablevisor_switches() ->
  ets:tab2list(tablevisor_switch).

-spec tablevisor_tables() -> true.
tablevisor_tables() ->
  Switches = tablevisor_switches(),
  [TableId || {TableId, _} <- Switches].

tablevisor_switch_get_outport(SrcTableId, DstTableId) ->
  OutportMap = tablevisor_switch_get(SrcTableId, outportmap),
  {DstTableId, Outport} = lists:keyfind(DstTableId, 1, OutportMap),
  Outport.

tablevisor_switch_get_gototable(SrcTableId, OutPort) ->
  OutportMap = tablevisor_switch_get(SrcTableId, outportmap),
  DstTables = [D || {D, OutPort2} <- OutportMap, OutPort2 == OutPort],
  case DstTables == [] of
    true ->
      false;
    false ->
      [DstTableId | _] = DstTables,
      DstTableId
  end.

%%%-----------------------------------------------------------------------------
%%% Sender
%%%-----------------------------------------------------------------------------

send(TableId, Message) when is_integer(TableId) ->
  Socket = tablevisor_switch_get(TableId, socket),
  send(Socket, Message);
send(Socket, Message) ->
  %lager:info("Send (cast) to ~p, message ~p", [Socket, Message]),
  do_send(Socket, Message),
  {noreply, ok}.

send(TableId, Message, Timeout) when is_integer(TableId) ->
  Socket = tablevisor_switch_get(TableId, socket),
  send(Socket, Message, Timeout);
send(Socket, Message, Timeout) ->
  Pid = tablevisor_switch_get(Socket, pid),
  Pid ! {add_waiter, self()},
  Xid = Message#ofp_message.xid,
  %lager:info("Send (call) to ~p, xid ~p, message ~p", [Socket, Xid, Message]),
  do_send(Socket, Message),
  receive
    {msg, Reply, Xid} ->
      ReplyBody = Reply#ofp_message.body,
      {reply, ReplyBody}
  after Timeout ->
    lager:error("Error while waiting for reply from ~p, xid ~p", [Socket, Xid]),
    {error, timeout}
  end.

%multisend(TableId, Message, Timeout) when is_integer(TableId) ->
%  Socket = tablevisor_switch_get(TableId, socket),
%  multisend(Socket, Message, Timeout);
%multisend(Socket, Message, Timeout) ->
%  Pid = tablevisor_switch_get(Socket, pid),
%  Pid ! {add_waiter, self()},
%  Xid = Message#ofp_message.xid,
%  lager:info("Send (call) to ~p, xid ~p, message ~p", [Socket, Xid, Message]),
%  do_send(Socket, Message),
%  receive
%    {msg, Reply, Xid} ->
%      ReplyBody = Reply#ofp_message.body,
%      %lager:info("Reply ~p", [ReplyBody]),
%      {reply, ReplyBody}
%  after Timeout ->
%    lager:error("Error while waiting for reply from ~p, xid ~p", [Socket, Xid]),
%    {error, timeout}
%  end.

do_send(Socket, Message) when is_tuple(Message) ->
  case of_protocol:encode(Message) of
    {ok, EncodedMessage} ->
      do_send(Socket, EncodedMessage);
    _Error ->
      lager:error("Error in encode of: ~p", [Message])
  end;
do_send(Socket, Message) when is_binary(Message) ->
  gen_tcp:send(Socket, Message).
%inet:setopts(Socket, [{active, once}]).
%try
%  inet:setopts(Socket, [{active, once}]),
%  gen_tcp:send(Socket, Message)
%catch
%  _:_ ->
%    ok
%end.


%%%-----------------------------------------------------------------------------
%%% Message generators
%%%-----------------------------------------------------------------------------

hello() ->
  message(#ofp_hello{}).

features_request() ->
  message(#ofp_features_request{}).

%echo_request() ->
%  echo_request(<<>>).
%echo_request(Data) ->
%  message(#ofp_echo_request{data = Data}).

echo_reply() ->
  echo_reply(<<>>).
echo_reply(Data) ->
  #ofp_echo_reply{data = Data}.

%get_config_request() ->
%  message(#ofp_get_config_request{}).
%
%barrier_request() ->
%  message(#ofp_barrier_request{}).
%
%queue_get_config_request() ->
%  message(#ofp_queue_get_config_request{port = any}).
%
%desc_request() ->
%  message(#ofp_desc_request{}).
%
%flow_stats_request() ->
%  message(#ofp_flow_stats_request{table_id = all}).
%
%flow_stats_request_with_cookie(Cookie) ->
%  message(#ofp_flow_stats_request{table_id = all,
%    cookie = Cookie,
%    cookie_mask = <<-1:64>>}).
%
%aggregate_stats_request() ->
%  message(#ofp_aggregate_stats_request{table_id = all}).
%
%table_stats_request() ->
%  message(#ofp_table_stats_request{}).
%
%port_stats_request() ->
%  message(#ofp_port_stats_request{port_no = any}).
%
%queue_stats_request() ->
%  message(#ofp_queue_stats_request{port_no = any, queue_id = all}).
%
%group_stats_request() ->
%  message(#ofp_group_stats_request{group_id = all}).
%
%group_desc_request() ->
%  message(#ofp_group_desc_request{}).
%
%group_features_request() ->
%  message(#ofp_group_features_request{}).
%
%remove_all_flows() ->
%  message(#ofp_flow_mod{command = delete}).
%
%set_config() ->
%  message(#ofp_set_config{miss_send_len = no_buffer}).
%
%group_mod() ->
%  message(#ofp_group_mod{
%    command  = add,
%    type = all,
%    group_id = 1,
%    buckets = [#ofp_bucket{
%      weight = 1,
%      watch_port = 1,
%      watch_group = 1,
%      actions = [#ofp_action_output{port = 2}]}]}).
%
%port_mod() ->
%  message(#ofp_port_mod{port_no = 1,
%    hw_addr = <<0,17,0,0,17,17>>,
%    config = [],
%    mask = [],
%    advertise = [fiber]}).
%
%group_mod_add_bucket_with_output_to_controller(GroupId) ->
%  message(#ofp_group_mod{
%    command  = add,
%    type = all,
%    group_id = GroupId,
%    buckets = [#ofp_bucket{
%      actions = [#ofp_action_output{port = controller}]}]
%  }).
%
%group_mod_modify_bucket(GroupId) ->
%  message(#ofp_group_mod{
%    command  = modify,
%    type = all,
%    group_id = GroupId,
%    buckets = [#ofp_bucket{
%      actions = [#ofp_action_output{port = 2}]}]
%  }).
%
%delete_all_groups() ->
%  message(#ofp_group_mod{
%    command = delete,
%    type = all,
%    group_id = 16#fffffffc
%  }).
%
%port_desc_request() ->
%  message(#ofp_port_desc_request{}).
%
%oe_port_desc_request() ->
%  message(#ofp_experimenter_request{
%    experimenter = ?INFOBLOX_EXPERIMENTER,
%    exp_type = port_desc,
%    data = <<>>}).
%
%role_request() ->
%  message(#ofp_role_request{role = nochange, generation_id = 1}).
%
%flow_mod_table_miss() ->
%  Action = #ofp_action_output{port = controller},
%  Instruction = #ofp_instruction_apply_actions{actions = [Action]},
%  message(#ofp_flow_mod{table_id = 0,
%    command = add,
%    priority = 0,
%    instructions = [Instruction]}).
%
%flow_mod_delete_all_flows() ->
%  message(#ofp_flow_mod{table_id = all,
%    command = delete}).
%
%%% Flow mod to test behaviour reported in:
%%% https://github.com/FlowForwarding/LINC-Switch/issues/68
%flow_mod_issue68() ->
%  %% Match fields
%  MatchField1 = #ofp_field{class = openflow_basic,
%    has_mask = false,
%    name = eth_type,
%    value = <<2048:16>>},
%  MatchField2 = #ofp_field{class = openflow_basic,
%    has_mask = false,
%    name = ipv4_src,
%    value = <<192:8,168:8,0:8,68:8>>},
%  Match = #ofp_match{fields = [MatchField1, MatchField2]},
%  %% Instructions
%  SetField = #ofp_field{class = openflow_basic,
%    has_mask = false,
%    name = ipv4_dst,
%    value = <<10:8,0:8,0:8,68:8>>},
%  Action1 = #ofp_action_set_field{field = SetField},
%  Action2 = #ofp_action_output{port = 2, max_len = no_buffer},
%  Instruction = #ofp_instruction_apply_actions{actions = [Action1, Action2]},
%  %% Flow Mod
%  message(#ofp_flow_mod{
%    cookie = <<0:64>>,
%    cookie_mask = <<0:64>>,
%    table_id = 0,
%    command = add,
%    idle_timeout = 0,
%    hard_timeout = 0,
%    priority = 1,
%    buffer_id = no_buffer,
%    out_port = any,
%    out_group = any,
%    flags = [],
%    match = Match,
%    instructions = [Instruction]
%  }).

