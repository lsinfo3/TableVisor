%%%-----------------------------------------------------------------------------
%%% @copyright (C) 2012, Erlang Solutions Ltd.
%%% @doc OpenFlow 1.2 Controller.
%%% @end
%%%-----------------------------------------------------------------------------
-module(tablevisortest_ctrl4).

-include_lib("stdlib/include/ms_transform.hrl").

-compile([{parse_transform, lager_transform}]).

%% API
-export([start/5,
  stop/1,
  get_connections/1,
  send/3,
  send/4,
  barrier/2]).

%% Message generators
-export([hello/0,
  flow_mod_issue68/0,
  flow_mod_issue79/0,
  set_config_issue87/0,
  flow_mod_issue90/0,
  flow_mod_table_miss/0,
  flow_mod_delete_all_flows/0,
  get_config_request/0,
  echo_request/0,
  echo_request/1,
  barrier_request/0,
  queue_get_config_request/0,
  features_request/0,
  remove_all_flows/0,
  group_mod/0,
  port_mod/0,
  port_desc_request/0,
  set_config/0,
  role_request/0,
  desc_request/0,
  flow_stats_request/0,
  aggregate_stats_request/0,
  table_stats_request/0,
  port_stats_request/0,
  queue_stats_request/0,
  group_stats_request/0,
  group_desc_request/0,
  group_features_request/0,
  meter_mod_add_meter/0,
  meter_mod_add_meter_17/0,
  meter_mod_modify_meter_17/0,
  config_request_meter_17/0,
  add_meter_19_with_burst_size/0,
  get_stats_meter_19/0,
  flow_mod_with_flags/0,
  set_async/0,
  get_async_request/0,
  bin_port_desc_request/0,
  flow_mod_issue91/0,
  flow_mod_output_to_port/3,
  async_config/3,
  role_request/2,
  flow_mod_issue153/0,
  table_features_keep_table_0/0,
  flow_mod_set_field_och_sigid_on_eth/0,
  flow_mod_remove_och_sigid/0,
  flow_mod_change_och_sigid/0
]).

-include_lib("../deps/of_protocol/include/of_protocol.hrl").
-include_lib("../deps/of_protocol/include/ofp_v4.hrl").
-include_lib("../deps/pkt/include/pkt.hrl").

-record(cstate, {
  parent :: pid(),
  socket,
  parser,
  fwd_table = [] :: [{binary(), integer()}]
}).

%%%-----------------------------------------------------------------------------
%%% API functions
%%%-----------------------------------------------------------------------------

start(Filename, Table, SingleTableRequest, Flows, DistributeFlows) ->
  PortOrRemotePeer = 6633,
  lager:start(),
  try passive_or_active_controller(PortOrRemotePeer) of
    {passive, Port} ->
      {ok, spawn(fun() ->
        init(passive, Port, Filename, Table, SingleTableRequest, Flows, DistributeFlows)
      end)};
    {active, Address, Port} ->
      {ok, spawn(fun() ->
        init(active, {Address, Port}, Filename, Table, SingleTableRequest, Flows, DistributeFlows)
      end)}
  catch
    error:bad_argument ->
      lager:error("Incorrectly formed RemotePeer argument: ~p",
        [PortOrRemotePeer]),
      init:stop()
  end.

stop(Pid) ->
  Pid ! stop.

get_connections(Pid) ->
  Pid ! {get_connections, Ref = make_ref(), self()},
  receive
    {connections, Ref, Connections} ->
      {ok, Connections}
  after 1000 ->
    {error, timeout}
  end.

send(Pid, To, Message) ->
  cast(Pid, To, Message).

send(Pid, To, Message, Timeout) ->
  call(Pid, To, Message, Timeout).

barrier(Pid, To) ->
  send(Pid, To, barrier_request(), 1000).

%%%-----------------------------------------------------------------------------
%%% Controller logic
%%%-----------------------------------------------------------------------------

init(passive, Port, Filename, Table2, AllTableRequest2, Flows2, DistributeFlows2) ->
  {Table, _} = string:to_integer(Table2),
  case string:to_integer(AllTableRequest2) of
    {1,[]} -> RequestTable = all;
    _ -> RequestTable = Table
  end,
  {Flows, _} = string:to_integer(Flows2),
  {DistributeFlows, _} = string:to_integer(DistributeFlows2),
  RefTime = generate_timestamp(),
  Filename2 = (Filename ++ "_t" ++ Table2 ++ "_a" ++ AllTableRequest2 ++ "_f" ++ Flows2 ++ "_d" ++ DistributeFlows2 ++ "_" ++ integer_to_list(RefTime)),
  Pid = self(),
  % start sender process
  Sender = spawn_link(fun() ->
    loop([], [])
  end),
  % start receiver process
  spawn_link(fun() ->
    Opts = [binary, {packet, raw},
      {active, once}, {reuseaddr, true}],
    {ok, LSocket} = gen_tcp:listen(Port, Opts),
    accept(Pid, LSocket, RefTime, Filename2)
  end),
  % wait for receiver process
  receive
    {connected, Type, Socket, Pid2} ->
      Sender ! {connected, Type, Socket, Pid2},
      timer:sleep(5000),
      case DistributeFlows of
        0 ->
          send_initial_flow_mod(Socket, Table, Flows);
        _ ->
          send_initial_flow_mod(Socket, Table, round(Flows/3)),
          send_initial_flow_mod(Socket, Table + 1, round(Flows/3)),
          send_initial_flow_mod(Socket, Table + 2, round(Flows/3))
      end,
      timer:sleep(10000),
      performance_test(Socket, RefTime, RequestTable);
    Any ->
      lager:info("Unexpected Message: ~p", [Any])
  end.

performance_test(Socket, RefTime, TableId) ->
  Message = #ofp_message{version = 4,
    xid = get_xid(),
    body = #ofp_flow_stats_request{
      table_id = TableId
    }
  },
  test_sender(Socket, Message, RefTime, 1000, 100).

send_initial_flow_mod(_, TableId, 0) ->
  lager:info("Initial FlowMods for Table ~p finished", [TableId]);
send_initial_flow_mod(Socket, TableId, Count) ->
  Message = initial_flow_mod(TableId),
  do_send(Socket, Message),
  timer:sleep(100),
  send_initial_flow_mod(Socket, TableId, Count - 1).

initial_flow_mod(TableId) ->
  FlowMod = #ofp_flow_mod{
    table_id = TableId,
    command = add,
    hard_timeout = 0,
    idle_timeout = 0,
    priority = 0,
    flags = [],
    match = #ofp_match{fields = [
      #ofp_field{name = eth_type, value = <<8,0>>},
      #ofp_field{name = ipv4_src, value = get_random_ip()},
      #ofp_field{name = ipv4_dst, value = get_random_ip()}
      %#ofp_field{name = eth_dst, value = get_random_mac()}
    ]},
    instructions = [
      #ofp_instruction_apply_actions{actions = [#ofp_action_output{port = 1}]}
    ]
  },
  %lager:info("FlowMod ~p",[FlowMod]),
  message(FlowMod).

get_random_ip() ->
  <<(random:uniform(255)):8, (random:uniform(255)):8, (random:uniform(255)):8, (random:uniform(255)):8>>.

get_random_mac() ->
  <<(random:uniform(255)):8, (random:uniform(255)):8, (random:uniform(255)):8, (random:uniform(255)):8, (random:uniform(255)):8, (random:uniform(255)):8>>.

test_sender(_, _, _, 0, _) ->
  lager:info("Test finished.");
test_sender(Socket, Message, RefTime, Count, Delay) ->
  spawn(fun() ->
    TimeStamp = generate_timestamp() - RefTime,
    Message2 = Message#ofp_message{xid = TimeStamp},
    do_send(Socket, Message2),
    lager:info("~p: send", [TimeStamp])
  end),
  timer:sleep(Delay),
  test_sender(Socket, Message, RefTime, Count - 1, Delay).

generate_timestamp() ->
  {Mega, Sec, Micro} = os:timestamp(),
  ((Mega * 1000000 + Sec) * 1000000 + Micro).

accept(Parent, LSocket, RefTime, Filename) ->
  {ok, Socket} = gen_tcp:accept(LSocket),
  Pid = spawn_link(fun() ->
    handle_connection(Parent, Socket, RefTime, Filename)
  end),
  ok = gen_tcp:controlling_process(Socket, Pid),
  Parent ! {connected, passive, Socket, Pid},
  accept(Parent, LSocket, RefTime, Filename).

handle_connection(Parent, Socket, RefTime, Filename) ->
  gen_tcp:send(Socket, encoded_hello_message(RefTime)),
  {ok, Parser} = ofp_parser:new(4),
  inet:setopts(Socket, [{active, once}]),
  handle(#cstate{parent = Parent, socket = Socket, parser = Parser}, RefTime, Filename).


%% multiply_msg(Message, 0) ->
%%   [Message];
%% multiply_msg(Message, Count) ->
%%   [Message | multiply_msg(Message, Count - 1)].


loop(Connections, RefTime) ->
  receive
    {connected, Type, Socket, Pid} ->
      {ok, {Address, Port}} = inet:peername(Socket),
      case Type of
        passive ->
          lager:info("Accepted connection from ~p {~p,~p}",
            [Socket, Address, Port]);
        active ->
          lager:info(
            "Connected to listening swtich through ~p {~p,~p}",
            [Socket, Address, Port])
      end,
      loop([{{Address, Port}, Socket, Pid} | Connections], RefTime);
    {cast, Message, AddressPort} ->
      NewConnections = filter_connections(Connections),
      do_send(NewConnections, AddressPort, Message),
      loop(NewConnections, RefTime);
    {call, #ofp_message{xid = Xid} = Message,
      AddressPort, Ref, ReplyPid, Timeout} ->
      NewConnections = filter_connections(Connections),
      do_send(NewConnections, AddressPort, Message),
      receive
        {message, #ofp_message{xid = Xid} = Reply} ->
          ReplyPid ! {reply, Ref, {reply, Reply}}
      after Timeout ->
        ReplyPid ! {reply, Ref, {error, timeout}}
      end,
      loop(NewConnections, RefTime);
    {get_connections, Ref, Pid} ->
      Pid ! {connections, Ref, [AP || {AP, _, _} <- Connections]},
      loop(Connections, RefTime);
    stop ->
      ok
  end.

handle(#cstate{parent = Parent, socket = Socket,
  parser = Parser, fwd_table = FwdTable} = State, RefTime, Filename) ->
  receive
    {tcp, Socket, Data} ->
      {ok, NewParser} = parse_tcp(Socket, Parser, Data),
      handle(State#cstate{parser = NewParser}, RefTime, Filename);
    {tcp_closed, Socket} ->
      lager:info("Socket ~p closed", [Socket]);
    {tcp_error, Socket, Reason} ->
      lager:error("Error on socket ~p: ~p", [Socket, Reason]);
    {msg, Socket, #ofp_message{
      body = #ofp_error_msg{type = hello_failed,
        code = incompatible}} = Message} ->
      lager:error("Received hello_failed from ~p: ~p",
        [Socket, Message]),
      gen_tcp:close(Socket);
    {msg, Socket, #ofp_message{
      body = #ofp_echo_request{}}} ->
      %lager:info("Received echo from ~p", [Socket]),
      do_send(Socket, echo_reply()),
      handle(State, RefTime, Filename);
    {msg, Socket, #ofp_message{
      body = #ofp_hello{}}} ->
      lager:info("Received hello from ~p", [Socket]),
      handle(State, RefTime, Filename);
    {msg, Socket, #ofp_message{body = #ofp_flow_stats_reply{}} = Message} ->
      % tablevisor evaluation begin
      spawn(fun() ->
        Xid = Message#ofp_message.xid,
        RTT = generate_timestamp() - RefTime - Xid,
        lager:info("~p: receive (~p msec)", [Xid, RTT / 1000]),
        file:write_file(("/home/sherrnleben/tvperformance/" ++ Filename ++ ".csv"), io_lib:fwrite("~p;~p~n", [Xid, RTT]), [append])
        % tablevisor evaluation end
      end),
      Parent ! {message, Message},
      handle(State, RefTime, Filename);
    {msg, Socket, Message} ->
      lager:info("Received message from ~p: ~p", [Socket, Message]),
      handle(State, RefTime, Filename)
  end.

binary_to_hex(Bin) ->
  binary_to_hex(Bin, "").

binary_to_hex(<<>>, Result) ->
  Result;
binary_to_hex(<<B:8, Rest/bits>>, Result) ->
  Hex = erlang:integer_to_list(B, 16),
  NewResult = Result ++ ":" ++ Hex,
  binary_to_hex(Rest, NewResult).

%%%-----------------------------------------------------------------------------
%%% Message generators
%%%-----------------------------------------------------------------------------

hello() ->
  message(#ofp_hello{}).

features_request() ->
  message(#ofp_features_request{}).

echo_request() ->
  echo_request(<<>>).
echo_request(Data) ->
  message(#ofp_echo_request{data = Data}).

echo_reply() ->
  message(#ofp_echo_reply{}).

get_config_request() ->
  message(#ofp_get_config_request{}).

barrier_request() ->
  message(#ofp_barrier_request{}).

queue_get_config_request() ->
  message(#ofp_queue_get_config_request{port = any}).

desc_request() ->
  message(#ofp_desc_request{}).

flow_stats_request() ->
  message(#ofp_flow_stats_request{table_id = all}).

flow_stats_request_with_cookie(Cookie) ->
  message(#ofp_flow_stats_request{table_id = all,
    cookie = Cookie,
    cookie_mask = <<-1:64>>}).

aggregate_stats_request() ->
  message(#ofp_aggregate_stats_request{table_id = all}).

table_stats_request() ->
  message(#ofp_table_stats_request{}).

port_stats_request() ->
  message(#ofp_port_stats_request{port_no = any}).

queue_stats_request() ->
  message(#ofp_queue_stats_request{port_no = any, queue_id = all}).

group_stats_request() ->
  message(#ofp_group_stats_request{group_id = all}).

group_desc_request() ->
  message(#ofp_group_desc_request{}).

group_features_request() ->
  message(#ofp_group_features_request{}).

remove_all_flows() ->
  message(#ofp_flow_mod{command = delete}).

set_config() ->
  message(#ofp_set_config{miss_send_len = no_buffer}).

group_mod() ->
  message(#ofp_group_mod{
    command = add,
    type = all,
    group_id = 1,
    buckets = [#ofp_bucket{
      weight = 1,
      watch_port = 1,
      watch_group = 1,
      actions = [#ofp_action_output{port = 2}]}]}).

port_mod() ->
  message(#ofp_port_mod{port_no = 1,
    hw_addr = <<0, 17, 0, 0, 17, 17>>,
    config = [],
    mask = [],
    advertise = [fiber]}).

group_mod_add_bucket_with_output_to_controller(GroupId) ->
  message(#ofp_group_mod{
    command = add,
    type = all,
    group_id = GroupId,
    buckets = [#ofp_bucket{
      actions = [#ofp_action_output{port = controller}]}]
  }).

group_mod_modify_bucket(GroupId) ->
  message(#ofp_group_mod{
    command = modify,
    type = all,
    group_id = GroupId,
    buckets = [#ofp_bucket{
      actions = [#ofp_action_output{port = 2}]}]
  }).

delete_all_groups() ->
  message(#ofp_group_mod{
    command = delete,
    type = all,
    group_id = 16#fffffffc
  }).

port_desc_request() ->
  message(#ofp_port_desc_request{}).

oe_port_desc_request() ->
  message(#ofp_experimenter_request{
    experimenter = ?INFOBLOX_EXPERIMENTER,
    exp_type = port_desc,
    data = <<>>}).

role_request() ->
  message(#ofp_role_request{role = nochange, generation_id = 1}).

flow_mod_table_miss() ->
  Action = #ofp_action_output{port = controller},
  Instruction = #ofp_instruction_apply_actions{actions = [Action]},
  message(#ofp_flow_mod{table_id = 0,
    command = add,
    priority = 0,
    instructions = [Instruction]}).

flow_mod_delete_all_flows() ->
  message(#ofp_flow_mod{table_id = all,
    command = delete}).

%% Flow mod to test behaviour reported in:
%% https://github.com/FlowForwarding/LINC-Switch/issues/68
flow_mod_issue68() ->
  %% Match fields
  MatchField1 = #ofp_field{class = openflow_basic,
    has_mask = false,
    name = eth_type,
    value = <<2048:16>>},
  MatchField2 = #ofp_field{class = openflow_basic,
    has_mask = false,
    name = ipv4_src,
    value = <<192:8, 168:8, 0:8, 68:8>>},
  Match = #ofp_match{fields = [MatchField1, MatchField2]},
  %% Instructions
  SetField = #ofp_field{class = openflow_basic,
    has_mask = false,
    name = ipv4_dst,
    value = <<10:8, 0:8, 0:8, 68:8>>},
  Action1 = #ofp_action_set_field{field = SetField},
  Action2 = #ofp_action_output{port = 2, max_len = no_buffer},
  Instruction = #ofp_instruction_apply_actions{actions = [Action1, Action2]},
  %% Flow Mod
  message(#ofp_flow_mod{
    cookie = <<0:64>>,
    cookie_mask = <<0:64>>,
    table_id = 0,
    command = add,
    idle_timeout = 0,
    hard_timeout = 0,
    priority = 1,
    buffer_id = no_buffer,
    out_port = any,
    out_group = any,
    flags = [],
    match = Match,
    instructions = [Instruction]
  }).

%% Flow mod to test behaviour reported in:
%% https://github.com/FlowForwarding/LINC-Switch/issues/79
flow_mod_issue79() ->
  %% Match fields
  MatchField1 = #ofp_field{class = openflow_basic,
    has_mask = false,
    name = eth_type,
    value = <<2048:16>>},
  MatchField2 = #ofp_field{class = openflow_basic,
    has_mask = false,
    name = ip_proto,
    value = <<6:8>>},
  MatchField3 = #ofp_field{class = openflow_basic,
    has_mask = false,
    name = ipv4_src,
    value = <<192:8, 168:8, 0:8, 79:8>>},
  Match = #ofp_match{fields = [MatchField1, MatchField2, MatchField3]},
  %% Instructions
  SetField = #ofp_field{class = openflow_basic,
    has_mask = false,
    name = tcp_dst,
    value = <<7979:16>>},
  Action1 = #ofp_action_set_field{field = SetField},
  Action2 = #ofp_action_output{port = 2, max_len = no_buffer},
  Instruction = #ofp_instruction_apply_actions{actions = [Action1, Action2]},
  %% Flow Mod
  message(#ofp_flow_mod{
    cookie = <<0:64>>,
    cookie_mask = <<0:64>>,
    table_id = 0,
    command = add,
    idle_timeout = 0,
    hard_timeout = 0,
    priority = 1,
    buffer_id = no_buffer,
    out_port = any,
    out_group = any,
    flags = [],
    match = Match,
    instructions = [Instruction]
  }).

%% Flow mod to test behaviour reported in:
%% https://github.com/FlowForwarding/LINC-Switch/issues/87
set_config_issue87() ->
  message(#ofp_set_config{
    flags = [frag_drop],
    miss_send_len = 16#FFFF - 100}).

%% Flow mod to test behaviour reported in:
%% https://github.com/FlowForwarding/LINC-Switch/issues/90
flow_mod_issue90() ->
  SetField = #ofp_field{class = openflow_basic,
    has_mask = false,
    name = vlan_vid,
    value = <<11:12>>},
  Action1 = #ofp_action_push_vlan{ethertype = 16#8100},
  Action2 = #ofp_action_set_field{field = SetField},
  Action3 = #ofp_action_output{port = 2, max_len = no_buffer},
  Instriction = #ofp_instruction_apply_actions{actions = [Action1,
    Action2,
    Action3]},
  message(#ofp_flow_mod{
    cookie = <<0:64>>,
    cookie_mask = <<0:64>>,
    table_id = 0,
    command = add,
    idle_timeout = 0,
    hard_timeout = 0,
    priority = 1,
    buffer_id = no_buffer,
    out_port = any,
    out_group = any,
    flags = [],
    match = #ofp_match{fields = []},
    instructions = [Instriction]}).

%% Meter mod to test behaviour related with pull request repotred in:
%% https://github.com/FlowForwarding/of_protocol/pull/28
meter_mod_add_meter() ->
  message(#ofp_meter_mod{
    command = add,
    flags = [kbps],
    meter_id = 1,
    bands = [#ofp_meter_band_drop{rate = 200}]}).

%% Meters' messages to test behaviour related with pull request
%% repotred in: https://github.com/FlowForwarding/of_protocol/pull/23
meter_mod_add_meter_17() ->
  message(#ofp_meter_mod{
    command = add,
    flags = [kbps],
    meter_id = 17,
    bands = [#ofp_meter_band_drop{rate = 200}]}).

meter_mod_modify_meter_17() ->
  message(#ofp_meter_mod{
    command = modify,
    flags = [kbps],
    meter_id = 17,
    bands = [#ofp_meter_band_drop{rate = 900}]}).

config_request_meter_17() ->
  message(#ofp_meter_config_request{
    flags = [],
    meter_id = 17}).

add_meter_19_with_burst_size() ->
  message(#ofp_meter_mod{
    command = add,
    flags = [pktps, burst, stats],
    meter_id = 19,
    bands = [#ofp_meter_band_drop{rate = 5, burst_size = 10}]}).

get_stats_meter_19() ->
  message(#ofp_meter_stats_request{meter_id = 19}).

%% Flow mod with flags set to check if they are correctly encoded/decoded.
flow_mod_with_flags() ->
  message(#ofp_flow_mod{
    cookie = <<0:64>>,
    cookie_mask = <<0:64>>,
    table_id = 0,
    command = add,
    idle_timeout = 0,
    hard_timeout = 0,
    priority = 99,
    buffer_id = no_buffer,
    out_port = any,
    out_group = any,
    flags = [send_flow_rem, reset_counts],
    match = #ofp_match{},
    instructions = []
  }).

set_async() ->
  message(#ofp_set_async{
    packet_in_mask = {
      [no_match],
      [action]},
    port_status_mask = {
      [add, delete, modify],
      [add, delete, modify]},
    flow_removed_mask = {
      [idle_timeout, hard_timeout, delete, group_delete],
      [idle_timeout, hard_timeout, delete, group_delete]
    }}).

get_async_request() ->
  message(#ofp_get_async_request{}).

-spec role_request(ofp_controller_role(), integer()) -> ofp_message().
role_request(Role, GenerationId) ->
  message(#ofp_role_request{role = Role, generation_id = GenerationId}).

%% Creates a flow mod message that forwards a packet received at one port
%% to another. If the output port is controller the MaxLen specifies
%% the amount of bytes of the received packet to be included in the packet in.
-spec flow_mod_output_to_port(integer(), ofp_port_no(), ofp_packet_in_bytes())
      -> ofp_message().
flow_mod_output_to_port(InPort, OutPort, MaxLen) ->
  MatchField = #ofp_field{class = openflow_basic,
    has_mask = false,
    name = in_port,
    value = <<InPort:32>>},
  Match = #ofp_match{fields = [MatchField]},
  Action = case OutPort =:= controller of
             true ->
               #ofp_action_output{port = OutPort, max_len = MaxLen};
             false ->
               #ofp_action_output{port = OutPort}
           end,
  Instruction = #ofp_instruction_apply_actions{actions = [Action]},
  message(#ofp_flow_mod{
    cookie = <<0:64>>,
    cookie_mask = <<0:64>>,
    table_id = 0,
    command = add,
    idle_timeout = 0,
    hard_timeout = 0,
    priority = 1,
    buffer_id = no_buffer,
    out_port = any,
    out_group = any,
    flags = [],
    match = Match,
    instructions = [Instruction]
  }).

flow_add(Opts, Matches, Instructions) ->
  message(ofp_v4_utils:flow_add(Opts, Matches, Instructions)).

%% Creates async config message that sets up filtering on an ofp channel.
-spec async_config({[ofp_packet_in_reason()], [ofp_packet_in_reason()]},
    {[ofp_port_status_reason()], [ofp_port_status_reason()]},
    {[ofp_flow_removed_reason()], [ofp_flow_removed_reason()]}) ->
  ofp_message().
async_config(PacketInMask, PortStatusMask, FlowRemovedMask) ->
  message(#ofp_set_async{
    packet_in_mask = PacketInMask,
    port_status_mask = PortStatusMask,
    flow_removed_mask = FlowRemovedMask
  }).

%% Binary port description request with 4 byte long random padding to check
%% behaviour reported in:
%% https://github.com/FlowForwarding/LINC-Switch/issues/110
bin_port_desc_request() ->
  {ok, EncodedMessage} = of_protocol:encode(message(#ofp_port_desc_request{})),
  %% Strip for 4 byte padding from the message.
  <<(binary:part(EncodedMessage, 0, byte_size(EncodedMessage) - 4))/binary,
  (random:uniform(16#FFFFFFFF)):32>>.

%% Flow mod to test behaviour reported in:
%% https://github.com/FlowForwarding/LINC-Switch/issues/91
flow_mod_issue91() ->
  MatchField1 = #ofp_field{class = openflow_basic,
    has_mask = false,
    name = eth_type,
    %% IPv6
    value = <<(16#86dd):16>>},
  MatchField2 = #ofp_field{class = openflow_basic,
    has_mask = false,
    name = in_port,
    value = <<1:32>>},
  Match = #ofp_match{fields = [MatchField1, MatchField2]},
  SetField = #ofp_field{class = openflow_basic,
    has_mask = false,
    name = ipv6_dst,
    value =
    <<(16#fe80):16, 0:48, (16#2420):16, (16#52ff):16,
    (16#fe8f):16, (16#5189):16>>},
  Action1 = #ofp_action_set_field{field = SetField},
  Action2 = #ofp_action_output{port = 2, max_len = no_buffer},
  Instruction = #ofp_instruction_apply_actions{actions = [Action1, Action2]},
  message(#ofp_flow_mod{
    cookie = <<0:64>>,
    cookie_mask = <<0:64>>,
    table_id = 0,
    command = add,
    idle_timeout = 0,
    hard_timeout = 0,
    priority = 1,
    buffer_id = no_buffer,
    out_port = any,
    out_group = any,
    flags = [],
    match = Match,
    instructions = [Instruction]
  }).

%% Flow mod to test behaviour reported in:
%% https://github.com/FlowForwarding/LINC-Switch/issues/153
%%
%% This should set the ECN field for any IPv4 packet to 2 (binary 10),
%% and the DSCP field to 10 (binary 001010).
flow_mod_issue153() ->
  MatchField = #ofp_field{class = openflow_basic,
    has_mask = false,
    name = eth_type,
    %% IPv4
    value = <<16#0800:16>>},
  SetField1 = #ofp_field{class = openflow_basic,
    has_mask = false,
    name = ip_ecn,
    value = <<2:2>>},
  SetField2 = #ofp_field{class = openflow_basic,
    has_mask = false,
    name = ip_dscp,
    value = <<10:6>>},
  Action1 = #ofp_action_set_field{field = SetField1},
  Action2 = #ofp_action_set_field{field = SetField2},
  Action3 = #ofp_action_output{port = 2, max_len = no_buffer},
  Instruction = #ofp_instruction_apply_actions{actions = [Action1,
    Action2,
    Action3]},
  message(#ofp_flow_mod{
    cookie = <<0:64>>,
    cookie_mask = <<0:64>>,
    table_id = 0,
    command = add,
    idle_timeout = 0,
    hard_timeout = 0,
    priority = 1,
    buffer_id = no_buffer,
    out_port = any,
    out_group = any,
    flags = [],
    match = #ofp_match{fields = [MatchField]},
    instructions = [Instruction]}).

flow_mod_set_field_och_sigid_on_eth() ->
  MatchField = #ofp_field{class = openflow_basic,
    has_mask = false,
    name = in_port,
    value = <<1:32>>},
  Field = #ofp_field{class = openflow_basic,
    has_mask = false,
    name = och_sigid,
    value = <<0:16, (_ChannelNumber = 10):16, 0:16>>},
  SetField = #ofp_action_set_field{field = Field},
  Action1 = #ofp_action_experimenter{experimenter = ?INFOBLOX_EXPERIMENTER,
    data = SetField},
  Action2 = #ofp_action_output{port = 2, max_len = no_buffer},
  Instruction = #ofp_instruction_apply_actions{actions = [Action1,
    Action2]},
  message(#ofp_flow_mod{
    cookie = <<0:64>>,
    cookie_mask = <<0:64>>,
    table_id = 0,
    command = add,
    idle_timeout = 0,
    hard_timeout = 0,
    priority = 1,
    buffer_id = no_buffer,
    out_port = any,
    out_group = any,
    flags = [],
    match = #ofp_match{fields = [MatchField]},
    instructions = [Instruction]}).

flow_mod_change_och_sigid() ->
  MatchField1 = #ofp_field{class = openflow_basic,
    has_mask = false,
    name = in_port,
    value = <<3:32>>},
  MatchField2 = #ofp_field{class = infoblox,
    has_mask = false,
    name = och_sigtype,
    value = <<10:8>>},
  MatchField3 = #ofp_field{class = infoblox,
    has_mask = false,
    name = och_sigid,
    value = <<0:16, (_InChannelNumber = 10):16, 0:16>>},
  Field = #ofp_field{class = openflow_basic,
    has_mask = false,
    name = och_sigid,
    value = <<0:16, (_OutChannelNumber = 20):16, 0:16>>},
  SetField = #ofp_action_set_field{field = Field},
  Action1 = #ofp_action_experimenter{experimenter = ?INFOBLOX_EXPERIMENTER,
    data = SetField},
  Action2 = #ofp_action_output{port = 4, max_len = no_buffer},
  Instruction = #ofp_instruction_apply_actions{actions = [Action1,
    Action2]},
  message(#ofp_flow_mod{
    cookie = <<0:64>>,
    cookie_mask = <<0:64>>,
    table_id = 0,
    command = add,
    idle_timeout = 0,
    hard_timeout = 0,
    priority = 1,
    buffer_id = no_buffer,
    out_port = any,
    out_group = any,
    flags = [],
    match = #ofp_match{fields = [MatchField1,
      MatchField2,
      MatchField3]},
    instructions = [Instruction]}).

flow_mod_remove_och_sigid() ->
  MatchField1 = #ofp_field{class = openflow_basic,
    has_mask = false,
    name = in_port,
    value = <<5:32>>},
  MatchField2 = #ofp_field{class = infoblox,
    has_mask = false,
    name = och_sigtype,
    value = <<10:8>>},
  MatchField3 = #ofp_field{class = infoblox,
    has_mask = false,
    name = och_sigid,
    value = <<0:16, (_InChannelNumber = 20):16, 0:16>>},
  Action = #ofp_action_output{port = 6, max_len = no_buffer},
  Instruction = #ofp_instruction_apply_actions{actions = [Action]},
  message(#ofp_flow_mod{
    cookie = <<0:64>>,
    cookie_mask = <<0:64>>,
    table_id = 0,
    command = add,
    idle_timeout = 0,
    hard_timeout = 0,
    priority = 1,
    buffer_id = no_buffer,
    out_port = any,
    out_group = any,
    flags = [],
    match = #ofp_match{fields = [MatchField1,
      MatchField2,
      MatchField3]},
    instructions = [Instruction]}).

table_features_keep_table_0() ->
  message(#ofp_table_features_request{
    body = [#ofp_table_features{
      table_id = 0,
      name = <<"flow table 0">>,
      metadata_match = <<0:64>>,
      metadata_write = <<0:64>>,
      max_entries = 10,
      properties = [#ofp_table_feature_prop_instructions{}
        , #ofp_table_feature_prop_next_tables{}
        , #ofp_table_feature_prop_write_actions{}
        , #ofp_table_feature_prop_apply_actions{}
        , #ofp_table_feature_prop_match{}
        , #ofp_table_feature_prop_wildcards{}
        , #ofp_table_feature_prop_write_setfield{}
        , #ofp_table_feature_prop_apply_setfield{}
      ]}]}).

%%% Helpers --------------------------------------------------------------------

message(Body) ->
  #ofp_message{version = 4,
    xid = get_xid(),
    body = Body}.

all_table_features_request(TableId) ->
  message(#ofp_table_features_request{
    body = [#ofp_table_features{
      table_id = TableId,
      name = <<"flow table 0">>,
      metadata_match = <<0:64>>,
      metadata_write = <<0:64>>,
      max_entries = 10,
      properties =
      [#ofp_table_feature_prop_instructions{},
        #ofp_table_feature_prop_instructions_miss{},
        #ofp_table_feature_prop_next_tables{},
        #ofp_table_feature_prop_next_tables_miss{},
        #ofp_table_feature_prop_write_actions{},
        #ofp_table_feature_prop_write_actions_miss{},
        #ofp_table_feature_prop_apply_actions{},
        #ofp_table_feature_prop_apply_actions_miss{},
        #ofp_table_feature_prop_match{},
        #ofp_table_feature_prop_wildcards{},
        #ofp_table_feature_prop_write_setfield{},
        #ofp_table_feature_prop_write_setfield_miss{},
        #ofp_table_feature_prop_apply_setfield{},
        #ofp_table_feature_prop_apply_setfield_miss{}]
    }]}).

get_xid() ->
  random:uniform(1 bsl 32 - 1).

%%%-----------------------------------------------------------------------------
%%% Helper functions
%%%-----------------------------------------------------------------------------

parse_tcp(Socket, Parser, Data) ->
  %% lager:info("Received TCP data from ~p: ~p", [Socket, Data]),
  inet:setopts(Socket, [{active, once}]),
  {ok, NewParser, Messages} = ofp_parser:parse(Parser, Data),
  lists:foreach(fun(Message) ->
    self() ! {msg, Socket, Message}
  end, Messages),
  {ok, NewParser}.

filter_connections(Connections) ->
  [Conn || {_, _, Pid} = Conn <- Connections, is_process_alive(Pid)].

cast(Pid, To, Message) ->
  case is_process_alive(Pid) of
    true ->
      lager:info("Sending ~p", [Message]),
      Pid ! {cast, Message, To};
    false ->
      {error, controller_dead}
  end.

call(Pid, To, Message, Timeout) ->
  case is_process_alive(Pid) of
    true ->
      lager:info("Sending ~p", [Message]),
      Pid ! {call, Message, To, Ref = make_ref(), self(), Timeout},
      lager:info("Waiting for reply"),
      receive
        {reply, Ref, Reply} ->
          Reply
      end;
    false ->
      {error, controller_dead}
  end.

do_send(Connections, {Address, Port}, Message) ->
  case lists:keyfind({Address, Port}, 1, Connections) of
    false ->
      lager:error("Sending message failed");
    {{Address, Port}, Socket, _} ->
      do_send(Socket, Message)
  end.

do_send(Socket, Message) when is_binary(Message) ->
  try
    gen_tcp:send(Socket, Message)
  catch
    _:_ ->
      ok
  end;
do_send(Socket, Message) when is_tuple(Message) ->
  case of_protocol:encode(Message) of
    {ok, EncodedMessage} ->
      do_send(Socket, EncodedMessage);
    _Error ->
      lager:error("Error in encode of: ~p", [Message])
  end.

generation_id() ->
  {Mega, Sec, Micro} = erlang:now(),
  (Mega * 1000000 + Sec) * 1000000 + Micro.

encoded_hello_message(Scenario) ->
  {ok, EncodedHello} = of_protocol:encode(hello()),
  case Scenario of
    hello_with_bad_version ->
      malform_version_in_hello(EncodedHello);
    _ ->
      EncodedHello
  end.

malform_version_in_hello(<<_:8, Rest/binary>>) ->
  <<(16#5):8, Rest/binary>>.

passive_or_active_controller(Port) when is_integer(Port) ->
  {passive, Port};
passive_or_active_controller(RemotePeer) ->
  case string:tokens(RemotePeer, ":") of
    [Address, Port] ->
      {ok, ParsedAddress} = inet_parse:address(Address),
      {active, ParsedAddress, erlang:list_to_integer(Port)};
    [Port] ->
      {passive, erlang:list_to_integer(Port)};
    _ ->
      erlang:error(bad_argument, RemotePeer)
  end.
