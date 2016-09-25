%%------------------------------------------------------------------------------
%% Copyright 2012 FlowForwarding.org
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%-----------------------------------------------------------------------------

%% @author Erlang Solutions Ltd. <openflow@erlang-solutions.com>
%% @copyright 2012 FlowForwarding.org
%% @doc Userspace implementation of the OpenFlow Switch logic.
-module(tablevisor_us4).

-behaviour(gen_switch).

%% gen_switch callbacks
-export([start/1,
  stop/1,
  handle_message/2]).

%% Backend API
-export([is_port_valid/2,
  is_queue_valid/3,
  set_datapath_mac/2,
  log_message_sent/1,
  set_monitor_data/3]).

%% Handle all message types
-export([ofp_features_request/2,
  ofp_flow_mod/2,
  ofp_table_mod/2,
  ofp_port_mod/2,
  ofp_group_mod/2,
  ofp_packet_out/2,
  ofp_echo_request/2,
  ofp_get_config_request/2,
  ofp_set_config/2,
  ofp_barrier_request/2,
  ofp_queue_get_config_request/2,
  ofp_desc_request/2,
  ofp_flow_stats_request/2,
  ofp_aggregate_stats_request/2,
  ofp_table_stats_request/2,
  ofp_table_features_request/2,
  ofp_port_desc_request/2,
  ofp_port_stats_request/2,
  ofp_queue_stats_request/2,
  ofp_group_stats_request/2,
  ofp_group_desc_request/2,
  ofp_group_features_request/2,
  ofp_meter_mod/2,
  ofp_meter_stats_request/2,
  ofp_meter_config_request/2,
  ofp_meter_features_request/2]).

%% Handle messages for tablevisor
-export([
  tablevisor_init_connection/1,
  tablevisor_log/1,
  tablevisor_log/2,
  tvlc/1,
  tvlc/2,
  tvlc/3
]).

%% Handle messages from switches to controller
-export([
  ofp_error_msg/1,
  ofp_packet_in/2
]).



-include_lib("of_protocol/include/of_protocol.hrl").
-include_lib("of_protocol/include/ofp_v4.hrl").
-include_lib("linc/include/linc_logger.hrl").
-include_lib("../include/linc_us4.hrl").

-record(state, {
  flow_state,
  buffer_state,
  switch_id :: integer(),
  datapath_mac :: binary(),
  switch_config = [{flags, []}, {miss_send_len, no_buffer}] ::
  [switch_config_opt()]
}).
-type state() :: #state{}.

-type switch_config_opt() :: {flags, list(ofp_config_flags())} |
{miss_send_len, ofp_packet_in_bytes()}.

%%%-----------------------------------------------------------------------------
%%% gen_switch callbacks
%%%-----------------------------------------------------------------------------

%% @doc Start the switch.
-spec start(any()) -> {ok, Version :: 4, state()}.
start(BackendOpts) ->
  try
    %lager:trace_file("rel/log/tablevisor.log", [{vhost, "example.com"}], warning),
    %lager:warning([{vhost, "example.com"}], "~s[32m Permission denied to~n", [ [27] ]),
    % initialize controller for table type pattern simulation
    {switch_id, SwitchId} = lists:keyfind(switch_id, 1, BackendOpts),
    {datapath_mac, DatapathMac} = lists:keyfind(datapath_mac, 1, BackendOpts),
    {config, Config} = lists:keyfind(config, 1, BackendOpts),
    tablevisor_read_config(SwitchId, Config),
    tablevsior_preparelog(),
    {ok} = init_controller(6633),
    lager:info("Waiting for Connections from TableVisor Hardware Switches"),
    tablevisor_log("~s--- TableVisor started ---", [tvlc(red, b)]),
    tablevisor_log("~sStart controller endpoint and wait for connection establishment of the hardware switches", [tvlc(red)]),
    % wait for hardware switches
    tablevisor_ctrl4:tablevisor_wait_for_switches(),
    tablevisor_ctrl4:tablevisor_topology_discovery(),
    tablevisor_ctrl4:tablevisor_identify_table_position(),
    lager:info("Waiting finished. Now initialize the switch and connect to external controller."),
    tablevisor_log("~sStart switch endpoint and connect to external controller", [tvlc(red)]),
    BufferState = linc_buffer:initialize(SwitchId),
    {ok, _Pid} = linc_us4_sup:start_backend_sup(SwitchId),
    linc_us4_groups:initialize(SwitchId),
    FlowState = linc_us4_flow:initialize(SwitchId),
    linc_us4_port:initialize(SwitchId, Config),
    {ok, 4, #state{flow_state = FlowState,
      buffer_state = BufferState,
      switch_id = SwitchId,
      datapath_mac = DatapathMac}}
  catch
    _:Error ->
      {error, Error}
  end.

%% @doc Stop the switch.
-spec stop(state()) -> any().
stop(#state{flow_state = FlowState,
  buffer_state = BufferState,
  switch_id = SwitchId}) ->
  linc_us4_port:terminate(SwitchId),
  linc_us4_flow:terminate(FlowState),
  linc_us4_groups:terminate(SwitchId),
  linc_buffer:terminate(BufferState),
  ok;
stop([]) ->
  ok.

-spec handle_message(ofp_message_body(), state()) ->
  {noreply, state()} |
  {reply, ofp_message(), state()}.
handle_message(MessageBody, State) ->
  MessageName = element(1, MessageBody),
  erlang:apply(?MODULE, MessageName, [State, MessageBody]).

%%%-----------------------------------------------------------------------------
%%% Controller Instance for Table Type Pattern Simulation
%%%-----------------------------------------------------------------------------

init_controller(Port) ->
  tablevisor_ctrl4:start(Port),
  {ok}.

%%%-----------------------------------------------------------------------------
%%% Config + ETS
%%%-----------------------------------------------------------------------------

tablevisor_read_config(_SwitchId, Config) ->
  {switch, _SwitchId2, Switch} = lists:keyfind(switch, 1, Config),
  {tablevisor_switches, TVSwitches} = lists:keyfind(tablevisor_switches, 1, Switch),
  ets:new(tablevisor_switch, [public, named_table, {read_concurrency, true}]),
  [tablevisor_create_switch_config(Switch2) || Switch2 <- TVSwitches],
  ets:new(tablevisor_socket, [public, named_table, {read_concurrency, true}]),
  % read TableVisor config from sys.config
  ets:new(tablevisor_config, [public, named_table, {read_concurrency, true}]),
  {tablevisor_config, TVConfig} = lists:keyfind(tablevisor_config, 1, Switch),
  case lists:keyfind(metadata_provider, 1, TVConfig) of
    {metadata_provider, srcmac} ->
      ets:insert(tablevisor_config, {metadata_provider, srcmac}),
      lager:info("Set metadata provider: Source MAC address.");
    {metadata_provider, dstmac} ->
      ets:insert(tablevisor_config, {metadata_provider, dstmac}),
      lager:info("Set metadata provider: Destination MAC address.");
    {metadata_provider, vid} ->
      ets:insert(tablevisor_config, {metadata_provider, vid}),
      lager:info("Set metadata provider: VLAN-ID.");
    false ->
      false
  end.

tablevisor_create_switch_config(Switch) ->
  {switch, SwitchId, SwitchConfig} = Switch,
  {dpid, DpId} = lists:keyfind(dpid, 1, SwitchConfig),
  {processtable, ProcessTable} = lists:keyfind(processtable, 1, SwitchConfig),
  TableId = case lists:keyfind(tableid, 1, SwitchConfig) of
              {tableid, TableId2} -> TableId2;
              _ -> 0
            end,
  OutportMap = tablevisor_config_read_outportmap(SwitchConfig),
% read back line mapping for connections from last table to switch 0
  case lists:keyfind(flowmods, 1, SwitchConfig) of
    {flowmods, FlowMods} ->
      true;
    false ->
      FlowMods = []
  end,
  % generate config
  Config = [
    {dpid, DpId},
    {tableid, TableId},
    {outportmap, OutportMap},
    {socket, false},
    {pid, false},
    {processtable, ProcessTable},
    {flowmods, FlowMods},
    {position, intermediate}
  ],
  ets:insert(tablevisor_switch, {SwitchId, Config}).

tablevisor_config_read_outportmap(SwitchConfig) ->
  ListEntry = lists:keyfind(outportmap, 1, SwitchConfig),
  case ListEntry of
    {outportmap, OutportMap} ->
      OutportMap;
    _ ->
      []
  end.

%%%-----------------------------------------------------------------------------
%%% Backend API
%%%-----------------------------------------------------------------------------

-spec is_port_valid(integer(), ofp_port_no()) -> boolean().
is_port_valid(SwitchId, PortNo) ->
  linc_us4_port:is_valid(SwitchId, PortNo).

-spec is_queue_valid(integer(), ofp_port_no(), ofp_queue_id()) -> boolean().
is_queue_valid(SwitchId, PortNo, QueueId) ->
  linc_us4_queue:is_valid(SwitchId, PortNo, QueueId).

set_datapath_mac(State, NewMac) ->
  State#state{datapath_mac = NewMac}.

-spec log_message_sent(ofp_message()) -> term().
log_message_sent(#ofp_message{body = Body} = Message)
  when is_record(Body, ofp_error_msg) ->
  ?DEBUG("[OF_ERROR] Sent message to controller: ~w~n", [Message]);
log_message_sent(Message) ->
  ?DEBUG("Sent message to controller: ~w~n", [Message]).

-spec set_monitor_data(pid(), integer(), state()) -> state().
set_monitor_data(_ClientPid, _Xid, State) ->
  State.


%%%-----------------------------------------------------------------------------
%%% Handling of messages
%%%-----------------------------------------------------------------------------

ofp_features_request(#state{switch_id = SwitchId,
  datapath_mac = DatapathMac} = State,
    #ofp_features_request{}) ->
  SwitchCount = length(tablevisor_ctrl4:tablevisor_switches()),
  FeaturesReply = #ofp_features_reply{datapath_mac = DatapathMac,
    datapath_id = SwitchId,
    n_buffers = 0,
    n_tables = SwitchCount,
    auxiliary_id = 0,
    capabilities = ?CAPABILITIES},
  {reply, FeaturesReply, State}.

generate_hash_from_match(Matches) ->
  IntHash = erlang:crc32(term_to_binary(Matches)),
  MaxHash = 16#ffffffff,
  IntHash / MaxHash.

get_tableno_from_match(Matches, SwitchCount) ->
  Hash = generate_hash_from_match(Matches),
  WeightedHash = Hash * SwitchCount,
  trunc(WeightedHash).

%% @doc Modify flow entry in the flow table.
-spec ofp_flow_mod(state(), ofp_flow_mod()) ->
  {noreply, #state{}} |
  {reply, ofp_message(), #state{}}.
ofp_flow_mod(#state{switch_id = _SwitchId} = State, #ofp_flow_mod{table_id = TableId} = FlowMod) ->
  LogFlow1 = tablevisor_logformat_flowmod(FlowMod),
  Matches = FlowMod#ofp_flow_mod.match#ofp_match.fields,
  lager:warning("TableNo ~p", [get_tableno_from_match(Matches, 1)]),
  tablevisor_log("~sReceived ~sflow-mod~s from controller:~s", [tvlc(yellow), tvlc(yellow, b), tvlc(yellow), LogFlow1]),
  lager:info("ofp_flow_mod to tablevisor-switch ~p: ~p", [TableId, FlowMod]),
  % get table id list
  SwitchIdList = [tablevisor_ctrl4:tablevisor_switch_get({tableid, TableId}, switchid)],
  % anonymous function to generate flow mod
  RefactorFlowMod = fun(SwitchId, FlowMod2) ->
    % extract apply-action-instructions from all instructions
    GotoTableInstructionList = [I || I <- FlowMod2#ofp_flow_mod.instructions, is_record(I, ofp_instruction_goto_table)],
    case GotoTableInstructionList == [] of
      true ->
        % there are no goto-table-instructions -> leave untouched
        FinalInstructionList = FlowMod2#ofp_flow_mod.instructions,
        DevTableId = tablevisor_ctrl4:tablevisor_switch_get({switchid, SwitchId}, processtable);
      false ->
        % get first (and only) goto-table-action-instruction
        [GotoTableInstruction | _] = GotoTableInstructionList,
        Outport = tablevisor_ctrl4:tablevisor_switch_get_outport(SwitchId, GotoTableInstruction#ofp_instruction_goto_table.table_id),
        case is_integer(Outport) of
          false ->
            % there is no output port for goto-table defined -> leave untouched
            FinalInstructionList = FlowMod2#ofp_flow_mod.instructions;
          true ->
            % extract apply-action-instructions from instructions
            ApplyActionInstructionList = [I || I <- FlowMod2#ofp_flow_mod.instructions, is_record(I, ofp_instruction_apply_actions)],
            case ApplyActionInstructionList == [] of
              true ->
                % no apply-action-instruction -> create new apply-action-instruction
                ApplyActionInstruction = #ofp_instruction_apply_actions{actions = []};
              false ->
                % the the first (and only) apply-action-instruction
                [ApplyActionInstruction | _] = ApplyActionInstructionList
            end,
            % create output action and append it to apply-action-instruction
            OutputAction = #ofp_action_output{port = Outport},
            % filter all apply-actions from instructions
            % lager:info("Instructions ~p", [FlowMod2#ofp_flow_mod.instructions]),
            FilteredInstructionList = [I || I <- FlowMod2#ofp_flow_mod.instructions, not(is_record(I, ofp_instruction_goto_table)) and not(is_record(I, ofp_instruction_apply_actions))],
            % filter all output-actions form apply-actions
            FinalApplyActionInstruction = ApplyActionInstruction#ofp_instruction_apply_actions{actions = ApplyActionInstruction#ofp_instruction_apply_actions.actions ++ [OutputAction]},
            % create final instruction by filtered instructions without goto-table-instruction
            %    + refactored apply-action-instruction
            FinalInstructionList = FilteredInstructionList ++ [FinalApplyActionInstruction]
        end,
        %lager:info("FinalInstructionList ~p", [FinalInstructionList]),
        % read device table id
        DevTableId = tablevisor_ctrl4:tablevisor_switch_get({switchid, SwitchId}, processtable)
    end,
    % insert instructions into flow entry and replace tableid
    FlowMod2#ofp_flow_mod{table_id = DevTableId, instructions = FinalInstructionList}
                    end,
  % build requests
  Requests = [{SwitchId, RefactorFlowMod(SwitchId, FlowMod)} || SwitchId <- SwitchIdList],
  % build requests by applying matadata to mac matching
  MetadataProvider = ets:lookup_element(tablevisor_config, metadata_provider, 2),
  case MetadataProvider of
    srcmac ->
      Requests2 = [apply_metadata_provider(srcmac, Request) || Request <- Requests];
    dstmac ->
      Requests2 = [apply_metadata_provider(dstmac, Request) || Request <- Requests];
    vid ->
      Requests2 = [apply_metadata_provider(vid, Request) || Request <- Requests];
    _ ->
      Requests2 = Requests
  end,
  % log
  LogFlow = fun(TableId4, FlowMod4) ->
    LogFlow2 = tablevisor_logformat_flowmod(FlowMod4),
    tablevisor_log("~sSend ~sflow-mod~s to switch with table ~w:~s", [tvlc(blue), tvlc(blue, b), tvlc(blue), TableId4, LogFlow2])
            end,
  [LogFlow(TableId5, FlowMod3) || {TableId5, FlowMod3} <- Requests2],
  % send requests and receives replies
  tablevisor_ctrl4:tablevisor_multi_request(Requests2),
  {noreply, State}.

apply_metadata_provider(Provider, {SwitchId, FlowMod1}) ->
  % remove set field
  FlowMod2 = FlowMod1#ofp_flow_mod{
    instructions = metadata_remove_instruction_setfield(Provider, FlowMod1#ofp_flow_mod.instructions)
  },
  % set position specific flow mods
  Position = tablevisor_ctrl4:tablevisor_switch_get({switchid, SwitchId}, position),
  FlowMod3 = metatdata_apply_tableposition_action(Provider, Position, FlowMod2),
  % apply write metatdata
  {MetadataWrite, OtherInstructions} = metadata_split_write(FlowMod3#ofp_flow_mod.instructions),
  NewInstructions = metadata_add_metadata_provider_apply(OtherInstructions, Provider, MetadataWrite),
  FlowMod4 = FlowMod3#ofp_flow_mod{
    instructions = NewInstructions
  },
  % apply metadata match
  {MetadataMatch, OtherMatches} = metadata_split_match(FlowMod4#ofp_flow_mod.match#ofp_match.fields),
  NewMatches = metadata_add_metadata_provider_match(OtherMatches, Provider, MetadataMatch),
  FlowMod5 = FlowMod4#ofp_flow_mod{
    match = #ofp_match{fields = NewMatches}
  },
  % return refactored flow mod
  {SwitchId, FlowMod5}.

metatdata_apply_tableposition_action(Provider, Position, FlowMod) ->
  case Position of
    first ->
      metadata_init_action(Provider, FlowMod);
    last ->
      metadata_concluding_action(Provider, FlowMod);
    _ ->
      FlowMod
  end.

metadata_init_action(srcmac, FlowMod) ->
  NewSetField = #ofp_action_set_field{field = #ofp_field{name = eth_src, value = <<0, 0, 0, 0, 0, 0>>}},
  NewInstructions = metadata_add_action_to_instruction(FlowMod#ofp_flow_mod.instructions, NewSetField),
  FlowMod#ofp_flow_mod{
    instructions = NewInstructions
  };
metadata_init_action(dstmac, FlowMod) ->
  NewSetField = #ofp_action_set_field{field = #ofp_field{name = eth_dst, value = <<0, 0, 0, 0, 0, 0>>}},
  NewInstructions = metadata_add_action_to_instruction(FlowMod#ofp_flow_mod.instructions, NewSetField),
  FlowMod#ofp_flow_mod{
    instructions = NewInstructions
  };
metadata_init_action(vid, FlowMod) ->
  InstructionList = FlowMod#ofp_flow_mod.instructions,
  % push vlan tag
  PushVlanTagAction = #ofp_action_push_vlan{ethertype = 16#8100},
  InstructionList1 = metadata_add_action_to_instruction(InstructionList, PushVlanTagAction),
  % set vlan id to 0
  SetVlanIdAction = #ofp_action_set_field{field = #ofp_field{name = vlan_vid, value = <<128, 0:5>>}},
  InstructionList2 = metadata_add_action_to_instruction(InstructionList1, SetVlanIdAction),
  FlowMod#ofp_flow_mod{
    instructions = InstructionList2
  }.

metadata_concluding_action(srcmac, FlowMod) ->
  NewSetField = #ofp_action_set_field{field = #ofp_field{name = eth_src, value = <<0, 0, 0, 0, 0, 0>>}},
  NewInstructions = metadata_add_action_to_instruction(FlowMod#ofp_flow_mod.instructions, NewSetField),
  FlowMod#ofp_flow_mod{
    instructions = NewInstructions
  };
metadata_concluding_action(dstmac, FlowMod) ->
  NewSetField = #ofp_action_set_field{field = #ofp_field{name = eth_dst, value = <<0, 0, 0, 0, 0, 0>>}},
  NewInstructions = metadata_add_action_to_instruction(FlowMod#ofp_flow_mod.instructions, NewSetField),
  FlowMod#ofp_flow_mod{
    instructions = NewInstructions
  };
metadata_concluding_action(vid, FlowMod) ->
  PopVlanTagAction = #ofp_action_pop_vlan{},
  NewInstructions = metadata_add_action_to_instruction(FlowMod#ofp_flow_mod.instructions, PopVlanTagAction),
  OtherMatches = FlowMod#ofp_flow_mod.match#ofp_match.fields,
  EthertypeMatch = #ofp_field{class = openflow_basic, name = eth_type, value = <<129, 0>>},
  VidMatch = #ofp_field{class = openflow_basic, name = vlan_vid, value = <<128, 0:5>>, has_mask = true, mask = <<128, 0:5>>},
  FlowMod#ofp_flow_mod{
    match = #ofp_match{fields = OtherMatches ++ ([EthertypeMatch] ++ [VidMatch])},
    instructions = NewInstructions
  }.

metadata_split_write(InstructionList) ->
  metadata_split_write(false, [], InstructionList).
metadata_split_write(MetadataWrite, OtherInstructions, []) ->
  {MetadataWrite, OtherInstructions};
metadata_split_write(_MetadataWrite, OtherInstructions, [#ofp_instruction_write_metadata{} = MetadataWrite | InstructionList]) ->
  metadata_split_write(MetadataWrite, OtherInstructions, InstructionList);
metadata_split_write(MetadataWrite, OtherInstructions, [Instruction | InstructionList]) ->
  metadata_split_write(MetadataWrite, OtherInstructions ++ [Instruction], InstructionList).

metadata_add_metadata_provider_apply(InstructionList, _Provider, false) ->
  InstructionList;
metadata_add_metadata_provider_apply(InstructionList, srcmac, MetadataWrite) ->
  InstructionList2 = remove_instruction_setfield(InstructionList, eth_src),
  <<_:16, MetadataValue/binary>> = MetadataWrite#ofp_instruction_write_metadata.metadata,
  <<_:16, MetadataMask/binary>> = MetadataWrite#ofp_instruction_write_metadata.metadata_mask,
  NewSetField = #ofp_action_set_field{field = #ofp_field{name = eth_src, value = MetadataValue, has_mask = true, mask = MetadataMask}},
  metadata_add_action_to_instruction(InstructionList2, NewSetField);
metadata_add_metadata_provider_apply(InstructionList, dstmac, MetadataWrite) ->
  InstructionList2 = remove_instruction_setfield(InstructionList, eth_dst),
  <<_:16, MetadataValue/binary>> = MetadataWrite#ofp_instruction_write_metadata.metadata,
  <<_:16, MetadataMask/binary>> = MetadataWrite#ofp_instruction_write_metadata.metadata_mask,
  NewSetField = #ofp_action_set_field{field = #ofp_field{name = eth_dst, value = MetadataValue, has_mask = true, mask = MetadataMask}},
  metadata_add_action_to_instruction(InstructionList2, NewSetField);
metadata_add_metadata_provider_apply(InstructionList, vid, MetadataWrite) ->
  InstructionList2 = remove_instruction_setfield(InstructionList, vlan_vid),
  <<_:52, MetadataValue:12>> = MetadataWrite#ofp_instruction_write_metadata.metadata,
  <<_:52, MetadataMask:12>> = MetadataWrite#ofp_instruction_write_metadata.metadata_mask,
  NewSetField = #ofp_action_set_field{field = #ofp_field{name = vlan_vid, value = <<(MetadataValue + 16#1000):13>>, has_mask = true, mask = <<(MetadataMask + 16#1000):13>>}},
  metadata_add_action_to_instruction(InstructionList2, NewSetField).

metadata_add_action_to_instruction(InstructionList, NewAction) ->
  metadata_add_action_to_instruction([], NewAction, InstructionList).
metadata_add_action_to_instruction(InstructionList, NewAction, [#ofp_instruction_apply_actions{} = Instruction | RemainingInstructions]) ->
  NewInstructions = InstructionList ++ [Instruction#ofp_instruction_apply_actions{actions = Instruction#ofp_instruction_apply_actions.actions ++ [NewAction]}],
  metadata_add_action_to_instruction(NewInstructions, false, RemainingInstructions);
metadata_add_action_to_instruction(InstructionList, NewAction, [Instruction | RemainingInstructions]) ->
  NewInstructions = InstructionList ++ [Instruction],
  metadata_add_action_to_instruction(NewInstructions, NewAction, RemainingInstructions);
metadata_add_action_to_instruction(InstructionList, false, []) ->
  InstructionList;
metadata_add_action_to_instruction(InstructionList, NewAction, []) ->
  NewInstructions = InstructionList ++ [#ofp_instruction_apply_actions{actions = [NewAction]}],
  metadata_add_action_to_instruction(NewInstructions, false, []).

metadata_split_match(MatchFields) ->
  metadata_split_match(false, [], MatchFields).
metadata_split_match(MetadataMatch, OtherMatches, []) ->
  {MetadataMatch, OtherMatches};
metadata_split_match(_MetadataMatch, OtherMatches, [#ofp_field{name = metadata} = MetadataMatch | MatchFields]) ->
  metadata_split_match(MetadataMatch, OtherMatches, MatchFields);
metadata_split_match(MetadataMatch, OtherMatches, [MatchField | MatchFields]) ->
  metadata_split_match(MetadataMatch, OtherMatches ++ [MatchField], MatchFields).

metadata_add_metadata_provider_match(OtherMatches, _Provider, false) ->
  OtherMatches;
metadata_add_metadata_provider_match(OtherMatches, srcmac, MetadataMatch) ->
  <<_:16, MetadataValue/binary>> = MetadataMatch#ofp_field.value,
  <<_:16, MetadataMask/binary>> = MetadataMatch#ofp_field.mask,
  TranslatedMatch = #ofp_field{class = openflow_basic, name = eth_src, value = MetadataValue, has_mask = MetadataMatch#ofp_field.has_mask, mask = MetadataMask},
  OtherMatches ++ [TranslatedMatch];
metadata_add_metadata_provider_match(OtherMatches, dstmac, MetadataMatch) ->
  <<_:16, MetadataValue/binary>> = MetadataMatch#ofp_field.value,
  <<_:16, MetadataMask/binary>> = MetadataMatch#ofp_field.mask,
  TranslatedMatch = #ofp_field{class = openflow_basic, name = eth_dst, value = MetadataValue, has_mask = MetadataMatch#ofp_field.has_mask, mask = MetadataMask},
  OtherMatches ++ [TranslatedMatch];
metadata_add_metadata_provider_match(OtherMatches1, vid, MetadataMatch) ->
  % filter previous vid match from concluding table
  OtherMatches2 = [Match || Match <- OtherMatches1, Match#ofp_field.name /= vlan_vid],
  % create vid match
  <<_:52, MetadataValue:12>> = MetadataMatch#ofp_field.value,
  <<_:52, MetadataMask:12>> = MetadataMatch#ofp_field.mask,
  TranslatedMatch = #ofp_field{class = openflow_basic, name = vlan_vid, value = <<(MetadataValue + 16#1000):13>>, has_mask = MetadataMatch#ofp_field.has_mask, mask = <<(MetadataMask + 16#1000):13>>},
  OtherMatches2 ++ [TranslatedMatch].

remove_instruction_setfield(InstructionList, FieldName) ->
  ActionFilter =
    fun(Field) ->
      case Field of
        #ofp_action_set_field{field = #ofp_field{name = FieldName}} ->
          nil;
        _ ->
          Field
      end
    end,
  InstructionFilter =
    fun
      (#ofp_instruction_apply_actions{} = Instruction) ->
        Instruction#ofp_instruction_apply_actions{
          actions = [
            A || A <- [
              ActionFilter(A) || A <- Instruction#ofp_instruction_apply_actions.actions
            ], A /= nil
          ]
        };
      (Instruction) ->
        Instruction
    end,
  [InstructionFilter(I) || I <- InstructionList].

remove_instruction_pushvlan(InstructionList) ->
  ActionFilter =
    fun(Field) ->
      case Field of
        #ofp_action_push_vlan{} ->
          nil;
        _ ->
          Field
      end
    end,
  InstructionFilter =
    fun
      (#ofp_instruction_apply_actions{} = Instruction) ->
        Instruction#ofp_instruction_apply_actions{
          actions = [
            A || A <- [
              ActionFilter(A) || A <- Instruction#ofp_instruction_apply_actions.actions
            ], A /= nil
          ]
        };
      (Instruction) ->
        Instruction
    end,
  [InstructionFilter(I) || I <- InstructionList].

% remove flowmod set mac address action
-spec metadata_remove_instruction_setfield(atom(), [ofp_instruction()])
      -> {[ofp_instruction()]}.
metadata_remove_instruction_setfield(srcmac, InstructionList) ->
  remove_instruction_setfield(InstructionList, eth_src);
metadata_remove_instruction_setfield(dstmac, InstructionList) ->
  remove_instruction_setfield(InstructionList, eth_dst);
metadata_remove_instruction_setfield(vid, InstructionList) ->
  remove_instruction_pushvlan(
    remove_instruction_setfield(InstructionList, vlan_vid)
  ).

%% @doc Modify flow table configuration.
-spec ofp_table_mod(state(), ofp_table_mod()) ->
  {noreply, #state{}} |
  {reply, ofp_message(), #state{}}.
ofp_table_mod(State, #ofp_table_mod{table_id = TableId} = TableMod) ->
  lager:info("ofp_table_mod to ttpsim-switch ~p: ~p", [TableId, TableMod]),
  NewTableMod = TableMod#ofp_table_mod{table_id = 0},
  ttpsim_request(TableId, NewTableMod),
  {noreply, State}.

%% @doc Modify port configuration.
-spec ofp_port_mod(state(), ofp_port_mod()) ->
  {noreply, #state{}} |
  {reply, ofp_message(), #state{}}.
ofp_port_mod(#state{switch_id = SwitchId} = State,
    #ofp_port_mod{} = PortMod) ->
  case linc_us4_port:modify(SwitchId, PortMod) of
    ok ->
      {noreply, State};
    {error, {Type, Code}} ->
      ErrorMsg = #ofp_error_msg{type = Type,
        code = Code},
      {reply, ErrorMsg, State}
  end.

%% @doc Modify group entry in the group table.
-spec ofp_group_mod(state(), ofp_group_mod()) ->
  {noreply, #state{}} |
  {reply, ofp_message(), #state{}}.
ofp_group_mod(#state{switch_id = SwitchId} = State,
    #ofp_group_mod{} = GroupMod) ->
  case linc_us4_groups:modify(SwitchId, GroupMod) of
    ok ->
      {noreply, State};
    {error, ErrorMsg} ->
      {reply, ErrorMsg, State}
  end.

%% @doc Send packet in to controller (TableVisor)
-spec ofp_packet_in(integer(), ofp_packet_in()) ->
  no_return().
ofp_packet_in(SwitchId, Message) ->
  TableId = tablevisor_ctrl4:tablevisor_switch_get({switchid, SwitchId}, tableid),
  NewMessage = Message#ofp_message{body = Message#ofp_message.body#ofp_packet_in{table_id = TableId}},
  linc_logic:send_to_controllers(0, NewMessage).

%% @doc Send error message to controller (TableVisor)
-spec ofp_error_msg(ofp_error_msg()) ->
  no_return().
ofp_error_msg(Message) ->
  linc_logic:send_to_controllers(0, Message).

%% @doc Handle a packet received from controller.
-spec ofp_packet_out(state(), ofp_packet_out()) ->
  {noreply, #state{}} |
  {reply, ofp_message(), #state{}}.
ofp_packet_out(#state{switch_id = SwitchId} = State,
    #ofp_packet_out{buffer_id = no_buffer,
      actions = Actions,
      in_port = InPort,
      data = Data}) ->
  Pkt = linc_us4_packet:binary_to_record(Data, SwitchId, InPort),
  linc_us4_actions:apply_list(Pkt, Actions),
  {noreply, State};
ofp_packet_out(#state{switch_id = SwitchId} = State,
    #ofp_packet_out{buffer_id = BufferId,
      in_port = InPort,
      actions = Actions}) ->
  case linc_buffer:get_buffer(SwitchId, BufferId) of
    not_found ->
      %% Buffer has been dropped, ignore
      ok;
    Pkt ->
      LincPkt = #linc_pkt{in_port = InPort, packet = Pkt},
      linc_us4_actions:apply_list(
        LincPkt#linc_pkt{packet_in_reason = packet_out}, Actions)
  end,
  {noreply, State}.

%% @doc Reply to echo request.
-spec ofp_echo_request(state(), ofp_echo_request()) ->
  {reply, ofp_echo_reply(), #state{}}.
ofp_echo_request(State, #ofp_echo_request{data = Data}) ->
  EchoReply = #ofp_echo_reply{data = Data},
  {reply, EchoReply, State}.

%% @doc Reply to get config request.
-spec ofp_get_config_request(state(), ofp_get_config_request()) ->
  {reply, ofp_get_config_reply(), #state{}}.
ofp_get_config_request(#state{switch_config = SwitchConfig} = State,
    #ofp_get_config_request{}) ->
  ConfigReply = #ofp_get_config_reply{flags = proplists:get_value(
    flags,
    SwitchConfig),
    miss_send_len = proplists:get_value(
      miss_send_len,
      SwitchConfig)},
  {reply, ConfigReply, State}.

%% @doc Set switch configuration.
-spec ofp_set_config(state(), ofp_set_config()) -> {noreply, state()}.
ofp_set_config(State, #ofp_set_config{flags = Flags,
  miss_send_len = MissSendLength}) ->
  SwitchConfig = [{flags, Flags}, {miss_send_len, MissSendLength}],
  {noreply, State#state{switch_config = SwitchConfig}}.

%% @doc Reply to barrier request.
-spec ofp_barrier_request(state(), ofp_barrier_request()) ->
  {reply, ofp_barrier_reply(), #state{}}.
ofp_barrier_request(State, #ofp_barrier_request{}) ->
  BarrierReply = #ofp_barrier_reply{},
  {reply, BarrierReply, State}.

%% @doc Reply to get queue config request.
-spec ofp_queue_get_config_request(state(), ofp_queue_get_config_request()) ->
  {reply, ofp_get_config_reply(),
    #state{}}.
ofp_queue_get_config_request(State,
    #ofp_queue_get_config_request{port = Port}) ->
  QueueConfigReply = #ofp_queue_get_config_reply{port = Port,
    queues = []},
  {reply, QueueConfigReply, State}.

%% @doc Get switch description statistics.
-spec ofp_desc_request(state(), ofp_desc_request()) ->
  {reply, ofp_desc_reply(), #state{}}.
ofp_desc_request(State, #ofp_desc_request{}) ->
  {reply, #ofp_desc_reply{flags = [],
    mfr_desc = get_env(manufacturer_desc),
    hw_desc = get_env(hardware_desc),
    sw_desc = get_env(software_desc),
    serial_num = get_env(serial_number),
    dp_desc = get_env(datapath_desc)
  }, State}.


%% @doc Get flow entry statistics.
-spec ofp_flow_stats_request(state(), ofp_flow_stats_request()) ->
  {reply, ofp_flow_stats_reply(), #state{}}.
ofp_flow_stats_request(#state{switch_id = _SwitchId} = State, #ofp_flow_stats_request{table_id = TableId10} = Request) ->
  tablevisor_log("~sReceived ~sflow-stats-request~s from controller: Requesting table ~p", [tvlc(yellow), tvlc(yellow, b), tvlc(yellow), TableId10]),
  % anonymous function for getting table id list
  GetSwitchIdListFromTableId =
    fun(TableId) ->
      case TableId of
        all ->
          tablevisor_ctrl4:tablevisor_switchid_list();
        _ ->
          [tablevisor_ctrl4:tablevisor_switch_get({tableid, TableId}, switchid)]
      end
    end,
  % get table id list
  SwitchIdList = GetSwitchIdListFromTableId(Request#ofp_flow_stats_request.table_id),
  % anonymous function to generate indivudal table request
  GenerateTableRequest =
    fun(SwitchId, Request2) ->
      DevTableId = tablevisor_ctrl4:tablevisor_switch_get({switchid, SwitchId}, processtable),
      Request2#ofp_flow_stats_request{table_id = DevTableId}
    end,
  % build requests
  Requests = [{SwitchId, GenerateTableRequest(SwitchId, Request)} || SwitchId <- SwitchIdList],
  % log
  [begin
     tablevisor_log("~sSend ~sflow-stats-request~s to switch with table ~p: Requesting table ~p", [tvlc(green), tvlc(green, b), tvlc(green), TableId11, TableId12])
   end
    || {TableId11, #ofp_flow_stats_request{table_id = TableId12}} <- Requests],
  % send requests and receives replies
  Replies = tablevisor_ctrl4:tablevisor_multi_request(Requests, 2000),
  % anonymous function to refactor flow entries
  RefactorFlowEntry =
    fun(SwitchId, FlowEntry) ->
      % extract apply-action-instructions from all instructions
      ApplyActionInstructionList = [I || I <- FlowEntry#ofp_flow_stats.instructions, is_record(I, ofp_instruction_apply_actions)],
      case ApplyActionInstructionList == [] of
        true ->
          % there are no apply-action-instructions -> leave untouched
          FinalInstructionList = FlowEntry#ofp_flow_stats.instructions;
        false ->
          % get first (and only available) apply-action-instruction
          [ApplyActionInstruction | _] = ApplyActionInstructionList,
          % extract output-actions from apply-actions
          OutputActionList = [A || A <- ApplyActionInstruction#ofp_instruction_apply_actions.actions, is_record(A, ofp_action_output)],
          case OutputActionList == [] of
            true ->
              % there are no output-actions -> leave untouched
              FinalInstructionList = FlowEntry#ofp_flow_stats.instructions;
            false ->
              % extract first (and only available) outupt-action
              [OutputAction | _] = OutputActionList,
              % read port
              OutPort = OutputAction#ofp_action_output.port,
              % check if the output-port is a goto-table-connection
              OutputTableId = tablevisor_ctrl4:tablevisor_switch_get_gototable(SwitchId, OutPort),
              case OutputTableId of
                false ->
                  % no mapping from output-port to destination table -> leave untouched
                  FinalInstructionList = FlowEntry#ofp_flow_stats.instructions;
                _ ->
                  % the inspected output-action is a goto-table-connection
                  % create goto-table instruction
                  GotoTableInstruction = #ofp_instruction_goto_table{table_id = OutputTableId},
                  % filter all apply-actions from instructions
                  FilteredInstructionList = [I || I <- FlowEntry#ofp_flow_stats.instructions, not(is_record(I, ofp_instruction_apply_actions))],
                  % filter all output-actions form apply-actions
                  FilteredApplyActionList = [A || A <- ApplyActionInstruction#ofp_instruction_apply_actions.actions, not(is_record(A, ofp_action_output))],
                  % set new filtered apply-actions to apply-action-instruction without ouput-action
                  FinalApplyActionInstruction = ApplyActionInstruction#ofp_instruction_apply_actions{actions = FilteredApplyActionList},
                  % lager:info("Filtered Instructions: ~p", [FilteredInstructionList]),
                  % lager:info("Final ApplyAction Instructions: ~p", [FinalApplyActionInstruction]),
                  % lager:info("GotoTableInstruction: ~p", [GotoTableInstruction]),
                  % create final instruction by filtered instructions without apply-actions-instruction
                  %    + filtered apply-action-instruction without output-action
                  %    + generated goto-table instruction
                  FinalInstructionList = FilteredInstructionList ++ [FinalApplyActionInstruction] ++ [GotoTableInstruction]
              end
          end
      end,
      %lager:info("FinalInstructionList ~p", [FinalInstructionList]),
      % insert instructions into flow entry and replace tableid
      TableId = tablevisor_ctrl4:tablevisor_switch_get({switchid, SwitchId}, tableid),
      FlowEntry#ofp_flow_stats{table_id = TableId, instructions = FinalInstructionList}
    end,
  % log
  [begin
     StatsBody = Reply12#ofp_flow_stats_reply.body,
     [begin
        LogFlow = tablevisor_logformat_flowstats(Stats),
        tablevisor_log("~sReceived ~sflow-stats-reply~s from switch ~p: ~s", [tvlc(blue), tvlc(blue, b), tvlc(blue), TableId12, LogFlow])
      end || Stats <- StatsBody]
   end
    || {TableId12, Reply12} <- Replies],
  % anonymous function to separate flow entries
  SeparateFlowEntries =
    fun(SwitchId, Reply) ->
      Body = Reply#ofp_flow_stats_reply.body,
      [{SwitchId, FlowStat} || FlowStat <- Body]
    end,
  % rebuild reply
  FlowEntries = lists:flatten([SeparateFlowEntries(SwitchId, Reply) || {SwitchId, Reply} <- Replies]),
  Reply = #ofp_flow_stats_reply{
    body = [RefactorFlowEntry(SwitchId, FlowEntry) || {SwitchId, FlowEntry} <- FlowEntries]
  },
  % log
  %[begin
  %   LogFlow = tablevisor_logformat_flowstats(Stats),
  %   tablevisor_log("~sSend ~sflow-stats-reply~s to controller: ~s", [tvlc(yellow), tvlc(yellow, b), tvlc(yellow), LogFlow])
  % end || Stats <- Reply#ofp_flow_stats_reply.body],
  Flows12 = [tablevisor_logformat_flowstats(Stats) || Stats <- Reply#ofp_flow_stats_reply.body],
  tablevisor_log("~sSend ~sflow-stats-reply~s to controller: ~s", [tvlc(yellow), tvlc(yellow, b), tvlc(yellow), Flows12]),
  % return
  lager:info("Reply ~p", [Reply]),
  {reply, Reply, State}.

tablevsior_preparelog() ->
  filelib:ensure_dir("rel/log/"),
  {ok, IoDevice} = file:open("rel/log/tablevisor.log", [write]),
  %io:format(IoDevice, "", []),
  file:close(IoDevice).

tablevisor_log(Message, Data) ->
  MessageF = io_lib:format(Message, Data),
  {H, M, S} = time(),
  {_, _, Micro} = os:timestamp(),
  MS = erlang:round(Micro / 1000),
  Time = io_lib:format('~2..0b:~2..0b:~2..0b.~3..0b', [H, M, S, MS]),
  {ok, IoDevice} = file:open("rel/log/tablevisor.log", [append]),
  io:format(IoDevice, "~s~s ~s~s~s~n", [tvlc(white), Time, tvlc(white), MessageF, tvlc(white)]),
  file:close(IoDevice).

tablevisor_log(Message) ->
  tablevisor_log(Message, []).

tvlc(Color) ->
  tvlc(Color, 0).
tvlc(Color, Style) ->
  tvlc(Color, Style, black).
tvlc(Color, Style, Background) ->
  case Color of
    black -> C = 90;
    red -> C = 31;
    green -> C = 32;
    yellow -> C = 33;
    blue -> C = 34;
    purple -> C = 35;
    cyan -> C = 36;
    _ -> C = 37
  end,
  case Style of
    b -> S = 1;
    _ -> S = 0
  end,
  case Background of
    red -> B = 41;
    green -> B = 42;
    yellow -> B = 43;
    blue -> B = 44;
    purple -> B = 45;
    cyan -> B = 46;
    white -> B = 47;
    _ -> B = 0
  end,
  io_lib:format("~s[~sm~s[~s;~sm", [[27], io_lib:format("~p", [B]), [27], io_lib:format("~p", [S]), io_lib:format("~p", [C])]).

tablevisor_logformat_flowmod(Flow) ->
  Commons = io_lib:format("FLOW-MOD: Table ID: ~w, Priority: ~w", [Flow#ofp_flow_mod.table_id, Flow#ofp_flow_mod.priority]),
  MatchList = tablevisor_logformat_flow_match(Flow#ofp_flow_mod.match),
  Matches = string:concat("  MATCHES: ", string:join(MatchList, ", ")),
  InstructionList = tablevisor_logformat_flow_instruction(Flow#ofp_flow_mod.instructions),
  Actions = string:concat("  ACTIONS: ", string:join(InstructionList, ", ")),
  io_lib:format(string:join(["", Commons, Matches, Actions], "~n             "), []).

tablevisor_logformat_flowstats(Flow) ->
  Commons = io_lib:format("FLOW-STAT: Table ID: ~w, Priority: ~w", [Flow#ofp_flow_stats.table_id, Flow#ofp_flow_stats.priority]),
  MatchList = tablevisor_logformat_flow_match(Flow#ofp_flow_stats.match),
  Matches = string:concat("  MATCHES: ", string:join(MatchList, ", ")),
  InstructionList = tablevisor_logformat_flow_instruction(Flow#ofp_flow_stats.instructions),
  Actions = string:concat("  ACTIONS: ", string:join(InstructionList, ", ")),
  StatsList2 = tablevisor_logformat_flow_stats(Flow),
  Stats = string:concat("  STATS: ", string:join(StatsList2, ", ")),
  io_lib:format(string:join(["", Commons, Matches, Actions, Stats], "~n             "), []).


tablevisor_logformat_flow_match({ofp_match, Matches}) ->
  tablevisor_logformat_flow_match(Matches, []).

tablevisor_logformat_flow_match([], Reply) ->
  Reply;
tablevisor_logformat_flow_match([#ofp_field{name = in_port, value = Value} | Matches], Reply) ->
  Reply2 = Reply ++ [io_lib:format("In Port: ~p", [binary_to_int(Value)])],
  tablevisor_logformat_flow_match(Matches, Reply2);
tablevisor_logformat_flow_match([#ofp_field{name = metadata, value = Value, mask = Mask} | Matches], Reply) ->
  Reply2 = Reply ++ [io_lib:format("Metadata: ~s/~s", [binary_to_metadata(Value), binary_to_metadata(Mask)])],
  tablevisor_logformat_flow_match(Matches, Reply2);
tablevisor_logformat_flow_match([#ofp_field{name = eth_type, value = Value} | Matches], Reply) ->
  Reply2 = Reply ++ [io_lib:format("EtherType: 0x~4.16.0B", [binary_to_int(Value)])],
  tablevisor_logformat_flow_match(Matches, Reply2);
tablevisor_logformat_flow_match([#ofp_field{name = eth_src, value = Value, has_mask = true, mask = Mask} | Matches], Reply) ->
  Reply2 = Reply ++ [io_lib:format("Src. MAC: ~s/~s", [binary_to_mac(Value), binary_to_mac(Mask)])],
  tablevisor_logformat_flow_match(Matches, Reply2);
tablevisor_logformat_flow_match([#ofp_field{name = eth_src, value = Value} | Matches], Reply) ->
  Reply2 = Reply ++ [io_lib:format("Src. MAC: ~s", [binary_to_mac(Value)])],
  tablevisor_logformat_flow_match(Matches, Reply2);
tablevisor_logformat_flow_match([#ofp_field{name = eth_dst, value = Value, has_mask = true, mask = Mask} | Matches], Reply) ->
  Reply2 = Reply ++ [io_lib:format("Dst. MAC: ~s/~s", [binary_to_mac(Value), binary_to_mac(Mask)])],
  tablevisor_logformat_flow_match(Matches, Reply2);
tablevisor_logformat_flow_match([#ofp_field{name = eth_dst, value = Value} | Matches], Reply) ->
  Reply2 = Reply ++ [io_lib:format("Dst. MAC: ~s", [binary_to_mac(Value)])],
  tablevisor_logformat_flow_match(Matches, Reply2);
tablevisor_logformat_flow_match([#ofp_field{name = ipv4_src, value = Value, mask = Mask} | Matches], Reply) ->
  Reply2 = Reply ++ [io_lib:format("Src. IP: ~s/~p", [binary_to_ipv4(Value), binary_to_ipv4_prefixlength(Mask)])],
  tablevisor_logformat_flow_match(Matches, Reply2);
tablevisor_logformat_flow_match([#ofp_field{name = ipv4_dst, value = Value, mask = Mask} | Matches], Reply) ->
  Reply2 = Reply ++ [io_lib:format("Dst. IP: ~s/~p", [binary_to_ipv4(Value), binary_to_ipv4_prefixlength(Mask)])],
  tablevisor_logformat_flow_match(Matches, Reply2);
tablevisor_logformat_flow_match([#ofp_field{name = vlan_vid, value = Value, has_mask = true, mask = Mask} | Matches], Reply) ->
  Reply2 = Reply ++ [io_lib:format("VLAN Id: ~s/~s", [binary_to_vlan_vid(Value), binary_to_vlan_vid(Mask)])],
  tablevisor_logformat_flow_match(Matches, Reply2);
tablevisor_logformat_flow_match([#ofp_field{name = vlan_vid, value = Value} | Matches], Reply) ->
  Reply2 = Reply ++ [io_lib:format("VLAN Id: ~s", [binary_to_vlan_vid(Value)])],
  tablevisor_logformat_flow_match(Matches, Reply2);
tablevisor_logformat_flow_match([#ofp_field{name = mpls_label, value = Value} | Matches], Reply) ->
  Reply2 = Reply ++ [io_lib:format("MPLS Label: ~s", [binary_to_mpls_label(Value)])],
  tablevisor_logformat_flow_match(Matches, Reply2);
tablevisor_logformat_flow_match([#ofp_field{name = mpls_bos, value = Value} | Matches], Reply) ->
  Reply2 = Reply ++ [io_lib:format("MPLS BOS: ~s", [binary_to_mpls_bos(Value)])],
  tablevisor_logformat_flow_match(Matches, Reply2);
tablevisor_logformat_flow_match([_Match | Matches], Reply) ->
  tablevisor_logformat_flow_match(Matches, Reply).

tablevisor_logformat_flow_instruction(Instructions) ->
  tablevisor_logformat_flow_instruction(Instructions, []).

tablevisor_logformat_flow_instruction([], Reply) ->
  Reply;
tablevisor_logformat_flow_instruction([#ofp_instruction_goto_table{table_id = TableId} | Instructions], Reply) ->
  Reply2 = Reply ++ [io_lib:format("Goto Table: ~p", [TableId])],
  tablevisor_logformat_flow_instruction(Instructions, Reply2);
tablevisor_logformat_flow_instruction([#ofp_instruction_apply_actions{actions = Actions} | Instructions], Reply) ->
  ActionList = tablevisor_logformat_flow_action(Actions),
  Reply2 = Reply ++ ActionList,
  tablevisor_logformat_flow_instruction(Instructions, Reply2);
tablevisor_logformat_flow_instruction([#ofp_instruction_write_metadata{metadata = Metadata, metadata_mask = MetadataMask} | Instructions], Reply) ->
  Reply2 = Reply ++ [io_lib:format("Write Metadata: ~s/~s", [binary_to_metadata(Metadata), binary_to_metadata(MetadataMask)])],
  tablevisor_logformat_flow_instruction(Instructions, Reply2);
tablevisor_logformat_flow_instruction([_Instruction | Instructions], Reply) ->
  tablevisor_logformat_flow_instruction(Instructions, Reply).

tablevisor_logformat_flow_action(Actions) ->
  tablevisor_logformat_flow_action(Actions, []).

tablevisor_logformat_flow_action([], Reply) ->
  Reply;
tablevisor_logformat_flow_action([#ofp_action_output{port = Port} | Actions], Reply) ->
  Reply2 = Reply ++ [io_lib:format("Output: ~p", [Port])],
  tablevisor_logformat_flow_action(Actions, Reply2);
tablevisor_logformat_flow_action([#ofp_action_pop_mpls{ethertype = EthType} | Actions], Reply) ->
  Reply2 = Reply ++ [io_lib:format("Pop MPLS: 0x~4.16.0B", [EthType])],
  tablevisor_logformat_flow_action(Actions, Reply2);
tablevisor_logformat_flow_action([#ofp_action_push_vlan{ethertype = EthType} | Actions], Reply) ->
  Reply2 = Reply ++ [io_lib:format("Push VLAN: 0x~4.16.0B", [EthType])],
  tablevisor_logformat_flow_action(Actions, Reply2);
tablevisor_logformat_flow_action([#ofp_action_pop_vlan{} | Actions], Reply) ->
  Reply2 = Reply ++ [io_lib:format("Pop VLAN", [])],
  tablevisor_logformat_flow_action(Actions, Reply2);
tablevisor_logformat_flow_action([#ofp_action_set_field{field = #ofp_field{name = eth_src, value = Value, has_mask = true, mask = Mask}} | Actions], Reply) ->
  Reply2 = Reply ++ [io_lib:format("Set Src. MAC: ~s/~s", [binary_to_mac(Value), binary_to_mac(Mask)])],
  tablevisor_logformat_flow_action(Actions, Reply2);
tablevisor_logformat_flow_action([#ofp_action_set_field{field = #ofp_field{name = eth_src, value = Value}} | Actions], Reply) ->
  Reply2 = Reply ++ [io_lib:format("Set Src. MAC: ~s", [binary_to_mac(Value)])],
  tablevisor_logformat_flow_action(Actions, Reply2);
tablevisor_logformat_flow_action([#ofp_action_set_field{field = #ofp_field{name = eth_dst, value = Value, has_mask = true, mask = Mask}} | Actions], Reply) ->
  Reply2 = Reply ++ [io_lib:format("Set Dst. MAC: ~s/~s", [binary_to_mac(Value), binary_to_mac(Mask)])],
  tablevisor_logformat_flow_action(Actions, Reply2);
tablevisor_logformat_flow_action([#ofp_action_set_field{field = #ofp_field{name = eth_dst, value = Value}} | Actions], Reply) ->
  Reply2 = Reply ++ [io_lib:format("Set Dst. MAC: ~s", [binary_to_mac(Value)])],
  tablevisor_logformat_flow_action(Actions, Reply2);
tablevisor_logformat_flow_action([#ofp_action_set_field{field = #ofp_field{name = vlan_vid, value = Value, has_mask = true, mask = Mask}} | Actions], Reply) ->
  Reply2 = Reply ++ [io_lib:format("Set VLAN-Id: ~s/~s", [binary_to_vlan_vid(Value), binary_to_vlan_vid(Mask)])],
  tablevisor_logformat_flow_action(Actions, Reply2);
tablevisor_logformat_flow_action([#ofp_action_set_field{field = #ofp_field{name = vlan_vid, value = Value}} | Actions], Reply) ->
  Reply2 = Reply ++ [io_lib:format("Set VLAN-Id: ~s", [binary_to_vlan_vid(Value)])],
  tablevisor_logformat_flow_action(Actions, Reply2);
tablevisor_logformat_flow_action([_Action | Actions], Reply) ->
  tablevisor_logformat_flow_action(Actions, Reply).

tablevisor_logformat_flow_stats(Flow) ->
  [
    io_lib:format("Packet Count: ~w", [Flow#ofp_flow_stats.packet_count]),
    io_lib:format("Duration (sec): ~w", [Flow#ofp_flow_stats.duration_sec])
  ].

binary_to_int(Bin) ->
  Size = size(Bin),
  <<Int:Size/integer-unit:8>> = Bin,
  Int.

binary_to_mac(Bin) ->
  <<A:8, B:8, C:8, D:8, E:8, F:8>> = Bin,
  io_lib:format("~2.16.0B:~2.16.0B:~2.16.0B:~2.16.0B:~2.16.0B:~2.16.0B", [A, B, C, D, E, F]).

binary_to_metadata(Bin) ->
  <<A:8, B:8, C:8, D:8, E:8, F:8, G:8, H:8>> = Bin,
  io_lib:format("~2.16.0B:~2.16.0B:~2.16.0B:~2.16.0B:~2.16.0B:~2.16.0B:~2.16.0B:~2.16.0B", [A, B, C, D, E, F, G, H]).

binary_to_ipv4(Bin) ->
  <<A:8, B:8, C:8, D:8>> = Bin,
  io_lib:format("~.10B.~.10B.~.10B.~.10B", [A, B, C, D]).

binary_to_vlan_vid(Bin) ->
  <<A, B:5>> = Bin,
  io_lib:format("~w", [(A * 32 + B) - 16#1000]).

binary_to_mpls_label(Bin) ->
  <<A, B, C:4>> = Bin,
  io_lib:format("~w", [(A * 2048 + B * 16 + C)]).

binary_to_mpls_bos(Bin) ->
  <<A:1>> = Bin,
  io_lib:format("~w", [(A)]).

binary_to_ipv4_prefixlength(Bin) ->
  Int = binary_to_int(Bin),
  String = lists:flatten(io_lib:format("~.2B", [Int])),
  string:rchr(String, $1).

%% @doc Get aggregated flow statistics.
-spec ofp_aggregate_stats_request(state(), ofp_aggregate_stats_request()) ->
  {reply, ofp_aggregate_stats_reply(),
    #state{}}.
ofp_aggregate_stats_request(#state{switch_id = SwitchId} = State,
    #ofp_aggregate_stats_request{} = Request) ->
  Reply = linc_us4_flow:get_aggregate_stats(SwitchId, Request),
  {reply, Reply, State}.

%% @doc Get flow table statistics.
-spec ofp_table_stats_request(state(), ofp_table_stats_request()) ->
  {reply, ofp_table_stats_reply(), #state{}}.
ofp_table_stats_request(#state{switch_id = SwitchId} = State,
    #ofp_table_stats_request{} = Request) ->
  Reply = linc_us4_flow:get_table_stats(SwitchId, Request),
  {reply, Reply, State}.

-spec ofp_table_features_request(state(), #ofp_table_features_request{}) ->
  {reply, #ofp_table_features_reply{},
    #state{}}.
ofp_table_features_request(#state{switch_id = _SwitchId} = State, #ofp_table_features_request{} = Request) ->
  tablevisor_log("~sReceived ~stable-features-request~s from controller", [tvlc(yellow), tvlc(yellow, b), tvlc(yellow)]),
  lager:info("Received table_features_request from Controller"),
  % get switch id list
  SwitchIdList = tablevisor_ctrl4:tablevisor_switchid_list(),
  % anonymous function to generate individual table request
  TableFeaturesRequest =
    fun(OriginalRequest) ->
      #ofp_table_features_request{
        flags = OriginalRequest#ofp_table_features_request.flags
      }
    end,
  % build requests
  Requests = [{SwitchId, TableFeaturesRequest(Request)} || SwitchId <- SwitchIdList],
  % send requests and receives replies
  Replies = tablevisor_ctrl4:tablevisor_multi_request(Requests, 2000),
  TableFeatures = [ofp_table_features_request_parse_tables(SwitchId, Reply) || {SwitchId, Reply} <- Replies],
  Reply = #ofp_table_features_reply{body = TableFeatures},
  %% Reply = linc_us4_table_features:handle_req(SwitchId, Request),
%%  lager:warning("Reply ~p", [Reply]),
  lager:info("Send table_features_reply to Controller"),
  tablevisor_log("~sSend ~sfeatures-reply~s to controller", [tvlc(yellow), tvlc(yellow, b), tvlc(yellow)]),
  {reply, Reply, State}.

ofp_table_features_request_parse_tables(SwitchId, Reply) ->
  ProcessTableId = tablevisor_ctrl4:tablevisor_switch_get({switchid, SwitchId}, processtable),
  TableFeaturesList = Reply#ofp_table_features_reply.body,
  ofp_table_features_request_filter_processtable(SwitchId, ProcessTableId, TableFeaturesList).

ofp_table_features_request_filter_processtable(SwitchId, ProcessTableId, [TableFeatures | TableFeaturesList]) ->
  case TableFeatures#ofp_table_features.table_id of
    ProcessTableId ->
      % metadata
      MetadataProvider = ets:lookup_element(tablevisor_config, metadata_provider, 2),
      case MetadataProvider of
        mac ->
          MetadataMatch = <<255, 255, 255, 255, 255, 255, 0, 0>>,
          MetadataWrite = <<255, 255, 255, 255, 255, 255, 0, 0>>;
        _ ->
          MetadataMatch = <<0, 0, 0, 0, 0, 0, 0, 0>>,
          MetadataWrite = <<0, 0, 0, 0, 0, 0, 0, 0>>
      end,
      % properties
      Properties = [
        P || P <- [ofp_table_features_request_rewrite_properties(SwitchId, P) || P <- TableFeatures#ofp_table_features.properties],
        P =/= false
      ],
      % get tableid from switchid
      TableId = tablevisor_ctrl4:tablevisor_switch_get({switchid, SwitchId}, tableid),
      % build table features
      TableFeatures#ofp_table_features{
        table_id = TableId,
        metadata_match = MetadataMatch,
        metadata_write = MetadataWrite,
        properties = Properties
      };
    _ ->
      ofp_table_features_request_filter_processtable(SwitchId, ProcessTableId, TableFeaturesList)
  end;
ofp_table_features_request_filter_processtable(_SwitchId, _ProcessTableId, []) ->
  [].

ofp_table_features_request_rewrite_properties(_SwitchId, Property)
  when is_record(Property, ofp_table_feature_prop_instructions) ->
  Property;
ofp_table_features_request_rewrite_properties(_SwitchId, Property)
  when is_record(Property, ofp_table_feature_prop_instructions_miss) ->
  Property;
ofp_table_features_request_rewrite_properties(SwitchId, Property)
  when is_record(Property, ofp_table_feature_prop_next_tables) ->
  OutportMap = tablevisor_ctrl4:tablevisor_switch_get({switchid, SwitchId}, outportmap),
  NextSwitches = [NextSwitchId || {NextSwitchId, _EgressPort} <- OutportMap],
  NextTables = [tablevisor_ctrl4:tablevisor_switch_get({switchid, NextSwitchId}, tableid) || NextSwitchId <- NextSwitches],
  Property2 = Property#ofp_table_feature_prop_next_tables{next_table_ids = NextTables},
  lager:debug("Table ~p, Outportmap ~p, Nexttables ~p", [SwitchId, OutportMap, NextTables]),
  Property2;
ofp_table_features_request_rewrite_properties(SwitchId, Property)
  when is_record(Property, ofp_table_feature_prop_next_tables_miss) ->
  OutportMap = tablevisor_ctrl4:tablevisor_switch_get({switchid, SwitchId}, outportmap),
  NextSwitches = [NextSwitchId || {NextSwitchId, _EgressPort} <- OutportMap],
  NextTables = [tablevisor_ctrl4:tablevisor_switch_get({switchid, NextSwitchId}, tableid) || NextSwitchId <- NextSwitches],
  Property2 = Property#ofp_table_feature_prop_next_tables_miss{next_table_ids = NextTables},
  lager:debug("Table ~p, Outportmap ~p, Nexttables ~p", [SwitchId, OutportMap, NextTables]),
  Property2;
ofp_table_features_request_rewrite_properties(_SwitchId, Property)
  when is_record(Property, ofp_table_feature_prop_write_actions) ->
  false;
ofp_table_features_request_rewrite_properties(_SwitchId, Property)
  when is_record(Property, ofp_table_feature_prop_write_actions_miss) ->
  false;
ofp_table_features_request_rewrite_properties(_SwitchId, Property)
  when is_record(Property, ofp_table_feature_prop_apply_actions) ->
  false;
ofp_table_features_request_rewrite_properties(_SwitchId, Property)
  when is_record(Property, ofp_table_feature_prop_apply_actions_miss) ->
  false;
ofp_table_features_request_rewrite_properties(_SwitchId, Property)
  when is_record(Property, ofp_table_feature_prop_match) ->
  lager:debug("#ofp_table_feature_prop_match: ~p", [Property]),
  %% TODO
  false;
ofp_table_features_request_rewrite_properties(_SwitchId, Property)
  when is_record(Property, ofp_table_feature_prop_wildcards) ->
  lager:debug("#ofp_table_feature_prop_wildcards: ~p", [Property]),
  %% TODO
  false;
ofp_table_features_request_rewrite_properties(_SwitchId, Property)
  when is_record(Property, ofp_table_feature_prop_write_setfield) ->
  lager:debug("#ofp_table_feature_prop_write_setfield: ~p", [Property]),
  %% TODO
  false;
ofp_table_features_request_rewrite_properties(_SwitchId, Property)
  when is_record(Property, ofp_table_feature_prop_write_setfield_miss) ->
  lager:debug("#ofp_table_feature_prop_write_setfield_miss: ~p", [Property]),
  %% TODO
  false;
ofp_table_features_request_rewrite_properties(_SwitchId, Property)
  when is_record(Property, ofp_table_feature_prop_apply_setfield) ->
  lager:debug("#ofp_table_feature_prop_apply_setfield: ~p", [Property]),
  %% TODO
  false;
ofp_table_features_request_rewrite_properties(_SwitchId, Property)
  when is_record(Property, ofp_table_feature_prop_apply_setfield_miss) ->
  lager:debug("#ofp_table_feature_prop_apply_setfield_miss: ~p", [Property]),
  %% TODO
  false;
ofp_table_features_request_rewrite_properties(_SwitchId, Property)
  when is_record(Property, ofp_table_feature_prop_experimenter) ->
  lager:debug("#ofp_table_feature_prop_experimenter: ~p", [Property]),
  %% TODO
  false;
ofp_table_features_request_rewrite_properties(_SwitchId, Property)
  when is_record(Property, ofp_table_feature_prop_experimenter_miss) ->
  lager:debug("#ofp_table_feature_prop_experimenter_miss: ~p", [Property]),
  %% TODO
  false;
ofp_table_features_request_rewrite_properties(_SwitchId, Property) ->
  lager:warning("Unknown table_feature_property: ~p", [Property]),
  false.


%% @doc Get port description.
-spec ofp_port_desc_request(state(), ofp_port_desc_request()) ->
  {reply, ofp_port_desc_reply(), #state{}}.
ofp_port_desc_request(#state{switch_id = SwitchId} = State,
    #ofp_port_desc_request{}) ->
  Reply = linc_us4_port:get_desc(SwitchId),
  {reply, Reply, State}.

%% @doc Get port statistics.
-spec ofp_port_stats_request(state(), ofp_port_stats_request()) ->
  {reply, ofp_port_stats_reply(), #state{}}.
ofp_port_stats_request(#state{switch_id = SwitchId} = State,
    #ofp_port_stats_request{} = Request) ->
  Reply = linc_us4_port:get_stats(SwitchId, Request),
  {reply, Reply, State}.

%% @doc Get queue statistics.
-spec ofp_queue_stats_request(state(), ofp_queue_stats_request()) ->
  {reply, ofp_queue_stats_reply(), #state{}}.
ofp_queue_stats_request(#state{switch_id = SwitchId} = State,
    #ofp_queue_stats_request{} = Request) ->
  Reply = linc_us4_queue:get_stats(SwitchId, Request),
  {reply, Reply, State}.

%% @doc Get group statistics.
-spec ofp_group_stats_request(state(), ofp_group_stats_request()) ->
  {reply, ofp_group_stats_reply(), #state{}}.
ofp_group_stats_request(#state{switch_id = SwitchId} = State,
    #ofp_group_stats_request{} = Request) ->
  Reply = linc_us4_groups:get_stats(SwitchId, Request),
  {reply, Reply, State}.

%% @doc Get group description statistics.
-spec ofp_group_desc_request(state(), ofp_group_desc_request()) ->
  {reply, ofp_group_desc_reply(), #state{}}.
ofp_group_desc_request(#state{switch_id = SwitchId} = State,
    #ofp_group_desc_request{} = Request) ->
  Reply = linc_us4_groups:get_desc(SwitchId, Request),
  {reply, Reply, State}.

%% @doc Get group features statistics.
-spec ofp_group_features_request(state(),
    ofp_group_features_request()) ->
  {reply, ofp_group_features_reply(),
    #state{}}.
ofp_group_features_request(State,
    #ofp_group_features_request{} = Request) ->
  Reply = linc_us4_groups:get_features(Request),
  {reply, Reply, State}.

%%%-----------------------------------------------------------------------------
%%% TableVisor Functions
%%%-----------------------------------------------------------------------------

tablevisor_init_connection(SwitchId) ->
  FlowMods = tablevisor_ctrl4:tablevisor_switch_get({switchid, SwitchId}, flowmods),
  % create instructions + actions
  CreateInstructions = fun(Actions) ->
    FunR = fun([], InstructionList, _) ->
      InstructionList;
      ([Action | Actions2], InstructionList, Fun) ->
        case Action of
          {gototable, TargetTableId} ->
            Instruction = #ofp_instruction_goto_table{table_id = TargetTableId};
          {output, OutputPort} ->
            Instruction = #ofp_instruction_apply_actions{actions = [#ofp_action_output{port = OutputPort}]};
          {pushvlan, EtherType, VlanId, OutputPort} ->
            Instruction = #ofp_instruction_apply_actions{actions = [#ofp_action_output{port = OutputPort}, #ofp_action_push_vlan{ethertype = EtherType}, #ofp_action_set_field{field = #ofp_field{name = vlan_vid, value = <<VlanId:16>>, mask = <<0:16>>}}]};
          {setvlanid, VlanId} ->
            Instruction = #ofp_instruction_apply_actions{actions = [#ofp_action_set_field{field = #ofp_field{name = vlan_vid, value = <<VlanId:16>>}}]};
          {_, _} ->
            Instruction = false
        end,
        Fun(Actions2, [Instruction | InstructionList], Fun)
           end,
    FunR(Actions, [], FunR)
                       end,
  % create matches
  CreateMatches = fun(Matches) ->
    FunR = fun([], MatchesList, _) ->
      MatchesList;
      ([Match | Matches2], MatchesList, Fun) ->
        case Match of
          {inport, InPort} ->
            MatchField = #ofp_field{name = in_port, value = <<InPort:32>>};
          {vlanid, VlanId} ->
            MatchField = #ofp_field{name = vlan_vid, value = <<VlanId:16>>};
          {ethdst, EthDst} ->
            MatchField = #ofp_field{name = eth_dst, value = <<EthDst:48>>};
          {ethertype, EtherType} ->
            MatchField = #ofp_field{name = eth_type, value = <<EtherType:16>>};
          {metadata, Metadata} ->
            MatchField = #ofp_field{name = metadata, value = <<Metadata:64>>};
          {_, _} ->
            MatchField = false
        end,
        Fun(Matches2, [MatchField | MatchesList], Fun)
           end,
    FunR(Matches, [], FunR)
                  end,
  % create flow entry
  CreateFlowMod = fun(FlowModConfig) ->
    % read and set values
    case lists:keyfind(tableid, 1, FlowModConfig) of
      {tableid, TableId2} -> false;
      false -> TableId2 = 0
    end,
    case lists:keyfind(priority, 1, FlowModConfig) of
      {priority, Priority} -> false;
      false -> Priority = 100
    end,
    case lists:keyfind(outport, 1, FlowModConfig) of
      {outport, OutPort} -> false;
      false -> OutPort = 0
    end,
    case lists:keyfind(match, 1, FlowModConfig) of
      {match, Matches} -> MatchList = CreateMatches(Matches);
      false -> MatchList = []
    end,
    case lists:keyfind(action, 1, FlowModConfig) of
      {action, Actions} -> InstructionList = CreateInstructions(Actions);
      false -> InstructionList = []
    end,
    % create flow mod
    FlowMod = #ofp_flow_mod{
      table_id = TableId2,
      command = add,
      hard_timeout = 0,
      idle_timeout = 0,
      priority = Priority,
      out_port = OutPort,
      flags = [send_flow_rem],
      match = #ofp_match{fields = MatchList},
      instructions = InstructionList
    },
    FlowMod
                  end,
  % send flow mod
  SendFlowMod = fun(FlowModConfig) ->
    FlowMod = CreateFlowMod(FlowModConfig),
    Message = tablevisor_ctrl4:message(FlowMod),
    tablevisor_ctrl4:send(SwitchId, Message)
                end,
  [SendFlowMod(FlowModConfig) || FlowModConfig <- FlowMods].

%% tablevisor_flow_add_backline(TableId) ->
%%   case TableId of
%%     0 ->
%%       ExtractMapPerTable = fun(TableId2) ->
%%         BackLineMap = tablevisor_ctrl4:tablevisor_switch_get(TableId2, backlinemap),
%%         [{DstPort, OriginPort} || {OriginPort, _SrcPort, DstPort} <- BackLineMap]
%%       end,
%%       TableList = tablevisor_ctrl4:tablevisor_tables(),
%%       List1 = [ExtractMapPerTable(TableId2) || TableId2 <- TableList],
%%       List2 = lists:flatten(List1),
%%       SendFlowMod = fun(DstPort, OriginPort) ->
%%         FlowMod = #ofp_flow_mod{
%%           table_id = 200,
%%           command = add,
%%           hard_timeout = 0,
%%           idle_timeout = 0,
%%           priority = 100,
%%           flags = [send_flow_rem],
%%           match = #ofp_match{fields = [#ofp_field{name = in_port, value = <<DstPort>>}]},
%%           instructions = [
%%             #ofp_instruction_apply_actions{actions = [#ofp_action_output{port = OriginPort}]}
%%           ]
%%         },
%%         Message = tablevisor_ctrl4:message(FlowMod),
%%         tablevisor_ctrl4:send(TableId, Message)
%%       end,
%%       [SendFlowMod(DstPort, OriginPort) || {DstPort, OriginPort} <- List2],
%%       true;
%%     _ ->
%%       false
%%   end.

ttpsim_request(RequestedTable, Request) ->
  % reformat requested table from integer or atom all to list
  case RequestedTable of
    all ->
      %lager:info("Table all"),
      RequestedTableList = tablevisor_ctrl4:tablevisor_tables();
    _ ->
      %lager:info("Table ~p", [RequestedTable]),
      RequestedTableList = [RequestedTable]
  end,
  % start sender process
  spawn(fun() ->
    ttpsim_transmit(RequestedTableList, Request)
        end),
  ok.

ttpsim_transmit([], _Request) ->
  true;
ttpsim_transmit([TableId | RequestedTable], Request) ->
  spawn(fun() ->
    %lager:info("send to ~p with message ~p", [TableId, Request]),
    Message = tablevisor_ctrl4:message(Request),
    {noreply, ok} = tablevisor_ctrl4:send(TableId, Message)
        end),
  ttpsim_transmit(RequestedTable, Request).


%% Meters ----------------------------------------------------------------------

ofp_meter_mod(#state{switch_id = SwitchId} = State,
    #ofp_meter_mod{} = MeterMod) ->
  case linc_us4_meter:modify(SwitchId, MeterMod) of
    noreply ->
      {noreply, State};
    {reply, Reply} ->
      {reply, Reply, State}
  end.

ofp_meter_stats_request(#state{switch_id = SwitchId} = State,
    #ofp_meter_stats_request{meter_id = Id}) ->
  {reply, linc_us4_meter:get_stats(SwitchId, Id), State}.

ofp_meter_config_request(#state{switch_id = SwitchId} = State,
    #ofp_meter_config_request{meter_id = Id}) ->
  {reply, linc_us4_meter:get_config(SwitchId, Id), State}.

ofp_meter_features_request(State, #ofp_meter_features_request{}) ->
  {reply, linc_us4_meter:get_features(), State}.

%%%-----------------------------------------------------------------------------
%%% Helpers
%%%-----------------------------------------------------------------------------

get_env(Env) ->
  {ok, Value} = application:get_env(linc, Env),
  Value.
