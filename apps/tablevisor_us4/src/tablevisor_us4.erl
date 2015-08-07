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
  tablevisor_init_connection/1
]).

%% Handle messages from switches to controller
-export([
  ofp_packet_in/2
]).



-include_lib("of_protocol/include/of_protocol.hrl").
-include_lib("of_protocol/include/ofp_v4.hrl").
-include_lib("linc/include/linc_logger.hrl").
-include("linc_us4.hrl").

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
    % initialize controller for table type pattern simulation
    {switch_id, SwitchId} = lists:keyfind(switch_id, 1, BackendOpts),
    {datapath_mac, DatapathMac} = lists:keyfind(datapath_mac, 1, BackendOpts),
    {config, Config} = lists:keyfind(config, 1, BackendOpts),
    tablevisor_read_config(SwitchId, Config),
    {ok} = init_controller(6633),
    lager:info("Switch initialization: We wait several seconds for ttpsim-switch initialization."),
    % wait for ttpsim switches
    timer:sleep(12000),
    lager:info("Waiting finished. Now initialize the switch and connect to external controller."),
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
  ets:new(tablevisor_socket, [public, named_table, {read_concurrency, true}]).

tablevisor_create_switch_config(Switch) ->
  {table, TableId, SwitchConfig} = Switch,
  {dpid, DpId} = lists:keyfind(dpid, 1, SwitchConfig),
  {processtable, ProcessTable} = lists:keyfind(processtable, 1, SwitchConfig),
  {egresstable, EgressTable} = lists:keyfind(egresstable, 1, SwitchConfig),
  {outportmap, OutportMap} = lists:keyfind(outportmap, 1, SwitchConfig),
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
    {egresstable, EgressTable},
    {flowmods, FlowMods}
  ],
  ets:insert(tablevisor_switch, {TableId, Config}).


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

%% @doc Modify flow entry in the flow table.
-spec ofp_flow_mod(state(), ofp_flow_mod()) ->
  {noreply, #state{}} |
  {reply, ofp_message(), #state{}}.
ofp_flow_mod(#state{switch_id = _SwitchId} = State, #ofp_flow_mod{table_id = TableId} = FlowMod) ->
  %lager:info("ofp_flow_mod to tablevisor-switch ~p: ~p", [TableId, FlowMod]),
  % get table id list
  TableIdList = [TableId],
  % anonymous function to generate flow mod
  RefactorFlowMod = fun(TableId2, FlowMod2) ->
    % extract apply-action-instructions from all instructions
    GotoTableInstructionList = [I || I <- FlowMod2#ofp_flow_mod.instructions, is_record(I, ofp_instruction_goto_table)],
    case GotoTableInstructionList == [] of
      true ->
        % there are no goto-table-instructions -> leave untouched
        FinalInstructionList = FlowMod2#ofp_flow_mod.instructions,
        DevTableId = tablevisor_ctrl4:tablevisor_switch_get(TableId2, processtable);
      false ->
        % get first (and only) goto-table-action-instruction
        [GotoTableInstruction | _] = GotoTableInstructionList,
        Outport = tablevisor_ctrl4:tablevisor_switch_get_outport(TableId2, GotoTableInstruction#ofp_instruction_goto_table.table_id),
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
                ApplyActionInstruction = #ofp_instruction_apply_actions{};
              false ->
                % the the first (and only) apply-action-instruction
                [ApplyActionInstruction | _] = ApplyActionInstructionList
            end,
            % create output action and append it to apply-action-instruction
            OutputAction = #ofp_action_output{port = Outport},
            % filter all apply-actions from instructions
            lager:info("Instructions ~p", [FlowMod2#ofp_flow_mod.instructions]),
            FilteredInstructionList = [I || I <- FlowMod2#ofp_flow_mod.instructions, not(is_record(I, ofp_instruction_goto_table)) and not(is_record(I, ofp_instruction_apply_actions))],
            % filter all output-actions form apply-actions
            FinalApplyActionInstruction = ApplyActionInstruction#ofp_instruction_apply_actions{actions = ApplyActionInstruction#ofp_instruction_apply_actions.actions ++ [OutputAction]},
            % create final instruction by filtered instructions without goto-table-instruction
            %    + refactored apply-action-instruction
            FinalInstructionList = FilteredInstructionList ++ [FinalApplyActionInstruction]
        end,
        %lager:info("FinalInstructionList ~p", [FinalInstructionList]),
        % read device table id
        DevTableId = tablevisor_ctrl4:tablevisor_switch_get(TableId2, processtable)
    end,
    % insert instructions into flow entry and replace tableid
    FlowMod2#ofp_flow_mod{table_id = DevTableId, instructions = FinalInstructionList}
  end,
  % build requests
  Requests = [{TableId3, RefactorFlowMod(TableId3, FlowMod)} || TableId3 <- TableIdList],
  % send requests and receives replies
  tv_request(Requests),
  {noreply, State}.

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
ofp_packet_in(TableId, Message) ->
  NewMessage = Message#ofp_message{body = Message#ofp_message.body#ofp_packet_in{table_id = TableId}},
  linc_logic:send_to_controllers(0, NewMessage).

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
ofp_flow_stats_request(#state{switch_id = _SwitchId} = State, #ofp_flow_stats_request{} = Request) ->
  % anonymous function for getting table id list
  GetTableIdList = fun(TableId) ->
    case TableId of
      all ->
        tablevisor_ctrl4:tablevisor_tables();
      _ ->
        [TableId]
    end
  end,
  % get table id list
  TableIdList = GetTableIdList(Request#ofp_flow_stats_request.table_id),
  % anonymous function to generate indivudal table request
  GetTableRequest = fun(TableId, Request2) ->
    DevTableId = tablevisor_ctrl4:tablevisor_switch_get(TableId, processtable),
    Request2#ofp_flow_stats_request{table_id = DevTableId}
  end,
  % build requests
  Requests = [{TableId2, GetTableRequest(TableId2, Request)} || TableId2 <- TableIdList],
  % send requests and receives replies
  Replies = tv_request(Requests, 2000),
  % anonymous function to refactor flow entries
  RefactorFlowEntry = fun(TableId, FlowEntry) ->
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
            OutputTableId = tablevisor_ctrl4:tablevisor_switch_get_gototable(TableId, OutPort),
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
    FlowEntry#ofp_flow_stats{table_id = TableId, instructions = FinalInstructionList}
  end,
  % anonymous function to separate flow entries
  SeparateFlowEntries = fun(TableId, Reply) ->
    Body = Reply#ofp_flow_stats_reply.body,
    [{TableId, FlowStat} || FlowStat <- Body]
  end,
  % rebuild reply
  FlowEntriesDeep = [SeparateFlowEntries(TableId, Reply) || {TableId, Reply} <- Replies],
  FlowEntries = lists:flatten(FlowEntriesDeep),
  Reply = #ofp_flow_stats_reply{
    body = [RefactorFlowEntry(TableId, FlowEntry) || {TableId, FlowEntry} <- FlowEntries]
  },
  % return
  lager:info("Reply ~p", [Reply]),
  {reply, Reply, State}.

tv_request(Requests) ->
% start transmitter
  [spawn(fun() ->
    tv_transmitter(TableId, Request)
  end) || {TableId, Request} <- Requests].

tv_request(Requests, Timeout) ->
  % define caller
  Caller = self(),
  % define receiver processes
  ReceiverPid = spawn_link(fun() ->
    tablevisor_receiver(length(Requests), Timeout, Caller, [])
  end),
  % start transmitter
  [spawn(fun() ->
    tv_transmitter(TableId, Request, Timeout, ReceiverPid)
  end) || {TableId, Request} <- Requests],
  % wait for response
  receive
    Any ->
      %lager:info("Responses: ~p", [Any]),
      Any
  after Timeout ->
    lager:error("Timeout"),
    []
  end.

tablevisor_receiver(0, _Timeout, Caller, Replies) ->
  % all replies are collected, return all replies to caller process (tv_request)
  %lager:info("Receiver 0: ~p", [Replies]),
  Caller ! Replies;
tablevisor_receiver(N, Timeout, Caller, Replies) ->
  receive
    {ok, TableId, Reply} ->
      % add reply to list of replies
      Replies2 = [{TableId, Reply} | Replies],
      % lager:info("Replies2: ~p",[Replies2]),
      % recursivly restart new receiver
      tablevisor_receiver(N - 1, Timeout, Caller, Replies2)
  after Timeout ->
    lager:error("Timeout")
  end.

tv_transmitter(TableId, Request, Timeout, ReceiverPid) ->
  lager:info("send to ~p with message ~p", [TableId, Request]),
  % convert request to valid OpenFlow message
  Message = tablevisor_ctrl4:message(Request),
  % send the request and wait for reply
  {reply, Reply} = tablevisor_ctrl4:send(TableId, Message, Timeout),
  % return reply to receiver
  ReceiverPid ! {ok, TableId, Reply}.

tv_transmitter(TableId, Request) ->
  lager:info("send to ~p with message ~p", [TableId, Request]),
  % convert request to valid OpenFlow message
  Message = tablevisor_ctrl4:message(Request),
  % send the request and wait for reply
  {noreply, ok} = tablevisor_ctrl4:send(TableId, Message),
  % return reply to receiver
  {ok, TableId}.

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
ofp_table_features_request(#state{switch_id = SwitchId} = State,
    #ofp_table_features_request{} = Request) ->
  Reply = linc_us4_table_features:handle_req(SwitchId, Request),
  {reply, Reply, State}.

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

tablevisor_init_connection(TableId) ->
  FlowMods = tablevisor_ctrl4:tablevisor_switch_get(TableId, flowmods),
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
          {_, _} ->
            Instruction = false
        end,
        Fun(Actions2, [Instruction  | InstructionList], Fun)
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
            MatchField = #ofp_field{name = in_port, value = <<InPort>>};
          {_, _} ->
            MatchField = false
        end,
        Fun(Matches2, [MatchField  | MatchesList], Fun)
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
    tablevisor_ctrl4:send(TableId, Message)
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
