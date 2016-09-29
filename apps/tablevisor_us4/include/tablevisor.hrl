
%% TableVisor Configuration
-record(tv_config, {
  metadata_provider = false :: false | srcmac | dstmac | vid,
  skip_tables_via_metadata = false :: boolean()
}).
-type tv_config() :: #tv_config{}.


%% TableVisor Switch
-record(tv_switch, {
  switchid :: integer(),
  tableid :: integer(),
  datapathid :: integer(),
  processtable = 0 :: integer(),
  flowmods = [] :: list(),
  outportmap = [] :: list(),
  socket = false :: any(),
  pid = false :: pid(),
  priority = false :: any(),
  position = intermediate :: atom()
}).
-type tv_switch() :: #tv_switch{}.