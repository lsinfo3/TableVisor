

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