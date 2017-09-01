# TableVisor - An Emulation Layer for Multi-Table OpenFlow Switches

## Introduction

TableVisor is an OpenFlow proxy layer for emulating a multi-table OpenFlow switch. The Open Networking Foundation describes the categories of independent actions and two stage processing as [the benefits of multiple flow tables and TTPs][benefits-multipletable]. Caused on the absence of OpenFlow hardware switches with multiple tables, it is difficult for application developer to write applications using multiple tables. TableVisor uses multiple OpenFlow switches to implement the pipeline processing between multiple tables. Each switch represents a table and the packets are passed from switch to switch instead of from table to table.

To the OpenFlow controller, TableVisor appears as a single switch with multiple tables. The underlying multi-switch structure is encapsualted by TableVisor. TableVisor interceps and rewrite messages, exchanged between the conroller and the tables. Application developer can use TableVisor to write applications with the use of multiple tables.


## Environment

### LINC-Switch

TableVisor bases on [LINC-Switch][linc] by FlowForwarding. LINC-Switch is a modular and powerfull OpenFlow software switch, written in Erlang. As the LINC-Switch repository was cloned, the LINC-Switch sources are not required to run TableVisor.

### Installation

To install TableVisor, just clone this repository and run "make". An advanced installation instruction for Erlang can be found on [LINC-Switch repository][linc].

### Configuration

For running TableVisor the LINC-Switch configuration file `rel/files/sys.config` has to be created and adapted. Set "tablevisor_us4" as backend module and add a TableVisor switch configuration for the hardware switches as shown in the following example configuration file:

```erlang
    {linc,
     [
      {of_config, enabled},
      {capable_switch_ports,
      {logical_switches,
       [
        {switch, 0,
         [
          {backend, tablevisor_us4},
          {controllers,
           [
            {"Switch0-DefaultController", "localhost", 6653, tcp}
           ]},
            {tablevisor_switches, [
                {switch, 1, [
                  {tableid, 0},
                  {devtableid, 0},
                  {outportmap, [{1, 2}]}
                ]},
                {switch, 2, [
                  {tableid, 1},
                  {devtableid, 0},
                  {outportmap, [{2, 2}]}
                ]},
                {switch, 3, [
                  {tableid, 2},
                  {devtableid, 0},
                  {outportmap, []}
                ]}
              ]}
            ]}
         ]}
       ]}
     ]}.
```

 [linc]: https://github.com/FlowForwarding/LINC-Switch
 [benefit-multipletable]: https://www.opennetworking.org/images/stories/downloads/sdn-resources/technical-reports/TR_Multiple_Flow_Tables_and_TTPs.pdf
