#!/bin/sh

help() {
    echo "\nUSAGE:\n$1 [-d] [-s <scenario>] [-p <port_number>]\n
-d\n   enable debug mode\n
-s <scenario>\n   run the scenario after starting the controller\n
-p <port_number>\n   listen on the specified port number\n
-r \"<ip_address:port_number>\"\n   connect to the given host\n
Sample usage: $1 -d -s table_miss -r \"127.0.0.1:6653\""
}


parse_opts() {
    DISTRIBUTE_FLOWS=0
    ALL_TABLE_REQUEST=0
    while getopts ":n:t:f:da" OPT
    do
        case $OPT in
            n)
                FILENAME=${OPTARG}
                ;;
            t)
                TABLE=${OPTARG}
                ;;
            f)
                FLOWS=${OPTARG}
                ;;
            d)
                DISTRIBUTE_FLOWS=1
                ;;
            a)
                ALL_TABLE_REQUEST=1
                ;;
            \?)
                echo "Invalid option: -${OPTARG}"
                help $0
                exit 1
                ;;
            :)
                echo "Option -${OPTARG} requires an argument"
                help $0
                exit 1
                ;;
        esac
    done
}

run_controller() {
    erlc tablevisortest_ctrl4.erl -pa ../deps/lager/ebin -pa ../deps/*/ebin -pa ../apps/*/ebin
    ERL_EVAL=ERL_EVAL="tablevisortest_ctrl4:start(\"${FILENAME}\",\"${TABLE}\",\"${ALL_TABLE_REQUEST}\",\"${FLOWS}\",\"${DISTRIBUTE_FLOWS}\")"
    erl -pa ../deps/*/ebin -eval "`echo ${ERL_EVAL}`"
}

parse_opts $@
run_controller
