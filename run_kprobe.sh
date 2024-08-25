#!/bin/bash

# Check if save directory and IP address arguments are provided
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <save_directory> <ip_address>"
    exit 1
fi

SAVE_DIR="result/$1"
IP_ADDRESS="$2"

echo "Directory to save files: $SAVE_DIR"
echo "Filtering for IP address: $IP_ADDRESS"

mkdir -p "$SAVE_DIR"
if [ ! -d "$SAVE_DIR" ]; then
    echo "Failed to create directory: $SAVE_DIR"
    exit 1
fi

# Convert IP address to hex
IP_HEX=$(printf '%02X' ${IP_ADDRESS//./ }; echo)
IP_HEX_REVERSED="0x${IP_HEX:6:2}${IP_HEX:4:2}${IP_HEX:2:2}${IP_HEX:0:2}"

# Function to clean up processes
cleanup() {
    echo "Terminating bpftrace process..."
    kill $BPFTRACE_PID
    wait $BPFTRACE_PID 2>/dev/null
    echo "Process terminated."
}

# Trap SIGINT and SIGTERM to clean up properly
trap cleanup SIGINT SIGTERM

# Update the CSV header
echo "elapsed_time,event,cwnd_bytes,ssthresh,is_slow_start,srtt,rttvar,min_rtt,packets_out_bytes,lost_bytes,retrans_bytes,ca_state,cc_name,daddr,mss_cache,adv_mss" > "$SAVE_DIR/cwnd.csv"

# Start BPF tracing
sudo bpftrace -e '
#include <net/sock.h>
#include <linux/tcp.h>

BEGIN
{
    @filter_ip = '$IP_HEX_REVERSED';
    @ca_state[0] = "Open";
    @ca_state[1] = "Disorder";
    @ca_state[2] = "CWR";
    @ca_state[3] = "Recovery";
    @ca_state[4] = "Loss";
    @start_time = nsecs;
}

kprobe:tcp_rcv_established
{
    $sock = (struct sock *)arg0;
    $tcps = (struct tcp_sock *)$sock;
    $daddr = $sock->__sk_common.skc_daddr;
    
    //if ($sock->__sk_common.skc_rcv_saddr == @filter_ip || $daddr == @filter_ip) {
        $elapsed_ns = nsecs - @start_time;
        $elapsed_seconds = $elapsed_ns / 1000000000;
        $elapsed_milliseconds = ($elapsed_ns % 1000000000) / 1000000;
        
        $inet_csk = (struct inet_connection_sock *)$tcps;
        $ca_ops = $inet_csk->icsk_ca_ops;
        
        $is_slow_start = $tcps->snd_cwnd < $tcps->snd_ssthresh ? 1 : 0;
        $cwnd_bytes = $tcps->snd_cwnd * $tcps->mss_cache;
        $packets_out_bytes = $tcps->packets_out * $tcps->mss_cache;
        $lost_bytes = $tcps->lost_out * $tcps->mss_cache;
        $retrans_bytes = $tcps->retrans_out * $tcps->mss_cache;
        $min_rtt = $tcps->rtt_min.s[0].v;
        
        printf("%llu.%03llu,%s,%u,%u,%d,%u,%u,%u,%u,%u,%u,%s,%s,%s,%u,%u\n", 
               $elapsed_seconds, $elapsed_milliseconds,
               probe,
               $cwnd_bytes,
               $tcps->snd_ssthresh * $tcps->mss_cache,
               $is_slow_start,
               $tcps->srtt_us >> 3,
               $tcps->rttvar_us >> 2,
               $min_rtt,
               $packets_out_bytes,
               $lost_bytes,
               $retrans_bytes,
               @ca_state[$inet_csk->icsk_ca_state],
               $ca_ops->name,
               ntop($daddr),
               $tcps->mss_cache,
               $tcps->advmss);
    //}
}' | tail -n +2 >> "$SAVE_DIR/cwnd.csv" &

BPFTRACE_PID=$!

wait $BPFTRACE_PID

