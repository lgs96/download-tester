#!/bin/bash

# Check if save directory and port number arguments are provided
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <save_directory> <port_number>"
    exit 1
fi

SAVE_DIR="result/$1"
PORT_NUMBER="$2"

echo "Directory to save files: $SAVE_DIR"
echo "Monitoring TCP traffic on port: $PORT_NUMBER"

mkdir -p "$SAVE_DIR"
if [ ! -d "$SAVE_DIR" ]; then
    echo "Failed to create directory: $SAVE_DIR"
    exit 1
fi

# Function to clean up processes
cleanup() {
    echo "Terminating bpftrace processes..."
    kill $CWND_PID $RETX_PID
    wait $CWND_PID $RETX_PID 2>/dev/null
    echo "Processes terminated."
}

# Trap SIGINT and SIGTERM to clean up properly
trap cleanup SIGINT SIGTERM

# Add headers to the cwnd.csv file
echo "time,cwnd,srtt" > "$SAVE_DIR/cwnd.csv"

# Start BPF tracing for CWND and SRTT using tcp_probe
sudo bpftrace -e "
tracepoint:tcp:tcp_probe /args->sport == $PORT_NUMBER || args->dport == $PORT_NUMBER/ {
    \$seconds = nsecs / 1000000000;
    \$milliseconds = (nsecs % 1000000000) / 1000000;
    printf(\"%llu.%03llu,%u,%u\n\", \$seconds, \$milliseconds, args->snd_cwnd * 1460, args->srtt);
}" | tail -n +2 >> "$SAVE_DIR/cwnd.csv" &
CWND_PID=$!

# Start BPF tracing for retransmissions using tcp_retransmit_skb
sudo bpftrace -e "
tracepoint:tcp:tcp_retransmit_skb {
    \$seconds = nsecs / 1000000000;
    \$milliseconds = (nsecs % 1000000000) / 1000000;
    printf(\"%llu.%03llu\n\", \$seconds, \$milliseconds);
}" > "$SAVE_DIR/retx.csv" &
RETX_PID=$!

wait $CWND_PID
wait $RETX_PID