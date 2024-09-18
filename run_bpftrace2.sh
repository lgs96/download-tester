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
IP_HEX=$(printf '%02X' ${IP_ADDRESS//./ })
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

# Add headers to the cwnd.csv file
echo "elapsed_time,cwnd,srtt,minrtt,ssthresh,is_slow_start" > "$SAVE_DIR/cwnd.csv"

# Start BPF tracing
sudo bpftrace -e '
BEGIN
{
    @start_time = nsecs;
    @minrtt = 18446744073709551615; // Initialize minrtt to maximum possible unsigned 64-bit integer
}

tracepoint:tcp:tcp_probe
{
    $target_ip = '$IP_HEX_REVERSED';

    // Iperf
    //$daddr_hex = (uint32)(args->daddr[20]) |
    //             ((uint32)(args->daddr[21]) << 8) |
    //             ((uint32)(args->daddr[22]) << 16) |
    //             ((uint32)(args->daddr[23]) << 24);

    // Short flow
    $daddr_hex = (uint32)(args->daddr[4]) |
                 ((uint32)(args->daddr[5]) << 8) |
                 ((uint32)(args->daddr[6]) << 16) |
                 ((uint32)(args->daddr[7]) << 24);

    $daddr_hex = ntop(args->daddr->sin6_addr)

    if ($daddr_hex == $target_ip) {
        // Calculate elapsed time
        $elapsed_ns = nsecs - @start_time;
        $elapsed_seconds = $elapsed_ns / 1000000000;
        $elapsed_milliseconds = ($elapsed_ns % 1000000000) / 1000000;

        // Extract relevant fields
        $cwnd = args->snd_cwnd * 1460;  // Assuming MSS is 1460
        $srtt = args->srtt;  // Smoothed round-trip time (in microseconds)
        $ssthresh = args->ssthresh * 1460;  // Slow start threshold in bytes, assuming MSS is 1460
        
        // Update minrtt
        if ($srtt < @minrtt) {
            @minrtt = $srtt;
        }

        $is_slow_start = args->snd_cwnd < args->ssthresh ? 1 : 0;  // Determine if in slow start phase

        // Print the extracted and calculated information
        printf("%llu.%03llu,%u,%u,%u,%u,%d\n",
            $elapsed_seconds,
            $elapsed_milliseconds,
            $cwnd,
            $srtt,
            @minrtt,
            $ssthresh,
            $is_slow_start);
    }
}' | tail -n +2 >> "$SAVE_DIR/cwnd.csv" &
BPFTRACE_PID=$!

wait $BPFTRACE_PID
