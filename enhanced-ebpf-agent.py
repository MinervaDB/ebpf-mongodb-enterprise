#!/usr/bin/env python3
"""
Enterprise-Grade MongoDB eBPF Monitoring Agent

This script deploys eBPF programs to monitor MongoDB performance at the kernel level,
collecting comprehensive metrics about operations, resource utilization, and performance
bottlenecks to provide actionable insights for database administrators.

Features:
- Advanced eBPF probes for MongoDB WiredTiger storage engine
- Detailed query performance tracking
- Connection and cursor monitoring
- Lock wait time analysis
- Replica set monitoring
- Sharding operations monitoring
- Integration with Prometheus and Grafana
- Automated anomaly detection
- Multi-instance monitoring support
"""

import argparse
import json
import logging
import os
import signal
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd
import psutil
import pymongo
from bcc import BPF, USDT
from prometheus_client import (
    Counter, Gauge, Histogram, Summary, start_http_server, 
    Enum, Info, push_to_gateway
)
from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily, REGISTRY

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('mongodb_ebpf_monitor.log')
    ]
)
logger = logging.getLogger(__name__)

# eBPF C program for MongoDB monitoring
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <net/sock.h>
#include <bcc/proto.h>

// Data structures for storing MongoDB metrics

// Structure for query events
struct mongodb_query_event_t {
    u64 timestamp;      // Timestamp when the query started
    u64 duration_ns;    // Duration in nanoseconds
    u32 pid;            // Process ID
    u32 tid;            // Thread ID
    char collection[64];// Collection name
    u8 operation;       // 0: find, 1: insert, 2: update, 3: delete, 4: aggregate, 5: other
    u64 docs_examined;  // Number of documents examined
    u64 docs_returned;  // Number of documents returned
    u64 docs_modified;  // Number of documents modified
    bool index_used;    // Whether an index was used
    char query_shape[128]; // Query shape/pattern hash
    u32 shard_id;       // Shard ID if sharded
    u32 error_code;     // Error code if query failed
};

// Structure for I/O events
struct mongodb_io_event_t {
    u64 timestamp;      // Timestamp of the I/O operation
    u32 pid;            // Process ID
    u32 tid;            // Thread ID
    u64 bytes;          // Number of bytes read/written
    char operation;     // 'r' for read, 'w' for write
    u64 latency_ns;     // Latency in nanoseconds
    u32 device_major;   // Major device number
    u32 device_minor;   // Minor device number
    char file_path[128];// File path if available
};

// Structure for network events
struct mongodb_net_event_t {
    u64 timestamp;      // Timestamp of the network operation
    u32 pid;            // Process ID
    u32 tid;            // Thread ID
    u32 dport;          // Destination port
    u32 sport;          // Source port
    u64 bytes;          // Number of bytes transferred
    char direction;     // 'i' for ingress, 'e' for egress
    u64 latency_ns;     // Latency in nanoseconds
    u32 client_ip;      // Client IP address
    u16 request_id;     // MongoDB wire protocol request ID
};

// Structure for lock events
struct mongodb_lock_event_t {
    u64 timestamp;      // Timestamp of the lock operation
    u32 pid;            // Process ID
    u32 tid;            // Thread ID
    u64 duration_ns;    // Duration the lock was held
    u32 db_id;          // Database ID
    u32 collection_id;  // Collection ID
    u8 lock_type;       // 0: shared, 1: exclusive, etc.
    u8 lock_mode;       // 0: read, 1: write
    u32 wait_time_ns;   // Time spent waiting for the lock
};

// Structure for WiredTiger events
struct mongodb_wt_event_t {
    u64 timestamp;      // Timestamp of the operation
    u32 pid;            // Process ID
    u32 tid;            // Thread ID
    u64 duration_ns;    // Duration of the operation
    u8 operation;       // Operation type
    u64 bytes;          // Bytes affected
    u32 page_id;        // Page ID
    u8 cache_hit;       // Whether cache was hit
    u8 checkpoint;      // Whether this was during checkpoint
};

// BPF maps to share data with user space
BPF_PERF_OUTPUT(mongodb_query_events);
BPF_PERF_OUTPUT(mongodb_io_events);
BPF_PERF_OUTPUT(mongodb_net_events);
BPF_PERF_OUTPUT(mongodb_lock_events);
BPF_PERF_OUTPUT(mongodb_wt_events);

// Hash maps to track operation start times and metadata
BPF_HASH(query_start, u64, u64);           // tid to start time
BPF_HASH(query_meta, u64, struct mongodb_query_event_t); // tid to partial query event
BPF_HASH(io_start, u64, u64);              // tid to start time
BPF_HASH(net_start, u64, u64);             // tid to start time
BPF_HASH(lock_start, u64, u64);            // tid to start time
BPF_HASH(wt_start, u64, u64);              // tid to start time

// Map to track MongoDB processes
BPF_HASH(mongodb_processes, u32, u8);      // pid to 1

// Histograms for detailed latency tracking
BPF_HISTOGRAM(query_latency_hist, u64);
BPF_HISTOGRAM(io_latency_hist, u64);
BPF_HISTOGRAM(lock_wait_hist, u64);

// Helper function to check if a process is MongoDB
static inline bool pid_is_mongodb(u32 pid) {
    u8 *found = mongodb_processes.lookup(&pid);
    if (found && *found) {
        return true;
    }
    
    // Check process name as a fallback
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // Check if process name contains "mongod"
    char mongod[7] = "mongod";
    for (int i = 0; i < TASK_COMM_LEN - 6; i++) {
        bool match = true;
        for (int j = 0; j < 6; j++) {
            if (comm[i+j] != mongod[j]) {
                match = false;
                break;
            }
        }
        if (match) {
            u8 val = 1;
            mongodb_processes.update(&pid, &val);
            return true;
        }
    }
    
    return false;
}

// Helper function to convert nanoseconds to histogram bucket
static inline u64 ns_to_slot(u64 ns) {
    // Convert to microseconds and limit to reasonable range
    u64 slot = ns / 1000;
    if (slot > 1000000) {
        slot = 1000000;
    }
    return slot;
}

// MongoDB query monitoring functions

// Track the start of a MongoDB query
int mongodb_query_start(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u64 id = ((u64)pid << 32) | tid;
    
    if (pid_is_mongodb(pid)) {
        u64 ts = bpf_ktime_get_ns();
        query_start.update(&id, &ts);
        
        // Initialize query metadata
        struct mongodb_query_event_t event = {};
        event.timestamp = ts;
        event.pid = pid;
        event.tid = tid;
        query_meta.update(&id, &event);
    }
    
    return 0;
}

// Track the end of a MongoDB query
int mongodb_query_end(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u64 id = ((u64)pid << 32) | tid;
    
    u64 *tsp = query_start.lookup(&id);
    struct mongodb_query_event_t *eventp = query_meta.lookup(&id);
    
    if (tsp != 0 && eventp != 0) {
        u64 duration = bpf_ktime_get_ns() - *tsp;
        
        // Update the event with duration and send it
        eventp->duration_ns = duration;
        
        // Update histogram for visualizing latency distribution
        query_latency_hist.increment(ns_to_slot(duration));
        
        mongodb_query_events.perf_submit(ctx, eventp, sizeof(struct mongodb_query_event_t));
        
        query_start.delete(&id);
        query_meta.delete(&id);
    }
    
    return 0;
}

// Capture the collection name during query parsing
int mongodb_query_collection(struct pt_regs *ctx, const char *collection) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u64 id = ((u64)pid << 32) | tid;
    
    struct mongodb_query_event_t *eventp = query_meta.lookup(&id);
    if (eventp != 0 && collection != 0) {
        bpf_probe_read_str(eventp->collection, sizeof(eventp->collection), collection);
    }
    
    return 0;
}

// Update query metadata for documents examined
int mongodb_docs_examined(struct pt_regs *ctx, u64 count) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u64 id = ((u64)pid << 32) | tid;
    
    struct mongodb_query_event_t *eventp = query_meta.lookup(&id);
    if (eventp != 0) {
        eventp->docs_examined = count;
    }
    
    return 0;
}

// Update query metadata for documents returned
int mongodb_docs_returned(struct pt_regs *ctx, u64 count) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u64 id = ((u64)pid << 32) | tid;
    
    struct mongodb_query_event_t *eventp = query_meta.lookup(&id);
    if (eventp != 0) {
        eventp->docs_returned = count;
    }
    
    return 0;
}

// Track the operation type
int mongodb_operation_type(struct pt_regs *ctx, u8 op_type) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u64 id = ((u64)pid << 32) | tid;
    
    struct mongodb_query_event_t *eventp = query_meta.lookup(&id);
    if (eventp != 0) {
        eventp->operation = op_type;
    }
    
    return 0;
}

// Track whether an index was used
int mongodb_index_used(struct pt_regs *ctx, bool used) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u64 id = ((u64)pid << 32) | tid;
    
    struct mongodb_query_event_t *eventp = query_meta.lookup(&id);
    if (eventp != 0) {
        eventp->index_used = used;
    }
    
    return 0;
}

// MongoDB file I/O tracking

int trace_wiredtiger_read_entry(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u64 id = ((u64)pid << 32) | tid;
    
    if (pid_is_mongodb(pid)) {
        u64 ts = bpf_ktime_get_ns();
        io_start.update(&id, &ts);
    }
    
    return 0;
}

int trace_wiredtiger_read_return(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u64 id = ((u64)pid << 32) | tid;
    
    u64 *tsp = io_start.lookup(&id);
    
    if (tsp != 0) {
        struct mongodb_io_event_t event = {};
        event.timestamp = *tsp;
        event.pid = pid;
        event.tid = tid;
        event.bytes = PT_REGS_RC(ctx);
        event.operation = 'r';
        event.latency_ns = bpf_ktime_get_ns() - *tsp;
        
        // Update histogram for visualizing latency distribution
        io_latency_hist.increment(ns_to_slot(event.latency_ns));
        
        mongodb_io_events.perf_submit(ctx, &event, sizeof(event));
        io_start.delete(&id);
    }
    
    return 0;
}

int trace_wiredtiger_write_entry(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u64 id = ((u64)pid << 32) | tid;
    
    if (pid_is_mongodb(pid)) {
        u64 ts = bpf_ktime_get_ns();
        io_start.update(&id, &ts);
    }
    
    return 0;
}

int trace_wiredtiger_write_return(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u64 id = ((u64)pid << 32) | tid;
    
    u64 *tsp = io_start.lookup(&id);
    
    if (tsp != 0) {
        struct mongodb_io_event_t event = {};
        event.timestamp = *tsp;
        event.pid = pid;
        event.tid = tid;
        event.bytes = PT_REGS_RC(ctx);
        event.operation = 'w';
        event.latency_ns = bpf_ktime_get_ns() - *tsp;
        
        // Update histogram for visualizing latency distribution
        io_latency_hist.increment(ns_to_slot(event.latency_ns));
        
        mongodb_io_events.perf_submit(ctx, &event, sizeof(event));
        io_start.delete(&id);
    }
    
    return 0;
}

// MongoDB network traffic monitoring

int trace_tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u64 id = ((u64)pid << 32) | tid;
    
    if (pid_is_mongodb(pid)) {
        struct mongodb_net_event_t event = {};
        u16 dport = 0;
        bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
        
        event.timestamp = bpf_ktime_get_ns();
        event.pid = pid;
        event.tid = tid;
        event.dport = ntohs(dport);
        event.bytes = size;
        event.direction = 'e';  // egress
        
        // Try to get the client IP
        u32 saddr = 0;
        bpf_probe_read(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
        event.client_ip = saddr;
        
        mongodb_net_events.perf_submit(ctx, &event, sizeof(event));
    }
    
    return 0;
}

int trace_tcp_recvmsg(struct pt_regs *ctx, struct sock *sk) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u64 id = ((u64)pid << 32) | tid;
    
    if (pid_is_mongodb(pid)) {
        u64 ts = bpf_ktime_get_ns();
        net_start.update(&id, &ts);
    }
    
    return 0;
}

int trace_tcp_recvmsg_return(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u64 id = ((u64)pid << 32) | tid;
    
    u64 *tsp = net_start.lookup(&id);
    
    if (tsp != 0) {
        ssize_t size = PT_REGS_RC(ctx);
        
        if (size > 0) {
            struct mongodb_net_event_t event = {};
            event.timestamp = *tsp;
            event.pid = pid;
            event.tid = tid;
            event.bytes = size;
            event.direction = 'i';  // ingress
            event.latency_ns = bpf_ktime_get_ns() - *tsp;
            
            mongodb_net_events.perf_submit(ctx, &event, sizeof(event));
        }
        
        net_start.delete(&id);
    }
    
    return 0;
}

// MongoDB lock monitoring

int mongodb_lock_acquire(struct pt_regs *ctx, u8 lock_type, u8 lock_mode) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u64 id = ((u64)pid << 32) | tid;
    
    if (pid_is_mongodb(pid)) {
        u64 ts = bpf_ktime_get_ns();
        lock_start.update(&id, &ts);
        
        // Store lock type and mode for when the lock is released
        struct mongodb_lock_event_t event = {};
        event.timestamp = ts;
        event.pid = pid;
        event.tid = tid;
        event.lock_type = lock_type;
        event.lock_mode = lock_mode;
        
        mongodb_lock_events.perf_submit(ctx, &event, sizeof(event));
    }
    
    return 0;
}

int mongodb_lock_release(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u64 id = ((u64)pid << 32) | tid;
    
    u64 *tsp = lock_start.lookup(&id);
    
    if (tsp != 0) {
        struct mongodb_lock_event_t event = {};
        event.timestamp = *tsp;
        event.pid = pid;
        event.tid = tid;
        event.duration_ns = bpf_ktime_get_ns() - *tsp;
        
        // Update histogram for visualizing lock duration distribution
        lock_wait_hist.increment(ns_to_slot(event.duration_ns));
        
        mongodb_lock_events.perf_submit(ctx, &event, sizeof(event));
        lock_start.delete(&id);
    }
    
    return 0;
}

// WiredTiger cache monitoring

int wiredtiger_cache_read(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u64 id = ((u64)pid << 32) | tid;
    
    if (pid_is_mongodb(pid)) {
        u64 ts = bpf_ktime_get_ns();
        wt_start.update(&id, &ts);
    }
    
    return 0;
}

int wiredtiger_cache_hit(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u64 id = ((u64)pid << 32) | tid;
    
    u64 *tsp = wt_start.lookup(&id);
    
    if (tsp != 0) {
        struct mongodb_wt_event_t event = {};
        event.timestamp = *tsp;
        event.pid = pid;
        event.tid = tid;
        event.duration_ns = bpf_ktime_get_ns() - *tsp;
        event.operation = 0;  // read
        event.cache_hit = 1;  // cache hit
        
        mongodb_wt_events.perf_submit(ctx, &event, sizeof(event));
        wt_start.delete(&id);
    }
    
    return 0;
}

int wiredtiger_cache_miss(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u64 id = ((u64)pid << 32) | tid;
    
    u64 *tsp = wt_start.lookup(&id);
    
    if (tsp != 0) {
        struct mongodb_wt_event_t event = {};
        event.timestamp = *tsp;
        event.pid = pid;
        event.tid = tid;
        event.duration_ns = bpf_ktime_get_ns() - *tsp;
        event.operation = 0;  // read
        event.cache_hit = 0;  // cache miss
        
        mongodb_wt_events.perf_submit(ctx, &event, sizeof(event));
        wt_start.delete(&id);
    }
    
    return 0;
}

// WiredTiger checkpoint monitoring

int wiredtiger_checkpoint_start(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u64 id = ((u64)pid << 32) | tid;
    
    if (pid_is_mongodb(pid)) {
        u64 ts = bpf_ktime_get_ns();
        wt_start.update(&id, &ts);
    }
    
    return 0;
}

int wiredtiger_checkpoint_end(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u64 id = ((u64)pid << 32) | tid;
    
    u64 *tsp = wt_start.lookup(&id);
    
    if (tsp != 0) {
        struct mongodb_wt_event_t event = {};
        event.timestamp = *tsp;
        event.pid = pid;
        event.tid = tid;
        event.duration_ns = bpf_ktime_get_ns() - *tsp;
        event.operation = 1;  // checkpoint
        event.checkpoint = 1;
        
        mongodb_wt_events.perf_submit(ctx, &event, sizeof(event));
        wt_start.delete(&id);
    }
    
    return 0;
}