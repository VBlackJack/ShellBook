---
title: "PromQL Cheatsheet"
description: "Prometheus Query Language essentials for metrics, alerting, and monitoring"
tags: ["prometheus", "promql", "monitoring", "observability", "cheatsheet"]
---

# PromQL Cheatsheet

## Basic Selectors

### Instant Vector Selectors

```promql
# Select all time series with metric name
http_requests_total

# With exact label match
http_requests_total{job="api", method="GET"}

# Label matching operators
http_requests_total{status!="200"}           # Not equal
http_requests_total{method=~"GET|POST"}      # Regex match
http_requests_total{path!~"/admin.*"}        # Negative regex

# Multiple labels
http_requests_total{job="api", status="200", method="GET"}

# All metrics for a job
{job="api"}
```

### Range Vector Selectors

```promql
# Last 5 minutes
http_requests_total[5m]

# Last 1 hour
http_requests_total{job="api"}[1h]

# Time units: s (seconds), m (minutes), h (hours), d (days), w (weeks), y (years)
http_requests_total[30s]
http_requests_total[2h]
http_requests_total[7d]
```

### Offset Modifier

```promql
# 5 minutes ago
http_requests_total offset 5m

# Compare to 1 hour ago
http_requests_total - (http_requests_total offset 1h)

# Range vector with offset
rate(http_requests_total[5m] offset 1h)
```

### @ Modifier (Prometheus 2.25+)

```promql
# At specific timestamp
http_requests_total @ 1609459200

# Combine with offset
http_requests_total @ 1609459200 offset 5m

# Range vector at specific time
rate(http_requests_total[5m] @ 1609459200)
```

## Operators

### Arithmetic Operators

```promql
# Addition
node_memory_MemTotal_bytes + node_memory_SwapTotal_bytes

# Subtraction
node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes

# Multiplication
rate(http_requests_total[5m]) * 60

# Division
(node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes

# Modulo
http_requests_total % 100

# Power
2 ^ 10
```

### Comparison Operators

```promql
# Equal, not equal
http_requests_total == 100
http_requests_total != 0

# Greater than, less than
http_requests_total > 1000
http_requests_total < 100

# Greater or equal, less or equal
http_requests_total >= 500
http_requests_total <= 50

# Filter values
http_requests_total > bool 1000    # Returns 1 or 0
```

### Logical Operators

```promql
# AND
up{job="api"} and up{instance="localhost:9090"}

# OR
up{job="api"} or up{job="web"}

# UNLESS (AND NOT)
up unless on(instance) down_instances
```

### Vector Matching

```promql
# One-to-one matching (default)
method:requests:rate5m{job="api"} / method:requests:total{job="api"}

# Ignoring labels
method:requests:rate5m / ignoring(method) method:requests:total

# On specific labels
method:requests:rate5m / on(job, instance) method:requests:total

# Group left/right (many-to-one, one-to-many)
method:requests:rate5m / on(job) group_left(instance) method:requests:total
```

## Aggregation Operators

### Basic Aggregations

```promql
# Sum
sum(http_requests_total)

# Average
avg(http_requests_total)

# Minimum and maximum
min(http_requests_total)
max(http_requests_total)

# Count
count(http_requests_total)

# Standard deviation
stddev(http_requests_total)
stdvar(http_requests_total)

# Quantiles
quantile(0.95, http_request_duration_seconds)
```

### Grouping

```promql
# Sum by labels
sum by(job, instance) (http_requests_total)
sum(http_requests_total) by(job, instance)  # Alternative syntax

# Sum without labels
sum without(method, status) (http_requests_total)

# Count unique label values
count(count by(instance) (up))

# Top K
topk(5, http_requests_total)
bottomk(3, http_requests_total)
```

### Examples

```promql
# Total requests per second by job
sum by(job) (rate(http_requests_total[5m]))

# Average CPU usage per node
avg by(instance) (rate(node_cpu_seconds_total{mode!="idle"}[5m]))

# Memory usage percentage
100 * (1 - avg by(instance) (node_memory_MemAvailable_bytes) / avg by(instance) (node_memory_MemTotal_bytes))

# 95th percentile response time
histogram_quantile(0.95, sum by(le) (rate(http_request_duration_seconds_bucket[5m])))
```

## Functions

### Rate & Increase

```promql
# Rate: per-second average increase
rate(http_requests_total[5m])

# Irate: instant rate (last 2 points)
irate(http_requests_total[5m])

# Increase: total increase over time range
increase(http_requests_total[1h])

# Delta: difference between first and last value
delta(cpu_temp_celsius[1h])

# Idelta: difference between last 2 samples
idelta(cpu_temp_celsius[5m])
```

### Comparison

| Function | Best For | Use Case |
|----------|----------|----------|
| `rate()` | Counters | Request rates, error rates |
| `irate()` | Volatile metrics | Short-term spikes |
| `increase()` | Total count | Total requests in period |
| `delta()` | Gauges | Temperature changes |

### Time Functions

```promql
# Current time (Unix timestamp)
time()

# Day of week (0=Sunday, 6=Saturday)
day_of_week()

# Day of month
day_of_month()

# Hour of day
hour()

# Minute
minute()

# Month
month()

# Year
year()

# Examples
# Alert only during business hours
ALERTS{severity="critical"} and hour() >= 9 and hour() <= 17 and day_of_week() > 0 and day_of_week() < 6
```

### Aggregation Over Time

```promql
# Average over time
avg_over_time(http_requests_total[5m])

# Max/min over time
max_over_time(http_requests_total[1h])
min_over_time(http_requests_total[1h])

# Sum over time
sum_over_time(http_requests_total[5m])

# Count over time
count_over_time(http_requests_total[5m])

# Quantile over time
quantile_over_time(0.95, http_request_duration_seconds[5m])

# Standard deviation over time
stddev_over_time(http_requests_total[5m])

# Last value (most recent)
last_over_time(http_requests_total[5m])

# First value (oldest)
first_over_time(http_requests_total[5m])
```

### Change Functions

```promql
# Predict value using linear regression
predict_linear(node_filesystem_free_bytes[1h], 3600 * 4)  # 4 hours ahead

# Derivative (rate of change per second)
deriv(node_cpu_seconds_total[5m])

# Changes: number of times value changed
changes(http_requests_total[1h])

# Resets: number of counter resets
resets(http_requests_total[1h])
```

### Math Functions

```promql
# Absolute value
abs(delta(cpu_temp_celsius[5m]))

# Ceiling/floor
ceil(http_request_duration_seconds)
floor(http_request_duration_seconds)

# Round
round(http_request_duration_seconds, 0.1)  # Round to 0.1

# Exponential and logarithm
exp(http_requests_total)
ln(http_requests_total)
log2(http_requests_total)
log10(http_requests_total)

# Square root
sqrt(http_requests_total)

# Clamp (limit to range)
clamp(http_requests_total, 0, 1000)
clamp_min(http_requests_total, 0)
clamp_max(http_requests_total, 1000)
```

### Label Functions

```promql
# Replace label values
label_replace(http_requests_total, "new_label", "$1", "instance", "(.+):.*")

# Join labels into new label
label_join(http_requests_total, "endpoint", "/", "job", "instance")
```

### Sorting

```promql
# Sort ascending
sort(http_requests_total)

# Sort descending
sort_desc(http_requests_total)
```

### Missing Data

```promql
# Check if metric absent
absent(http_requests_total{job="api"})

# Check if metric absent over time
absent_over_time(http_requests_total[5m])
```

### Histogram Functions

```promql
# Calculate quantile from histogram
histogram_quantile(0.95, sum by(le) (rate(http_request_duration_seconds_bucket[5m])))

# Multiple quantiles
histogram_quantile(0.50, sum by(le) (rate(http_request_duration_seconds_bucket[5m])))
histogram_quantile(0.90, sum by(le) (rate(http_request_duration_seconds_bucket[5m])))
histogram_quantile(0.99, sum by(le) (rate(http_request_duration_seconds_bucket[5m])))
```

## Common Queries

### CPU Metrics

```promql
# CPU usage percentage
100 - (avg by(instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)

# CPU usage by mode
sum by(mode) (rate(node_cpu_seconds_total[5m]))

# Per-core CPU usage
rate(node_cpu_seconds_total{mode!="idle"}[5m]) * 100

# CPU load average
node_load1
node_load5
node_load15
```

### Memory Metrics

```promql
# Memory usage percentage
100 * (1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)

# Available memory
node_memory_MemAvailable_bytes / 1024 / 1024 / 1024  # GB

# Memory used
(node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / 1024 / 1024 / 1024

# Swap usage
(node_memory_SwapTotal_bytes - node_memory_SwapFree_bytes) / node_memory_SwapTotal_bytes * 100
```

### Disk Metrics

```promql
# Disk usage percentage
100 - ((node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"}) * 100)

# Disk space remaining
node_filesystem_avail_bytes{mountpoint="/"} / 1024 / 1024 / 1024  # GB

# Disk I/O rate
rate(node_disk_read_bytes_total[5m])
rate(node_disk_written_bytes_total[5m])

# IOPS
rate(node_disk_reads_completed_total[5m])
rate(node_disk_writes_completed_total[5m])

# Predict disk full time
predict_linear(node_filesystem_free_bytes{mountpoint="/"}[1h], 3600 * 24 * 7)  # 1 week
```

### Network Metrics

```promql
# Network traffic (bytes/sec)
rate(node_network_receive_bytes_total{device="eth0"}[5m])
rate(node_network_transmit_bytes_total{device="eth0"}[5m])

# Network traffic (megabits/sec)
rate(node_network_receive_bytes_total{device="eth0"}[5m]) * 8 / 1024 / 1024
rate(node_network_transmit_bytes_total{device="eth0"}[5m]) * 8 / 1024 / 1024

# Packet errors
rate(node_network_receive_errs_total[5m])
rate(node_network_transmit_errs_total[5m])

# Dropped packets
rate(node_network_receive_drop_total[5m])
rate(node_network_transmit_drop_total[5m])
```

### HTTP Metrics

```promql
# Request rate
sum by(job) (rate(http_requests_total[5m]))

# Request rate by status code
sum by(status) (rate(http_requests_total[5m]))

# Error rate (4xx + 5xx)
sum(rate(http_requests_total{status=~"4..|5.."}[5m])) / sum(rate(http_requests_total[5m])) * 100

# 5xx error rate
sum(rate(http_requests_total{status=~"5.."}[5m])) / sum(rate(http_requests_total[5m])) * 100

# Average response time
avg(rate(http_request_duration_seconds_sum[5m]) / rate(http_request_duration_seconds_count[5m]))

# 95th percentile response time
histogram_quantile(0.95, sum by(le) (rate(http_request_duration_seconds_bucket[5m])))

# Requests per second by endpoint
sum by(path) (rate(http_requests_total[5m]))
```

### Service Availability

```promql
# Service uptime percentage
avg_over_time(up{job="api"}[1h]) * 100

# Number of instances up
count(up{job="api"} == 1)

# Number of instances down
count(up{job="api"} == 0)

# Alert if service down
up{job="api"} == 0

# SLO: 99.9% availability
(1 - (sum(rate(http_requests_total{status=~"5.."}[30d])) / sum(rate(http_requests_total[30d])))) * 100 > 99.9
```

## Alerting Rules

### Alert Rule Syntax

```yaml
groups:
  - name: example
    interval: 30s
    rules:
      - alert: HighErrorRate
        expr: |
          (
            sum(rate(http_requests_total{status=~"5.."}[5m]))
            /
            sum(rate(http_requests_total[5m]))
          ) * 100 > 5
        for: 5m
        labels:
          severity: critical
          team: backend
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{ $value | humanizePercentage }} on {{ $labels.instance }}"
```

### Common Alert Rules

```yaml
groups:
  - name: host_alerts
    rules:
      # High CPU usage
      - alert: HighCPUUsage
        expr: |
          100 - (avg by(instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High CPU usage on {{ $labels.instance }}"
          description: "CPU usage is {{ $value | printf \"%.2f\" }}%"

      # High memory usage
      - alert: HighMemoryUsage
        expr: |
          100 * (1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) > 90
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High memory usage on {{ $labels.instance }}"
          description: "Memory usage is {{ $value | printf \"%.2f\" }}%"

      # Disk space low
      - alert: DiskSpaceLow
        expr: |
          100 - ((node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"}) * 100) > 85
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Disk space low on {{ $labels.instance }}"
          description: "Disk usage is {{ $value | printf \"%.2f\" }}%"

      # Disk will fill in 4 hours
      - alert: DiskWillFillSoon
        expr: |
          predict_linear(node_filesystem_free_bytes{mountpoint="/"}[1h], 3600 * 4) < 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Disk will fill soon on {{ $labels.instance }}"
          description: "Disk is predicted to fill in 4 hours"

      # Instance down
      - alert: InstanceDown
        expr: up == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Instance {{ $labels.instance }} is down"
          description: "{{ $labels.job }} on {{ $labels.instance }} has been down for more than 5 minutes"

  - name: application_alerts
    rules:
      # High error rate
      - alert: HighErrorRate
        expr: |
          (
            sum by(job) (rate(http_requests_total{status=~"5.."}[5m]))
            /
            sum by(job) (rate(http_requests_total[5m]))
          ) * 100 > 5
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High error rate in {{ $labels.job }}"
          description: "Error rate is {{ $value | printf \"%.2f\" }}%"

      # High response time
      - alert: HighResponseTime
        expr: |
          histogram_quantile(0.95,
            sum by(le, job) (rate(http_request_duration_seconds_bucket[5m]))
          ) > 1
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High response time in {{ $labels.job }}"
          description: "95th percentile response time is {{ $value | printf \"%.2f\" }}s"

      # High request rate
      - alert: HighRequestRate
        expr: |
          sum by(job) (rate(http_requests_total[5m])) > 1000
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High request rate in {{ $labels.job }}"
          description: "Request rate is {{ $value | printf \"%.0f\" }} req/s"

      # Service down
      - alert: ServiceDown
        expr: absent(up{job="api"})
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Service {{ $labels.job }} is not reporting metrics"
          description: "No metrics received from {{ $labels.job }} for 5 minutes"
```

### Template Functions in Alerts

```yaml
annotations:
  # Formatting
  description: "Value is {{ $value | printf \"%.2f\" }}"
  description: "Value is {{ $value | humanize }}"
  description: "Percentage: {{ $value | humanizePercentage }}"
  description: "Duration: {{ $value | humanizeDuration }}"
  description: "Timestamp: {{ $value | humanizeTimestamp }}"

  # Labels
  description: "Instance: {{ $labels.instance }}"
  description: "Job: {{ $labels.job }}"

  # External labels
  description: "Environment: {{ $externalLabels.env }}"

  # Links
  description: "Dashboard: https://grafana.example.com/d/{{ $labels.job }}"
```

## Recording Rules

### Syntax

```yaml
groups:
  - name: example_recording
    interval: 30s
    rules:
      - record: job:http_requests:rate5m
        expr: sum by(job) (rate(http_requests_total[5m]))
        labels:
          team: backend
```

### Best Practices

```yaml
groups:
  - name: http_recording_rules
    interval: 30s
    rules:
      # Level 1: Aggregate by all labels
      - record: instance:http_requests:rate5m
        expr: sum by(instance, job, method, status) (rate(http_requests_total[5m]))

      # Level 2: Aggregate by job
      - record: job:http_requests:rate5m
        expr: sum by(job) (instance:http_requests:rate5m)

      # Level 3: Global aggregate
      - record: http_requests:rate5m
        expr: sum(job:http_requests:rate5m)

      # Error rate
      - record: job:http_requests_errors:rate5m
        expr: |
          sum by(job) (rate(http_requests_total{status=~"5.."}[5m]))
          /
          sum by(job) (rate(http_requests_total[5m]))

      # 95th percentile response time
      - record: job:http_request_duration_seconds:p95
        expr: |
          histogram_quantile(0.95,
            sum by(le, job) (rate(http_request_duration_seconds_bucket[5m]))
          )
```

## Tips & Best Practices

### Performance

- Use recording rules for expensive queries
- Avoid high cardinality label values (IP addresses, UUIDs)
- Use `rate()` over `irate()` for alerting
- Limit time range on range vectors
- Use `without` instead of `by` when grouping many labels

### Naming Conventions

```xml
# Metrics
<component>_<metric>_<unit>_<type>

# Examples
http_requests_total          # Counter
http_request_duration_seconds # Histogram
node_memory_bytes            # Gauge

# Recording rules
<level>:<metric>:<operation>

# Examples
job:http_requests:rate5m
instance:cpu:usage
```

### Common Mistakes

```promql
# WRONG: rate() on gauge
rate(node_memory_MemAvailable_bytes[5m])

# CORRECT: Use for counters only
rate(http_requests_total[5m])

# WRONG: aggregation without by/without
sum(rate(http_requests_total[5m]))  # Loses labels

# CORRECT: Specify grouping
sum by(job, instance) (rate(http_requests_total[5m]))

# WRONG: comparing instant vectors
http_requests_total > http_requests_total offset 1h

# CORRECT: Use scalar or aggregation
sum(http_requests_total) > sum(http_requests_total offset 1h)
```

## Resources

- [PromQL Documentation](https://prometheus.io/docs/prometheus/latest/querying/basics/)
- [PromQL Cheat Sheet (Robust Perception)](https://promlabs.com/promql-cheat-sheet/)
- [Query Examples](https://prometheus.io/docs/prometheus/latest/querying/examples/)
- [Recording Rules](https://prometheus.io/docs/prometheus/latest/configuration/recording_rules/)
- [Alerting Rules](https://prometheus.io/docs/prometheus/latest/configuration/alerting_rules/)
