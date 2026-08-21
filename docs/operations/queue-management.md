# MailOpen Operations Runbook: Queue Management

## 1. Inspecting Postfix Mail Queues
```bash
# View summary count (Active, Deferred, Hold, Corrupt)
mailopen queue status

# List messages in queue
mailopen queue list --status deferred

# Detailed inspection of specific message
mailopen queue inspect <queue-id>
```

## 2. Queue Operations
```bash
# Retry delivery for specific message
mailopen queue retry <queue-id>

# Flush entire deferred queue
mailopen queue flush

# Place message on administrative hold
mailopen queue hold <queue-id>

# Release message from hold
mailopen queue release <queue-id>

# Delete message from queue
mailopen queue delete <queue-id>
```

## 3. Queue Doctor & Diagnostics
Detect corrupt queue entries or orphaned spool files:
```bash
mailopen queue doctor
```
