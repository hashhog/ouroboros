# Block Sync Architecture

This document describes the per-peer receive architecture for block sync, as implemented in Step 1 and refined in Step 3.

## Design Choice: Round-Based vs. Whole-Sync Long-Lived

**Option A: Round-based (current)**  
At the start of each "receive round":
1. Drain all peers from PeerManager
2. Spawn one task per peer; each task runs until timeout or error
3. Main loop receives from channel until all tasks have sent PeerDone
4. Add peers back to PeerManager
5. Next round: repeat

**Option B: Whole-sync long-lived**  
At block sync start:
1. Drain peers once
2. Spawn one task per peer; tasks run for the entire sync
3. Main sends GetData via command channel to tasks
4. Tasks receive from peers and forward to main
5. When sync completes, send Shutdown to all tasks, add peers back

**Chosen: Option B (whole-sync long-lived)** for Step 3:
- Tasks run for the entire block sync, not per round
- No per-round drain/add overhead
- Bidirectional channel: main → task (SendGetData, Shutdown), task → main (Message, PeerDone)
- Peers stay in tasks until sync complete or disconnect

## Channel Types

### Main → Task (PeerTaskCommand)
```rust
enum PeerTaskCommand {
    SendGetData(Message),  // Request peer to send a GetData message
    Shutdown,              // Sync complete, return peer to manager
}
```

### Task → Main (RecvEvent)
```rust
enum RecvEvent {
    Message(SocketAddr, Message),           // Block or other message to process
    PeerDone(SocketAddr, Peer, PeerDoneReason),  // Task finished
}

enum PeerDoneReason {
    Timeout,    // Reserved (not used in long-lived architecture)
    Error(PeerError),  // Receive error or disconnect
    Shutdown,   // Explicit shutdown when sync complete
}
```

## Task Lifecycle

1. **Spawn:** Main drains peers, spawns one task per (addr, peer)
2. **Loop:** Task runs `select!`:
   - Receive from peer → send Message to main
   - Receive command from main → send GetData or return (Shutdown)
3. **Exit:** On PeerError (disconnect, etc.) → send PeerDone(Error), drop peer
4. **Shutdown:** On Shutdown command → send PeerDone(Shutdown) with peer, main adds back

## Main Loop Flow

1. Wait for peers (if peer_tasks empty, drain from PeerManager)
2. Assign blocks to peers (round-robin from peer_tasks)
3. Send GetData to each task via command channel
4. Receive event from channel (blocks until one arrives)
5. Process: store block, or handle PeerDone (re-queue, add back)
6. When queue empty and in_flight empty: send Shutdown to all, receive PeerDone, add back, exit

## Peer Recovery

When a task exits due to error, we remove it from peer_tasks. If peer_tasks becomes empty:
- Wait for PeerManager to reconnect (background task)
- Drain again, spawn new tasks
