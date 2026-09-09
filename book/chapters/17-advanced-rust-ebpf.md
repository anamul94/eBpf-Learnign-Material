# Chapter 17: Advanced Rust Patterns for eBPF

## What This Chapter Covers

- Async eBPF with tokio
- Channel-based event processing
- Shared state patterns
- Performance optimization
- Error propagation
- Testing eBPF programs
- Multi-program coordination

---

## 17.1 Async eBPF Architecture

```rust
use tokio::sync::{mpsc, broadcast, RwLock};
use std::sync::Arc;

// Event types
#[derive(Debug, Clone)]
enum Event {
    ProcessExec(ProcessEvent),
    NetworkConnect(NetworkEvent),
    FileAccess(FileEvent),
}

// Shared state
struct AppState {
    processes: RwLock<HashMap<u32, ProcessInfo>>,
    connections: RwLock<HashMap<ConnKey, ConnStats>>,
}

// Channel-based architecture
struct EventPipeline {
    tx: mpsc::Sender<Event>,
    rx: mpsc::Receiver<Event>,
    state: Arc<AppState>,
}

impl EventPipeline {
    fn new(buffer_size: usize) -> Self {
        let (tx, rx) = mpsc::channel(buffer_size);
        let state = Arc::new(AppState {
            processes: RwLock::new(HashMap::new()),
            connections: RwLock::new(HashMap::new()),
        });

        EventPipeline { tx, rx, state }
    }

    async fn run(mut self) {
        while let Some(event) = self.rx.recv().await {
            match event {
                Event::ProcessExec(e) => self.handle_process_exec(e).await,
                Event::NetworkConnect(e) => self.handle_network_connect(e).await,
                Event::FileAccess(e) => self.handle_file_access(e).await,
            }
        }
    }

    async fn handle_process_exec(&self, event: ProcessEvent) {
        let mut processes = self.state.processes.write().await;
        processes.insert(event.pid, ProcessInfo::from(event));
    }

    async fn handle_network_connect(&self, event: NetworkEvent) {
        let mut connections = self.state.connections.write().await;
        // Process network event
    }

    async fn handle_file_access(&self, event: FileEvent) {
        // Process file event
    }
}
```

---

## 17.2 Multi-Producer Event Pipeline

```rust
use tokio::sync::mpsc;

struct EventBus {
    sender: mpsc::Sender<Event>,
}

impl EventBus {
    fn new(capacity: usize) -> (Self, mpsc::Receiver<Event>) {
        let (sender, receiver) = mpsc::channel(capacity);
        (EventBus { sender }, receiver)
    }

    fn subscribe(&self) -> mpsc::Sender<Event> {
        self.sender.clone()
    }
}

// Multiple eBPF programs send events
async fn run_process_monitor(tx: mpsc::Sender<Event>) -> Result<(), anyhow::Error> {
    let mut bpf = Bpf::load(include_bytes!("process.bpf.o"))?;
    // ... attach programs ...

    let mut ring_buf = RingBuf::try_from(bpf.map("EVENTS")?)?;

    while let Some(event) = ring_buf.next().await {
        let process_event = parse_process_event(&event);
        tx.send(Event::ProcessExec(process_event)).await?;
    }

    Ok(())
}

async fn run_network_monitor(tx: mpsc::Sender<Event>) -> Result<(), anyhow::Error> {
    let mut bpf = Bpf::load(include_bytes!("network.bpf.o"))?;
    // ... attach programs ...

    let mut ring_buf = RingBuf::try_from(bpf.map("EVENTS")?)?;

    while let Some(event) = ring_buf.next().await {
        let network_event = parse_network_event(&event);
        tx.send(Event::NetworkConnect(network_event)).await?;
    }

    Ok(())
}

// Single consumer processes all events
async fn run_event_processor(mut rx: mpsc::Receiver<Event>) {
    while let Some(event) = rx.recv().await {
        match event {
            Event::ProcessExec(e) => println!("Process: {:?}", e),
            Event::NetworkConnect(e) => println!("Network: {:?}", e),
            Event::FileAccess(e) => println!("File: {:?}", e),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let (event_bus, rx) = EventBus::new(10000);

    let process_tx = event_bus.subscribe();
    let network_tx = event_bus.subscribe();

    tokio::select! {
        _ = run_process_monitor(process_tx) => {},
        _ = run_network_monitor(network_tx) => {},
        _ = run_event_processor(rx) => {},
        _ = tokio::signal::ctrl_c() => {
            println!("Shutting down...");
        }
    }

    Ok(())
}
```

---

## 17.3 Shared State with RwLock

```rust
use tokio::sync::RwLock;
use std::sync::Arc;

struct SharedState {
    process_cache: RwLock<LruCache<u32, ProcessInfo>>,
    connection_table: RwLock<HashMap<ConnKey, ConnStats>>,
    config: RwLock<Config>,
}

impl SharedState {
    fn new() -> Self {
        SharedState {
            process_cache: RwLock::new(LruCache::new(10000)),
            connection_table: RwLock::new(HashMap::new()),
            config: RwLock::new(Config::default()),
        }
    }

    async fn get_process(&self, pid: u32) -> Option<ProcessInfo> {
        let cache = self.process_cache.read().await;
        cache.get(&pid).cloned()
    }

    async fn update_connection(&self, key: ConnKey, stats: ConnStats) {
        let mut table = self.connection_table.write().await;
        table.insert(key, stats);
    }

    async fn get_config(&self) -> Config {
        self.config.read().await.clone()
    }
}

// Usage
async fn process_events(state: Arc<SharedState>, mut rx: mpsc::Receiver<Event>) {
    while let Some(event) = rx.recv().await {
        match event {
            Event::ProcessExec(e) => {
                let info = state.get_process(e.pid).await;
                // Process with cached info
            }
            Event::NetworkConnect(e) => {
                state.update_connection(e.key, e.stats).await;
            }
            _ => {}
        }
    }
}
```

---

## 17.4 Performance Optimization

### 17.4.1 Batch Processing

```rust
async fn process_events_batched(
    mut rx: mpsc::Receiver<Event>,
    state: Arc<SharedState>,
) {
    let mut batch = Vec::with_capacity(100);
    let mut interval = tokio::time::interval(Duration::from_millis(100));

    loop {
        tokio::select! {
            Some(event) = rx.recv() => {
                batch.push(event);
                if batch.len() >= 100 {
                    process_batch(&batch, &state).await;
                    batch.clear();
                }
            }
            _ = interval.tick() => {
                if !batch.is_empty() {
                    process_batch(&batch, &state).await;
                    batch.clear();
                }
            }
        }
    }
}

async fn process_batch(batch: &[Event], state: &SharedState) {
    // Batch update shared state
    let mut table = state.connection_table.write().await;
    for event in batch {
        if let Event::NetworkConnect(e) = event {
            table.insert(e.key, e.stats);
        }
    }
}
```

### 17.4.2 Lock-Free Data Structures

```rust
use crossbeam::queue::SegQueue;
use std::sync::Arc;

struct EventQueue {
    queue: Arc<SegQueue<Event>>,
}

impl EventQueue {
    fn new() -> Self {
        EventQueue {
            queue: Arc::new(SegQueue::new()),
        }
    }

    fn push(&self, event: Event) {
        self.queue.push(event);
    }

    fn try_pop(&self) -> Option<Event> {
        self.queue.pop()
    }
}

// Usage: Multiple producers, single consumer
async fn producer(queue: Arc<EventQueue>, mut ring_buf: RingBuf) {
    while let Some(event) = ring_buf.next().await {
        queue.push(event);
    }
}

async fn consumer(queue: Arc<EventQueue>) {
    loop {
        if let Some(event) = queue.try_pop() {
            process_event(event).await;
        } else {
            tokio::task::yield_now().await;
        }
    }
}
```

---

## 17.5 Error Propagation and Recovery

```rust
use thiserror::Error;

#[derive(Error, Debug)]
enum EbpfError {
    #[error("Failed to load BPF program: {0}")]
    LoadError(String),

    #[error("Failed to attach program: {0}")]
    AttachError(String),

    #[error("Map error: {0}")]
    MapError(String),

    #[error("Event processing error: {0}")]
    EventError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

struct ResilientApp {
    bpf: Bpf,
    retry_count: u32,
}

impl ResilientApp {
    async fn run_with_retry(&mut self) -> Result<(), EbpfError> {
        loop {
            match self.try_run().await {
                Ok(()) => break Ok(()),
                Err(e) if self.retry_count < 3 => {
                    eprintln!("Error: {}, retrying...", e);
                    self.retry_count += 1;
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Err(e) => return Err(e),
            }
        }
    }

    async fn try_run(&self) -> Result<(), EbpfError> {
        // Main event loop with error handling
        Ok(())
    }
}
```

---

## 17.6 Testing eBPF Programs

### 17.6.1 Unit Testing Map Operations

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conn_key_equality() {
        let key1 = ConnKey {
            saddr: 0x0100007f,
            daddr: 0x01000080,
            sport: 8080,
            dport: 443,
            pid: 1234,
        };

        let key2 = key1.clone();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500.0B");
        assert_eq!(format_bytes(1024), "1.0KB");
        assert_eq!(format_bytes(1024 * 1024), "1.0MB");
    }
}
```

### 17.6.2 Integration Testing

```rust
#[cfg(test)]
mod integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_event_pipeline() {
        let (tx, mut rx) = mpsc::channel(100);

        // Send test event
        let event = Event::ProcessExec(ProcessEvent {
            pid: 1234,
            uid: 1000,
            comm: [0u8; 16],
            timestamp: 0,
        });

        tx.send(event.clone()).await.unwrap();

        // Verify event received
        let received = rx.recv().await.unwrap();
        match received {
            Event::ProcessExec(e) => assert_eq!(e.pid, 1234),
            _ => panic!("Wrong event type"),
        }
    }
}
```

---

## 17.7 Multi-Program Coordination

```rust
use aya::programs::{KProbe, TracePoint, Xdp};
use aya::Bpf;

struct MultiProgramApp {
    bpf: Bpf,
    programs: Vec<String>,
}

impl MultiProgramApp {
    fn new(bpf: Bpf) -> Self {
        MultiProgramApp {
            bpf,
            programs: Vec::new(),
        }
    }

    fn attach_kprobe(&mut self, name: &str, func: &str) -> Result<(), anyhow::Error> {
        let prog: &mut KProbe = self.bpf.program_mut(name)
            .ok_or_else(|| anyhow!("Program {} not found", name))?
            .try_into()?;
        prog.load()?;
        prog.attach(func, 0)?;
        self.programs.push(name.to_string());
        Ok(())
    }

    fn attach_tracepoint(&mut self, name: &str, category: &str, tp: &str) -> Result<(), anyhow::Error> {
        let prog: &mut TracePoint = self.bpf.program_mut(name)
            .ok_or_else(|| anyhow!("Program {} not found", name))?
            .try_into()?;
        prog.load()?;
        prog.attach(category, tp)?;
        self.programs.push(name.to_string());
        Ok(())
    }

    fn attach_xdp(&mut self, name: &str, iface: &str) -> Result<(), anyhow::Error> {
        let prog: &mut Xdp = self.bpf.program_mut(name)
            .ok_or_else(|| anyhow!("Program {} not found", name))?
            .try_into()?;
        prog.load()?;

        let ifindex = iface_to_index(iface)?;
        bpf_xdp_attach(ifindex, prog.fd().unwrap(), XDP_FLAGS_UPDATE_IF_NOEXIST, None)?;
        self.programs.push(name.to_string());
        Ok(())
    }

    fn detach_all(&self) {
        for name in &self.programs {
            // Detach logic
            println!("Detaching: {}", name);
        }
    }
}
```

---

## 17.8 Graceful Shutdown

```rust
use tokio::signal;
use std::sync::atomic::{AtomicBool, Ordering};

struct GracefulApp {
    running: Arc<AtomicBool>,
}

impl GracefulApp {
    fn new() -> Self {
        GracefulApp {
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    async fn run(&self) -> Result<(), anyhow::Error> {
        let running = self.running.clone();

        // Spawn worker tasks
        let workers: Vec<_> = (0..4)
            .map(|i| {
                let running = running.clone();
                tokio::spawn(async move {
                    worker_loop(i, running).await
                })
            })
            .collect();

        // Wait for shutdown signal
        tokio::select! {
            _ = signal::ctrl_c() => {
                println!("Received Ctrl+C, shutting down...");
            }
            _ = signal::terminate() => {
                println!("Received SIGTERM, shutting down...");
            }
        }

        // Signal workers to stop
        self.running.store(false, Ordering::SeqCst);

        // Wait for workers to finish
        for worker in workers {
            worker.await??;
        }

        println!("Shutdown complete");
        Ok(())
    }
}

async fn worker_loop(id: usize, running: Arc<AtomicBool>) -> Result<(), anyhow::Error> {
    while running.load(Ordering::Relaxed) {
        // Do work
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    println!("Worker {} stopped", id);
    Ok(())
}
```

---

## 17.9 Summary

- **Async architecture** with tokio for concurrent event processing
- **Channel-based** communication between producers and consumers
- **RwLock** for shared state with read-heavy workloads
- **Batch processing** for improved throughput
- **Error propagation** with custom error types
- **Testing** with unit and integration tests
- **Graceful shutdown** with signal handling

---

## 17.10 Looking Ahead

Now we move to **Part V: Advanced Topics**. Chapter 18 covers **CO-RE (Compile Once, Run Everywhere)** — portable eBPF with BTF.

---

*Next: [Chapter 18 — CO-RE: Compile Once, Run Everywhere](./18-core.md)*
