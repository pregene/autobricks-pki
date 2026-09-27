use crate::{
    Result,
    integration::{
        dns::{Dns, Record},
        truelog::TrueLog,
    },
    server::service::Service,
};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

enum Work {
    Audit(TrueLog, serde_json::Value),
    Dns(Dns, Record),
    Complete,
}

fn prepare(service: &Service, id: i64, kind: &str, payload: &str) -> Result<Work> {
    if !service.db.is_pending(id)? {
        return Ok(Work::Complete);
    }
    match kind {
        "audit" => {
            let mut event: serde_json::Value = serde_json::from_str(payload)?;
            event["event_id"] = format!("{}:{id}", service.db.root_id()?).into();
            Ok(Work::Audit(
                TrueLog {
                    executable: service.truelog.executable.clone(),
                },
                event,
            ))
        }
        "dns" => Ok(Work::Dns(
            Dns {
                socket: service.dns.socket.clone(),
            },
            serde_json::from_str(payload)?,
        )),
        _ => Err("unknown outbox operation".into()),
    }
}

fn deliver(service: &Mutex<Service>, id: i64, kind: &str, payload: &str) -> Result<()> {
    let work = {
        let service = service.lock().map_err(|_| "service lock failed")?;
        prepare(&service, id, kind, payload)?
    };
    // External I/O must never hold the shared service lock.
    match work {
        Work::Audit(log, event) => log.submit(&event)?,
        Work::Dns(dns, record) => dns.register(&record)?,
        Work::Complete => return Ok(()),
    }
    service
        .lock()
        .map_err(|_| "service lock failed")?
        .db
        .complete(id)
}

pub fn run(service: Arc<Mutex<Service>>) -> Result<()> {
    let mut after = 0;
    loop {
        let pending = service
            .lock()
            .map_err(|_| "service lock failed")?
            .db
            .pending_external_after(after)?;
        let full = pending.len() == 64;
        for (id, kind, payload) in pending {
            // Advance even on failure so one unavailable integration cannot starve later jobs.
            after = id;
            if let Err(error) = deliver(&service, id, &kind, &payload) {
                eprintln!("integration delivery pending: {error}");
            }
        }
        if !full {
            after = 0;
            std::thread::sleep(Duration::from_secs(30));
        } else {
            std::thread::yield_now();
        }
    }
}

#[cfg(test)]
#[path = "../../tests/performance/delivery.rs"]
mod tests;
