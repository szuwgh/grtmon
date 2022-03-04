use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{thread, time};

use anyhow::{bail, Result};
use structopt::StructOpt;

#[path = "bpf/.output/tcpconnect.skel.rs"]
mod tcpconnect;
use tcpconnect::*;

#[derive(Debug, StructOpt)]
struct Command {
    #[structopt(default_value = "10000")]
    latency: u64,
    /// Process PID to trace
    #[structopt(default_value = "0")]
    pid: i32,
    /// Thread TID to trace
    #[structopt(default_value = "0")]
    tid: i32,
    #[structopt(short, long)]
    verbose: bool,
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

fn main() -> Result<()> {
    let opts = Command::from_args();

    bump_memlock_rlimit()?;

    let skel_builder = TcpconnectSkelBuilder::default();
    if opts.verbose {
        // skel_builder.obj_builder.verbose(true);
    }

    bump_memlock_rlimit()?;

    let mut open_skel = skel_builder.open()?;
    //Pass configuration to BPF
    // Write arguments into prog
    open_skel.rodata().min_us = opts.latency;
    open_skel.rodata().targ_pid = opts.pid;
    open_skel.rodata().targ_tgid = opts.tid;

    let mut skel = open_skel.load()?;
    skel.attach()?;
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    while running.load(Ordering::SeqCst) {
        eprint!(".");
        thread::sleep(time::Duration::from_secs(1));
    }

    Ok(())
}
