use aya::maps::{PerCpuArray, PerCpuValues};
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::util::nr_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{debug, info, warn};
use tc_sni_extractor_common::SniBuffer;
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/tc-sni-extractor"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/tc-sni-extractor"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let mut array = PerCpuArray::try_from(bpf.map_mut("SNI_BUFFER").unwrap())?;
    let nr_cpus = nr_cpus()?;
    array.set(
        0,
        PerCpuValues::try_from(vec![SniBuffer { buf: [0; 64] }; nr_cpus]).unwrap(),
        0,
    )?;
    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev <iface> clsact'.
    let _ = tc::qdisc_add_clsact(&opt.iface);
    let program: &mut SchedClassifier = bpf.program_mut("tc_sni_extractor").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, TcAttachType::Egress)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
