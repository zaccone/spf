use mail_auth::{MessageAuthenticator, SpfResult, spf::verify::SpfParameters};
use mail_auth::hickory_resolver::config::{ResolverConfig, ResolverOpts, NameServerConfig};
use std::{sync::Arc, time::{Duration, Instant}};

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let scenario = args.get(1).expect("scenario").clone();
    let workers: usize = args.get(2).expect("workers").parse().unwrap();
    let duration: f64 = args.get(3).expect("seconds").parse().unwrap();
    assert!(workers > 0 && duration > 0.0);
    assert!(["simple", "include", "chain0"].contains(&scenario.as_str()));
    let mut opts = ResolverOpts::default();
    let config = ResolverConfig::from_parts(None, vec![], vec![NameServerConfig::udp_and_tcp("127.0.0.1".parse().unwrap())]);
    opts.cache_size = 0;
    opts.attempts = 1;
    opts.timeout = Duration::from_secs(2);
    let shared = args.get(4).is_some_and(|v| v == "shared");
    let auth = Arc::new(MessageAuthenticator::new(config.clone(), opts.clone()).unwrap());
    let domain = format!("{scenario}.benchmark.test");
    let sender = format!("sender@{domain}");
    let ip = "192.0.2.1".parse().unwrap();
    for _ in 0..100 {
        let out = auth.verify_spf(SpfParameters::verify_mail_from(ip, "mail.benchmark.test", "receiver.benchmark.test", &sender)).await;
        assert_eq!(out.result(), SpfResult::Pass);
    }
    let barrier = Arc::new(tokio::sync::Barrier::new(workers + 1));
    let (tx, rx) = tokio::sync::watch::channel(None::<Instant>);
    let mut tasks = Vec::new();
    for _ in 0..workers {
        let worker_auth = if shared { auth.clone() } else { Arc::new(MessageAuthenticator::new(config.clone(), opts.clone()).unwrap()) };
        let (auth, sender, barrier, mut rx) = (worker_auth, sender.clone(), barrier.clone(), rx.clone());
        tasks.push(tokio::spawn(async move {
            let mut histogram = vec![0u64; 100001];
            let (mut n, mut errors) = (0u64, 0u64);
            barrier.wait().await;
            rx.changed().await.unwrap();
            let deadline = rx.borrow().unwrap();
            while Instant::now() < deadline {
                let t = Instant::now();
                let out = auth.verify_spf(SpfParameters::verify_mail_from(ip, "mail.benchmark.test", "receiver.benchmark.test", &sender)).await;
                if out.result() != SpfResult::Pass { errors += 1; }
                histogram[t.elapsed().as_micros().min(100000) as usize] += 1;
                n += 1;
            }
            (n, errors, histogram)
        }));
    }
    barrier.wait().await;
    let start = Instant::now();
    tx.send(Some(start + Duration::from_secs_f64(duration))).unwrap();
    let (mut n, mut errors) = (0u64, 0u64);
    let mut hist = vec![0u64; 100001];
    for task in tasks {
        let (count, errs, h) = task.await.unwrap();
        n += count; errors += errs;
        for (a, b) in hist.iter_mut().zip(h) { *a += b; }
    }
    let seconds = start.elapsed().as_secs_f64();
    let mut out = serde_json::json!({"implementation":"mail-auth", "resolver_sharing":if shared {"shared"} else {"per-worker"}, "scenario":scenario, "workers":workers, "n":n, "errors":errors, "seconds":seconds, "qps":n as f64/seconds, "runtime_threads":4});
    for p in [50, 75, 90, 99] {
        let mut sum = 0;
        for (i, v) in hist.iter().enumerate() {
            sum += v;
            if sum >= (n*p+99)/100 { out[format!("p{p}_us")] = i.into(); break; }
        }
    }
    println!("{out}");
    assert_eq!(errors, 0);
}
