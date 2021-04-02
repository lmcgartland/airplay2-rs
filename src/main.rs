use std::any::Any;
use std::sync::Arc;
use tokio::runtime::Builder;
use tokio::time;
use zeroconf::prelude::*;
use zeroconf::{MdnsBrowser, ServiceDiscovery};
use std::time::{Instant, Duration};

#[tokio::main]
pub async fn main() {
    // Create a dedicated thread that allows us to use our !Send browser service
    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    std::thread::spawn(move || {
        let local = tokio::task::LocalSet::new();

        local.spawn_local(async move {
            let mut browser = MdnsBrowser::new("_airplay._tcp");

            browser.set_service_discovered_callback(Box::new(on_service_discovered));

            let start_time = Instant::now();

            let event_loop = browser.browse_services().unwrap();
            let loop_timeout = 3;
            loop {
                let current_time = Instant::now();
                if current_time.duration_since(start_time) > Duration::from_secs(loop_timeout) {
                    println!("\nEnded scan after {} seconds!\n", loop_timeout);
                    break;
                }
                // calling `poll()` will keep this browser alive
                let poll_timeout = Duration::from_secs(0);
                event_loop.poll(poll_timeout).unwrap(); 
            }
        });

        rt.block_on(local);
    });

    // Loop to keep the main program running
    loop {}
}

fn on_service_discovered(
    result: zeroconf::Result<ServiceDiscovery>,
    _context: Option<Arc<dyn Any>>,
) {
    match result {
        Ok(service_discovered) => {
            println!("Service discovered: {:?}", service_discovered);
            let txt = service_discovered.txt();
            match txt {
                Some(txt) => {
                    println!("{:?}", txt.to_map());
                }
                None => {
                    println!("No txt record!");
                }
            }
        }
        Err(err) => {
            println!("Err {:?}", err);
        }
    }

}
